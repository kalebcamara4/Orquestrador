# BB Orchestrator — MVP local

CLI local para organizar ativos de programas de bug bounty **explicitamente autorizados**.
Esta etapa acrescenta descoberta passiva com aprovação humana obrigatória. Somente
`bb recon passive --confirm` pode executar uma ferramenta externa: o `subfinder`, em modo
passivo. Nenhum comando consulta por DNS, HTTP ou scan os hosts descobertos, e não há integração
com modelos de linguagem.

## Requisitos

- Linux
- Python 3.12 ou superior
- `subfinder` no `PATH` (opcional; necessário somente para `recon passive --confirm`)
- VS Code (opcional)

## Instalação

Na raiz do projeto:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Confira a CLI:

```bash
bb --help
```

Ao abrir a pasta no VS Code, instale as extensões recomendadas. O workspace já aponta para o
interpretador `.venv`, habilita a descoberta dos testes pytest e usa Ruff para formatar Python.

## Uso passo a passo

### Antes de começar: crie e selecione um programa

Cada programa possui banco e artefatos próprios:

```text
.bb/
├── current-program.json
└── programs/<slug>/
    ├── orchestrator.db
    └── runs/
```

Crie um programa. Ao final, a CLI pergunta se ele deve ser selecionado:

```bash
bb program create acme --name "Acme Bug Bounty"
```

Gerencie e consulte os programas com:

```bash
bb program list
bb program show
bb program select acme
bb program archive acme
```

`bb program select <slug>` é não interativo e apropriado para scripts. Sem o slug, o comando abre
um seletor `questionary` com setas e `Enter`, mostrando somente programas não arquivados:

```bash
bb program select
```

Arquivar retira o programa do seletor e limpa a seleção se ele estiver ativo, mas nunca apaga seu
banco nem seus artefatos. Sem programa ativo, comandos como `scope`, `recon`, `run`, `candidates`,
`assets`, `sanitize`, `queue` e `triage` recusam a operação com:

```text
Nenhum programa selecionado. Execute: bb program select
```

Todo comando que usa dados mostra `Program: <slug>` e acessa exclusivamente o banco e o diretório
`runs/` desse programa.

O fluxo seguro é:

```text
scope import → recon passivo → candidatos em escopo → aprovação humana
             → assets export → sanitize → fila → triage --dry-run
```

### 1. Importe o escopo autorizado

Este arquivo não é uma lista de descobertas. Ele descreve os domínios e wildcards que o programa
de bug bounty autorizou. Crie `scope.txt` com uma regra por linha. Linhas vazias e comentários
iniciados por `#` são ignorados.

```text
example.com
*.example.com
```

Importe as regras:

```bash
bb scope import scope.txt
```

- `example.com` autoriza somente o domínio exato e **não** autoriza enumeração.
- `*.example.com` é a única forma que autoriza enumerar a raiz `example.com`; ela aceita
  subdomínios como `api.example.com`, mas não o domínio raiz.
- Comparações usam limites de rótulos DNS. Por isso, `example.com.attacker.test` e
  `notexample.com` são recusados.
- URLs, portas, credenciais, IPs, wildcards em outras posições e domínios inválidos são recusados.

`scope import` define o que foi autorizado. Descoberta, aprovação e exportação nunca ampliam esse
perímetro.

### 2. Confira ou execute a descoberta passiva

Veja quais raízes wildcard poderiam ser enumeradas, sem subprocesso e sem tráfego de rede:

```bash
bb recon passive --dry-run
```

Para executar a descoberta, confirme explicitamente:

```bash
bb recon passive --confirm
```

Antes de criar a run, a CLI mostra todas as raízes e pede uma segunda confirmação `s/N`. Responder
“não” cancela sem executar subprocessos. Após a confirmação, o comando executa somente
`subfinder -silent -duc`, passando as raízes autorizadas por `-d`. Não habilita modo ativo,
resolução DNS, HTTP contra os hosts, port scan, crawler, ffuf, nuclei ou qualquer outra ferramenta.
Se o binário não estiver no `PATH`, a CLI explica que ele deve ser instalado manualmente e não
tenta instalar nada.

A saída anterior ao filtro de escopo fica em
`.bb/programs/<slug>/runs/<run-id>/raw/subfinder.txt`. Por segurança,
somente linhas que sejam hostnames válidos podem ser persistidas nesse arquivo; URLs, IPs e outras
linhas inesperadas são descartados. Cada hostname é normalizado e deduplicado e volta a passar
pelo escopo default-deny. Resultados fora do escopo nunca entram em `candidates`.

### 3. Aprove ou rejeite candidatos

Liste somente os candidatos pendentes e em escopo:

```bash
bb candidates list 1
```

A descoberta nunca cria assets automaticamente. Uma ação humana explícita é obrigatória. Cada
comando abre um checklist no terminal, sem exigir a digitação de hosts:

```bash
bb candidates approve 1
bb candidates reject 1
bb candidates delete 1
```

Use `↑`/`↓` para mover, `Espaço` para marcar, `a` para selecionar todos, `n` para desmarcar todos,
`Enter` para confirmar ou `q` para cancelar. Aprovação e rejeição preservam estados terminais. A
exclusão aceita múltiplos itens, pede confirmação adicional e é lógica: o candidato deixa de
aparecer e nunca vira asset, mas `deleted_at` preserva o histórico auditável no SQLite.

### 4. Exporte os assets aprovados

```bash
bb assets export 1
```

Somente candidatos aprovados e ainda em escopo são gravados, em ordem determinística, em
`.bb/programs/<slug>/runs/<run-id>/assets.jsonl`:

```jsonl
{"domain":"api.example.com"}
```

Uma nova exportação sobrescreve apenas esse arquivo da run. Candidatos pendentes, rejeitados ou
fora do escopo não aparecem.

### Entrada manual e de teste

`bb run ingest` continua disponível para hosts obtidos de uma fonte local autorizada:

```bash
bb run ingest entrada.jsonl
```

Cada linha deve ter **somente** o campo `domain`:

```jsonl
{"domain":"example.com"}
{"domain":"api.example.com"}
{"domain":"third-party.test"}
```

A ingestão aplica a mesma normalização, filtro e deduplicação. Ela cria uma nova run com
**candidatos pendentes**, nunca assets aprovados. Portanto, depois dela também é obrigatório abrir
um dos checklists de `candidates approve`, `candidates reject` ou `candidates delete`. Campos
extras são recusados para evitar HTTP bruto, headers, cookies, tokens, query strings ou PII.

Cada execução de `run ingest` cria uma nova run. A CLI mostra seu ID, por exemplo:

```text
Run 1: aceitos=2, rejeitados=1, duplicados=0.
```

### 5. Sanitize a run

```bash
bb sanitize 1
```

Sanitizar materializa somente candidatos aprovados e ainda em escopo como assets canônicos e cria
referências na fila. A operação é idempotente e a fila não contém payload bruto.

### 6. Consulte a fila

```bash
bb queue list
```

### 7. Prepare a triagem em modo local

Somente itens pendentes associados a assets sanitizados entram nos lotes:

```bash
bb triage 1 --dry-run
```

O tamanho padrão é 10. É possível escolher entre 1 e 20 itens por lote:

```bash
bb triage 1 --dry-run --batch-size 20
```

Os arquivos são gravados em
`.bb/programs/<slug>/runs/<run-id>/llm/triage-input-<batch-id>.json`. Por exemplo:

```text
.bb/programs/acme/runs/1/llm/triage-input-0001.json
.bb/programs/acme/runs/1/llm/triage-input-0002.json
```

`run-id` e `batch-id` são identificadores diferentes:

- Em `bb triage 1 --dry-run`, o `1` é o ID persistente da run no SQLite.
- `0001` significa “primeiro lote desta run”; a numeração começa novamente em cada run.
- Com o tamanho padrão, uma run com 1 a 10 itens gera apenas `triage-input-0001.json`; com 11 a
  20 itens, gera `0001` e `0002`.
- Assim, as runs 1 e 2 podem ter, cada uma, seu próprio arquivo `triage-input-0001.json`, em
  diretórios diferentes dentro de `.bb/programs/<slug>/runs/`.

Executar novamente a triagem da mesma run recria os mesmos lotes deterministicamente e substitui
os arquivos `triage-input-*.json` daquele diretório. Nesta etapa, triage não consome a fila e não
altera `pending`: ela apenas prepara arquivos locais para a futura integração com LLM.

Cada item possui um `asset_id` derivado deterministicamente do host canônico e contém somente a
allowlist abaixo:

```json
{
  "asset_id": "asset-<sha256>",
  "host": "api.example.com",
  "status": null,
  "title": null,
  "technologies": [],
  "paths": []
}
```

O JSON final passa por um policy gate default-deny antes da gravação. Campos extras, URLs, query
strings, IPs, portas, headers, corpo HTTP, cookies, tokens, chaves e PII fazem a preparação falhar.
Uma run inexistente ou sem itens sanitizados e pendentes também falha sem criar lotes.

O schema estrito reservado para uma futura resposta é:

```json
{
  "items": [
    {
      "asset_id": "asset-<sha256>",
      "decision": "IGNORE|LOW_PRIORITY|NEEDS_REVIEW",
      "confidence": "LOW|MEDIUM|HIGH",
      "evidence": [],
      "missing_context": [],
      "manual_review_question": null
    }
  ]
}
```

Nesta etapa, `triage` exige explicitamente `--dry-run`. Ele apenas lê o SQLite e grava arquivos
locais; não importa clientes HTTP, LiteLLM ou Ollama e não envia requisições.

## Bancos locais isolados

Cada programa usa exclusivamente `.bb/programs/<slug>/orchestrator.db`. Fechar o terminal não
apaga regras, runs, candidatos, assets ou itens da fila, e trocar a seleção não mistura dados entre
programas. O arquivo `.bb/current-program.json` contém somente o slug atualmente selecionado.

As tabelas incluem `programs`, `scope_rules`, `runs`, `candidates`, `assets` e `queue_items`. Cada
banco armazena apenas os metadados e dados daquele programa: regras, hosts normalizados, fonte,
estados, timestamps, contadores, referências e hashes SHA-256. O conteúdo bruto e o caminho do
JSONL manual não são persistidos. A saída segura do subfinder existe somente no diretório `runs/`
do programa ativo.

Não coloque API keys em código, arquivos JSON/JSONL ou SQLite. O orquestrador não lê, grava ou
gerencia credenciais de provedores do subfinder.

## Qualidade

Com o ambiente virtual ativo:

```bash
ruff format --check .
ruff check .
pytest
```

Para aplicar a formatação automaticamente:

```bash
ruff format .
```

## Limites desta entrega

- Sem LLMs, LiteLLM, DeepSeek ou GPT-OSS.
- Sem GUI, servidor web ou Docker.
- A única descoberta automática é o subfinder passivo, após `--confirm`; sem dnsx, httpx, port
  scan, crawler, ffuf, nuclei ou tráfego DNS/HTTP contra os hosts descobertos.
- Sem processamento de requisições/respostas HTTP brutas ou segredos.
