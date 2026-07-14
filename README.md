# BB Orchestrator — MVP local

CLI local para organizar ativos de programas de bug bounty **explicitamente autorizados**.
O fluxo começa com descoberta passiva e aprovação humana obrigatória. Depois da aprovação,
esta etapa permite a primeira verificação ativa: uma resolução DNS mínima com `dnsx`. Nenhum
comando faz HTTP, crawling, port scan, fuzzing, nuclei ou integração com modelos de linguagem.

## Requisitos

- Linux
- Python 3.12 ou superior
- `subfinder` no `PATH` (opcional; necessário somente para `recon passive --confirm`)
- `dnsx` no `PATH` (opcional; necessário somente para `verify dns <run-id> --confirm`)
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
`verify`, `assets`, `sanitize`, `queue` e `triage` recusam a operação com:

```text
Nenhum programa selecionado. Execute: bb program select
```

Todo comando que usa dados mostra `Program: <slug>` e acessa exclusivamente o banco e o diretório
`runs/` desse programa.

O fluxo seguro é:

```text
scope import → recon passivo → candidatos em escopo → aprovação humana
             → verificação DNS → assets list/export → sanitize → fila → triage --dry-run
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

Para criar a run e executar a descoberta autorizada, confirme explicitamente pela própria flag:

```bash
bb recon passive --confirm
```

`--confirm` é a autorização explícita e não abre uma segunda pergunta. O comando executa somente
`subfinder -silent -duc`, passando por `-d` as raízes que tenham uma regra wildcard. Não habilita
modo ativo, resolução DNS, HTTP contra os hosts, port scan, crawler, ffuf, nuclei ou qualquer outra
ferramenta. Se houver wildcard e o binário não estiver no `PATH`, a CLI explica que ele deve ser
instalado manualmente e não tenta instalar nada.

Regras exatas não são enviadas ao subfinder: cada uma gera diretamente um candidato pendente com
fonte `scope_exact`. Assim, uma run que tenha somente regras exatas não procura nem executa o
binário. Se um host exato também aparecer na saída do subfinder, a fonte `scope_exact` prevalece e
o host continua único na run.

A saída validada e já filtrada pelo escopo fica em
`.bb/programs/<slug>/runs/<run-id>/raw/subfinder.txt`. Por segurança,
somente hostnames válidos e em escopo podem ser persistidos nesse arquivo. Cada linha é normalizada
e deduplicada. URLs, IPs, linhas inesperadas e hosts fora do escopo são descartados sem aparecer em
`candidates` ou na listagem.

### 3. Aprove ou rejeite candidatos

Liste somente os candidatos pendentes e em escopo:

```bash
bb candidates list 1
```

A descoberta nunca cria assets automaticamente. Uma ação humana explícita é obrigatória. Aprove
todos os pendentes em escopo ou informe um ou mais hosts repetindo `--host`:

```bash
bb candidates approve 1 --all
bb candidates approve 1 --host api.example.com --host dev.example.com
bb candidates reject 1 --host old.example.com --host legacy.example.com
```

Aprovação e rejeição são idempotentes: repetir a mesma decisão não altera o timestamp nem cria
registros duplicados. Os estados aprovados e rejeitados são terminais, preservando no SQLite o
host, a fonte, o estado, a criação e o momento da aprovação para auditoria.

### 3A. Faça a primeira verificação ativa por DNS

Antes de autorizar tráfego DNS, confira o plano da run:

```bash
bb verify dns 1 --dry-run
```

O modo `--dry-run` mostra `Program: <slug>`, a quantidade de hosts aprovados, os limites e o
comando planejado. Ele não procura nem executa o binário, não grava os arquivos DNS e não usa a
rede. Runs inexistentes ou sem candidatos aprovados são recusadas.

Para confirmar explicitamente a verificação:

```bash
bb verify dns 1 --confirm
```

Essa é a primeira verificação ativa do fluxo e executa **somente** `dnsx`, com uma lista de entrada,
saída silenciosa, 5 threads e limite de 5 consultas DNS por segundo:

```text
dnsx -l .bb/programs/<slug>/runs/<run-id>/dns/input-hosts.txt -silent -t 5 -rl 5
```

Não são habilitadas flags de resposta, IP, ASN, CNAME, TXT, MX ou qualquer outro registro. A saída
do processo é tratada como não confiável: somente hostnames normalizados que já estavam na lista
aprovada podem ser gravados. IPs, respostas DNS brutas, URLs e linhas inesperadas são descartados.
Se `dnsx` não estiver no `PATH`, a CLI pede instalação manual e nunca tenta instalá-lo.

Os únicos artefatos desta etapa são:

```text
.bb/programs/<slug>/runs/<run-id>/dns/input-hosts.txt
.bb/programs/<slug>/runs/<run-id>/dns/resolved-hosts.txt
```

O primeiro contém somente os candidatos aprovados e em escopo; o segundo, somente os hosts que
resolveram. Ambos são ordenados e substituídos atomicamente para manter uma saída determinística.
No SQLite, cada confirmação cria uma nova tentativa por candidato, preservando o histórico com
host, estado `pending|resolved|unresolved`, horário, versão do dnsx quando informada pelo processo,
run e programa. Nenhum IP ou conteúdo DNS bruto é persistido.

Consulte aprovação e o estado DNS mais recente sem materializar ou alterar assets:

```bash
bb assets list 1
```

Esse comando mostra `host`, estado de aprovação e estado DNS. Um candidato ainda não verificado
aparece como DNS `pending`. Esta etapa não altera o comportamento de `assets export`, `sanitize`
ou `triage`.

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
**candidatos pendentes**, nunca assets aprovados. Portanto, depois dela também é obrigatório usar
`candidates approve` ou `candidates reject`. Campos extras são recusados para evitar HTTP bruto,
headers, cookies, tokens, query strings ou PII.

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

Somente itens pendentes associados a assets sanitizados e a candidatos aprovados entram nos lotes:

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

As tabelas incluem `programs`, `scope_rules`, `runs`, `candidates`,
`dns_verification_attempts`, `assets` e `queue_items`. Cada banco armazena apenas os metadados e
dados daquele programa: regras, hosts normalizados, fonte, estados, timestamps, contadores,
referências e hashes SHA-256. O conteúdo bruto e o caminho do JSONL manual não são persistidos.
As saídas seguras do subfinder e do dnsx existem somente no diretório `runs/` do programa ativo.

Não coloque API keys em código, arquivos JSON/JSONL ou SQLite. O orquestrador não lê, grava ou
gerencia credenciais de provedores do subfinder.

## Qualidade

Com o ambiente virtual ativo:

```bash
ruff format --check .
ruff check .
pytest
python -m compileall -q src tests
```

Para aplicar a formatação automaticamente:

```bash
ruff format .
```

## Limites desta entrega

- Sem LLMs, LiteLLM, DeepSeek ou GPT-OSS.
- Sem GUI, servidor web ou Docker.
- A única descoberta automática é o subfinder passivo, após `--confirm`.
- A única verificação ativa é o dnsx limitado a 5 threads e 5 DNS/s, após aprovação humana e
  `verify dns <run-id> --confirm`.
- Sem httpx, port scan, crawler, ffuf, nuclei ou tráfego HTTP contra os hosts descobertos.
- Sem processamento de requisições/respostas HTTP brutas ou segredos.
