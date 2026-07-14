# BB Orchestrator — MVP local

CLI local para organizar ativos de programas de bug bounty **explicitamente autorizados**.
Esta etapa prepara lotes determinísticos para triagem futura, mas não faz requisições de rede,
não executa ferramentas contra alvos e não integra modelos de linguagem.

## Requisitos

- Linux
- Python 3.12 ou superior
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

### Antes de começar: escopo não é ingestão

Os dois comandos recebem domínios, mas têm responsabilidades diferentes:

| Comando | Arquivo de entrada | O que representa | O que grava |
| --- | --- | --- | --- |
| `bb scope import scope.txt` | Regras como `example.com` e `*.example.com` | O perímetro que o programa autorizou | Regras reutilizáveis em `scope_rules` |
| `bb run ingest assets.jsonl` | Hosts concretos como `api.example.com` | Ativos observados que você quer processar agora | Uma nova run e somente os assets autorizados |

Em outras palavras, `scope import` responde **“o que posso aceitar?”** e `run ingest` responde
**“quais ativos encontrei nesta coleta?”**. A ingestão sempre consulta o escopo já importado. Um
domínio fora dele é recusado e não vira asset.

O fluxo completo é:

```text
scope.txt ──> scope import ──> regras autorizadas
                                  │
assets.jsonl ──> run ingest ──────┘──> run ──> sanitize ──> fila ──> triage
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

- `example.com` autoriza somente o domínio exato.
- `*.example.com` autoriza subdomínios como `api.example.com`, mas não o domínio raiz.
- Comparações usam limites de rótulos DNS. Por isso, `example.com.attacker.test` e
  `notexample.com` são recusados.
- URLs, portas, credenciais, IPs, wildcards em outras posições e domínios inválidos são recusados.

### 2. Faça uma ingestão local

Agora crie `assets.jsonl` com os hosts concretos obtidos de uma fonte local autorizada. Cada linha
deve ter **somente** o campo `domain`:

```jsonl
{"domain":"example.com"}
{"domain":"api.example.com"}
{"domain":"third-party.test"}
```

Execute:

```bash
bb run ingest assets.jsonl
```

A ingestão aplica normalização, filtro de escopo e deduplicação em Python determinístico. Ativos
fora do escopo são contados e descartados; não entram no SQLite. Campos extras são recusados para
evitar a ingestão acidental de HTTP bruto, headers, cookies, tokens, query strings ou PII.

Cada execução de `run ingest` cria uma nova run. A CLI mostra seu ID, por exemplo:

```text
Run 1: aceitos=2, rejeitados=1, duplicados=0.
```

Guarde esse número para `sanitize` e `triage`. Se fechar o terminal, ele pode ser consultado na
coluna `RUN` de `bb queue list` depois que a run tiver sido sanitizada.

### 3. Sanitize a run

Use o identificador exibido pela ingestão:

```bash
bb sanitize 1
```

Nesta etapa, sanitizar significa promover apenas os domínios canônicos já validados e criar
referências na fila. A operação é idempotente e a fila não contém payload bruto.

### 4. Consulte a fila

```bash
bb queue list
```

### 5. Prepare a triagem em modo local

Somente itens pendentes associados a assets sanitizados entram nos lotes:

```bash
bb triage 1 --dry-run
```

O tamanho padrão é 10. É possível escolher entre 1 e 20 itens por lote:

```bash
bb triage 1 --dry-run --batch-size 20
```

Os arquivos são gravados em `runs/<run-id>/llm/triage-input-<batch-id>.json`. Por exemplo:

```text
runs/1/llm/triage-input-0001.json
runs/1/llm/triage-input-0002.json
```

`run-id` e `batch-id` são identificadores diferentes:

- Em `bb triage 1 --dry-run`, o `1` é o ID persistente da run no SQLite.
- `0001` significa “primeiro lote desta run”; a numeração começa novamente em cada run.
- Com o tamanho padrão, uma run com 1 a 10 itens gera apenas `triage-input-0001.json`; com 11 a
  20 itens, gera `0001` e `0002`.
- Assim, as runs 1 e 2 podem ter, cada uma, seu próprio arquivo `triage-input-0001.json`, em
  diretórios diferentes: `runs/1/llm/` e `runs/2/llm/`.

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

## Banco local

O banco é criado automaticamente em `.bb/orchestrator.db`. Para escolher outro caminho:

```bash
export BB_DB_PATH=/caminho/local/orchestrator.db
bb queue list
```

O SQLite é persistente: fechar o terminal não apaga regras, runs, assets ou itens da fila. Ao abrir
outro terminal no mesmo diretório, a CLI volta a usar `.bb/orchestrator.db`. Uma nova ingestão cria
uma nova run; ela não reinicia a numeração anterior.

Para fazer uma demonstração isolada sem reutilizar o banco padrão, escolha outro arquivo antes de
executar os comandos:

```bash
export BB_DB_PATH=.bb/demo.db
```

As tabelas são `scope_rules`, `runs`, `assets` e `queue_items`. O banco armazena regras, domínios
normalizados, estados, contadores, referências e o SHA-256 do arquivo de entrada. O conteúdo bruto
do JSONL e seu caminho não são persistidos.

Não coloque API keys em código, arquivos JSON/JSONL ou SQLite. Este MVP não lê nem utiliza API
keys.

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
- Sem scanners, clientes HTTP, resolução DNS ou qualquer tráfego contra alvos.
- Sem processamento de requisições/respostas HTTP brutas ou segredos.
