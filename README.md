# BB Orchestrator — MVP local

CLI local para organizar ativos de programas de bug bounty **explicitamente autorizados**.
Esta primeira entrega não faz requisições de rede, não executa ferramentas contra alvos e não
integra modelos de linguagem.

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

### 1. Importe o escopo autorizado

Crie `scope.txt` com uma regra por linha. Linhas vazias e comentários iniciados por `#` são
ignorados.

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

Crie `assets.jsonl`. Cada linha deve ter **somente** o campo `domain`:

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

## Banco local

O banco é criado automaticamente em `.bb/orchestrator.db`. Para escolher outro caminho:

```bash
export BB_DB_PATH=/caminho/local/orchestrator.db
bb queue list
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
