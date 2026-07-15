# BB Orchestrator — MVP local

CLI local para organizar ativos de programas de bug bounty **explicitamente autorizados**.
O fluxo começa com descoberta passiva e aprovação humana obrigatória. Depois da aprovação,
ele permite três verificações ativas mínimas: resolução DNS com `dnsx`, consulta HTTP raiz com
`httpx` e quatro portas TCP fixas com `naabu`. Depois do mapa local, o Katana pode descobrir paths
públicos com profundidade 1, sem autenticação, JavaScript ou headless. Não há fuzzing, nuclei ou
agentes autônomos. Opcionalmente, uma LLM já instalada no Ollama local pode organizar lacunas de
contexto e perguntas defensivas sobre lotes sanitizados, sem ferramentas ou acesso aos alvos.
Depois dessas verificações, um mapa local consolida os estados já persistidos sem gerar tráfego
adicional.

## Requisitos

- Linux
- Python 3.12 ou superior
- `subfinder` no `PATH` (opcional; necessário somente para `recon passive --confirm`)
- `dnsx` no `PATH` (opcional; necessário somente para `verify dns <run-id> --confirm`)
- ProjectDiscovery `httpx` no `PATH` (opcional; necessário somente para
  `verify http <run-id> --confirm`)
- ProjectDiscovery `naabu` no `PATH` (opcional; necessário somente para
  `verify ports <run-id> --confirm`)
- ProjectDiscovery `katana` no `PATH` (opcional; necessário somente para
  `crawl katana <run-id> --confirm`)
- Ollama local em `127.0.0.1:11434`, com o modelo já instalado (opcional; necessário somente para
  `llm triage <run-id> --confirm`)
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
    ├── llm-config.json (opcional)
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
`policy`, `verify`, `ports`, `surface`, `crawl`, `paths`, `assets`, `sanitize`, `queue`, `triage` e
`llm`
recusam a operação com:

```text
Nenhum programa selecionado. Execute: bb program select
```

Os comandos acessam exclusivamente o banco e o diretório `runs/` do programa ativo. Em geral, a
CLI também mostra `Program: <slug>`; `bb llm results` omite metadados para exibir somente as quatro
colunas seguras definidas adiante.

O fluxo seguro é:

```text
scope import → recon passivo → candidatos em escopo → aprovação humana
             → verificação DNS → verificação HTTP → verificação de portas
             → mapa local da superfície
             → descoberta pública de paths → mapa local atualizado
             → assets list/export
             → sanitize → fila → triage --dry-run
             → mapeamento local de fluxos → perguntas opcionais da LLM → revisão humana
```

### Política de execução do programa

Todo programa começa com a política tipada `conservative`. Nesta versão ela é o único perfil
disponível e não há argumentos livres para as ferramentas externas:

```bash
bb policy list
bb policy show
bb policy set conservative
```

DNS mantém 5 threads e 5 consultas/s. HTTP usa 2 threads, 2 req/s, timeout de 10 segundos e zero
retries. Portas usa 2 workers, 4 pacotes/s, timeout de 1000 ms, zero retries, TCP CONNECT e somente
`80,443,8080,8443`. Katana usa modo padrão sem headless ou JavaScript, um processo por host,
concorrência e paralelismo 1, 1 req/s, depth 1, timeout de 10 segundos, zero retry, duração máxima
de 60 segundos, leitura máxima de 1 MiB por resposta e até 100 paths por host. Todo dry-run de
verificação mostra nome, versão e parâmetros efetivos. Cada
confirmação cria no SQLite um snapshot independente com somente nome, versão e parâmetros da
etapa; atualizações futuras da definição não reescrevem o histórico.

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

### 3B. Faça uma verificação HTTP mínima

Somente candidatos aprovados cujo registro DNS mais recente seja `resolved` podem entrar nesta
etapa. Confira o plano sem executar subprocessos, gravar a entrada ou usar a rede:

```bash
bb verify http 1 --dry-run
```

O plano mostra a quantidade elegível, 2 threads, limite de 2 requisições por segundo, timeout de
10 segundos, uma única tentativa e o comando completo. Para autorizar explicitamente a consulta:

```bash
bb verify http 1 --confirm
```

A confirmação executa **somente** o ProjectDiscovery `httpx`. A lista contém apenas hostnames e o
único caminho consultado é `/`. O comando usa JSONL silencioso em memória, omite body, desabilita
o update check e o stdin, e define `-retries 0` porque essa flag conta repetições além da primeira
tentativa:

```text
httpx -l .bb/programs/<slug>/runs/<run-id>/http/input-hosts.txt -json -silent -probe
      -sc -title -td -ob -t 2 -rl 2 -timeout 10 -retries 0 -path /
      -config /dev/null -duc -no-stdin
```

Não são usadas flags para seguir redirects, testar todos os IPs, escolher portas, enviar headers
ou body customizados, capturar screenshots, favicon ou JARM, consultar ASN, fazer TLS probe,
crawling ou adicionar outros paths. Respostas 200, redirects, 401, 403 e 404 são `reachable`;
ausência de uma resposta HTTP válida é `unreachable`.

O JSONL bruto do `httpx` nunca é salvo. Ele é processado somente em memória e reduzido a host,
status code, reachability, ao esquema `http|https` usado e, opcionalmente, título e tecnologias.
Nenhuma URL é persistida. Títulos têm limite de 200
caracteres; tecnologias têm até 20 itens de 80 caracteres. Caracteres de controle são removidos.
Campos com URL, IP, porta, token, e-mail, telefone ou outro padrão proibido são descartados por um
gate default-deny. Headers, cookies, body, resposta raw, query strings e redirect location nunca
são persistidos nem mostrados.

A única gravação em disco fora do SQLite é a entrada determinística:

```text
.bb/programs/<slug>/runs/<run-id>/http/input-hosts.txt
```

Cada confirmação cria uma nova tentativa HTTP por host e preserva o histórico. `bb assets list 1`
mostra os últimos estados DNS e HTTP e o status code; hosts ainda não verificados aparecem como
HTTP `pending` e status `-`. A etapa continua sem alterar `assets export`, `sanitize` ou `triage`.
Se `httpx` não estiver no `PATH`, a CLI pede instalação manual e não instala nada.
Tentativas criadas por versões antigas podem não ter esquema; elas continuam válidas no histórico,
mas o host só fica elegível ao crawler depois de repetir `bb verify http 1 --confirm`.

### 3C. Verifique quatro portas TCP com Naabu

Somente candidatos do programa ativo que continuem `approved`, cujo DNS mais recente seja
`resolved` e cujo HTTP mais recente seja `reachable` são elegíveis:

```bash
bb verify ports 1 --dry-run
bb verify ports 1 --confirm
bb ports list 1
```

O dry-run não consulta o `PATH`, não cria arquivos, não inicia subprocessos e não usa rede. A
confirmação exige `naabu` já instalado e executa uma lista fixa de argumentos: TCP CONNECT,
2 workers, 4 pacotes/s, timeout de 1000 ms, zero retries e portas `80,443,8080,8443`. Update check,
stdin e configuração do usuário ficam desabilitados. Não são habilitados SYN/raw socket, UDP,
ranges, top ports, full scan, scan-all-ips, host discovery, reverse DNS, passive APIs, proxy, Nmap,
service discovery, debug ou verbose.

Os únicos arquivos são:

```text
.bb/programs/<slug>/runs/<run-id>/ports/input-hosts.txt
.bb/programs/<slug>/runs/<run-id>/ports/ports.jsonl
```

O stdout JSONL é tratado como não confiável. Somente pares únicos de hostname elegível e porta
permitida são persistidos. IPs, banners, ASN, payloads e saídas brutas nunca entram no banco, no
JSONL seguro ou na CLI. `ports.jsonl` contém somente host, porta, estado `open`, timestamp, versão
do Naabu, run e referência ao snapshot da política. `bb ports list` exibe apenas `HOST`, `PORTA` e
`STATUS`.

### 3D. Consulte o mapa local da superfície

O mapa consolida dinamicamente somente os dados seguros que já estão no SQLite do programa
ativo. Os dois comandos são locais: não consultam o `PATH`, não iniciam subprocessos e não fazem
DNS, HTTP, conexões de porta ou qualquer outro acesso de rede:

```bash
bb surface list 1
bb surface export 1
```

`surface list` mostra, em ordem de hostname, aprovação, último DNS, último HTTP, status code,
título e tecnologias HTTP sanitizados, portas abertas ordenadas, quantidade de paths e um estágio
objetivo. Candidatos
`pending` e `rejected` continuam visíveis, mas seus dados de verificações ficam ocultos. Para os
aprovados, HTTP só é mostrado quando o último DNS está `resolved`; portas só são mostradas quando
o último HTTP está `reachable`.

O estágio consolidado segue regras fixas e não representa vulnerabilidade, criticidade ou
exploração:

- sem DNS `resolved`: `pending`;
- DNS `resolved` e HTTP `pending|unreachable`: `dns_resolved`;
- HTTP `reachable` sem portas ou paths registrados: `http_reachable`;
- HTTP `reachable` com ao menos uma porta aberta e sem paths: `ports_observed`;
- HTTP `reachable` com paths registrados: `paths_observed`.

O export grava atomicamente um único JSONL determinístico e substitui somente esse artefato:

```text
.bb/programs/<slug>/runs/<run-id>/surface/surface.jsonl
```

Cada linha contém os mesmos dez campos seguros da listagem, incluindo somente `path_count`, nunca
a lista de paths. Valores ausentes usam `null` ou
listas vazias no JSONL. IPs, URLs, headers, cookies, body, redirects, banners, versões de
ferramentas, snapshots de política e dados brutos não são consultados nem exportados. A operação
não cria assets e não altera candidatos, tentativas, portas, fila ou triage.

### 3E. Descubra paths públicos básicos com Katana

Somente candidatos que continuem `approved`, com últimos estados DNS `resolved` e HTTP
`reachable`, e cujo HTTP mais recente possua esquema sanitizado, são elegíveis:

```bash
bb crawl katana 1 --dry-run
bb crawl katana 1 --confirm
bb paths list 1
```

O dry-run consulta apenas o banco local: não procura o binário, não cria arquivo, não inicia
subprocesso e não usa rede. A confirmação exige Katana já presente no `PATH`, consulta `katana -h`
para validar as flags suportadas e nunca instala, atualiza ou baixa ferramentas. Cada host roda
sequencialmente em um processo separado, com seed formado somente em memória como
`<scheme>://<host>/` e stdin em `DEVNULL`; nenhuma lista de URLs é criada.

O comando limita concorrência e paralelismo a 1, taxa a 1 req/s, depth a 1, timeout a 10 segundos,
zero retry, duração a 60 segundos e leitura de resposta a 1 MiB. O escopo é o FQDN do seed,
redirects são desabilitados e a única saída pedida é `path`. Update check e configuração do usuário
ficam desabilitados. Headless, Chrome, JavaScript crawl, JSluice, XHR, forms, headers, cookies,
autenticação, proxy, resolvers customizados, known-files, respostas brutas, debug, verbose e métodos
não GET não são habilitados.

O stdout é processado somente em memória e tratado como não confiável. Apenas paths relativos que
começam com `/` são considerados; query e fragmento são removidos. URLs, hostnames, IPs, portas,
credenciais, controles, tokens, e-mails, telefones e valores acima de 512 caracteres são recusados.
Depois de normalização e deduplicação, no máximo 100 paths por host entram no SQLite. A listagem
mostra exclusivamente `HOST`, `PATH` e `SOURCE`.

O único artefato da etapa é substituído atomicamente e contém somente `host`, `path` e
`source="katana"`:

```text
.bb/programs/<slug>/runs/<run-id>/crawl/paths.jsonl
```

A etapa cria um snapshot próprio da política e registros em `crawl_paths`, mas não altera
candidatos, aprovação, DNS, HTTP, portas, assets, fila ou triage.

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

### 7. Gere o mapeamento determinístico de fluxos

Esta fase mapeia **pistas de fluxos de produto**, não vulnerabilidades, severidade ou prioridade.
Um nome conhecido é somente um sinal lexical inicial. Ele não prova tipo real de dado, vínculo com
usuário, presença ou ausência de controle, impacto ou regra violada. A regra central é:

> Contexto não observado nunca significa controle ausente.

Gere os lotes localmente, sem rede, subprocesso ou chamada à LLM:

```bash
bb triage 3 --dry-run
bb triage 3 --dry-run --batch-size 20
```

Os novos arquivos são
`.bb/programs/<slug>/runs/<run-id>/llm/flow-map-input-<batch-id>.json`. Lotes antigos
`triage-input-*.json`, snapshots, resultados antigos, `route-priority-v1` e a política de execução
`conservative` não são alterados. Reexecutar o comando substitui somente `flow-map-input-*` da
mesma run, de forma determinística.

O Python aplica `flow-signal-policy-v1` antes da LLM e ordena a taxonomia:
`IDENTITY_ACCESS`, `USER_DATA_RESOURCE`, `TRANSACTION_ORDER`, `MONEY_VALUE`,
`BENEFIT_ENTITLEMENT`, `STATE_WORKFLOW`, `ADMIN_PRIVILEGED`, `INTEGRATION_API`,
`CONTENT_PUBLIC` e `UNKNOWN_DYNAMIC`. A correspondência usa segmentos completos em lowercase;
por isso `/accounting` não corresponde a `account`. Hífens só correspondem quando o alias composto
está explicitamente na política.

Paths estáticos, JavaScript e CSS nunca são evidência de fluxo. Status HTTP, título, Cloudflare ou
outra tecnologia também não entram no novo lote. Cada sinal guarda até cinco paths lexicográficos
e mantém o total em `evidence_paths_total`. Um path dinâmico sem correspondência — inclusive
`/workspace` ou `/x7/portal` — é preservado em `unknown_dynamic_paths`; nome incomum nunca equivale
a descarte.

Aliases confirmados manualmente podem ser colocados somente em
`.bb/programs/<slug>/flow-aliases-v1.json`. Cada entrada registra o mesmo `program_id`, origem
`manual`, versão e timestamp com timezone, e associa um segmento ou path a uma categoria geral:

```json
{
  "policy": "flow-aliases-v1",
  "program_id": "acme",
  "aliases": [
    {
      "program_id": "acme",
      "origin": "manual",
      "version": "1",
      "timestamp": "2026-07-15T12:00:00-03:00",
      "match_type": "segment",
      "value": "workspace",
      "flow_type": "USER_DATA_RESOURCE"
    }
  ]
}
```

O arquivo é estrito e isolado pelo diretório e `program_id`: aliases não vazam entre programas.
A LLM nunca cria ou persiste aliases. Uma inferência da LLM sobre path desconhecido permanece
explicitamente `TENTATIVE_PATH_SEMANTIC_INFERENCE`, exige `OTHER_CONTEXT_NOT_OBSERVED` e continua
dependendo de revisão humana.

### 8. Organize lacunas com uma LLM local, sem ferramentas

A LLM recebe exclusivamente `flow-map-input-*.json`. Ela não pode alterar ou omitir sinais
determinísticos; apenas organiza lacunas permitidas, mantém cada path desconhecido ou sugere uma
categoria tentativa e formula até três perguntas defensivas em português brasileiro. Ela não lê
os lotes legados, SQLite de superfície, status, títulos, tecnologias, respostas HTTP, headers,
cookies, tokens, IPs, portas ou conteúdo JavaScript.

Configure um modelo já instalado. O endpoint continua fixo em
`http://127.0.0.1:11434/api/chat`; não há provedor remoto, ferramentas ou tool-calling:

```bash
bb llm ollama configure --model qwen2.5:7b
bb llm ollama configure --model gpt-oss:20b --profile gpt_oss_json
bb llm ollama profiles
bb llm status
```

`generic_ollama_json` omite `think`; `gpt_oss_json` envia somente `think: "low"`. Ambos usam
`stream: false`, temperatura zero e structured output. O schema de `FlowMappingResponse` é a fonte
única usada pelo Pydantic, pelo campo Ollama `format`, pela cópia compacta no prompt e pelo
fingerprint persistido.

Como schema e protocolo mudaram, uma verificação anterior fica `stale`. Revalide com o JSON
inofensivo `{"ok": true}`; essa chamada nunca recebe hosts, paths, fluxos ou dados de programa:

```bash
bb llm ollama verify --confirm
```

Inspecione o plano sem abrir conexão e depois confirme explicitamente:

```bash
bb llm triage 3 --dry-run
bb llm triage 3 --confirm
bb llm results 3
```

Em sequência, o fluxo da etapa é:

```bash
bb triage 3 --dry-run
bb llm ollama verify --confirm
bb llm triage 3 --dry-run
bb llm triage 3 --confirm
bb llm results 3
```

O dry-run mostra programa, modelo, profile, prompt, políticas, lotes, assets, sinais
determinísticos, paths desconhecidos e fluxos que exigem contexto. A confirmação processa lotes
serialmente, uma vez cada, sem retry e com timeout de 90 segundos. O Ollama fornece somente
`message.content`; `message.thinking` é descartado integralmente.

`flow-output-policy-v1` falha fechado se houver asset, path, enum, fluxo ou alias inventado; sinal
determinístico ou path desconhecido ausente/duplicado; lacuna mínima omitida; pergunta sem fluxo ou
lacuna correspondente; asset `CONTEXT_REQUIRED` sem pergunta; campo extra; Markdown; texto fora do
JSON; URL, query, fragmento, IP, porta, credencial, header, cookie ou PII; ou pergunta que antecipe
vulnerabilidade, IDOR, bypass, exploit, controle ausente ou regra violada. Nada é completado ou
reinterpretado silenciosamente.

Somente a resposta integralmente validada é gravada em novas tabelas e em
`.bb/programs/<slug>/runs/<run-id>/llm/results/flow-mapping-results.json`. Resposta bruta,
chain-of-thought, `message.thinking` e conteúdo inválido nunca são persistidos. A listagem nova usa
`HOST | FLUXOS | LACUNAS | PERGUNTAS`. Se houver somente resultados antigos, ela os identifica
como `legacy_triage` e não mistura formatos. A revisão humana continua obrigatória.

## Bancos locais isolados

Cada programa usa exclusivamente `.bb/programs/<slug>/orchestrator.db`. Fechar o terminal não
apaga regras, runs, candidatos, assets ou itens da fila, e trocar a seleção não mistura dados entre
programas. O arquivo `.bb/current-program.json` contém somente o slug atualmente selecionado.

As tabelas incluem `programs`, `program_policies`, `execution_policy_snapshots`, `scope_rules`,
`runs`, `candidates`, `dns_verification_attempts`, `http_verification_attempts`,
`port_observations`, `crawl_paths`, `assets`, `queue_items`, `llm_triage_attempts`,
`llm_triage_results`, `flow_mapping_attempts`, `flow_mapping_results` e
`ollama_compatibility_verifications`. Cada banco
armazena apenas os metadados e dados daquele programa: regras, hosts normalizados, fonte, estados,
timestamps, contadores, referências e hashes SHA-256. O conteúdo bruto e o caminho do JSONL
manual não são persistidos. As saídas reduzidas e entradas seguras existem somente no diretório
`runs/` do programa ativo; não há saída DNS, HTTP ou Naabu bruta em disco.
O mapa da superfície não possui tabela própria: listagem e exportação são projeções das tabelas
existentes.

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

- A única LLM suportada é um modelo já instalado no Ollama local, acessado no endpoint fixo de
  loopback. Sem LiteLLM, LM Studio, DeepSeek ou provedores remotos.
- A LLM somente organiza contexto não observado e formula perguntas defensivas sobre lotes
  sanitizados; não classifica vulnerabilidade ou prioridade e não possui ferramentas, ações contra
  alvos, comandos, PoC ou capacidade de confirmação.
- Sem GUI, servidor web ou Docker.
- A descoberta de hosts é somente o subfinder passivo, após `--confirm`.
- A verificação DNS usa somente dnsx, com 5 threads e 5 DNS/s, após aprovação humana.
- A verificação HTTP usa somente httpx, com 2 threads, 2 req/s, raiz, timeout de 10 segundos e sem
  redirects, somente após o DNS mais recente estar `resolved`.
- A verificação de portas usa somente Naabu em TCP CONNECT, nas quatro portas fixas, após HTTP
  `reachable` e sempre com `--confirm`.
- O mapa da superfície apenas consolida estados locais já persistidos e não gera novo tráfego.
- O crawler é somente Katana público, depth 1, sem autenticação, JavaScript ou headless, sempre com
  `--confirm` e limites fixos.
- Sem ranges/full scan, UDP, SYN/raw socket, Nmap, ffuf, nuclei ou crawling autenticado.
- Sem processamento de requisições/respostas HTTP brutas ou segredos.
