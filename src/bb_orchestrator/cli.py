"""CLI Typer do MVP local."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Annotated

import questionary
import typer

from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.llm import (
    ADAPTER_PROTOCOL_VERSION,
    COMPATIBILITY_PROMPT_VERSION,
    FLOW_PROMPT_VERSION,
    OLLAMA_PROFILES,
    LlmError,
    OllamaProfileName,
    configure_ollama,
    inspect_flow_mapping,
    inspect_ollama_verification,
    llm_results_view,
    load_ollama_config,
    ollama_compatibility_state,
    run_flow_mapping,
    verify_ollama_compatibility,
)
from bb_orchestrator.policies import (
    PolicyError,
    PolicyName,
    available_policies,
    get_program_policy,
    set_program_policy,
)
from bb_orchestrator.programs import (
    ProgramError,
    archive_program,
    create_program,
    current_program_slug,
    list_programs,
    require_active_program,
    select_program,
)
from bb_orchestrator.services import (
    DEFAULT_TRIAGE_BATCH_SIZE,
    MAX_TRIAGE_BATCH_SIZE,
    InputError,
    approve_candidates,
    build_surface_map,
    crawl_with_katana,
    export_assets,
    export_surface_map,
    import_scope_file,
    ingest_jsonl,
    list_assets_with_dns,
    list_candidates,
    list_crawl_paths,
    list_open_ports,
    list_queue,
    passive_recon_roots,
    plan_dns_verification,
    plan_http_verification,
    plan_katana_crawl,
    plan_port_verification,
    prepare_flow_mapping,
    reject_candidates,
    run_passive_recon,
    sanitize_run,
    verify_dns,
    verify_http,
    verify_ports,
)

app = typer.Typer(name="bb", help="Orquestrador local para bug bounty autorizado.")
scope_app = typer.Typer(help="Gerencia regras determinísticas de escopo.")
run_app = typer.Typer(help="Gerencia execuções locais de ingestão.")
queue_app = typer.Typer(help="Consulta a fila local sanitizada.")
recon_app = typer.Typer(help="Executa descoberta estritamente passiva.")
candidates_app = typer.Typer(help="Gerencia a aprovação humana de candidatos.")
assets_app = typer.Typer(help="Consulta e exporta assets aprovados.")
verify_app = typer.Typer(help="Executa verificações ativas estritamente limitadas.")
program_app = typer.Typer(help="Gerencia programas isolados.")
policy_app = typer.Typer(help="Gerencia políticas tipadas do programa ativo.")
ports_app = typer.Typer(help="Consulta portas abertas verificadas com segurança.")
surface_app = typer.Typer(help="Consolida localmente DNS, HTTP e portas por host.")
crawl_app = typer.Typer(help="Executa descoberta pública estritamente limitada.")
paths_app = typer.Typer(help="Consulta caminhos públicos sanitizados.")
llm_app = typer.Typer(help="Organiza lacunas de contexto com uma LLM estritamente local.")
ollama_app = typer.Typer(help="Configura somente o provedor Ollama local fixo.")
app.add_typer(scope_app, name="scope")
app.add_typer(run_app, name="run")
app.add_typer(queue_app, name="queue")
app.add_typer(recon_app, name="recon")
app.add_typer(candidates_app, name="candidates")
app.add_typer(assets_app, name="assets")
app.add_typer(verify_app, name="verify")
app.add_typer(program_app, name="program")
app.add_typer(policy_app, name="policy")
app.add_typer(ports_app, name="ports")
app.add_typer(surface_app, name="surface")
app.add_typer(crawl_app, name="crawl")
app.add_typer(paths_app, name="paths")
app.add_typer(llm_app, name="llm")
llm_app.add_typer(ollama_app, name="ollama")

InputFile = Annotated[
    Path,
    typer.Argument(exists=True, file_okay=True, dir_okay=False, readable=True),
]


def _program_session(*, announce: bool = True):
    try:
        program = require_active_program()
    except ProgramError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if announce:
        typer.echo(f"Program: {program.slug}")
    engine = create_sqlite_engine(program.database_path)
    initialize_database(engine)
    return create_session_factory(engine)(), program


def _session(*, announce: bool = True):
    session, _ = _program_session(announce=announce)
    return session


def _abort(message: str) -> None:
    typer.echo(f"Erro: {message}", err=True)
    raise typer.Exit(code=1)


@ollama_app.command("configure")
def llm_ollama_configure(
    model_id: Annotated[
        str,
        typer.Option("--model", help="ID local seguro de um modelo já instalado no Ollama."),
    ],
    profile: Annotated[
        OllamaProfileName,
        typer.Option("--profile", help="Perfil técnico fixo de compatibilidade Ollama."),
    ] = OllamaProfileName.GENERIC_OLLAMA_JSON,
) -> None:
    """Persiste provider, model_id e profile; não consulta nem modifica o Ollama."""
    try:
        program = require_active_program()
    except ProgramError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    try:
        config = configure_ollama(program.database_path.parent, model_id, profile)
    except LlmError as exc:
        _abort(str(exc))
    typer.echo(f"Program: {program.slug}")
    typer.echo(f"Provider: {config.provider}")
    typer.echo(f"Model: {config.model_id}")
    typer.echo(f"Profile: {config.profile}")


@ollama_app.command("profiles")
def llm_ollama_profiles() -> None:
    """Lista somente os perfis técnicos fixos implementados."""
    typer.echo("PROFILE  STRUCTURED_OUTPUT  THINK  STREAM  TEMPERATURE")
    for profile in OLLAMA_PROFILES.values():
        think = profile.think if profile.think is not None else "omitted"
        structured = "required" if profile.structured_output_required else "optional"
        typer.echo(
            f"{profile.name.value}  {structured}  {think}  "
            f"{str(profile.stream).lower()}  {profile.temperature}"
        )


@llm_app.command("status")
def llm_status() -> None:
    """Mostra somente a configuração persistida, sem conexão de rede."""
    try:
        program = require_active_program()
    except ProgramError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    try:
        config = load_ollama_config(program.database_path.parent)
    except LlmError as exc:
        _abort(str(exc))
    session, _ = _program_session(announce=False)
    with session:
        state = ollama_compatibility_state(
            session,
            program_slug=program.slug,
            config=config,
        )
    typer.echo(f"Program: {program.slug}")
    typer.echo(f"Provider: {config.provider}")
    typer.echo(f"Model: {config.model_id}")
    typer.echo(f"Profile: {config.profile}")
    typer.echo(f"Compatibility: {state.state}")
    typer.echo(f"Last verification: {state.verified_at.isoformat() if state.verified_at else '-'}")


@ollama_app.command("verify")
def llm_ollama_verify(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Mostra a verificação local sem abrir conexão."),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Confirma a verificação inofensiva no Ollama local."),
    ] = False,
) -> None:
    """Verifica structured output sem enviar qualquer dado de programa ou run."""
    if dry_run == confirm:
        _abort("escolha exatamente uma opção: --dry-run ou --confirm")
    try:
        program = require_active_program()
    except ProgramError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Program: {program.slug}")
    if dry_run:
        try:
            plan = inspect_ollama_verification(program.database_path.parent)
        except LlmError as exc:
            _abort(str(exc))
        typer.echo(f"Provider: {plan.config.provider}")
        typer.echo(f"Model: {plan.config.model_id}")
        typer.echo(f"Profile: {plan.config.profile}")
        typer.echo(f"Prompt: {plan.prompt_version}")
        typer.echo(f"Adapter: {plan.adapter_protocol_version}")
        typer.echo(f"Schema: {plan.schema_version}")
        typer.echo("Verificação local: sem conexão.")
        return

    session, _ = _program_session(announce=False)
    with session:
        try:
            result = verify_ollama_compatibility(
                session,
                program_slug=program.slug,
                program_directory=program.database_path.parent,
            )
        except LlmError as exc:
            _abort(str(exc))
    typer.echo(
        f"Compatibilidade: {result.status}; "
        f"adapter={ADAPTER_PROTOCOL_VERSION}; prompt={COMPATIBILITY_PROMPT_VERSION}."
    )


@llm_app.command("triage")
def llm_triage(
    run_id: Annotated[int, typer.Argument(min=1)],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Inspeciona somente configuração e lotes locais."),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Confirma o POST fixo para o Ollama local."),
    ] = False,
) -> None:
    """Mapeia contexto exclusivamente a partir de lotes flow-map-input v1."""
    if dry_run == confirm:
        _abort("escolha exatamente uma opção: --dry-run ou --confirm")
    try:
        program = require_active_program()
    except ProgramError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Program: {program.slug}")

    if dry_run:
        try:
            plan = inspect_flow_mapping(
                run_id,
                program_id=program.slug,
                program_directory=program.database_path.parent,
                runs_path=program.runs_path,
            )
        except LlmError as exc:
            _abort(str(exc))
        typer.echo(f"Provider: {plan.config.provider}")
        typer.echo(f"Model: {plan.config.model_id}")
        typer.echo(f"Profile: {plan.config.profile}")
        typer.echo(f"Prompt: {FLOW_PROMPT_VERSION}")
        typer.echo(f"Mapping policy: {plan.mapping_policy}")
        typer.echo(f"Output policy: {plan.output_policy}")
        typer.echo(f"Selection policy: {plan.selection_policy}")
        typer.echo(f"Lotes: {', '.join(plan.batch_ids)}")
        typer.echo(
            f"Run {run_id}: lotes={plan.batch_count}; assets={plan.item_count}; "
            f"sinais determinísticos={plan.deterministic_signal_count}; "
            f"paths desconhecidos={plan.unknown_dynamic_path_count}; "
            f"fluxos CONTEXT_REQUIRED={plan.context_required_flow_count}; sem conexão."
        )
        return

    session, _ = _program_session(announce=False)
    with session:
        try:
            result = run_flow_mapping(
                run_id,
                session,
                program_id=program.slug,
                program_directory=program.database_path.parent,
                runs_path=program.runs_path,
            )
        except LlmError as exc:
            _abort(str(exc))
    typer.echo(
        f"Run {run_id}: lotes validados={result.batch_count}; "
        f"itens validados={result.item_count}; arquivo={result.result_path}."
    )


@llm_app.command("results")
def llm_results(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Exibe flow_mapping validado ou identifica resultados antigos sem misturá-los."""
    session, program = _program_session(announce=False)
    with session:
        try:
            view = llm_results_view(
                run_id,
                session,
                program_id=program.slug,
                program_directory=program.database_path.parent,
                runs_path=program.runs_path,
            )
        except LlmError as exc:
            _abort(str(exc))
    if view.analysis_type == "none":
        input_directory = program.runs_path / str(run_id) / "llm"
        if (
            not input_directory.is_symlink()
            and input_directory.is_dir()
            and any(input_directory.glob("flow-map-input-*.json"))
        ):
            typer.echo("Nenhum resultado flow_mapping validado.")
        else:
            typer.echo(f"Execute bb triage {run_id} --dry-run para gerar flow-map-input v1.")
        return
    if view.analysis_type == "legacy_triage":
        typer.echo("Analysis: legacy_triage")
        typer.echo("HOST  DECISÃO  CONFIANÇA  PERGUNTA")
        for result in view.legacy_triage:
            question = result.manual_review_question or "-"
            typer.echo(f"{result.host}  {result.decision}  {result.confidence}  {question}")
        return
    typer.echo("HOST | FLUXOS | LACUNAS | PERGUNTAS")
    for result in view.flow_mapping:
        flows = ", ".join(result.flows) or "-"
        gaps = ", ".join(result.context_gaps) or "-"
        questions = " / ".join(result.questions) or "-"
        typer.echo(f"{result.host} | {flows} | {gaps} | {questions}")


@program_app.command("create")
def program_create(
    slug: Annotated[str, typer.Argument()],
    name: Annotated[str, typer.Option("--name", help="Nome legível do programa.")],
) -> None:
    """Cria um programa com banco e diretório de runs isolados."""
    try:
        program = create_program(slug, name)
    except ProgramError as exc:
        _abort(str(exc))
    typer.echo(f"Programa criado: {program.slug} — {program.name}")
    typer.echo(f"Banco: {program.database_path}")
    if typer.confirm("Deseja selecionar este programa agora?", default=True):
        try:
            select_program(program.slug)
        except ProgramError as exc:
            _abort(str(exc))
        typer.echo(f"Programa selecionado: {program.slug}")


@program_app.command("list")
def program_list() -> None:
    """Lista programas ativos e arquivados sem abrir dados de outras runs."""
    programs = list_programs()
    if not programs:
        typer.echo("Nenhum programa cadastrado.")
        return
    try:
        active_slug = current_program_slug()
    except ProgramError:
        active_slug = None
    typer.echo("ATIVO  SLUG  NOME  ESTADO")
    for program in programs:
        marker = "*" if program.slug == active_slug and not program.archived else " "
        status = "archived" if program.archived else "active"
        typer.echo(f"{marker}  {program.slug}  {program.name}  {status}")


@program_app.command("show")
def program_show() -> None:
    """Mostra o programa ativo e os caminhos isolados usados por ele."""
    try:
        program = require_active_program()
    except ProgramError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Program: {program.slug}")
    typer.echo(f"Name: {program.name}")
    typer.echo(f"Database: {program.database_path}")
    typer.echo(f"Runs: {program.runs_path}")


@program_app.command("select")
def program_select(
    slug: Annotated[str | None, typer.Argument(help="Slug para seleção não interativa.")] = None,
) -> None:
    """Seleciona por slug ou abre um menu interativo para programas não arquivados."""
    selected_slug = slug
    if selected_slug is None:
        programs = list_programs(include_archived=False)
        if not programs:
            _abort("nenhum programa não arquivado disponível")
        selected_slug = questionary.select(
            "Selecione o programa:",
            choices=[
                questionary.Choice(
                    title=f"{program.slug} — {program.name}",
                    value=program.slug,
                )
                for program in programs
            ],
            use_shortcuts=True,
        ).ask()
        if selected_slug is None:
            typer.echo("Seleção cancelada; o programa ativo não foi alterado.")
            return

    try:
        program = select_program(selected_slug)
    except ProgramError as exc:
        _abort(str(exc))
    typer.echo(f"Programa selecionado: {program.slug}")


@program_app.command("archive")
def program_archive(slug: Annotated[str, typer.Argument()]) -> None:
    """Arquiva um programa sem apagar seu banco ou seus artefatos."""
    try:
        program = archive_program(slug)
    except ProgramError as exc:
        _abort(str(exc))
    typer.echo(f"Programa arquivado: {program.slug}")


@policy_app.command("show")
def policy_show() -> None:
    """Mostra a política selecionada e todos os parâmetros tipados."""
    session, program = _program_session()
    with session:
        try:
            policy = get_program_policy(session, program_slug=program.slug)
        except PolicyError as exc:
            _abort(str(exc))
    typer.echo(f"Política: {policy.name.value}")
    typer.echo(f"Versão: {policy.version}")
    typer.echo(
        "DNS: "
        f"threads={policy.dns.threads}; DNS/s={policy.dns.rate_limit_per_second}; "
        f"timeout-processo={policy.dns.process_timeout_seconds}s"
    )
    typer.echo(
        "HTTP: "
        f"threads={policy.http.threads}; req/s={policy.http.rate_limit_per_second}; "
        f"timeout={policy.http.timeout_seconds}s; retries={policy.http.retries}; "
        f"timeout-processo={policy.http.process_timeout_seconds}s"
    )
    typer.echo(
        "Portas: "
        f"workers={policy.ports.workers}; pacotes/s={policy.ports.rate_limit_per_second}; "
        f"timeout={policy.ports.timeout_milliseconds}ms; retries={policy.ports.retries}; "
        f"portas={','.join(str(port) for port in policy.ports.ports)}; "
        f"tipo={policy.ports.scan_type}"
    )
    typer.echo(
        "Katana: "
        f"modo={policy.katana.mode}; headless={str(policy.katana.headless).lower()}; "
        f"javascript={str(policy.katana.javascript).lower()}; "
        f"concorrência={policy.katana.concurrency}; "
        f"paralelismo={policy.katana.parallelism}; "
        f"req/s={policy.katana.rate_limit_per_second}; depth={policy.katana.depth}; "
        f"timeout={policy.katana.timeout_seconds}s; retries={policy.katana.retries}; "
        f"duração-máxima={policy.katana.max_duration_seconds}s; "
        f"resposta-máxima={policy.katana.max_response_read_bytes} bytes; "
        f"paths/host={policy.katana.max_paths_per_host}; escopo={policy.katana.scope}; "
        f"saída={policy.katana.output_field}; métodos={','.join(policy.katana.methods)}"
    )


@policy_app.command("list")
def policy_list() -> None:
    """Lista exclusivamente os perfis implementados nesta versão."""
    session, program = _program_session()
    with session:
        try:
            selected = get_program_policy(session, program_slug=program.slug)
        except PolicyError as exc:
            _abort(str(exc))
    typer.echo("ATIVA  POLÍTICA  VERSÃO")
    for policy in available_policies():
        marker = "*" if policy.name is selected.name else " "
        typer.echo(f"{marker}  {policy.name.value}  {policy.version}")


@policy_app.command("set")
def policy_set(name: Annotated[PolicyName, typer.Argument()]) -> None:
    """Seleciona uma política implementada para o programa ativo."""
    session, program = _program_session()
    with session:
        try:
            policy = set_program_policy(session, program_slug=program.slug, name=name)
        except PolicyError as exc:
            _abort(str(exc))
    typer.echo(f"Política selecionada: {policy.name.value} (versão {policy.version}).")


@scope_app.command("import")
def import_scope(file: InputFile) -> None:
    """Importa regras de um arquivo de texto, uma por linha."""
    with _session() as session:
        try:
            result = import_scope_file(file, session)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Escopo importado: {result.imported}; duplicadas ignoradas: {result.duplicates}.")


@run_app.command("ingest")
def ingest(file: InputFile) -> None:
    """Ingere JSONL local como candidatos pendentes de aprovação."""
    with _session() as session:
        try:
            run = ingest_jsonl(file, session)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(
        f"Run {run.id}: aceitos={run.accepted_count}, "
        f"rejeitados={run.rejected_count}, duplicados={run.duplicate_count}."
    )


@recon_app.command("passive")
def recon_passive(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Lista raízes sem executar subprocessos ou rede."),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Autoriza a criação da run e a execução do subfinder."),
    ] = False,
) -> None:
    """Cria candidatos exatos e enumera apenas raízes autorizadas por wildcard."""
    if dry_run == confirm:
        _abort("informe exatamente uma opção: --dry-run ou --confirm")

    session, program = _program_session()
    with session:
        if dry_run:
            roots = passive_recon_roots(session)
            if not roots:
                typer.echo("Nenhum domínio-raiz autorizado por regra wildcard.")
                return
            typer.echo("Domínios-raiz autorizados para enumeração passiva:")
            for root in roots:
                typer.echo(root)
            return

        try:
            result = run_passive_recon(session, runs_path=program.runs_path)
        except InputError as exc:
            _abort(str(exc))
    summary = f"Run {result.run_id}: candidatos={result.accepted}, duplicados={result.duplicates}."
    if result.raw_path is not None:
        summary += f" Raw: {result.raw_path}."
    typer.echo(summary)


@candidates_app.command("list")
def candidates_list(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Lista somente candidatos pendentes e atualmente em escopo."""
    with _session() as session:
        try:
            candidates = list_candidates(run_id, session)
        except InputError as exc:
            _abort(str(exc))
    if not candidates:
        typer.echo("Nenhum candidato pendente em escopo.")
        return
    typer.echo("ID  HOST  FONTE  ESTADO")
    for candidate in candidates:
        typer.echo(f"{candidate.id}  {candidate.host}  {candidate.source}  {candidate.status}")


@candidates_app.command("approve")
def candidates_approve(
    run_id: Annotated[int, typer.Argument(min=1)],
    approve_all: Annotated[
        bool,
        typer.Option("--all", help="Aprova todos os candidatos pendentes em escopo."),
    ] = False,
    hosts: Annotated[
        list[str] | None,
        typer.Option("--host", help="Host a aprovar; a opção pode ser repetida."),
    ] = None,
) -> None:
    """Aprova todos os pendentes ou uma lista explícita de hosts."""
    with _session() as session:
        try:
            result = approve_candidates(
                run_id,
                session,
                hosts=hosts,
                approve_all=approve_all,
            )
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: aprovados={result.changed}, inalterados={result.unchanged}.")


@candidates_app.command("reject")
def candidates_reject(
    run_id: Annotated[int, typer.Argument(min=1)],
    hosts: Annotated[
        list[str] | None,
        typer.Option("--host", help="Host a rejeitar; a opção pode ser repetida."),
    ] = None,
) -> None:
    """Rejeita uma lista explícita de candidatos."""
    with _session() as session:
        try:
            result = reject_candidates(run_id, session, hosts=hosts or ())
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: rejeitados={result.changed}, inalterados={result.unchanged}.")


@assets_app.command("export")
def assets_export(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Exporta somente candidatos aprovados para o assets.jsonl da run."""
    session, program = _program_session()
    with session:
        try:
            result = export_assets(run_id, session, runs_path=program.runs_path)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: assets exportados={result.exported}; arquivo={result.path}.")


@assets_app.command("list")
def assets_list(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Lista aprovação e os últimos estados DNS e HTTP dos candidatos."""
    session, program = _program_session()
    with session:
        try:
            assets = list_assets_with_dns(run_id, session, program_slug=program.slug)
        except InputError as exc:
            _abort(str(exc))
    if not assets:
        typer.echo("Nenhum candidato nesta run.")
        return
    typer.echo("HOST  APROVAÇÃO  DNS  HTTP  STATUS")
    for asset in assets:
        status_code = asset.http_status_code if asset.http_status_code is not None else "-"
        typer.echo(
            f"{asset.host}  {asset.approval_status}  {asset.dns_status}  "
            f"{asset.http_reachability}  {status_code}"
        )


@verify_app.command("dns")
def verify_dns_command(
    run_id: Annotated[int, typer.Argument(min=1)],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Mostra o plano sem subprocesso, arquivo ou rede."),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Autoriza explicitamente a execução limitada do dnsx."),
    ] = False,
) -> None:
    """Verifica por DNS somente candidatos aprovados da run informada."""
    session, program = _program_session()
    with session:
        if dry_run == confirm:
            _abort("informe exatamente uma opção: --dry-run ou --confirm")
        try:
            if dry_run:
                plan = plan_dns_verification(
                    run_id,
                    session,
                    program_slug=program.slug,
                    runs_path=program.runs_path,
                )
                typer.echo(f"Política: {plan.policy_name}")
                typer.echo(f"Versão da política: {plan.policy_version}")
                typer.echo(f"Hosts aprovados: {plan.host_count}")
                typer.echo(
                    f"Parâmetros efetivos: threads={plan.threads}; DNS/s={plan.rate_limit}; "
                    f"timeout-processo={plan.parameters.process_timeout_seconds}s"
                )
                typer.echo(f"Comando planejado: {shlex.join(plan.command)}")
                return
            result = verify_dns(
                run_id,
                session,
                program_slug=program.slug,
                runs_path=program.runs_path,
            )
        except InputError as exc:
            _abort(str(exc))
    typer.echo(
        f"Run {run_id}: verificados={result.attempted}, resolvidos={result.resolved}, "
        f"não resolvidos={result.unresolved}."
    )
    typer.echo(f"Entrada: {result.input_path}")
    typer.echo(f"Resolvidos: {result.resolved_path}")


@verify_app.command("http")
def verify_http_command(
    run_id: Annotated[int, typer.Argument(min=1)],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Mostra o plano sem subprocesso, arquivo ou rede."),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Autoriza explicitamente a execução limitada do httpx."),
    ] = False,
) -> None:
    """Verifica por HTTP somente aprovados cujo último DNS esteja resolved."""
    session, program = _program_session()
    with session:
        if dry_run == confirm:
            _abort("informe exatamente uma opção: --dry-run ou --confirm")
        try:
            if dry_run:
                plan = plan_http_verification(
                    run_id,
                    session,
                    program_slug=program.slug,
                    runs_path=program.runs_path,
                )
                typer.echo(f"Política: {plan.policy_name}")
                typer.echo(f"Versão da política: {plan.policy_version}")
                typer.echo(f"Hosts aprovados e resolvidos: {plan.host_count}")
                typer.echo(
                    f"Parâmetros efetivos: threads={plan.threads}; req/s={plan.rate_limit}; "
                    f"timeout={plan.request_timeout}s; tentativas={plan.attempts}; "
                    f"retries={plan.parameters.retries}; "
                    f"timeout-processo={plan.parameters.process_timeout_seconds}s"
                )
                typer.echo(f"Comando planejado: {shlex.join(plan.command)}")
                return
            result = verify_http(
                run_id,
                session,
                program_slug=program.slug,
                runs_path=program.runs_path,
            )
        except InputError as exc:
            _abort(str(exc))
    typer.echo(
        f"Run {run_id}: verificados={result.attempted}, alcançáveis={result.reachable}, "
        f"inalcançáveis={result.unreachable}."
    )
    typer.echo(f"Entrada: {result.input_path}")


@verify_app.command("ports")
def verify_ports_command(
    run_id: Annotated[int, typer.Argument(min=1)],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Mostra o plano sem subprocesso, arquivo ou rede."),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Autoriza a execução TCP CONNECT limitada do Naabu."),
    ] = False,
) -> None:
    """Verifica quatro portas fixas em aprovados, resolvidos e HTTP alcançáveis."""
    session, program = _program_session()
    with session:
        if dry_run == confirm:
            _abort("informe exatamente uma opção: --dry-run ou --confirm")
        try:
            if dry_run:
                plan = plan_port_verification(
                    run_id,
                    session,
                    program_slug=program.slug,
                    runs_path=program.runs_path,
                )
                typer.echo(f"Política: {plan.policy_name}")
                typer.echo(f"Versão da política: {plan.policy_version}")
                typer.echo(f"Hosts elegíveis: {plan.host_count}")
                typer.echo(
                    f"Parâmetros efetivos: workers={plan.workers}; "
                    f"pacotes/s={plan.rate_limit}; timeout={plan.timeout_milliseconds}ms; "
                    f"retries={plan.retries}; portas="
                    f"{','.join(str(port) for port in plan.ports)}; tipo={plan.scan_type}; "
                    f"timeout-processo={plan.parameters.process_timeout_seconds}s"
                )
                typer.echo(f"Comando planejado: {shlex.join(plan.command)}")
                return
            result = verify_ports(
                run_id,
                session,
                program_slug=program.slug,
                runs_path=program.runs_path,
            )
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: verificados={result.attempted}, portas abertas={result.open_ports}.")


@ports_app.command("list")
def ports_list(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Lista somente host, porta e estado aberto da run no programa ativo."""
    with _session(announce=False) as session:
        try:
            ports = list_open_ports(run_id, session)
        except InputError as exc:
            _abort(str(exc))
    if not ports:
        typer.echo("Nenhuma porta aberta.")
        return
    typer.echo("HOST  PORTA  STATUS")
    for port in ports:
        typer.echo(f"{port.host}  {port.port}  {port.status}")


@crawl_app.command("katana")
def crawl_katana_command(
    run_id: Annotated[int, typer.Argument(min=1)],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Mostra o plano sem PATH, arquivo, processo ou rede."),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Autoriza o crawl público limitado do Katana."),
    ] = False,
) -> None:
    """Descobre paths públicos em aprovados, resolvidos e HTTP alcançáveis."""
    session, program = _program_session()
    with session:
        if dry_run == confirm:
            _abort("informe exatamente uma opção: --dry-run ou --confirm")
        try:
            if dry_run:
                plan = plan_katana_crawl(
                    run_id,
                    session,
                    program_slug=program.slug,
                    runs_path=program.runs_path,
                )
                typer.echo(f"Política: {plan.policy_name}")
                typer.echo(f"Versão da política: {plan.policy_version}")
                typer.echo(f"Hosts elegíveis: {plan.host_count}")
                typer.echo(
                    "Parâmetros efetivos: "
                    f"modo={plan.parameters.mode}; headless=false; javascript=false; "
                    f"concorrência={plan.parameters.concurrency}; "
                    f"paralelismo={plan.parameters.parallelism}; "
                    f"req/s={plan.parameters.rate_limit_per_second}; "
                    f"depth={plan.parameters.depth}; timeout={plan.parameters.timeout_seconds}s; "
                    f"retries={plan.parameters.retries}; "
                    f"duração-máxima={plan.parameters.max_duration_seconds}s; "
                    f"resposta-máxima={plan.parameters.max_response_read_bytes} bytes; "
                    f"paths/host={plan.parameters.max_paths_per_host}; "
                    f"escopo={plan.parameters.scope}; saída={plan.parameters.output_field}; "
                    f"métodos={','.join(plan.parameters.methods)}"
                )
                typer.echo(f"Comando por host planejado: {shlex.join(plan.command)}")
                if plan.skipped_without_scheme:
                    typer.echo(
                        f"Ignorados sem esquema HTTP sanitizado: {plan.skipped_without_scheme}. "
                        f"Execute bb verify http {run_id} --confirm para atualizá-los."
                    )
                return
            result = crawl_with_katana(
                run_id,
                session,
                program_slug=program.slug,
                runs_path=program.runs_path,
            )
        except InputError as exc:
            _abort(str(exc))
    typer.echo(
        f"Run {run_id}: hosts processados={result.attempted}, "
        f"caminhos sanitizados={result.observed_paths}."
    )
    if result.skipped_without_scheme:
        typer.echo(
            f"Ignorados sem esquema HTTP sanitizado: {result.skipped_without_scheme}. "
            f"Execute bb verify http {run_id} --confirm para atualizá-los."
        )
    typer.echo(f"Caminhos: {result.output_path}")


@paths_app.command("list")
def paths_list(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Lista somente host, path e origem da run no programa ativo."""
    with _session(announce=False) as session:
        try:
            paths = list_crawl_paths(run_id, session)
        except InputError as exc:
            _abort(str(exc))
    if not paths:
        typer.echo("Nenhum caminho sanitizado.")
        return
    typer.echo("HOST  PATH  SOURCE")
    for path in paths:
        typer.echo(f"{path.host}  {path.path}  {path.source}")


@surface_app.command("list")
def surface_list(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Mostra a superfície consolidada sem subprocesso, arquivo ou rede."""
    session, program = _program_session()
    with session:
        try:
            records = build_surface_map(run_id, session, program_slug=program.slug)
        except InputError as exc:
            _abort(str(exc))
    if not records:
        typer.echo("Nenhum candidato nesta run.")
        return
    typer.echo("HOST  APROVAÇÃO  DNS  HTTP  STATUS  TÍTULO  TECNOLOGIAS  PORTAS  CAMINHOS  ESTÁGIO")
    for record in records:
        status_code = str(record.http_status_code) if record.http_status_code is not None else "-"
        title = record.http_title or "-"
        technologies = ",".join(record.http_technologies) or "-"
        ports = ",".join(str(port) for port in record.open_ports) or "-"
        typer.echo(
            f"{record.host}  {record.approval_status.value}  {record.dns_status.value}  "
            f"{record.http_reachability.value}  {status_code}  {title}  {technologies}  "
            f"{ports}  {record.path_count}  {record.stage.value}"
        )


@surface_app.command("export")
def surface_export(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Exporta somente a projeção local segura e determinística da run."""
    session, program = _program_session()
    with session:
        try:
            result = export_surface_map(
                run_id,
                session,
                program_slug=program.slug,
                runs_path=program.runs_path,
            )
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: superfície exportada={result.exported}; arquivo={result.path}.")


@app.command("sanitize")
def sanitize(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Promove somente assets canônicos e cria itens de fila sem payload bruto."""
    with _session() as session:
        try:
            result = sanitize_run(run_id, session)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: sanitizados={result.sanitized}, enfileirados={result.queued}.")


@app.command("triage")
def triage(
    run_id: Annotated[int, typer.Argument(min=1)],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Somente prepara arquivos locais; não usa rede."),
    ] = False,
    batch_size: Annotated[
        int,
        typer.Option(
            "--batch-size",
            min=1,
            max=MAX_TRIAGE_BATCH_SIZE,
            help="Quantidade de itens por lote.",
        ),
    ] = DEFAULT_TRIAGE_BATCH_SIZE,
) -> None:
    """Prepara lotes locais v1 de sinais de fluxo sem rede, LLM ou subprocessos."""
    if not dry_run:
        _abort("triage está disponível somente com --dry-run nesta etapa")

    session, program = _program_session()
    with session:
        try:
            result = prepare_flow_mapping(
                run_id,
                session,
                program_id=program.slug,
                program_directory=program.database_path.parent,
                batch_size=batch_size,
                runs_path=program.runs_path,
            )
        except InputError as exc:
            _abort(str(exc))
    typer.echo(
        f"Run {run_id}: assets={result.item_count}, "
        f"sinais determinísticos={result.deterministic_signal_count}, "
        f"paths desconhecidos={result.unknown_dynamic_path_count}, "
        f"fluxos CONTEXT_REQUIRED={result.context_required_flow_count}, "
        f"lotes={result.batch_count}; "
        f"arquivos em {program.runs_path}/{run_id}/llm/."
    )


@queue_app.command("list")
def queue_list() -> None:
    """Lista referências da fila; nenhum payload sensível é persistido."""
    with _session() as session:
        items = list_queue(session)
    if not items:
        typer.echo("Fila vazia.")
        return
    typer.echo("ID  RUN  ASSET  STATUS")
    for item in items:
        typer.echo(f"{item.id}  {item.run_id}  {item.asset_id}  {item.status}")
