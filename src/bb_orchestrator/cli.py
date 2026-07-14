"""CLI Typer do MVP local."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import questionary
import typer

from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
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
    delete_candidates,
    export_assets,
    import_scope_file,
    ingest_jsonl,
    list_candidates,
    list_queue,
    passive_recon_roots,
    prepare_triage,
    reject_candidates,
    run_passive_recon,
    sanitize_run,
)
from bb_orchestrator.terminal_ui import ChecklistItem, SelectionCancelled, select_checkboxes

app = typer.Typer(name="bb", help="Orquestrador local para bug bounty autorizado.")
scope_app = typer.Typer(help="Gerencia regras determinísticas de escopo.")
run_app = typer.Typer(help="Gerencia execuções locais de ingestão.")
queue_app = typer.Typer(help="Consulta a fila local sanitizada.")
recon_app = typer.Typer(help="Executa descoberta estritamente passiva.")
candidates_app = typer.Typer(help="Gerencia a aprovação humana de candidatos.")
assets_app = typer.Typer(help="Exporta assets aprovados.")
program_app = typer.Typer(help="Gerencia programas isolados.")
app.add_typer(scope_app, name="scope")
app.add_typer(run_app, name="run")
app.add_typer(queue_app, name="queue")
app.add_typer(recon_app, name="recon")
app.add_typer(candidates_app, name="candidates")
app.add_typer(assets_app, name="assets")
app.add_typer(program_app, name="program")

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
        typer.Option("--confirm", help="Abre a confirmação antes de executar o subfinder."),
    ] = False,
) -> None:
    """Enumera passivamente apenas raízes autorizadas por wildcard."""
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

        roots = passive_recon_roots(session)
        if not roots:
            _abort("nenhuma regra wildcard autoriza enumeração passiva")
        typer.echo("O subfinder será executado passivamente para:")
        for root in roots:
            typer.echo(f"- {root}")
        if not typer.confirm("Confirma a execução do recon passivo?", default=False):
            typer.echo("Recon passivo cancelado; nenhum subprocesso foi executado.")
            return
        try:
            result = run_passive_recon(session, runs_path=program.runs_path)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(
        f"Run {result.run_id}: candidatos={result.accepted}, "
        f"descartados={result.rejected}, duplicados={result.duplicates}; "
        f"raw={result.raw_path}."
    )


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


def _select_pending_candidates(run_id: int, action: str) -> list[str]:
    with _session() as session:
        try:
            candidates = list_candidates(run_id, session)
        except InputError as exc:
            _abort(str(exc))
    if not candidates:
        typer.echo("Nenhum candidato pendente em escopo.")
        return []

    items = [
        ChecklistItem(
            value=candidate.host,
            label=f"{candidate.host}  ({candidate.source}, {candidate.status})",
        )
        for candidate in candidates
    ]
    try:
        return select_checkboxes(f"Selecione os candidatos para {action}:", items)
    except SelectionCancelled:
        typer.echo("Seleção cancelada; nenhuma alteração foi aplicada.")
        return []


@candidates_app.command("approve")
def candidates_approve(
    run_id: Annotated[int, typer.Argument(min=1)],
) -> None:
    """Seleciona e aprova candidatos pendentes em um checklist."""
    hosts = _select_pending_candidates(run_id, "aprovar")
    if not hosts:
        return
    with _session(announce=False) as session:
        try:
            result = approve_candidates(run_id, session, hosts=hosts)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: aprovados={result.changed}, inalterados={result.unchanged}.")


@candidates_app.command("reject")
def candidates_reject(
    run_id: Annotated[int, typer.Argument(min=1)],
) -> None:
    """Seleciona e rejeita candidatos pendentes em um checklist."""
    hosts = _select_pending_candidates(run_id, "rejeitar")
    if not hosts:
        return
    with _session(announce=False) as session:
        try:
            result = reject_candidates(run_id, session, hosts=hosts)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: rejeitados={result.changed}, inalterados={result.unchanged}.")


@candidates_app.command("delete")
def candidates_delete(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Seleciona e exclui logicamente candidatos pendentes."""
    hosts = _select_pending_candidates(run_id, "excluir")
    if not hosts:
        return
    if not typer.confirm(
        f"Excluir {len(hosts)} candidato(s) da seleção, preservando o histórico?",
        default=False,
    ):
        typer.echo("Exclusão cancelada; nenhuma alteração foi aplicada.")
        return
    with _session(announce=False) as session:
        try:
            result = delete_candidates(run_id, session, hosts=hosts)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: excluídos={result.changed}, inalterados={result.unchanged}.")


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
    """Prepara lotes determinísticos para triagem futura por LLM."""
    if not dry_run:
        _abort("triage está disponível somente com --dry-run nesta etapa")

    session, program = _program_session()
    with session:
        try:
            result = prepare_triage(
                run_id,
                session,
                batch_size=batch_size,
                runs_path=program.runs_path,
            )
        except InputError as exc:
            _abort(str(exc))
    typer.echo(
        f"Run {run_id}: itens={result.item_count}, lotes={result.batch_count}; "
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
