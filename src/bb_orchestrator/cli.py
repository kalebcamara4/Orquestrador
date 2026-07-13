"""CLI Typer do MVP local."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.services import (
    InputError,
    import_scope_file,
    ingest_jsonl,
    list_queue,
    sanitize_run,
)

app = typer.Typer(name="bb", help="Orquestrador local para bug bounty autorizado.")
scope_app = typer.Typer(help="Gerencia regras determinísticas de escopo.")
run_app = typer.Typer(help="Gerencia execuções locais de ingestão.")
queue_app = typer.Typer(help="Consulta a fila local sanitizada.")
app.add_typer(scope_app, name="scope")
app.add_typer(run_app, name="run")
app.add_typer(queue_app, name="queue")

InputFile = Annotated[
    Path,
    typer.Argument(exists=True, file_okay=True, dir_okay=False, readable=True),
]


def _session():
    engine = create_sqlite_engine()
    initialize_database(engine)
    return create_session_factory(engine)()


def _abort(message: str) -> None:
    typer.echo(f"Erro: {message}", err=True)
    raise typer.Exit(code=1)


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
    """Ingere JSONL local contendo exclusivamente o campo domain."""
    with _session() as session:
        try:
            run = ingest_jsonl(file, session)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(
        f"Run {run.id}: aceitos={run.accepted_count}, "
        f"rejeitados={run.rejected_count}, duplicados={run.duplicate_count}."
    )


@app.command("sanitize")
def sanitize(run_id: Annotated[int, typer.Argument(min=1)]) -> None:
    """Promove somente assets canônicos e cria itens de fila sem payload bruto."""
    with _session() as session:
        try:
            result = sanitize_run(run_id, session)
        except InputError as exc:
            _abort(str(exc))
    typer.echo(f"Run {run_id}: sanitizados={result.sanitized}, enfileirados={result.queued}.")


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
