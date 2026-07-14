import json
from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

import bb_orchestrator.policies as policies
from bb_orchestrator.cli import app
from bb_orchestrator.database import create_session_factory, create_sqlite_engine
from bb_orchestrator.models import ExecutionPolicySnapshotModel, ProgramPolicyModel
from bb_orchestrator.policies import PolicyName, get_program_policy, persist_policy_snapshot
from bb_orchestrator.programs import create_program, select_program


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)


def _create_run(runner: CliRunner, slug: str = "acme") -> None:
    create_program(slug, slug.title())
    select_program(slug)
    Path("scope.txt").write_text("*.example.com\n", encoding="utf-8")
    Path("input.jsonl").write_text(
        f"{json.dumps({'domain': 'api.example.com'})}\n",
        encoding="utf-8",
    )
    assert runner.invoke(app, ["scope", "import", "scope.txt"]).exit_code == 0
    assert runner.invoke(app, ["run", "ingest", "input.jsonl"]).exit_code == 0


def test_conservative_is_the_default_and_only_available_policy() -> None:
    create_program("acme", "Acme")
    select_program("acme")
    runner = CliRunner()

    shown = runner.invoke(app, ["policy", "show"])
    listed = runner.invoke(app, ["policy", "list"])
    selected = runner.invoke(app, ["policy", "set", "conservative"])
    refused = runner.invoke(app, ["policy", "set", "balanced"])

    assert shown.exit_code == listed.exit_code == selected.exit_code == 0
    assert "Política: conservative" in shown.output
    assert "Versão: 1" in shown.output
    assert "threads=5; DNS/s=5" in shown.output
    assert "threads=2; req/s=2; timeout=10s; retries=0" in shown.output
    assert "workers=2; pacotes/s=4; timeout=1000ms; retries=0" in shown.output
    assert "portas=80,443,8080,8443; tipo=tcp_connect" in shown.output
    assert "*  conservative  1" in listed.output
    assert "balanced" not in listed.output
    assert "aggressive" not in listed.output
    assert refused.exit_code == 2


def test_policy_selection_is_persisted_in_each_program_database() -> None:
    alpha = create_program("alpha", "Alpha")
    beta = create_program("beta", "Beta")
    runner = CliRunner()

    for program in (alpha, beta):
        select_program(program.slug)
        assert runner.invoke(app, ["policy", "set", "conservative"]).exit_code == 0

    for program in (alpha, beta):
        engine = create_sqlite_engine(program.database_path)
        with create_session_factory(engine)() as session:
            selections = list(session.scalars(select(ProgramPolicyModel)))
            assert [(item.program_slug, item.policy_name) for item in selections] == [
                (program.slug, "conservative")
            ]


def test_policy_snapshot_is_a_copy_and_does_not_follow_registry_changes(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner)
    program = create_sqlite_engine(Path(".bb/programs/acme/orchestrator.db"))
    with create_session_factory(program)() as session:
        original = get_program_policy(session, program_slug="acme")
        snapshot = persist_policy_snapshot(
            session,
            run_id=1,
            program_slug="acme",
            step="dns",
            policy=original,
        )
        session.commit()
        snapshot_id = snapshot.id

    changed = original.model_copy(update={"version": "2"})
    monkeypatch.setitem(policies.POLICY_REGISTRY, PolicyName.CONSERVATIVE, changed)

    with create_session_factory(program)() as session:
        persisted = session.get(ExecutionPolicySnapshotModel, snapshot_id)
        assert persisted is not None
        assert persisted.snapshot == {
            "name": "conservative",
            "version": "1",
            "parameters": {
                "threads": 5,
                "rate_limit_per_second": 5,
                "process_timeout_seconds": 300,
            },
        }
