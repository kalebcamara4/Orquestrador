import json
from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

import bb_orchestrator.policies as policies
from bb_orchestrator.cli import app
from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.models import (
    ExecutionPolicySnapshotModel,
    ProgramModel,
    ProgramPolicyModel,
    RunModel,
)
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
    assert "Versão: 2" in shown.output
    assert "threads=5; DNS/s=5" in shown.output
    assert "threads=2; req/s=2; timeout=10s; retries=0" in shown.output
    assert "workers=2; pacotes/s=4; timeout=1000ms; retries=0" in shown.output
    assert "portas=80,443,8080,8443; tipo=tcp_connect" in shown.output
    assert "modo=standard; headless=false; javascript=false" in shown.output
    assert "concorrência=1; paralelismo=1; req/s=1; depth=1" in shown.output
    assert "duração-máxima=60s; resposta-máxima=1048576 bytes" in shown.output
    assert "paths/host=100; escopo=fqdn; saída=path; métodos=GET" in shown.output
    assert "*  conservative  2" in listed.output
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

    changed = original.model_copy(update={"version": "3"})
    monkeypatch.setitem(policies.POLICY_REGISTRY, PolicyName.CONSERVATIVE, changed)

    with create_session_factory(program)() as session:
        persisted = session.get(ExecutionPolicySnapshotModel, snapshot_id)
        assert persisted is not None
        assert persisted.snapshot == {
            "name": "conservative",
            "version": "2",
            "parameters": {
                "threads": 5,
                "rate_limit_per_second": 5,
                "process_timeout_seconds": 300,
            },
        }


def test_legacy_snapshot_survives_schema_upgrade_unchanged(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy.db"
    engine = create_sqlite_engine(database_path)
    initialize_database(engine)
    old_snapshot = {
        "name": "conservative",
        "version": "1",
        "parameters": {"threads": 5, "rate_limit_per_second": 5},
    }
    with create_session_factory(engine)() as session:
        session.add(ProgramModel(slug="legacy", name="Legacy"))
        run = RunModel(source_sha256="0" * 64, status="ingested")
        session.add(run)
        session.flush()
        snapshot = ExecutionPolicySnapshotModel(
            run_id=run.id,
            program_slug="legacy",
            step="dns",
            snapshot=old_snapshot,
        )
        session.add(snapshot)
        session.commit()
        snapshot_id = snapshot.id

    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.commit()
        try:
            with connection.begin():
                connection.exec_driver_sql(
                    """
                    CREATE TABLE execution_policy_snapshots_legacy (
                        id INTEGER NOT NULL PRIMARY KEY,
                        run_id INTEGER NOT NULL,
                        program_slug VARCHAR(64) NOT NULL,
                        step VARCHAR(16) NOT NULL,
                        snapshot JSON NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                        CONSTRAINT ck_policy_snapshot_step
                            CHECK (step IN ('dns', 'http', 'ports')),
                        FOREIGN KEY(run_id) REFERENCES runs (id),
                        FOREIGN KEY(program_slug) REFERENCES programs (slug)
                    )
                    """
                )
                connection.exec_driver_sql(
                    """
                    INSERT INTO execution_policy_snapshots_legacy
                    SELECT id, run_id, program_slug, step, snapshot, created_at
                    FROM execution_policy_snapshots
                    """
                )
                connection.exec_driver_sql("DROP TABLE execution_policy_snapshots")
                connection.exec_driver_sql(
                    "ALTER TABLE execution_policy_snapshots_legacy "
                    "RENAME TO execution_policy_snapshots"
                )
        finally:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.commit()

    initialize_database(engine)
    with create_session_factory(engine)() as session:
        persisted = session.get(ExecutionPolicySnapshotModel, snapshot_id)
        assert persisted is not None
        assert persisted.snapshot == old_snapshot
    with engine.connect() as connection:
        table_sql = connection.exec_driver_sql(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = 'execution_policy_snapshots'"
        ).scalar_one()
    assert "'katana'" in table_sql
