import json
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

import bb_orchestrator.services as services
from bb_orchestrator.cli import app
from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.models import AssetModel, CandidateModel
from bb_orchestrator.programs import create_program, select_program
from bb_orchestrator.schemas import CandidateStatus
from bb_orchestrator.services import (
    InputError,
    approve_candidates,
    export_assets,
    import_scope_file,
    ingest_jsonl,
    list_candidates,
    passive_recon_roots,
    reject_candidates,
    run_passive_recon,
)


@pytest.fixture
def session(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "recon.db")
    initialize_database(engine)
    with create_session_factory(engine)() as db_session:
        yield db_session


def _import_scope(tmp_path: Path, session, content: str) -> None:
    scope_path = tmp_path / "scope.txt"
    scope_path.write_text(content, encoding="utf-8")
    import_scope_file(scope_path, session)


def _ingest(tmp_path: Path, session, domains: list[str]):
    input_path = tmp_path / "manual.jsonl"
    input_path.write_text(
        "".join(f"{json.dumps({'domain': domain})}\n" for domain in domains),
        encoding="utf-8",
    )
    return ingest_jsonl(input_path, session)


def _activate_program(slug: str = "test-program") -> None:
    create_program(slug, "Test Program")
    select_program(slug)


def test_only_wildcards_produce_enumerable_roots(tmp_path: Path, session) -> None:
    _import_scope(
        tmp_path,
        session,
        "api.example.com\n*.example.com\n*.EXAMPLE.COM.\n*.example.net\n",
    )

    assert passive_recon_roots(session) == ["example.com", "example.net"]


def test_exact_rule_does_not_run_subfinder(tmp_path: Path, session, monkeypatch) -> None:
    _import_scope(tmp_path, session, "api.example.com\n")

    def refuse_subprocess(*args, **kwargs):
        pytest.fail("uma regra exata tentou enumerar subdomínios")

    monkeypatch.setattr(services.subprocess, "run", refuse_subprocess)
    monkeypatch.setattr(
        services.shutil,
        "which",
        lambda name: pytest.fail("uma regra exata procurou o subfinder"),
    )

    result = run_passive_recon(session, runs_path=tmp_path / "runs")

    candidate = session.scalar(select(CandidateModel))
    assert result.accepted == 1
    assert result.raw_path is None
    assert (candidate.host, candidate.source, candidate.status) == (
        "api.example.com",
        "scope_exact",
        "pending",
    )


def test_dry_run_lists_roots_without_subprocess(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _activate_program()
    Path("scope.txt").write_text("api.example.com\n*.example.com\n", encoding="utf-8")
    env = {"BB_DB_PATH": str(tmp_path / "cli.db")}
    runner = CliRunner()
    assert runner.invoke(app, ["scope", "import", "scope.txt"], env=env).exit_code == 0

    def refuse_subprocess(*args, **kwargs):
        pytest.fail("recon --dry-run executou um subprocesso")

    monkeypatch.setattr(services.subprocess, "run", refuse_subprocess)
    result = runner.invoke(app, ["recon", "passive", "--dry-run"], env=env)

    assert result.exit_code == 0, result.output
    assert "example.com" in result.output
    assert "api.example.com" not in result.output
    assert not (tmp_path / ".bb/programs/test-program/runs/1").exists()


def test_confirm_flag_is_the_explicit_authorization(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _activate_program()
    Path("scope.txt").write_text("*.example.com\n", encoding="utf-8")
    env = {"BB_DB_PATH": str(tmp_path / "cli.db")}
    runner = CliRunner()
    assert runner.invoke(app, ["scope", "import", "scope.txt"], env=env).exit_code == 0

    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/subfinder")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="api.example.com\n", stderr="")

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    result = runner.invoke(app, ["recon", "passive", "--confirm"], env=env)

    assert result.exit_code == 0, result.output
    assert calls == [["/mock/bin/subfinder", "-silent", "-duc", "-d", "example.com"]]
    assert (tmp_path / ".bb/programs/test-program/runs/1/raw/subfinder.txt").is_file()


def test_confirm_uses_only_subfinder_and_filters_untrusted_output(
    tmp_path: Path, session, monkeypatch
) -> None:
    _import_scope(tmp_path, session, "*.example.com\n")
    calls = []

    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/subfinder")

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                "API.EXAMPLE.COM.\n"
                "api.example.com\n"
                "outside.test\n"
                "example.com.attacker.test\n"
                "example.com\n"
                "https://api.example.com/private\n"
                "192.0.2.10\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(services.subprocess, "run", fake_run)

    result = run_passive_recon(session, runs_path=tmp_path / "runs")

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command == ["/mock/bin/subfinder", "-silent", "-duc", "-d", "example.com"]
    assert kwargs["shell"] is False
    assert kwargs["capture_output"] is True
    assert result.accepted == 1
    assert result.duplicates == 1
    assert result.rejected == 5
    assert list(session.scalars(select(CandidateModel.host))) == ["api.example.com"]
    raw = result.raw_path.read_text(encoding="utf-8")
    assert raw == "api.example.com\n"


def test_missing_subfinder_has_clear_error(tmp_path: Path, session, monkeypatch) -> None:
    _import_scope(tmp_path, session, "*.example.com\n")
    monkeypatch.setattr(services.shutil, "which", lambda name: None)

    with pytest.raises(InputError, match=r"instale-o manualmente.*PATH"):
        run_passive_recon(session, runs_path=tmp_path / "runs")


def test_candidates_list_is_pending_and_default_deny(tmp_path: Path, session) -> None:
    _import_scope(tmp_path, session, "*.example.com\n")
    run = _ingest(tmp_path, session, ["api.example.com"])
    session.add(
        CandidateModel(
            run_id=run.id,
            host="example.com.attacker.test",
            source="untrusted",
            status=CandidateStatus.PENDING.value,
        )
    )
    session.commit()

    candidates = list_candidates(run.id, session)

    assert [(item.host, item.source, item.status) for item in candidates] == [
        ("api.example.com", "ingest", "pending")
    ]


def test_candidate_cli_accepts_repeated_hosts_and_all(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _activate_program()
    Path("scope.txt").write_text("*.example.com\n", encoding="utf-8")
    Path("assets.jsonl").write_text(
        '{"domain":"api.example.com"}\n{"domain":"dev.example.com"}\n',
        encoding="utf-8",
    )
    runner = CliRunner()
    assert runner.invoke(app, ["scope", "import", "scope.txt"]).exit_code == 0
    assert runner.invoke(app, ["run", "ingest", "assets.jsonl"]).exit_code == 0

    approved = runner.invoke(
        app,
        ["candidates", "approve", "1", "--host", "api.example.com"],
    )
    approve_all = runner.invoke(app, ["candidates", "approve", "1", "--all"])

    assert approved.exit_code == approve_all.exit_code == 0
    assert "Program: test-program" in approved.output
    assert "aprovados=1" in approved.output
    assert "aprovados=1" in approve_all.output


def test_approve_all_approve_host_and_reject_host_are_idempotent(tmp_path: Path, session) -> None:
    _import_scope(tmp_path, session, "example.com\n*.example.com\n")
    run = _ingest(
        tmp_path,
        session,
        ["example.com", "api.example.com", "dev.example.com"],
    )

    first_approval = approve_candidates(run.id, session, hosts=["API.EXAMPLE.COM."])
    approved = session.scalar(
        select(CandidateModel).where(CandidateModel.host == "api.example.com")
    )
    approved_at = approved.approved_at
    repeated_approval = approve_candidates(run.id, session, hosts=["api.example.com"])
    first_rejection = reject_candidates(run.id, session, hosts=["example.com"])
    repeated_rejection = reject_candidates(run.id, session, hosts=["example.com"])
    all_result = approve_candidates(run.id, session, approve_all=True)
    repeated_all = approve_candidates(run.id, session, approve_all=True)

    assert (first_approval.changed, first_approval.unchanged) == (1, 0)
    assert (repeated_approval.changed, repeated_approval.unchanged) == (0, 1)
    assert approved.approved_at == approved_at is not None
    assert (first_rejection.changed, first_rejection.unchanged) == (1, 0)
    assert (repeated_rejection.changed, repeated_rejection.unchanged) == (0, 1)
    assert (all_result.changed, all_result.unchanged) == (1, 0)
    assert (repeated_all.changed, repeated_all.unchanged) == (0, 0)


def test_terminal_candidate_cannot_be_changed_to_opposite_state(tmp_path: Path, session) -> None:
    _import_scope(tmp_path, session, "*.example.com\n")
    run = _ingest(tmp_path, session, ["api.example.com"])
    approve_candidates(run.id, session, hosts=["api.example.com"])

    with pytest.raises(InputError, match="estado terminal preservado"):
        reject_candidates(run.id, session, hosts=["api.example.com"])


def test_assets_export_is_deterministic_and_contains_only_approved(tmp_path: Path, session) -> None:
    _import_scope(tmp_path, session, "example.com\n*.example.com\n")
    run = _ingest(
        tmp_path,
        session,
        ["z.example.com", "example.com", "a.example.com"],
    )
    approve_candidates(run.id, session, hosts=["z.example.com", "a.example.com"])
    reject_candidates(run.id, session, hosts=["example.com"])
    output_dir = tmp_path / "runs" / str(run.id)
    output_dir.mkdir(parents=True)
    (output_dir / "keep.txt").write_text("preservar", encoding="utf-8")
    (output_dir / "assets.jsonl").write_text("stale\n", encoding="utf-8")

    first = export_assets(run.id, session, runs_path=tmp_path / "runs")
    first_content = first.path.read_text(encoding="utf-8")
    second = export_assets(run.id, session, runs_path=tmp_path / "runs")

    assert first.exported == second.exported == 2
    assert first_content == second.path.read_text(encoding="utf-8")
    assert first_content == ('{"domain":"a.example.com"}\n{"domain":"z.example.com"}\n')
    assert (output_dir / "keep.txt").read_text(encoding="utf-8") == "preservar"
    assert list(session.scalars(select(AssetModel))) == []


def test_manual_ingest_creates_only_pending_candidates(tmp_path: Path, session) -> None:
    _import_scope(tmp_path, session, "*.example.com\n")

    run = _ingest(tmp_path, session, ["api.example.com"])

    candidate = session.scalar(select(CandidateModel))
    assert (candidate.run_id, candidate.host, candidate.source, candidate.status) == (
        run.id,
        "api.example.com",
        "ingest",
        "pending",
    )
    assert list(session.scalars(select(AssetModel))) == []


def test_fake_data_end_to_end_without_real_network(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _activate_program()
    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/subfinder")

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=("api.example.com\ndev.example.com\nold.example.com\noutside.test\n"),
            stderr="",
        )

    monkeypatch.setattr(services.subprocess, "run", fake_run)

    Path("scope.txt").write_text("example.com\n*.example.com\n", encoding="utf-8")
    env = {"BB_DB_PATH": str(tmp_path / "cli.db")}
    runner = CliRunner()

    assert runner.invoke(app, ["scope", "import", "scope.txt"], env=env).exit_code == 0
    recon = runner.invoke(
        app,
        ["recon", "passive", "--confirm"],
        env=env,
    )
    pending = runner.invoke(app, ["candidates", "list", "1"], env=env)
    approved = runner.invoke(
        app,
        [
            "candidates",
            "approve",
            "1",
            "--host",
            "api.example.com",
            "--host",
            "dev.example.com",
        ],
        env=env,
    )
    rejected = runner.invoke(
        app,
        ["candidates", "reject", "1", "--host", "old.example.com"],
        env=env,
    )
    exported = runner.invoke(app, ["assets", "export", "1"], env=env)
    sanitized = runner.invoke(app, ["sanitize", "1"], env=env)
    triaged = runner.invoke(app, ["triage", "1", "--dry-run"], env=env)

    for result in (recon, pending, approved, rejected, exported, sanitized, triaged):
        assert result.exit_code == 0, result.output
    assert "outside.test" not in pending.output
    assert "aprovados=2" in approved.output
    assert "rejeitados=1" in rejected.output
    program_runs = tmp_path / ".bb/programs/test-program/runs"
    assert (program_runs / "1/assets.jsonl").read_text(encoding="utf-8") == (
        '{"domain":"api.example.com"}\n{"domain":"dev.example.com"}\n'
    )
    triage_payload = json.loads(
        (program_runs / "1/llm/triage-input-0001.json").read_text(encoding="utf-8")
    )
    assert {item["host"] for item in triage_payload["items"]} == {
        "api.example.com",
        "dev.example.com",
    }
