import json
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

import bb_orchestrator.services as services
from bb_orchestrator.cli import app
from bb_orchestrator.database import create_session_factory, create_sqlite_engine
from bb_orchestrator.models import DnsVerificationAttemptModel, ExecutionPolicySnapshotModel
from bb_orchestrator.programs import (
    NO_ACTIVE_PROGRAM_MESSAGE,
    create_program,
    select_program,
)


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)


def _create_run(
    runner: CliRunner,
    domains: list[str],
    *,
    slug: str = "test-program",
) -> None:
    create_program(slug, "Test Program")
    select_program(slug)
    Path(f"{slug}-scope.txt").write_text("*.example.com\n", encoding="utf-8")
    Path(f"{slug}-input.jsonl").write_text(
        "".join(f"{json.dumps({'domain': domain})}\n" for domain in domains),
        encoding="utf-8",
    )
    assert runner.invoke(app, ["scope", "import", f"{slug}-scope.txt"]).exit_code == 0
    assert runner.invoke(app, ["run", "ingest", f"{slug}-input.jsonl"]).exit_code == 0


def _approve(runner: CliRunner, *hosts: str) -> None:
    command = ["candidates", "approve", "1"]
    for host in hosts:
        command.extend(("--host", host))
    result = runner.invoke(app, command)
    assert result.exit_code == 0, result.output


def _attempts(database_path: Path) -> list[DnsVerificationAttemptModel]:
    engine = create_sqlite_engine(database_path)
    with create_session_factory(engine)() as session:
        return list(
            session.scalars(
                select(DnsVerificationAttemptModel).order_by(DnsVerificationAttemptModel.id)
            )
        )


def _snapshots(database_path: Path) -> list[ExecutionPolicySnapshotModel]:
    engine = create_sqlite_engine(database_path)
    with create_session_factory(engine)() as session:
        return list(
            session.scalars(
                select(ExecutionPolicySnapshotModel).order_by(ExecutionPolicySnapshotModel.id)
            )
        )


def test_dns_commands_require_an_active_program() -> None:
    runner = CliRunner()

    verified = runner.invoke(app, ["verify", "dns", "1", "--dry-run"])
    listed = runner.invoke(app, ["assets", "list", "1"])

    assert verified.exit_code == listed.exit_code == 1
    assert verified.output.strip() == listed.output.strip() == NO_ACTIVE_PROGRAM_MESSAGE


def test_dns_rejects_nonexistent_run_and_run_without_approved_candidates(
    monkeypatch,
) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com"])

    def refuse_subprocess(*args, **kwargs):
        pytest.fail("uma run inválida tentou executar subprocesso")

    monkeypatch.setattr(services.subprocess, "run", refuse_subprocess)
    missing = runner.invoke(app, ["verify", "dns", "999", "--dry-run"])
    empty = runner.invoke(app, ["verify", "dns", "1", "--dry-run"])

    assert missing.exit_code == empty.exit_code == 1
    assert "Program: test-program" in missing.output
    assert "run 999 não encontrada" in missing.output
    assert "não possui candidatos aprovados" in empty.output


def test_dns_dry_run_only_prints_count_limits_and_planned_command(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com", "dev.example.com"])
    _approve(runner, "api.example.com", "dev.example.com")

    def refuse_subprocess(*args, **kwargs):
        pytest.fail("verify dns --dry-run executou subprocesso")

    monkeypatch.setattr(services.subprocess, "run", refuse_subprocess)
    monkeypatch.setattr(
        services.shutil,
        "which",
        lambda name: pytest.fail("verify dns --dry-run consultou o binário"),
    )

    result = runner.invoke(app, ["verify", "dns", "1", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "Program: test-program" in result.output
    assert "Hosts aprovados: 2" in result.output
    assert "threads=5; DNS/s=5" in result.output
    assert (
        "dnsx -l .bb/programs/test-program/runs/1/dns/input-hosts.txt -silent -t 5 -rl 5"
    ) in result.output
    assert not Path(".bb/programs/test-program/runs/1/dns").exists()


def test_dns_missing_binary_fails_clearly_without_installing_or_running(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com"])
    _approve(runner, "api.example.com")
    monkeypatch.setattr(services.shutil, "which", lambda name: None)

    def refuse_subprocess(*args, **kwargs):
        pytest.fail("dnsx ausente ainda tentou executar um subprocesso")

    monkeypatch.setattr(services.subprocess, "run", refuse_subprocess)
    result = runner.invoke(app, ["verify", "dns", "1", "--confirm"])

    assert result.exit_code == 1
    assert "dnsx não está instalado" in result.output
    assert "instale-o manualmente" in result.output
    assert "PATH" in result.output
    assert not Path(".bb/programs/test-program/runs/1/dns/input-hosts.txt").exists()


def test_dns_confirm_uses_only_approved_hosts_and_persists_minimal_results(
    monkeypatch,
) -> None:
    runner = CliRunner()
    _create_run(
        runner,
        [
            "resolved.example.com",
            "unresolved.example.com",
            "rejected.example.com",
            "pending.example.com",
        ],
    )
    _approve(runner, "resolved.example.com", "unresolved.example.com")
    rejected = runner.invoke(
        app,
        ["candidates", "reject", "1", "--host", "rejected.example.com"],
    )
    assert rejected.exit_code == 0, rejected.output

    calls = []
    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/dnsx")

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                "RESOLVED.EXAMPLE.COM.\n"
                "resolved.example.com [A] [192.0.2.10]\n"
                "192.0.2.10\n"
                "rejected.example.com\n"
                "pending.example.com\n"
                "https://resolved.example.com/private\n"
                "outside.test\n"
            ),
            stderr="dnsx version: v1.2.3\nresolver 192.0.2.53",
        )

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    result = runner.invoke(app, ["verify", "dns", "1", "--confirm"])

    assert result.exit_code == 0, result.output
    assert "Program: test-program" in result.output
    assert "verificados=2, resolvidos=1, não resolvidos=1" in result.output
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command == [
        "/mock/bin/dnsx",
        "-l",
        ".bb/programs/test-program/runs/1/dns/input-hosts.txt",
        "-silent",
        "-t",
        "5",
        "-rl",
        "5",
    ]
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["capture_output"] is True

    dns_dir = Path(".bb/programs/test-program/runs/1/dns")
    assert (dns_dir / "input-hosts.txt").read_text(encoding="utf-8") == (
        "resolved.example.com\nunresolved.example.com\n"
    )
    assert (dns_dir / "resolved-hosts.txt").read_text(encoding="utf-8") == (
        "resolved.example.com\n"
    )

    attempts = _attempts(Path(".bb/programs/test-program/orchestrator.db"))
    assert [(item.host, item.status) for item in attempts] == [
        ("resolved.example.com", "resolved"),
        ("unresolved.example.com", "unresolved"),
    ]
    assert {item.program_slug for item in attempts} == {"test-program"}
    assert {item.run_id for item in attempts} == {1}
    assert {item.dnsx_version for item in attempts} == {"v1.2.3"}
    assert all(item.verified_at is not None for item in attempts)
    snapshots = _snapshots(Path(".bb/programs/test-program/orchestrator.db"))
    assert [(item.run_id, item.program_slug, item.step) for item in snapshots] == [
        (1, "test-program", "dns")
    ]
    assert snapshots[0].snapshot == {
        "name": "conservative",
        "version": "2",
        "parameters": {
            "threads": 5,
            "rate_limit_per_second": 5,
            "process_timeout_seconds": 300,
        },
    }
    serialized_values = "\n".join(
        str(value)
        for item in attempts
        for value in (
            item.host,
            item.status,
            item.program_slug,
            item.dnsx_version,
        )
    )
    assert "192.0.2.10" not in serialized_values
    assert "[A]" not in serialized_values

    listed = runner.invoke(app, ["assets", "list", "1"])
    assert listed.exit_code == 0, listed.output
    assert "resolved.example.com  approved  resolved" in listed.output
    assert "unresolved.example.com  approved  unresolved" in listed.output
    assert "rejected.example.com  rejected  pending" in listed.output
    assert "pending.example.com  pending  pending" in listed.output


def test_repeated_dns_confirmation_preserves_history_and_updates_latest_state(
    monkeypatch,
) -> None:
    runner = CliRunner()
    _create_run(runner, ["one.example.com", "two.example.com"])
    _approve(runner, "one.example.com", "two.example.com")
    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/dnsx")
    outputs = iter(["one.example.com\n", "two.example.com\n"])

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=next(outputs),
            stderr="dnsx version: 1.2.4",
        )

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    first = runner.invoke(app, ["verify", "dns", "1", "--confirm"])
    second = runner.invoke(app, ["verify", "dns", "1", "--confirm"])

    assert first.exit_code == second.exit_code == 0
    attempts = _attempts(Path(".bb/programs/test-program/orchestrator.db"))
    assert [(item.host, item.status) for item in attempts] == [
        ("one.example.com", "resolved"),
        ("two.example.com", "unresolved"),
        ("one.example.com", "unresolved"),
        ("two.example.com", "resolved"),
    ]
    assert (
        Path(".bb/programs/test-program/runs/1/dns/resolved-hosts.txt").read_text(encoding="utf-8")
        == "two.example.com\n"
    )
    listed = runner.invoke(app, ["assets", "list", "1"])
    assert "one.example.com  approved  unresolved" in listed.output
    assert "two.example.com  approved  resolved" in listed.output


def test_dns_runs_and_attempts_are_isolated_between_programs(monkeypatch) -> None:
    runner = CliRunner()
    alpha = create_program("alpha", "Alpha")
    beta = create_program("beta", "Beta")
    Path("scope.txt").write_text("*.example.com\n", encoding="utf-8")
    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/dnsx")

    def fake_run(command, **kwargs):
        input_path = Path(command[command.index("-l") + 1])
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=input_path.read_text(encoding="utf-8"),
            stderr="",
        )

    monkeypatch.setattr(services.subprocess, "run", fake_run)

    for slug, host in (("alpha", "alpha.example.com"), ("beta", "beta.example.com")):
        select_program(slug)
        Path("input.jsonl").write_text(
            f'{{"domain":"{host}"}}\n',
            encoding="utf-8",
        )
        assert runner.invoke(app, ["scope", "import", "scope.txt"]).exit_code == 0
        assert runner.invoke(app, ["run", "ingest", "input.jsonl"]).exit_code == 0
        assert runner.invoke(app, ["candidates", "approve", "1", "--all"]).exit_code == 0
        verified = runner.invoke(app, ["verify", "dns", "1", "--confirm"])
        assert verified.exit_code == 0, verified.output
        assert f"Program: {slug}" in verified.output

    assert (alpha.runs_path / "1/dns/input-hosts.txt").read_text(encoding="utf-8") == (
        "alpha.example.com\n"
    )
    assert (beta.runs_path / "1/dns/input-hosts.txt").read_text(encoding="utf-8") == (
        "beta.example.com\n"
    )
    assert [(item.program_slug, item.host) for item in _attempts(alpha.database_path)] == [
        ("alpha", "alpha.example.com")
    ]
    assert [(item.program_slug, item.host) for item in _attempts(beta.database_path)] == [
        ("beta", "beta.example.com")
    ]

    select_program("beta")
    listed = runner.invoke(app, ["assets", "list", "1"])
    assert "beta.example.com" in listed.output
    assert "alpha.example.com" not in listed.output
