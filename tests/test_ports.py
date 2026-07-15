import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

import bb_orchestrator.services as services
from bb_orchestrator.cli import app
from bb_orchestrator.database import create_session_factory, create_sqlite_engine
from bb_orchestrator.models import (
    CandidateModel,
    DnsVerificationAttemptModel,
    ExecutionPolicySnapshotModel,
    HttpVerificationAttemptModel,
    PortObservationModel,
)
from bb_orchestrator.programs import create_program, load_program, select_program


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)


def _create_run(runner: CliRunner, hosts: list[str]) -> None:
    create_program("test-program", "Test Program")
    select_program("test-program")
    Path("scope.txt").write_text("*.example.com\n", encoding="utf-8")
    Path("input.jsonl").write_text(
        "".join(f"{json.dumps({'domain': host})}\n" for host in hosts),
        encoding="utf-8",
    )
    assert runner.invoke(app, ["scope", "import", "scope.txt"]).exit_code == 0
    assert runner.invoke(app, ["run", "ingest", "input.jsonl"]).exit_code == 0


def _transition(runner: CliRunner, action: str, *hosts: str) -> None:
    command = ["candidates", action, "1"]
    for host in hosts:
        command.extend(("--host", host))
    result = runner.invoke(app, command)
    assert result.exit_code == 0, result.output


def _record_states(dns: dict[str, str], http: dict[str, str]) -> None:
    program = load_program("test-program")
    engine = create_sqlite_engine(program.database_path)
    with create_session_factory(engine)() as session:
        candidates = {
            candidate.host: candidate
            for candidate in session.scalars(
                select(CandidateModel).where(CandidateModel.run_id == 1)
            )
        }
        now = datetime.now(UTC)
        for host, status in dns.items():
            session.add(
                DnsVerificationAttemptModel(
                    run_id=1,
                    candidate_id=candidates[host].id,
                    program_slug="test-program",
                    host=host,
                    status=status,
                    verified_at=now,
                    dnsx_version="v1.2.3",
                )
            )
        for host, reachability in http.items():
            session.add(
                HttpVerificationAttemptModel(
                    run_id=1,
                    candidate_id=candidates[host].id,
                    program_slug="test-program",
                    host=host,
                    reachability=reachability,
                    status_code=200 if reachability == "reachable" else None,
                    title=None,
                    technologies=None,
                    verified_at=now,
                )
            )
        session.commit()


class FakeNaabuAdapter:
    def __init__(self, stdout: str = "", *, returncode: int = 0, stderr: str = "") -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.lookups: list[str] = []

    def find_executable(self, name: str) -> str | None:
        self.lookups.append(name)
        return "/mock/bin/naabu"

    def run(self, command, *, timeout_seconds, environment):
        command = list(command)
        self.calls.append(
            (
                command,
                {"timeout_seconds": timeout_seconds, "environment": dict(environment)},
            )
        )
        if "-version" in command:
            return subprocess.CompletedProcess(command, 0, stdout="naabu v2.6.1\n", stderr="")
        return subprocess.CompletedProcess(
            command,
            self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


def test_ports_requires_exactly_one_confirmation_mode() -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com"])
    _transition(runner, "approve", "api.example.com")
    _record_states(
        {"api.example.com": "resolved"},
        {"api.example.com": "reachable"},
    )

    absent = runner.invoke(app, ["verify", "ports", "1"])
    both = runner.invoke(app, ["verify", "ports", "1", "--dry-run", "--confirm"])

    assert absent.exit_code == both.exit_code == 1
    assert "exatamente uma opção" in absent.output
    assert "exatamente uma opção" in both.output


def test_ports_dry_run_has_no_adapter_files_or_network(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com"])
    _transition(runner, "approve", "api.example.com")
    _record_states(
        {"api.example.com": "resolved"},
        {"api.example.com": "reachable"},
    )

    class RefuseAdapter:
        def find_executable(self, name):
            pytest.fail("dry-run consultou o PATH")

        def run(self, *args, **kwargs):
            pytest.fail("dry-run executou subprocesso")

    monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", RefuseAdapter())
    result = runner.invoke(app, ["verify", "ports", "1", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "Política: conservative" in result.output
    assert "Versão da política: 2" in result.output
    assert "workers=2; pacotes/s=4; timeout=1000ms; retries=0" in result.output
    assert "portas=80,443,8080,8443; tipo=tcp_connect" in result.output
    assert "-scan-type c" in result.output
    assert not Path(".bb/programs/test-program/runs/1/ports").exists()


def test_ports_filters_eligibility_uses_safe_args_sanitizes_and_deduplicates(
    monkeypatch,
) -> None:
    runner = CliRunner()
    hosts = [
        "eligible.example.com",
        "unreachable.example.com",
        "unresolved.example.com",
        "rejected.example.com",
        "pending.example.com",
    ]
    _create_run(runner, hosts)
    _transition(
        runner,
        "approve",
        "eligible.example.com",
        "unreachable.example.com",
        "unresolved.example.com",
    )
    _transition(runner, "reject", "rejected.example.com")
    _record_states(
        {
            "eligible.example.com": "resolved",
            "unreachable.example.com": "resolved",
            "unresolved.example.com": "unresolved",
            "rejected.example.com": "resolved",
            "pending.example.com": "resolved",
        },
        {
            "eligible.example.com": "reachable",
            "unreachable.example.com": "unreachable",
            "unresolved.example.com": "reachable",
            "rejected.example.com": "reachable",
            "pending.example.com": "reachable",
        },
    )
    raw_lines = [
        {
            "host": "eligible.example.com",
            "ip": "192.0.2.10",
            "port": 443,
            "banner": "raw-secret",
            "asn": "AS64500",
        },
        {"host": "eligible.example.com", "ip": "192.0.2.10", "port": 443},
        {"host": "eligible.example.com", "ip": "2001:db8::1", "port": 8080},
        {"host": "eligible.example.com", "port": 22},
        {"host": "unreachable.example.com", "port": 80},
        {"host": "192.0.2.50", "port": 80},
        {"host": "outside.test", "port": 80},
    ]
    adapter = FakeNaabuAdapter(
        "".join(f"{json.dumps(line)}\n" for line in raw_lines) + "not-json\n"
    )
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8443")
    monkeypatch.setenv("NAABU_CONFIG", "unsafe")
    monkeypatch.setenv("PDCP_API_KEY", "raw-secret")
    monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", adapter)

    first = runner.invoke(app, ["verify", "ports", "1", "--confirm"])
    second = runner.invoke(app, ["verify", "ports", "1", "--confirm"])

    assert first.exit_code == second.exit_code == 0, first.output + second.output
    assert "Run 1: verificados=1, portas abertas=2." in first.output
    assert adapter.lookups == ["naabu", "naabu"]
    scan_command, scan_kwargs = adapter.calls[1]
    assert scan_command == [
        "/mock/bin/naabu",
        "-l",
        ".bb/programs/test-program/runs/1/ports/input-hosts.txt",
        "-p",
        "80,443,8080,8443",
        "-scan-type",
        "c",
        "-c",
        "2",
        "-rate",
        "4",
        "-timeout",
        "1000",
        "-retries",
        "0",
        "-json",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-no-stdin",
        "-config",
        "/dev/null",
    ]
    assert scan_kwargs["timeout_seconds"] == 300
    assert "HTTPS_PROXY" not in scan_kwargs["environment"]
    assert "NAABU_CONFIG" not in scan_kwargs["environment"]
    assert "PDCP_API_KEY" not in scan_kwargs["environment"]
    forbidden = {
        "-top-ports",
        "-scan-all-ips",
        "-passive",
        "-nmap",
        "-nmap-cli",
        "-proxy",
        "-rev-ptr",
        "-debug",
        "-verbose",
        "-service-version",
        "-service-discovery",
    }
    assert forbidden.isdisjoint(scan_command)

    ports_dir = Path(".bb/programs/test-program/runs/1/ports")
    assert (ports_dir / "input-hosts.txt").read_text(encoding="utf-8") == ("eligible.example.com\n")
    payloads = [
        json.loads(line)
        for line in (ports_dir / "ports.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [(item["host"], item["port"], item["status"]) for item in payloads] == [
        ("eligible.example.com", 443, "open"),
        ("eligible.example.com", 8080, "open"),
    ]
    assert all(
        set(item)
        == {
            "host",
            "port",
            "status",
            "timestamp",
            "tool_version",
            "run_id",
            "policy_snapshot_id",
        }
        for item in payloads
    )
    persisted = json.dumps(payloads)
    for forbidden_value in ("192.0.2.", "2001:db8", "raw-secret", "AS64500", "banner"):
        assert forbidden_value not in persisted

    program = load_program("test-program")
    engine = create_sqlite_engine(program.database_path)
    with create_session_factory(engine)() as session:
        observations = list(session.scalars(select(PortObservationModel)))
        snapshots = list(
            session.scalars(
                select(ExecutionPolicySnapshotModel).where(
                    ExecutionPolicySnapshotModel.step == "ports"
                )
            )
        )
        assert len(observations) == 2
        assert len(snapshots) == 2
        assert snapshots[0].snapshot == snapshots[1].snapshot
        assert snapshots[0].snapshot["parameters"]["ports"] == [80, 443, 8080, 8443]

    listed = runner.invoke(app, ["ports", "list", "1"])
    assert listed.exit_code == 0, listed.output
    assert listed.output.splitlines() == [
        "HOST  PORTA  STATUS",
        "eligible.example.com  443  open",
        "eligible.example.com  8080  open",
    ]


def test_ports_missing_naabu_and_subprocess_failure_are_safe(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com"])
    _transition(runner, "approve", "api.example.com")
    _record_states(
        {"api.example.com": "resolved"},
        {"api.example.com": "reachable"},
    )

    class MissingAdapter:
        def find_executable(self, name):
            return None

        def run(self, *args, **kwargs):
            pytest.fail("naabu ausente ainda executou subprocesso")

    monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", MissingAdapter())
    missing = runner.invoke(app, ["verify", "ports", "1", "--confirm"])
    assert missing.exit_code == 1
    assert "naabu não está instalado" in missing.output
    assert "instale-o manualmente" in missing.output
    assert not Path(".bb/programs/test-program/runs/1/ports/input-hosts.txt").exists()

    failed_adapter = FakeNaabuAdapter(
        returncode=1,
        stderr="dial tcp 192.0.2.10:443 with token=raw-secret",
    )
    monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", failed_adapter)
    failed = runner.invoke(app, ["verify", "ports", "1", "--confirm"])

    assert failed.exit_code == 1
    assert "naabu falhou (código 1): falha reportada pela ferramenta" in failed.output
    assert "192.0.2.10" not in failed.output
    assert "raw-secret" not in failed.output
    assert not Path(".bb/programs/test-program/runs/1/ports/ports.jsonl").exists()
