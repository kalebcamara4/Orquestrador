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
)
from bb_orchestrator.programs import (
    NO_ACTIVE_PROGRAM_MESSAGE,
    create_program,
    load_program,
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


def _record_dns(slug: str, records: list[tuple[str, str]]) -> None:
    program = load_program(slug)
    engine = create_sqlite_engine(program.database_path)
    with create_session_factory(engine)() as session:
        candidates = {
            candidate.host: candidate
            for candidate in session.scalars(
                select(CandidateModel).where(CandidateModel.run_id == 1)
            )
        }
        for host, status in records:
            session.add(
                DnsVerificationAttemptModel(
                    run_id=1,
                    candidate_id=candidates[host].id,
                    program_slug=slug,
                    host=host,
                    status=status,
                    verified_at=datetime.now(UTC),
                    dnsx_version=None,
                )
            )
        session.commit()


def _http_attempts(database_path: Path) -> list[HttpVerificationAttemptModel]:
    engine = create_sqlite_engine(database_path)
    with create_session_factory(engine)() as session:
        return list(
            session.scalars(
                select(HttpVerificationAttemptModel).order_by(HttpVerificationAttemptModel.id)
            )
        )


def test_http_requires_an_active_program() -> None:
    result = CliRunner().invoke(app, ["verify", "http", "1", "--dry-run"])

    assert result.exit_code == 1
    assert result.output.strip() == NO_ACTIVE_PROGRAM_MESSAGE


def test_http_rejects_nonexistent_run_and_run_without_approved_resolved_hosts(
    monkeypatch,
) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com"])
    _approve(runner, "api.example.com")
    _record_dns("test-program", [("api.example.com", "unresolved")])

    def refuse_subprocess(*args, **kwargs):
        pytest.fail("uma run inelegível tentou executar subprocesso")

    monkeypatch.setattr(services.subprocess, "run", refuse_subprocess)
    missing = runner.invoke(app, ["verify", "http", "999", "--dry-run"])
    empty = runner.invoke(app, ["verify", "http", "1", "--dry-run"])

    assert missing.exit_code == empty.exit_code == 1
    assert "Program: test-program" in missing.output
    assert "run 999 não encontrada" in missing.output
    assert "não possui candidatos aprovados com último DNS resolved" in empty.output


def test_http_dry_run_has_no_subprocess_or_files(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com", "dev.example.com"])
    _approve(runner, "api.example.com", "dev.example.com")
    _record_dns(
        "test-program",
        [("api.example.com", "resolved"), ("dev.example.com", "resolved")],
    )

    def refuse_subprocess(*args, **kwargs):
        pytest.fail("verify http --dry-run executou subprocesso")

    monkeypatch.setattr(services.subprocess, "run", refuse_subprocess)
    monkeypatch.setattr(
        services.shutil,
        "which",
        lambda name: pytest.fail("verify http --dry-run consultou o binário"),
    )
    result = runner.invoke(app, ["verify", "http", "1", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "Program: test-program" in result.output
    assert "Hosts aprovados e resolvidos: 2" in result.output
    assert "threads=2; req/s=2; timeout=10s; tentativas=1" in result.output
    assert "-retries 0" in result.output
    assert "-path /" in result.output
    assert not Path(".bb/programs/test-program/runs/1/http").exists()


def test_http_missing_binary_fails_clearly_without_installing(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com"])
    _approve(runner, "api.example.com")
    _record_dns("test-program", [("api.example.com", "resolved")])
    monkeypatch.setattr(services.shutil, "which", lambda name: None)

    def refuse_subprocess(*args, **kwargs):
        pytest.fail("httpx ausente ainda tentou executar subprocesso")

    monkeypatch.setattr(services.subprocess, "run", refuse_subprocess)
    result = runner.invoke(app, ["verify", "http", "1", "--confirm"])

    assert result.exit_code == 1
    assert "httpx não está instalado" in result.output
    assert "instale-o manualmente" in result.output
    assert "PATH" in result.output
    assert not Path(".bb/programs/test-program/runs/1/http/input-hosts.txt").exists()


def test_http_input_contains_only_approved_with_latest_dns_resolved(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(
        runner,
        [
            "eligible.example.com",
            "unresolved.example.com",
            "rejected.example.com",
            "pending.example.com",
        ],
    )
    _approve(runner, "eligible.example.com", "unresolved.example.com")
    rejected = runner.invoke(
        app,
        ["candidates", "reject", "1", "--host", "rejected.example.com"],
    )
    assert rejected.exit_code == 0, rejected.output
    _record_dns(
        "test-program",
        [
            ("eligible.example.com", "resolved"),
            ("unresolved.example.com", "resolved"),
            ("unresolved.example.com", "unresolved"),
            ("rejected.example.com", "resolved"),
            ("pending.example.com", "resolved"),
        ],
    )
    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/httpx")
    monkeypatch.setattr(
        services.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )

    result = runner.invoke(app, ["verify", "http", "1", "--confirm"])

    assert result.exit_code == 0, result.output
    input_path = Path(".bb/programs/test-program/runs/1/http/input-hosts.txt")
    assert input_path.read_text(encoding="utf-8") == "eligible.example.com\n"
    attempts = _http_attempts(Path(".bb/programs/test-program/orchestrator.db"))
    assert [(attempt.host, attempt.reachability) for attempt in attempts] == [
        ("eligible.example.com", "unreachable")
    ]


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "Bearer raw-secret token",
        "person@example.com",
        "+55 11 99999-9999",
        "https://unsafe.example/private",
        "origin 192.0.2.10",
    ],
)
def test_http_default_deny_discards_unsafe_titles_and_technologies(unsafe_value: str) -> None:
    assert services._sanitize_http_text(unsafe_value, max_length=200) is None
    assert services._sanitize_http_technologies(["React", unsafe_value]) is None


def test_http_mocked_results_are_minimal_sanitized_and_reachable_by_response(
    monkeypatch,
) -> None:
    runner = CliRunner()
    status_hosts = {
        "ok.example.com": 200,
        "redirect.example.com": 301,
        "auth.example.com": 401,
        "forbidden.example.com": 403,
        "missing.example.com": 404,
    }
    down_host = "down.example.com"
    all_hosts = [*status_hosts, down_host]
    _create_run(runner, all_hosts)
    _approve(runner, *all_hosts)
    _record_dns("test-program", [(host, "resolved") for host in all_hosts])
    monkeypatch.setenv("ENABLE_CLOUD_UPLOAD", "true")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8443")
    monkeypatch.setenv("PDCP_API_KEY", "raw-secret")
    calls = []
    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/httpx")

    payloads = []
    for host, status_code in status_hosts.items():
        payloads.append(
            {
                "input": host,
                "url": f"https://{host}:8443/?token=raw-secret",
                "host": "192.0.2.10",
                "port": "8443",
                "status_code": status_code,
                "title": (
                    "Safe\u0000 Title"
                    if status_code == 200
                    else "person@example.com token=raw-secret"
                ),
                "tech": ["React", "nginx"]
                if status_code == 200
                else ["React", "https://unsafe.example/path"],
                "header": {"Authorization": "Bearer raw-secret"},
                "body": "raw body with token=raw-secret",
                "location": "https://redirect.example/private?token=raw-secret",
            }
        )
    payloads.append(
        {
            "input": down_host,
            "failed": True,
            "error": "dial tcp 192.0.2.20:443 with token=raw-secret",
        }
    )
    stdout = "".join(f"{json.dumps(payload)}\n" for payload in payloads)

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=stdout,
            stderr="header Authorization: Bearer raw-secret at 192.0.2.30",
        )

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    result = runner.invoke(app, ["verify", "http", "1", "--confirm"])

    assert result.exit_code == 0, result.output
    assert "Program: test-program" in result.output
    assert "verificados=6, alcançáveis=5, inalcançáveis=1" in result.output
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command == [
        "/mock/bin/httpx",
        "-l",
        ".bb/programs/test-program/runs/1/http/input-hosts.txt",
        "-json",
        "-silent",
        "-probe",
        "-sc",
        "-title",
        "-td",
        "-ob",
        "-t",
        "2",
        "-rl",
        "2",
        "-timeout",
        "10",
        "-retries",
        "0",
        "-path",
        "/",
        "-config",
        "/dev/null",
        "-duc",
        "-no-stdin",
    ]
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["capture_output"] is True
    assert "ENABLE_CLOUD_UPLOAD" not in kwargs["env"]
    assert "HTTPS_PROXY" not in kwargs["env"]
    assert "PDCP_API_KEY" not in kwargs["env"]
    forbidden_flags = {
        "-fr",
        "-fhr",
        "-pa",
        "-p",
        "-H",
        "-body",
        "-ss",
        "-favicon",
        "-jarm",
        "-asn",
        "-tls-probe",
        "-csp-probe",
    }
    assert forbidden_flags.isdisjoint(command)

    attempts = _http_attempts(Path(".bb/programs/test-program/orchestrator.db"))
    by_host = {attempt.host: attempt for attempt in attempts}
    assert {by_host[host].status_code for host in status_hosts} == {200, 301, 401, 403, 404}
    assert all(by_host[host].reachability == "reachable" for host in status_hosts)
    assert (by_host[down_host].reachability, by_host[down_host].status_code) == (
        "unreachable",
        None,
    )
    assert by_host["ok.example.com"].title == "Safe Title"
    assert by_host["ok.example.com"].technologies == ["nginx", "React"]
    engine = create_sqlite_engine(Path(".bb/programs/test-program/orchestrator.db"))
    with create_session_factory(engine)() as session:
        snapshots = list(session.scalars(select(ExecutionPolicySnapshotModel)))
    assert [(item.run_id, item.program_slug, item.step) for item in snapshots] == [
        (1, "test-program", "http")
    ]
    assert snapshots[0].snapshot == {
        "name": "conservative",
        "version": "1",
        "parameters": {
            "threads": 2,
            "rate_limit_per_second": 2,
            "timeout_seconds": 10,
            "retries": 0,
            "process_timeout_seconds": 300,
        },
    }
    for host in status_hosts.keys() - {"ok.example.com"}:
        assert by_host[host].title is None
        assert by_host[host].technologies is None

    persisted = "\n".join(
        str(value)
        for attempt in attempts
        for value in (
            attempt.host,
            attempt.reachability,
            attempt.status_code,
            attempt.title,
            attempt.technologies,
            attempt.program_slug,
        )
    )
    for forbidden in (
        "https://",
        "?token",
        "192.0.2.",
        ":8443",
        "Authorization",
        "raw body",
        "raw-secret",
        "person@example.com",
    ):
        assert forbidden not in persisted
    http_dir = Path(".bb/programs/test-program/runs/1/http")
    assert [path.name for path in http_dir.iterdir()] == ["input-hosts.txt"]

    listed = runner.invoke(app, ["assets", "list", "1"])
    assert listed.exit_code == 0, listed.output
    assert "ok.example.com  approved  resolved  reachable  200" in listed.output
    assert "redirect.example.com  approved  resolved  reachable  301" in listed.output
    assert "down.example.com  approved  resolved  unreachable  -" in listed.output
    assert "https://" not in listed.output


def test_repeated_http_confirmation_preserves_history_and_updates_latest_state(
    monkeypatch,
) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com"])
    _approve(runner, "api.example.com")
    _record_dns("test-program", [("api.example.com", "resolved")])
    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/httpx")
    outputs = iter(
        [
            f"{json.dumps({'input': 'api.example.com', 'status_code': 200})}\n",
            "",
        ]
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=next(outputs), stderr="")

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    first = runner.invoke(app, ["verify", "http", "1", "--confirm"])
    second = runner.invoke(app, ["verify", "http", "1", "--confirm"])

    assert first.exit_code == second.exit_code == 0
    attempts = _http_attempts(Path(".bb/programs/test-program/orchestrator.db"))
    assert [(attempt.reachability, attempt.status_code) for attempt in attempts] == [
        ("reachable", 200),
        ("unreachable", None),
    ]
    listed = runner.invoke(app, ["assets", "list", "1"])
    assert "api.example.com  approved  resolved  unreachable  -" in listed.output


def test_http_attempts_are_isolated_between_programs(monkeypatch) -> None:
    runner = CliRunner()
    alpha = create_program("alpha", "Alpha")
    beta = create_program("beta", "Beta")
    Path("scope.txt").write_text("*.example.com\n", encoding="utf-8")
    monkeypatch.setattr(services.shutil, "which", lambda name: "/mock/bin/httpx")

    def fake_run(command, **kwargs):
        host = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").strip()
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=f"{json.dumps({'input': host, 'status_code': 200})}\n",
            stderr="",
        )

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    for slug, host in (("alpha", "alpha.example.com"), ("beta", "beta.example.com")):
        select_program(slug)
        Path("input.jsonl").write_text(f'{{"domain":"{host}"}}\n', encoding="utf-8")
        assert runner.invoke(app, ["scope", "import", "scope.txt"]).exit_code == 0
        assert runner.invoke(app, ["run", "ingest", "input.jsonl"]).exit_code == 0
        assert runner.invoke(app, ["candidates", "approve", "1", "--all"]).exit_code == 0
        _record_dns(slug, [(host, "resolved")])
        verified = runner.invoke(app, ["verify", "http", "1", "--confirm"])
        assert verified.exit_code == 0, verified.output
        assert f"Program: {slug}" in verified.output

    assert [(item.program_slug, item.host) for item in _http_attempts(alpha.database_path)] == [
        ("alpha", "alpha.example.com")
    ]
    assert [(item.program_slug, item.host) for item in _http_attempts(beta.database_path)] == [
        ("beta", "beta.example.com")
    ]
    select_program("beta")
    listed = runner.invoke(app, ["assets", "list", "1"])
    assert "beta.example.com" in listed.output
    assert "alpha.example.com" not in listed.output


def test_fake_end_to_end_dns_then_http_without_real_network(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner, ["api.example.com"])
    _approve(runner, "api.example.com")
    monkeypatch.setattr(
        services.shutil,
        "which",
        lambda name: f"/mock/bin/{name}" if name in {"dnsx", "httpx"} else None,
    )

    def fake_run(command, **kwargs):
        if command[0].endswith("dnsx"):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="api.example.com\n",
                stderr="",
            )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=f"{json.dumps({'input': 'api.example.com', 'status_code': 403})}\n",
            stderr="",
        )

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    dns = runner.invoke(app, ["verify", "dns", "1", "--confirm"])
    http = runner.invoke(app, ["verify", "http", "1", "--confirm"])
    listed = runner.invoke(app, ["assets", "list", "1"])

    assert dns.exit_code == http.exit_code == listed.exit_code == 0
    assert "api.example.com  approved  resolved  reachable  403" in listed.output
