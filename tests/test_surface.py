import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from typer.testing import CliRunner

import bb_orchestrator.services as services
from bb_orchestrator.cli import app
from bb_orchestrator.database import create_session_factory, create_sqlite_engine
from bb_orchestrator.models import (
    AssetModel,
    CandidateModel,
    DnsVerificationAttemptModel,
    ExecutionPolicySnapshotModel,
    HttpVerificationAttemptModel,
    PortObservationModel,
    QueueItemModel,
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


def _create_run(runner: CliRunner, slug: str, hosts: list[str]) -> None:
    create_program(slug, slug.title())
    select_program(slug)
    Path(f"{slug}-scope.txt").write_text("*.example.com\n", encoding="utf-8")
    Path(f"{slug}-input.jsonl").write_text(
        "".join(f"{json.dumps({'domain': host})}\n" for host in hosts),
        encoding="utf-8",
    )
    assert runner.invoke(app, ["scope", "import", f"{slug}-scope.txt"]).exit_code == 0
    assert runner.invoke(app, ["run", "ingest", f"{slug}-input.jsonl"]).exit_code == 0


def _transition(runner: CliRunner, action: str, *hosts: str) -> None:
    command = ["candidates", action, "1"]
    for host in hosts:
        command.extend(("--host", host))
    result = runner.invoke(app, command)
    assert result.exit_code == 0, result.output


def _record_surface_state(
    slug: str,
    *,
    dns: list[tuple[str, str]],
    http: list[dict[str, object]],
    ports: list[tuple[str, int]],
) -> None:
    program = load_program(slug)
    engine = create_sqlite_engine(program.database_path)
    with create_session_factory(engine)() as session:
        candidates = {
            candidate.host: candidate
            for candidate in session.scalars(
                select(CandidateModel).where(CandidateModel.run_id == 1)
            )
        }
        now = datetime.now(UTC)
        for host, status in dns:
            session.add(
                DnsVerificationAttemptModel(
                    run_id=1,
                    candidate_id=candidates[host].id,
                    program_slug=slug,
                    host=host,
                    status=status,
                    verified_at=now,
                    dnsx_version="v1.2.3",
                )
            )
        for item in http:
            host = str(item["host"])
            session.add(
                HttpVerificationAttemptModel(
                    run_id=1,
                    candidate_id=candidates[host].id,
                    program_slug=slug,
                    host=host,
                    reachability=str(item["reachability"]),
                    status_code=item.get("status_code"),
                    title=item.get("title"),
                    technologies=item.get("technologies"),
                    verified_at=now,
                )
            )
        snapshot = ExecutionPolicySnapshotModel(
            run_id=1,
            program_slug=slug,
            step="ports",
            snapshot={
                "name": "conservative",
                "version": "1",
                "parameters": {"raw": "192.0.2.99 Authorization raw body"},
            },
        )
        session.add(snapshot)
        session.flush()
        session.add_all(
            PortObservationModel(
                run_id=1,
                host=host,
                port=port,
                status="open",
                observed_at=now,
                tool_version="naabu v2.6.1 at 192.0.2.50",
                policy_snapshot_id=snapshot.id,
            )
            for host, port in ports
        )
        session.commit()


def _prepare_complete_surface(runner: CliRunner) -> None:
    hosts = [
        "ports.example.com",
        "pending.example.com",
        "dns.example.com",
        "rejected.example.com",
        "http.example.com",
        "unresolved.example.com",
    ]
    _create_run(runner, "test-program", hosts)
    _transition(
        runner,
        "approve",
        "dns.example.com",
        "http.example.com",
        "ports.example.com",
        "unresolved.example.com",
    )
    _transition(runner, "reject", "rejected.example.com")
    _record_surface_state(
        "test-program",
        dns=[
            ("dns.example.com", "resolved"),
            ("http.example.com", "resolved"),
            ("ports.example.com", "resolved"),
            ("unresolved.example.com", "resolved"),
            ("unresolved.example.com", "unresolved"),
            ("pending.example.com", "resolved"),
            ("rejected.example.com", "resolved"),
        ],
        http=[
            {
                "host": "dns.example.com",
                "reachability": "reachable",
                "status_code": 200,
                "title": "Old reachable title",
                "technologies": ["OldTech"],
            },
            {"host": "dns.example.com", "reachability": "unreachable"},
            {
                "host": "http.example.com",
                "reachability": "reachable",
                "status_code": 200,
                "title": "https://unsafe.example/private?token=raw-secret 192.0.2.10",
                "technologies": ["nginx", "Authorization: Bearer raw-secret"],
            },
            {
                "host": "ports.example.com",
                "reachability": "reachable",
                "status_code": 403,
                "title": "Safe\u0000 Title",
                "technologies": ["React", "nginx", "React"],
            },
            {
                "host": "unresolved.example.com",
                "reachability": "reachable",
                "status_code": 200,
                "title": "Must stay hidden",
                "technologies": ["HiddenTech"],
            },
            {
                "host": "pending.example.com",
                "reachability": "reachable",
                "status_code": 200,
                "title": "Header: raw body at 192.0.2.20",
                "technologies": ["HiddenTech"],
            },
            {
                "host": "rejected.example.com",
                "reachability": "reachable",
                "status_code": 200,
                "title": "Cookie: raw body",
                "technologies": ["HiddenTech"],
            },
        ],
        ports=[
            ("ports.example.com", 8443),
            ("ports.example.com", 80),
            ("ports.example.com", 443),
            ("dns.example.com", 8080),
            ("unresolved.example.com", 80),
            ("pending.example.com", 80),
            ("rejected.example.com", 80),
        ],
    )


def _database_state(slug: str) -> tuple[object, ...]:
    program = load_program(slug)
    engine = create_sqlite_engine(program.database_path)
    with create_session_factory(engine)() as session:
        candidates = tuple(
            session.execute(
                select(CandidateModel.host, CandidateModel.status).order_by(CandidateModel.host)
            ).all()
        )
        return (
            candidates,
            session.scalar(select(func.count()).select_from(DnsVerificationAttemptModel)),
            session.scalar(select(func.count()).select_from(HttpVerificationAttemptModel)),
            session.scalar(select(func.count()).select_from(PortObservationModel)),
            session.scalar(select(func.count()).select_from(AssetModel)),
            session.scalar(select(func.count()).select_from(QueueItemModel)),
        )


def test_surface_commands_require_an_active_program() -> None:
    runner = CliRunner()

    listed = runner.invoke(app, ["surface", "list", "1"])
    exported = runner.invoke(app, ["surface", "export", "1"])

    assert listed.exit_code == exported.exit_code == 1
    assert listed.output.strip() == exported.output.strip() == NO_ACTIVE_PROGRAM_MESSAGE


def test_surface_rejects_nonexistent_run_without_creating_artifact() -> None:
    create_program("test-program", "Test Program")
    select_program("test-program")
    runner = CliRunner()

    listed = runner.invoke(app, ["surface", "list", "999"])
    exported = runner.invoke(app, ["surface", "export", "999"])

    assert listed.exit_code == exported.exit_code == 1
    assert "run 999 não encontrada" in listed.output
    assert "run 999 não encontrada" in exported.output
    assert not Path(".bb/programs/test-program/runs/999").exists()


def test_surface_list_is_local_latest_sanitized_and_deterministic(monkeypatch) -> None:
    runner = CliRunner()
    _prepare_complete_surface(runner)

    def refuse_io(*args, **kwargs):
        pytest.fail("surface list tentou usar subprocesso, PATH ou rede")

    monkeypatch.setattr(services.subprocess, "run", refuse_io)
    monkeypatch.setattr(services.shutil, "which", refuse_io)
    monkeypatch.setattr(socket, "socket", refuse_io)
    monkeypatch.setattr(socket, "create_connection", refuse_io)

    result = runner.invoke(app, ["surface", "list", "1"])

    assert result.exit_code == 0, result.output
    assert "Program: test-program" in result.output
    assert "HOST  APROVAÇÃO  DNS  HTTP" in result.output
    rows = [
        line
        for line in result.output.splitlines()
        if line.endswith(
            (
                "pending",
                "dns_resolved",
                "http_reachable",
                "ports_observed",
            )
        )
    ]
    assert [line.split()[0] for line in rows] == sorted(
        [
            "dns.example.com",
            "http.example.com",
            "pending.example.com",
            "ports.example.com",
            "rejected.example.com",
            "unresolved.example.com",
        ]
    )
    assert "dns.example.com  approved  resolved  unreachable  -  -  -  -  dns_resolved" in rows
    assert "http.example.com  approved  resolved  reachable  200  -  -  -  http_reachable" in rows
    assert "pending.example.com  pending  pending  pending  -  -  -  -  pending" in rows
    assert (
        "ports.example.com  approved  resolved  reachable  403  Safe Title  nginx,React  "
        "80,443,8443  ports_observed"
    ) in rows
    assert "rejected.example.com  rejected  pending  pending  -  -  -  -  pending" in rows
    assert "unresolved.example.com  approved  unresolved  pending  -  -  -  -  pending" in rows
    assert not Path(".bb/programs/test-program/runs/1/surface").exists()
    for forbidden in (
        "192.0.2.",
        "https://",
        "Authorization",
        "Cookie:",
        "raw body",
        "raw-secret",
        "Old reachable title",
        "Must stay hidden",
    ):
        assert forbidden not in result.output


def test_surface_export_is_safe_deterministic_atomic_and_side_effect_free(
    monkeypatch,
) -> None:
    runner = CliRunner()
    _prepare_complete_surface(runner)
    before = _database_state("test-program")

    def refuse_io(*args, **kwargs):
        pytest.fail("surface export tentou usar subprocesso, PATH ou rede")

    monkeypatch.setattr(services.subprocess, "run", refuse_io)
    monkeypatch.setattr(services.shutil, "which", refuse_io)
    monkeypatch.setattr(socket, "socket", refuse_io)
    monkeypatch.setattr(socket, "create_connection", refuse_io)
    surface_dir = Path(".bb/programs/test-program/runs/1/surface")
    surface_dir.mkdir(parents=True)
    (surface_dir / "keep.txt").write_text("preservar", encoding="utf-8")
    (surface_dir / "surface.jsonl").write_text("stale 192.0.2.1\n", encoding="utf-8")

    first = runner.invoke(app, ["surface", "export", "1"])
    first_bytes = (surface_dir / "surface.jsonl").read_bytes()
    (surface_dir / "surface.jsonl").write_text("stale again\n", encoding="utf-8")
    second = runner.invoke(app, ["surface", "export", "1"])
    second_bytes = (surface_dir / "surface.jsonl").read_bytes()

    assert first.exit_code == second.exit_code == 0, first.output + second.output
    assert "superfície exportada=6" in first.output
    assert first_bytes == second_bytes
    assert not (surface_dir / "surface.jsonl.tmp").exists()
    assert (surface_dir / "keep.txt").read_text(encoding="utf-8") == "preservar"
    assert sorted(path.name for path in surface_dir.iterdir()) == ["keep.txt", "surface.jsonl"]
    payloads = [json.loads(line) for line in first_bytes.decode().splitlines()]
    expected_keys = {
        "host",
        "approval_status",
        "dns_status",
        "http_reachability",
        "http_status_code",
        "http_title",
        "http_technologies",
        "open_ports",
        "stage",
    }
    assert [payload["host"] for payload in payloads] == sorted(
        payload["host"] for payload in payloads
    )
    assert all(set(payload) == expected_keys for payload in payloads)
    assert all(list(payload) == sorted(payload) for payload in payloads)
    by_host = {payload["host"]: payload for payload in payloads}
    assert by_host["ports.example.com"] == {
        "approval_status": "approved",
        "dns_status": "resolved",
        "host": "ports.example.com",
        "http_reachability": "reachable",
        "http_status_code": 403,
        "http_technologies": ["nginx", "React"],
        "http_title": "Safe Title",
        "open_ports": [80, 443, 8443],
        "stage": "ports_observed",
    }
    assert by_host["pending.example.com"]["dns_status"] == "pending"
    assert by_host["rejected.example.com"]["http_reachability"] == "pending"
    assert by_host["unresolved.example.com"]["open_ports"] == []
    serialized = first_bytes.decode()
    for forbidden in (
        "192.0.2.",
        "https://",
        "Authorization",
        "Cookie",
        "raw body",
        "raw-secret",
        "Old reachable title",
        "Must stay hidden",
    ):
        assert forbidden not in serialized
    assert _database_state("test-program") == before


def test_surface_is_isolated_between_programs_with_same_run_id() -> None:
    runner = CliRunner()
    for slug, host, port in (
        ("alpha", "alpha.example.com", 80),
        ("beta", "beta.example.com", 443),
    ):
        _create_run(runner, slug, [host])
        _transition(runner, "approve", host)
        _record_surface_state(
            slug,
            dns=[(host, "resolved")],
            http=[
                {
                    "host": host,
                    "reachability": "reachable",
                    "status_code": 200,
                    "title": slug.title(),
                    "technologies": [f"{slug.title()}Tech"],
                }
            ],
            ports=[(host, port)],
        )

    select_program("alpha")
    alpha_list = runner.invoke(app, ["surface", "list", "1"])
    alpha_export = runner.invoke(app, ["surface", "export", "1"])
    select_program("beta")
    beta_list = runner.invoke(app, ["surface", "list", "1"])
    beta_export = runner.invoke(app, ["surface", "export", "1"])

    assert all(
        result.exit_code == 0 for result in (alpha_list, alpha_export, beta_list, beta_export)
    )
    assert "alpha.example.com" in alpha_list.output
    assert "beta.example.com" not in alpha_list.output
    assert "beta.example.com" in beta_list.output
    assert "alpha.example.com" not in beta_list.output
    alpha_payload = json.loads(Path(".bb/programs/alpha/runs/1/surface/surface.jsonl").read_text())
    beta_payload = json.loads(Path(".bb/programs/beta/runs/1/surface/surface.jsonl").read_text())
    assert (alpha_payload["host"], alpha_payload["open_ports"]) == (
        "alpha.example.com",
        [80],
    )
    assert (beta_payload["host"], beta_payload["open_ports"]) == (
        "beta.example.com",
        [443],
    )
