import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, inspect, select
from typer.testing import CliRunner

import bb_orchestrator.services as services
from bb_orchestrator.cli import app
from bb_orchestrator.database import create_session_factory, create_sqlite_engine
from bb_orchestrator.models import (
    AssetModel,
    CandidateModel,
    CrawlPathModel,
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

KATANA_FLAGS = (
    "-u",
    "-d",
    "-c",
    "-p",
    "-rl",
    "-timeout",
    "-retry",
    "-ct",
    "-mrs",
    "-fs",
    "-f",
    "-silent",
    "-nc",
    "-dr",
    "-config",
    "-duc",
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


def _record_state(
    slug: str,
    host: str,
    *,
    dns: str = "resolved",
    http: str = "reachable",
    scheme: str | None = "https",
) -> None:
    program = load_program(slug)
    engine = create_sqlite_engine(program.database_path)
    with create_session_factory(engine)() as session:
        candidate = session.scalar(
            select(CandidateModel).where(CandidateModel.run_id == 1, CandidateModel.host == host)
        )
        assert candidate is not None
        now = datetime.now(UTC)
        session.add(
            DnsVerificationAttemptModel(
                run_id=1,
                candidate_id=candidate.id,
                program_slug=slug,
                host=host,
                status=dns,
                verified_at=now,
                dnsx_version=None,
            )
        )
        session.add(
            HttpVerificationAttemptModel(
                run_id=1,
                candidate_id=candidate.id,
                program_slug=slug,
                host=host,
                reachability=http,
                status_code=200 if http == "reachable" else None,
                scheme=scheme,
                title=None,
                technologies=None,
                verified_at=now,
            )
        )
        session.commit()


class FakeKatanaAdapter:
    def __init__(
        self,
        outputs: dict[str, str] | None = None,
        *,
        executable: str | None = "/mock/bin/katana",
        help_flags: tuple[str, ...] = KATANA_FLAGS,
    ) -> None:
        self.outputs = outputs or {}
        self.executable = executable
        self.help_flags = help_flags
        self.lookups: list[str] = []
        self.calls: list[tuple[list[str], int, dict[str, str]]] = []

    def find_executable(self, name: str) -> str | None:
        self.lookups.append(name)
        return self.executable

    def run(self, command, *, timeout_seconds, environment):
        command = list(command)
        self.calls.append((command, timeout_seconds, dict(environment)))
        if command[1:] == ["-h"]:
            help_text = "usage: katana\n" + "\n".join(self.help_flags) + "\n"
            return subprocess.CompletedProcess(command, 0, stdout=help_text, stderr="")
        seed = command[command.index("-u") + 1]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=self.outputs.get(seed, ""),
            stderr="",
        )


def _database_state(slug: str) -> tuple[object, ...]:
    program = load_program(slug)
    engine = create_sqlite_engine(program.database_path)
    with create_session_factory(engine)() as session:
        return (
            tuple(
                session.execute(
                    select(CandidateModel.host, CandidateModel.status).order_by(CandidateModel.host)
                ).all()
            ),
            session.scalar(select(func.count()).select_from(DnsVerificationAttemptModel)),
            session.scalar(select(func.count()).select_from(HttpVerificationAttemptModel)),
            session.scalar(select(func.count()).select_from(PortObservationModel)),
            session.scalar(select(func.count()).select_from(AssetModel)),
            session.scalar(select(func.count()).select_from(QueueItemModel)),
        )


def test_katana_and_paths_require_an_active_program() -> None:
    runner = CliRunner()

    crawled = runner.invoke(app, ["crawl", "katana", "1", "--dry-run"])
    listed = runner.invoke(app, ["paths", "list", "1"])

    assert crawled.exit_code == listed.exit_code == 1
    assert crawled.output.strip() == listed.output.strip() == NO_ACTIVE_PROGRAM_MESSAGE


def test_katana_requires_one_mode_and_dry_run_has_no_path_process_or_file(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner, "test-program", ["api.example.com"])
    _transition(runner, "approve", "api.example.com")
    _record_state("test-program", "api.example.com")

    class RefuseAdapter:
        def find_executable(self, name):
            pytest.fail("dry-run consultou o PATH")

        def run(self, *args, **kwargs):
            pytest.fail("dry-run executou subprocesso")

    monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", RefuseAdapter())
    absent = runner.invoke(app, ["crawl", "katana", "1"])
    both = runner.invoke(app, ["crawl", "katana", "1", "--dry-run", "--confirm"])
    dry_run = runner.invoke(app, ["crawl", "katana", "1", "--dry-run"])

    assert absent.exit_code == both.exit_code == 1
    assert "exatamente uma opção" in absent.output
    assert "exatamente uma opção" in both.output
    assert dry_run.exit_code == 0, dry_run.output
    assert "Versão da política: 2" in dry_run.output
    assert "Hosts elegíveis: 1" in dry_run.output
    assert "headless=false; javascript=false; concorrência=1; paralelismo=1; req/s=1" in (
        dry_run.output
    )
    assert "depth=1; timeout=10s; retries=0; duração-máxima=60s" in dry_run.output
    assert "resposta-máxima=1048576 bytes; paths/host=100; escopo=fqdn" in dry_run.output
    assert "<scheme>://<host>/" in dry_run.output
    assert not Path(".bb/programs/test-program/runs/1/crawl").exists()


def test_katana_eligibility_ignores_old_http_without_scheme_with_guidance(monkeypatch) -> None:
    runner = CliRunner()
    hosts = [
        "eligible.example.com",
        "legacy.example.com",
        "unreachable.example.com",
        "unresolved.example.com",
        "rejected.example.com",
        "pending.example.com",
    ]
    _create_run(runner, "test-program", hosts)
    _transition(
        runner,
        "approve",
        "eligible.example.com",
        "legacy.example.com",
        "unreachable.example.com",
        "unresolved.example.com",
    )
    _transition(runner, "reject", "rejected.example.com")
    _record_state("test-program", "eligible.example.com")
    _record_state("test-program", "legacy.example.com", scheme=None)
    _record_state("test-program", "unreachable.example.com", http="unreachable", scheme=None)
    _record_state("test-program", "unresolved.example.com", dns="unresolved")
    _record_state("test-program", "rejected.example.com")
    _record_state("test-program", "pending.example.com")

    adapter = FakeKatanaAdapter({"https://eligible.example.com/": "/public\n"})
    monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", adapter)
    dry_run = runner.invoke(app, ["crawl", "katana", "1", "--dry-run"])
    confirmed = runner.invoke(app, ["crawl", "katana", "1", "--confirm"])

    assert dry_run.exit_code == confirmed.exit_code == 0, dry_run.output + confirmed.output
    assert "Hosts elegíveis: 1" in dry_run.output
    assert "Ignorados sem esquema HTTP sanitizado: 1" in dry_run.output
    assert "bb verify http 1 --confirm" in dry_run.output
    assert adapter.lookups == ["katana"]
    seeds = [call[0][call[0].index("-u") + 1] for call in adapter.calls if "-u" in call[0]]
    assert seeds == ["https://eligible.example.com/"]


def test_katana_missing_binary_or_incompatible_help_fails_before_crawl(monkeypatch) -> None:
    runner = CliRunner()
    _create_run(runner, "test-program", ["api.example.com"])
    _transition(runner, "approve", "api.example.com")
    _record_state("test-program", "api.example.com")

    missing_adapter = FakeKatanaAdapter(executable=None)
    monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", missing_adapter)
    missing = runner.invoke(app, ["crawl", "katana", "1", "--confirm"])

    assert missing.exit_code == 1
    assert "katana não está instalado" in missing.output
    assert "instale-o manualmente" in missing.output
    assert missing_adapter.calls == []
    assert not Path(".bb/programs/test-program/runs/1/crawl").exists()

    incompatible_adapter = FakeKatanaAdapter(
        help_flags=tuple(flag for flag in KATANA_FLAGS if flag != "-fs")
    )
    monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", incompatible_adapter)
    incompatible = runner.invoke(app, ["crawl", "katana", "1", "--confirm"])

    assert incompatible.exit_code == 1
    assert "não reconhece a sintaxe segura" in incompatible.output
    assert "-fs" in incompatible.output
    assert len(incompatible_adapter.calls) == 1
    assert incompatible_adapter.calls[0][0] == ["/mock/bin/katana", "-h"]
    assert not Path(".bb/programs/test-program/runs/1/crawl").exists()


def test_katana_is_sequential_scoped_sanitized_limited_and_deterministic(monkeypatch) -> None:
    runner = CliRunner()
    hosts = ["alpha.example.com", "beta.example.com"]
    _create_run(runner, "test-program", hosts)
    _transition(runner, "approve", *hosts)
    _record_state("test-program", "alpha.example.com", scheme="https")
    _record_state("test-program", "beta.example.com", scheme="http")
    safe_paths = [f"/public/{index:03d}" for index in range(105)]
    unsafe = [
        "/public/001",
        "/login?next=/admin#fragment",
        "/assets/app.js",
        "https://alpha.example.com/private",
        "//outside.example/path",
        "/outside.example/path",
        "/192.0.2.10/admin",
        "/admin:8443",
        "/token/raw-secret",
        "/person@example.com",
        "/+55-11-99999-9999",
        "/control\x00value",
        "/" + "a" * 513,
    ]
    adapter = FakeKatanaAdapter(
        {
            "https://alpha.example.com/": "\n".join([*reversed(safe_paths), *unsafe]) + "\n",
            "http://beta.example.com/": "/zeta\n/alpha/../normalized\n",
        }
    )
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8443")
    monkeypatch.setenv("KATANA_CONFIG", "/unsafe/config")
    monkeypatch.setenv("PDCP_API_KEY", "raw-secret")
    monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", adapter)
    before = _database_state("test-program")

    first = runner.invoke(app, ["crawl", "katana", "1", "--confirm"])
    artifact = Path(".bb/programs/test-program/runs/1/crawl/paths.jsonl")
    first_bytes = artifact.read_bytes()
    second = runner.invoke(app, ["crawl", "katana", "1", "--confirm"])
    second_bytes = artifact.read_bytes()

    assert first.exit_code == second.exit_code == 0, first.output + second.output
    assert "hosts processados=2, caminhos sanitizados=102" in first.output
    assert adapter.lookups == ["katana", "katana"]
    assert len(adapter.calls) == 6
    for invocation_calls in (adapter.calls[:3], adapter.calls[3:]):
        assert invocation_calls[0][0] == ["/mock/bin/katana", "-h"]
        assert [call[0][call[0].index("-u") + 1] for call in invocation_calls[1:]] == [
            "https://alpha.example.com/",
            "http://beta.example.com/",
        ]

    command, timeout_seconds, environment = adapter.calls[1]
    assert command == [
        "/mock/bin/katana",
        "-u",
        "https://alpha.example.com/",
        "-d",
        "1",
        "-c",
        "1",
        "-p",
        "1",
        "-rl",
        "1",
        "-timeout",
        "10",
        "-retry",
        "0",
        "-ct",
        "60s",
        "-mrs",
        "1048576",
        "-fs",
        "fqdn",
        "-f",
        "path",
        "-silent",
        "-nc",
        "-dr",
        "-config",
        "/dev/null",
        "-duc",
    ]
    assert timeout_seconds == 60
    assert "HTTPS_PROXY" not in environment
    assert "KATANA_CONFIG" not in environment
    assert "PDCP_API_KEY" not in environment
    forbidden_flags = {
        "-hl",
        "-scu",
        "-jc",
        "-jsl",
        "-xhr",
        "-aff",
        "-fx",
        "-H",
        "-proxy",
        "-r",
        "-kf",
        "-sr",
        "-o",
        "-debug",
        "-v",
        "-do",
        "-ns",
    }
    assert forbidden_flags.isdisjoint(command)

    assert first_bytes == second_bytes
    assert sorted(path.name for path in artifact.parent.iterdir()) == ["paths.jsonl"]
    payloads = [json.loads(line) for line in first_bytes.decode().splitlines()]
    assert len(payloads) == 102
    assert all(set(payload) == {"host", "path", "source"} for payload in payloads)
    assert payloads == sorted(payloads, key=lambda item: (item["host"], item["path"]))
    assert sum(payload["host"] == "alpha.example.com" for payload in payloads) == 100
    assert {payload["path"] for payload in payloads if payload["host"] == "alpha.example.com"} >= {
        "/assets/app.js",
        "/login",
    }
    assert {payload["path"] for payload in payloads if payload["host"] == "beta.example.com"} == {
        "/normalized",
        "/zeta",
    }
    serialized = first_bytes.decode()
    for forbidden in (
        "https://",
        "?next",
        "#fragment",
        "outside.example",
        "192.0.2.10",
        ":8443",
        "raw-secret",
        "person@example.com",
        "+55-11",
    ):
        assert forbidden not in serialized

    program = load_program("test-program")
    engine = create_sqlite_engine(program.database_path)
    with create_session_factory(engine)() as session:
        paths = list(
            session.scalars(
                select(CrawlPathModel).order_by(CrawlPathModel.host, CrawlPathModel.path)
            )
        )
        snapshots = list(
            session.scalars(
                select(ExecutionPolicySnapshotModel).where(
                    ExecutionPolicySnapshotModel.step == "katana"
                )
            )
        )
        assert len(paths) == 102
        assert len(snapshots) == 2
        assert snapshots[0].snapshot == snapshots[1].snapshot
        assert snapshots[0].snapshot["version"] == "2"
        assert snapshots[0].snapshot["parameters"]["max_paths_per_host"] == 100
        assert all(path.policy_snapshot_id == snapshots[0].id for path in paths)
    assert _database_state("test-program") == before

    listed = runner.invoke(app, ["paths", "list", "1"])
    assert listed.exit_code == 0, listed.output
    assert listed.output.splitlines()[0] == "HOST  PATH  SOURCE"
    assert "Program:" not in listed.output
    assert "beta.example.com  /normalized  katana" in listed.output
    assert "https://" not in listed.output

    surface = runner.invoke(app, ["surface", "list", "1"])
    exported = runner.invoke(app, ["surface", "export", "1"])
    assert surface.exit_code == exported.exit_code == 0
    assert (
        "alpha.example.com  approved  resolved  reachable  200  -  -  -  100  paths_observed"
        in (surface.output)
    )
    surface_payloads = [
        json.loads(line)
        for line in Path(".bb/programs/test-program/runs/1/surface/surface.jsonl")
        .read_text()
        .splitlines()
    ]
    assert {payload["host"]: payload["path_count"] for payload in surface_payloads} == {
        "alpha.example.com": 100,
        "beta.example.com": 2,
    }
    assert all("paths" not in payload for payload in surface_payloads)


def test_crawl_paths_schema_and_program_isolation(monkeypatch) -> None:
    runner = CliRunner()
    adapters: dict[str, FakeKatanaAdapter] = {}
    for slug, host, path in (
        ("alpha", "alpha.example.com", "/alpha"),
        ("beta", "beta.example.com", "/beta"),
    ):
        _create_run(runner, slug, [host])
        _transition(runner, "approve", host)
        _record_state(slug, host)
        adapter = FakeKatanaAdapter({f"https://{host}/": f"{path}\n"})
        adapters[slug] = adapter
        monkeypatch.setattr(services, "DEFAULT_SUBPROCESS_ADAPTER", adapter)
        result = runner.invoke(app, ["crawl", "katana", "1", "--confirm"])
        assert result.exit_code == 0, result.output

    select_program("alpha")
    alpha = runner.invoke(app, ["paths", "list", "1"])
    select_program("beta")
    beta = runner.invoke(app, ["paths", "list", "1"])
    assert "alpha.example.com  /alpha  katana" in alpha.output
    assert "beta.example.com" not in alpha.output
    assert "beta.example.com  /beta  katana" in beta.output
    assert "alpha.example.com" not in beta.output

    engine = create_sqlite_engine(load_program("alpha").database_path)
    assert {column["name"] for column in inspect(engine).get_columns("crawl_paths")} == {
        "id",
        "run_id",
        "host",
        "path",
        "source",
        "observed_at",
        "policy_snapshot_id",
    }
