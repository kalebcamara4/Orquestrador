import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import bb_orchestrator.cli as cli
import bb_orchestrator.services as services
from bb_orchestrator.cli import app
from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.models import AssetModel, QueueItemModel, RunModel
from bb_orchestrator.schemas import (
    AssetStatus,
    QueueStatus,
    RunStatus,
    TriageAsset,
    TriageDecision,
    TriageRequest,
    TriageResponse,
)
from bb_orchestrator.services import (
    InputError,
    PolicyViolation,
    enforce_triage_policy,
    prepare_triage,
)


@pytest.fixture
def session(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "triage.db")
    initialize_database(engine)
    with create_session_factory(engine)() as db_session:
        yield db_session


def _add_run(session, domains: list[str]) -> RunModel:
    run = RunModel(
        source_sha256="0" * 64,
        status=RunStatus.SANITIZED.value,
        accepted_count=len(domains),
        rejected_count=0,
        duplicate_count=0,
    )
    session.add(run)
    session.flush()
    for domain in domains:
        asset = AssetModel(
            run_id=run.id,
            domain=domain,
            status=AssetStatus.SANITIZED.value,
            sanitized_at=datetime.now(UTC),
        )
        session.add(asset)
        session.flush()
        session.add(
            QueueItemModel(
                run_id=run.id,
                asset_id=asset.id,
                status=QueueStatus.PENDING.value,
            )
        )
    session.commit()
    return run


def _domains(count: int) -> list[str]:
    return [f"host-{index:02d}.example.com" for index in range(count)]


@pytest.mark.parametrize(
    ("item_count", "expected_batch_sizes"),
    [
        (1, [1]),
        (10, [10]),
        (11, [10, 1]),
        (21, [10, 10, 1]),
    ],
)
def test_default_batch_creation(
    tmp_path: Path,
    session,
    item_count: int,
    expected_batch_sizes: list[int],
) -> None:
    run = _add_run(session, _domains(item_count))

    result = prepare_triage(run.id, session, runs_path=tmp_path / "runs")

    assert result.item_count == item_count
    assert result.batch_count == len(expected_batch_sizes)
    assert [len(json.loads(path.read_text())["items"]) for path in result.paths] == (
        expected_batch_sizes
    )
    assert [path.name for path in result.paths] == [
        f"triage-input-{index:04d}.json" for index in range(1, len(expected_batch_sizes) + 1)
    ]


def test_configurable_batch_size_accepts_twenty_as_maximum(tmp_path: Path, session) -> None:
    run = _add_run(session, _domains(21))

    result = prepare_triage(
        run.id,
        session,
        batch_size=20,
        runs_path=tmp_path / "runs",
    )

    assert [len(json.loads(path.read_text())["items"]) for path in result.paths] == [20, 1]


@pytest.mark.parametrize("batch_size", [0, 21, True, 10.5])
def test_service_refuses_invalid_batch_sizes(tmp_path: Path, session, batch_size) -> None:
    run = _add_run(session, ["example.com"])

    with pytest.raises(InputError):
        prepare_triage(
            run.id,
            session,
            batch_size=batch_size,
            runs_path=tmp_path / "runs",
        )


def test_asset_ids_are_stable_unique_and_input_order_independent(tmp_path: Path, session) -> None:
    domains = _domains(11)
    first_run = _add_run(session, domains)
    second_run = _add_run(session, list(reversed(domains)))

    first = prepare_triage(first_run.id, session, runs_path=tmp_path / "first")
    second = prepare_triage(second_run.id, session, runs_path=tmp_path / "second")
    first_payloads = [path.read_bytes() for path in first.paths]
    second_payloads = [path.read_bytes() for path in second.paths]
    ids = [item["asset_id"] for payload in first_payloads for item in json.loads(payload)["items"]]

    assert first_payloads == second_payloads
    assert len(ids) == len(set(ids)) == len(domains)
    assert all(asset_id.startswith("asset-") for asset_id in ids)


def test_triage_schemas_refuse_extra_fields_and_invalid_response_values() -> None:
    item = {
        "asset_id": "asset-1",
        "host": "example.com",
        "status": None,
        "title": None,
        "technologies": [],
        "paths": [],
    }
    with pytest.raises(ValidationError):
        TriageAsset.model_validate({**item, "url": "https://example.com"})
    with pytest.raises(ValidationError):
        TriageAsset.model_validate({key: value for key, value in item.items() if key != "paths"})
    with pytest.raises(ValidationError):
        TriageRequest.model_validate(
            {"batch_id": "0001", "items": [item], "headers": {"X-Test": "value"}}
        )
    with pytest.raises(ValidationError):
        TriageDecision.model_validate(
            {
                "asset_id": "asset-1",
                "decision": "EXECUTE",
                "confidence": "HIGH",
                "evidence": [],
                "missing_context": [],
                "manual_review_question": None,
            }
        )

    response = TriageResponse.model_validate(
        {
            "items": [
                {
                    "asset_id": "asset-1",
                    "decision": "NEEDS_REVIEW",
                    "confidence": "LOW",
                    "evidence": [],
                    "missing_context": [],
                    "manual_review_question": None,
                }
            ]
        }
    )
    assert response.items[0].decision == "NEEDS_REVIEW"


@pytest.mark.parametrize(
    "forbidden_value",
    [
        "https://example.com/private",
        "example.com/private",
        "origin 192.0.2.10",
        "origin 2001:db8::1",
        "example.com:8443",
        "Bearer abc123",
        "token=super-secret",
        "sk-example-secret-value",
        "search?q=private",
        "page=1&sort=desc",
        "Cookie: session=abc",
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain",
        "person@example.com",
        "+55 11 99999-9999",
    ],
)
def test_policy_gate_blocks_prohibited_patterns(forbidden_value: str) -> None:
    payload = {
        "batch_id": "0001",
        "items": [
            {
                "asset_id": "asset-1",
                "host": "example.com",
                "status": None,
                "title": forbidden_value,
                "technologies": [],
                "paths": [],
            }
        ],
    }

    with pytest.raises(PolicyViolation):
        enforce_triage_policy(json.dumps(payload))


def test_policy_gate_blocks_extra_fields_in_serialized_json() -> None:
    payload = {
        "batch_id": "0001",
        "items": [
            {
                "asset_id": "asset-1",
                "host": "example.com",
                "status": None,
                "title": None,
                "technologies": [],
                "paths": [],
                "body": "raw HTTP body",
            }
        ],
    }

    with pytest.raises(PolicyViolation):
        enforce_triage_policy(json.dumps(payload))


def test_policy_gate_finishes_before_any_file_is_written(
    tmp_path: Path, session, monkeypatch
) -> None:
    run = _add_run(session, ["example.com"])

    def refuse_payload(serialized: str) -> None:
        raise PolicyViolation("bloqueado para o teste")

    monkeypatch.setattr(services, "enforce_triage_policy", refuse_payload)

    with pytest.raises(PolicyViolation):
        prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    assert not (tmp_path / "runs").exists()


def test_nonexistent_run_and_run_without_pending_items_fail_default_deny(
    tmp_path: Path, session
) -> None:
    with pytest.raises(InputError, match="não encontrada"):
        prepare_triage(999, session, runs_path=tmp_path / "runs")

    empty_run = _add_run(session, [])
    with pytest.raises(InputError, match="não possui itens"):
        prepare_triage(empty_run.id, session, runs_path=tmp_path / "runs")


def test_only_sanitized_pending_queue_items_are_included(tmp_path: Path, session) -> None:
    run = _add_run(session, ["included.example.com"])
    pending_unsanitized = AssetModel(
        run_id=run.id,
        domain="unsanitized.example.com",
        status=AssetStatus.INGESTED.value,
        sanitized_at=None,
    )
    done_sanitized = AssetModel(
        run_id=run.id,
        domain="done.example.com",
        status=AssetStatus.SANITIZED.value,
        sanitized_at=datetime.now(UTC),
    )
    session.add_all([pending_unsanitized, done_sanitized])
    session.flush()
    session.add_all(
        [
            QueueItemModel(
                run_id=run.id,
                asset_id=pending_unsanitized.id,
                status=QueueStatus.PENDING.value,
            ),
            QueueItemModel(run_id=run.id, asset_id=done_sanitized.id, status="done"),
        ]
    )
    session.commit()

    result = prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    payload = json.loads(result.paths[0].read_text())

    assert [item["host"] for item in payload["items"]] == ["included.example.com"]


def test_serialized_json_is_reproducible_for_same_input(tmp_path: Path, session) -> None:
    run = _add_run(session, _domains(11))
    first = prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    first_contents = {path.name: path.read_bytes() for path in first.paths}

    second = prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    second_contents = {path.name: path.read_bytes() for path in second.paths}

    assert first_contents == second_contents


def test_preparation_makes_zero_network_calls(tmp_path: Path, session, monkeypatch) -> None:
    run = _add_run(session, ["example.com"])

    def refuse_network(*args, **kwargs):
        pytest.fail("triage --dry-run tentou acessar a rede")

    monkeypatch.setattr(socket, "socket", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)

    result = prepare_triage(run.id, session, runs_path=tmp_path / "runs")

    assert result.item_count == 1


def test_cli_dry_run_end_to_end(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()

    def refuse_network(*args, **kwargs):
        pytest.fail("CLI de triage tentou acessar a rede")

    monkeypatch.setattr(socket, "socket", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    monkeypatch.chdir(tmp_path)
    Path("scope.txt").write_text("example.com\n*.example.com\n", encoding="utf-8")
    Path("assets.jsonl").write_text(
        '{"domain":"example.com"}\n{"domain":"api.example.com"}\n',
        encoding="utf-8",
    )
    env = {"BB_DB_PATH": str(tmp_path / "cli.db")}

    assert runner.invoke(app, ["scope", "import", "scope.txt"], env=env).exit_code == 0
    assert runner.invoke(app, ["run", "ingest", "assets.jsonl"], env=env).exit_code == 0
    monkeypatch.setattr(
        cli,
        "select_checkboxes",
        lambda title, items: [item.value for item in items],
    )
    assert runner.invoke(app, ["candidates", "approve", "1"], env=env).exit_code == 0
    assert runner.invoke(app, ["sanitize", "1"], env=env).exit_code == 0
    result = runner.invoke(app, ["triage", "1", "--dry-run"], env=env)

    assert result.exit_code == 0, result.output
    assert "itens=2, lotes=1" in result.output
    output_path = tmp_path / "runs/1/llm/triage-input-0001.json"
    payload = json.loads(output_path.read_text())
    assert len(payload["items"]) == 2
    assert set(payload["items"][0]) == {
        "asset_id",
        "host",
        "status",
        "title",
        "technologies",
        "paths",
    }


def test_cli_requires_explicit_dry_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        ["triage", "1"],
        env={"BB_DB_PATH": str(tmp_path / "cli.db")},
    )

    assert result.exit_code == 1
    assert "somente com --dry-run" in result.output
