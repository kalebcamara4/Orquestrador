import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from typer.testing import CliRunner

import bb_orchestrator.services as services
from bb_orchestrator.cli import app
from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.models import (
    AssetModel,
    CandidateModel,
    CrawlPathModel,
    ExecutionPolicySnapshotModel,
    HttpVerificationAttemptModel,
    QueueItemModel,
    RunModel,
    ScopeRuleModel,
)
from bb_orchestrator.programs import create_program, load_program, select_program
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
    if session.scalar(select(ScopeRuleModel.id).limit(1)) is None:
        session.add_all(
            [
                ScopeRuleModel(pattern="example.com", kind="exact"),
                ScopeRuleModel(pattern="*.example.com", kind="wildcard"),
            ]
        )
        session.flush()
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
        session.add(
            CandidateModel(
                run_id=run.id,
                host=domain,
                source="test",
                status="approved",
                approved_at=datetime.now(UTC),
            )
        )
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


def _add_http(
    session,
    run_id: int,
    host: str,
    *,
    status: int = 200,
    title: str | None = None,
    technologies: list[str] | None = None,
) -> None:
    candidate = session.scalar(
        select(CandidateModel).where(
            CandidateModel.run_id == run_id,
            CandidateModel.host == host,
        )
    )
    assert candidate is not None
    session.add(
        HttpVerificationAttemptModel(
            run_id=run_id,
            candidate_id=candidate.id,
            program_slug="test-program",
            host=host,
            reachability="reachable",
            status_code=status,
            scheme="https",
            title=title,
            technologies=technologies,
            verified_at=datetime.now(UTC),
        )
    )
    session.commit()


def _add_paths(
    session,
    run_id: int,
    host: str,
    paths: list[str],
    *,
    program_slug: str = "test-program",
) -> None:
    snapshot = session.scalar(
        select(ExecutionPolicySnapshotModel)
        .where(
            ExecutionPolicySnapshotModel.run_id == run_id,
            ExecutionPolicySnapshotModel.step == "katana",
        )
        .limit(1)
    )
    if snapshot is None:
        snapshot = ExecutionPolicySnapshotModel(
            run_id=run_id,
            program_slug=program_slug,
            step="katana",
            snapshot={
                "name": "conservative",
                "version": "2",
                "parameters": {"max_paths_per_host": 100},
            },
        )
        session.add(snapshot)
        session.flush()
    now = datetime.now(UTC)
    session.add_all(
        CrawlPathModel(
            run_id=run_id,
            host=host,
            path=path,
            source="katana",
            observed_at=now,
            policy_snapshot_id=snapshot.id,
        )
        for path in paths
    )
    session.commit()


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


def test_triage_uses_sanitized_sqlite_surface_and_ignores_paths_artifact(
    tmp_path: Path,
    session,
) -> None:
    run = _add_run(session, ["api.example.com", "without-crawl.example.com"])
    _add_http(
        session,
        run.id,
        "api.example.com",
        status=404,
        title="Old title",
        technologies=["OldTech"],
    )
    _add_http(
        session,
        run.id,
        "api.example.com",
        status=200,
        title="Safe Title",
        technologies=["nginx", "React"],
    )
    _add_paths(
        session,
        run.id,
        "api.example.com",
        ["/login", "/", "/api/v1/users"],
    )
    poisoned_artifact = tmp_path / "runs" / str(run.id) / "crawl" / "paths.jsonl"
    poisoned_artifact.parent.mkdir(parents=True)
    poisoned_artifact.write_text(
        '{"host":"api.example.com","path":"/artifact-only","source":"katana"}\n',
        encoding="utf-8",
    )

    result = prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    payload = json.loads(result.paths[0].read_text())
    by_host = {item["host"]: item for item in payload["items"]}

    assert (result.item_count, result.included_paths, result.omitted_paths) == (2, 3, 0)
    assert by_host["api.example.com"] == {
        "asset_id": services._stable_asset_id("api.example.com"),
        "host": "api.example.com",
        "status": 200,
        "title": "Safe Title",
        "technologies": ["nginx", "React"],
        "paths": ["/", "/api/v1/users", "/login"],
        "paths_total": 3,
        "paths_included": 3,
        "paths_omitted_by_policy": 0,
        "paths_omitted_by_limit": 0,
    }
    assert by_host["without-crawl.example.com"]["paths"] == []
    assert by_host["without-crawl.example.com"]["paths_total"] == 0
    assert payload["selection_policy"] == "route-priority-v1"
    assert "/artifact-only" not in result.paths[0].read_text()


def test_triage_limits_paths_to_fifty_and_counts_omitted(tmp_path: Path, session) -> None:
    run = _add_run(session, ["api.example.com"])
    all_paths = [f"/path/{index:03d}" for index in reversed(range(60))]
    _add_paths(session, run.id, "api.example.com", all_paths)

    result = prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    item = json.loads(result.paths[0].read_text())["items"][0]

    assert item["paths"] == [f"/path/{index:03d}" for index in range(50)]
    assert item["paths_total"] == 60
    assert item["paths_included"] == 50
    assert item["paths_omitted_by_policy"] == 0
    assert item["paths_omitted_by_limit"] == 10
    assert (
        result.included_paths,
        result.paths_omitted_by_policy,
        result.paths_omitted_by_limit,
    ) == (50, 0, 10)


def test_triage_prioritizes_routes_without_changing_the_complete_inventory(
    tmp_path: Path,
    session,
) -> None:
    run = _add_run(session, ["shop.example.com"])
    inventory = [
        "/media/menu.css",
        "/minha-conta",
        "/meu-pedido",
        "/media/theme.css",
        "/meus-pedidos",
        "/promocoes",
        "/cardapio",
        "/area-de-entrega",
        "/assets/application.js",
        "/",
    ]
    _add_paths(session, run.id, "shop.example.com", inventory)
    artifact = tmp_path / "runs" / str(run.id) / "crawl" / "paths.jsonl"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("inventário completo preservado\n", encoding="utf-8")
    rows_before = tuple(
        session.execute(
            select(CrawlPathModel.host, CrawlPathModel.path)
            .where(CrawlPathModel.run_id == run.id)
            .order_by(CrawlPathModel.id)
        ).all()
    )

    result = prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    payload = json.loads(result.paths[0].read_text())
    item = payload["items"][0]

    assert payload["selection_policy"] == "route-priority-v1"
    assert item["paths"] == [
        "/",
        "/meu-pedido",
        "/meus-pedidos",
        "/promocoes",
        "/area-de-entrega",
        "/cardapio",
        "/minha-conta",
        "/assets/application.js",
    ]
    assert (
        item["paths_total"],
        item["paths_included"],
        item["paths_omitted_by_policy"],
        item["paths_omitted_by_limit"],
    ) == (10, 8, 2, 0)
    assert artifact.read_text(encoding="utf-8") == "inventário completo preservado\n"
    assert (
        tuple(
            session.execute(
                select(CrawlPathModel.host, CrawlPathModel.path)
                .where(CrawlPathModel.run_id == run.id)
                .order_by(CrawlPathModel.id)
            ).all()
        )
        == rows_before
    )


def test_triage_accepts_recognized_dynamic_file_extensions(tmp_path: Path, session) -> None:
    run = _add_run(session, ["legacy.example.com"])
    _add_paths(
        session,
        run.id,
        "legacy.example.com",
        ["/action.do", "/index.php", "/login.aspx", "/view.jsp"],
    )

    result = prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    item = json.loads(result.paths[0].read_text())["items"][0]

    assert item["paths"] == ["/action.do", "/index.php", "/login.aspx", "/view.jsp"]
    assert item["paths_included"] == item["paths_total"] == 4


def test_triage_allows_password_as_a_route_segment_without_secret_data(
    tmp_path: Path,
    session,
) -> None:
    run = _add_run(session, ["accounts.example.com"])
    _add_paths(
        session,
        run.id,
        "accounts.example.com",
        ["/reset/password", "/password/reset"],
    )

    result = prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    item = json.loads(result.paths[0].read_text())["items"][0]

    assert item["paths"] == ["/password/reset", "/reset/password"]
    assert item["paths_omitted_by_policy"] == item["paths_omitted_by_limit"] == 0


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "/https://outside.example/private",
        "/login?next=/admin",
        "/login#fragment",
        "/outside.example/private",
        "/192.0.2.10/admin",
        "/admin:8443",
        "/token/raw-secret",
        "/person@example.com",
        "/+55-11-99999-9999",
        "/control\x00value",
    ],
)
def test_triage_rejects_unsafe_persisted_paths_before_writing(
    tmp_path: Path,
    session,
    unsafe_path: str,
) -> None:
    run = _add_run(session, ["api.example.com"])
    _add_paths(session, run.id, "api.example.com", [unsafe_path])

    with pytest.raises(PolicyViolation, match="path persistido"):
        prepare_triage(run.id, session, runs_path=tmp_path / "runs")

    assert not (tmp_path / "runs").exists()


def test_triage_rejects_noncanonical_persisted_http_before_writing(
    tmp_path: Path,
    session,
) -> None:
    run = _add_run(session, ["api.example.com"])
    _add_http(
        session,
        run.id,
        "api.example.com",
        title="https://outside.example/private?token=raw-secret",
    )

    with pytest.raises(PolicyViolation, match="título HTTP persistido"):
        prepare_triage(run.id, session, runs_path=tmp_path / "runs")

    assert not (tmp_path / "runs").exists()


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
        "paths_total": 0,
        "paths_included": 0,
        "paths_omitted_by_policy": 0,
        "paths_omitted_by_limit": 0,
    }
    with pytest.raises(ValidationError):
        TriageAsset.model_validate({**item, "url": "https://example.com"})
    with pytest.raises(ValidationError):
        TriageAsset.model_validate({key: value for key, value in item.items() if key != "paths"})
    with pytest.raises(ValidationError):
        TriageAsset.model_validate(
            {key: value for key, value in item.items() if key != "paths_total"}
        )
    with pytest.raises(ValidationError):
        TriageAsset.model_validate(
            {key: value for key, value in item.items() if key != "paths_included"}
        )
    with pytest.raises(ValidationError):
        TriageAsset.model_validate(
            {**item, "paths": ["/login"], "paths_total": 0, "paths_included": 1}
        )
    with pytest.raises(ValidationError):
        TriageAsset.model_validate(
            {**item, "paths": ["/z", "/a"], "paths_total": 2, "paths_included": 2}
        )
    with pytest.raises(ValidationError):
        TriageRequest.model_validate(
            {
                "batch_id": "0001",
                "selection_policy": "route-priority-v1",
                "items": [item],
                "headers": {"X-Test": "value"},
            }
        )
    with pytest.raises(ValidationError):
        TriageRequest.model_validate({"batch_id": "0001", "items": [item]})
    with pytest.raises(ValidationError):
        TriageRequest.model_validate(
            {
                "batch_id": "0001",
                "selection_policy": "conservative",
                "items": [item],
            }
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
        "selection_policy": "route-priority-v1",
        "items": [
            {
                "asset_id": "asset-1",
                "host": "example.com",
                "status": None,
                "title": forbidden_value,
                "technologies": [],
                "paths": [],
                "paths_total": 0,
                "paths_included": 0,
                "paths_omitted_by_policy": 0,
                "paths_omitted_by_limit": 0,
            }
        ],
    }

    with pytest.raises(PolicyViolation):
        enforce_triage_policy(json.dumps(payload))


@pytest.mark.parametrize(
    "forbidden_path",
    [
        "/https://outside.example/private",
        "/login?token=secret",
        "/outside.example",
        "/192.0.2.10",
        "/admin:8443",
        "/token/raw-secret",
        "/person@example.com",
        "/control\x00value",
    ],
)
def test_policy_gate_blocks_prohibited_paths(forbidden_path: str) -> None:
    payload = {
        "batch_id": "0001",
        "selection_policy": "route-priority-v1",
        "items": [
            {
                "asset_id": "asset-1",
                "host": "example.com",
                "status": None,
                "title": None,
                "technologies": [],
                "paths": [forbidden_path],
                "paths_total": 1,
                "paths_included": 1,
                "paths_omitted_by_policy": 0,
                "paths_omitted_by_limit": 0,
            }
        ],
    }

    with pytest.raises(PolicyViolation):
        enforce_triage_policy(json.dumps(payload))


def test_policy_gate_blocks_extra_fields_in_serialized_json() -> None:
    payload = {
        "batch_id": "0001",
        "selection_policy": "route-priority-v1",
        "items": [
            {
                "asset_id": "asset-1",
                "host": "example.com",
                "status": None,
                "title": None,
                "technologies": [],
                "paths": [],
                "paths_total": 0,
                "paths_included": 0,
                "paths_omitted_by_policy": 0,
                "paths_omitted_by_limit": 0,
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
    output_dir = tmp_path / "runs" / str(run.id) / "llm"
    keep_path = output_dir / "keep.txt"
    keep_path.write_text("preserve", encoding="utf-8")
    (output_dir / "triage-input-9999.json").write_text("stale", encoding="utf-8")

    second = prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    second_contents = {path.name: path.read_bytes() for path in second.paths}

    assert first_contents == second_contents
    assert keep_path.read_text(encoding="utf-8") == "preserve"
    assert sorted(path.name for path in output_dir.iterdir()) == [
        "keep.txt",
        "triage-input-0001.json",
        "triage-input-0002.json",
    ]


def test_preparation_makes_zero_network_calls(tmp_path: Path, session, monkeypatch) -> None:
    run = _add_run(session, ["example.com"])

    def refuse_network(*args, **kwargs):
        pytest.fail("triage --dry-run tentou acessar a rede")

    monkeypatch.setattr(socket, "socket", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    monkeypatch.setattr(services.subprocess, "run", refuse_network)
    monkeypatch.setattr(services.shutil, "which", refuse_network)

    result = prepare_triage(run.id, session, runs_path=tmp_path / "runs")

    assert result.item_count == 1


def test_triage_does_not_consume_or_mutate_persisted_state(tmp_path: Path, session) -> None:
    run = _add_run(session, ["api.example.com"])
    _add_http(session, run.id, "api.example.com", title="Safe")
    _add_paths(session, run.id, "api.example.com", ["/", "/login"])

    def state() -> tuple[object, ...]:
        return (
            tuple(
                session.execute(
                    select(CandidateModel.id, CandidateModel.status).order_by(CandidateModel.id)
                ).all()
            ),
            tuple(
                session.execute(
                    select(AssetModel.id, AssetModel.status).order_by(AssetModel.id)
                ).all()
            ),
            tuple(
                session.execute(
                    select(QueueItemModel.id, QueueItemModel.status).order_by(QueueItemModel.id)
                ).all()
            ),
            tuple(
                session.execute(
                    select(
                        HttpVerificationAttemptModel.id,
                        HttpVerificationAttemptModel.status_code,
                    ).order_by(HttpVerificationAttemptModel.id)
                ).all()
            ),
            tuple(
                session.execute(
                    select(CrawlPathModel.id, CrawlPathModel.path).order_by(CrawlPathModel.id)
                ).all()
            ),
            tuple(
                session.scalars(
                    select(ExecutionPolicySnapshotModel.id).order_by(
                        ExecutionPolicySnapshotModel.id
                    )
                )
            ),
        )

    before = state()
    prepare_triage(run.id, session, runs_path=tmp_path / "runs")
    session.expire_all()

    assert state() == before


def test_triage_is_isolated_by_run_and_active_program(tmp_path: Path, monkeypatch) -> None:
    direct_engine = create_sqlite_engine(tmp_path / "runs.db")
    initialize_database(direct_engine)
    with create_session_factory(direct_engine)() as direct_session:
        first_run = _add_run(direct_session, ["api.example.com"])
        second_run = _add_run(direct_session, ["api.example.com"])
        _add_paths(direct_session, first_run.id, "api.example.com", ["/run-one"])
        _add_paths(direct_session, second_run.id, "api.example.com", ["/run-two"])
        first = prepare_triage(first_run.id, direct_session, runs_path=tmp_path / "direct")
        second = prepare_triage(second_run.id, direct_session, runs_path=tmp_path / "direct")
        assert json.loads(first.paths[0].read_text())["items"][0]["paths"] == ["/run-one"]
        assert json.loads(second.paths[0].read_text())["items"][0]["paths"] == ["/run-two"]

    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    for slug, host, expected_path in (
        ("alpha", "alpha.example.com", "/alpha"),
        ("beta", "beta.example.com", "/beta"),
    ):
        program = create_program(slug, slug.title())
        engine = create_sqlite_engine(program.database_path)
        with create_session_factory(engine)() as program_session:
            run = _add_run(program_session, [host])
            _add_paths(
                program_session,
                run.id,
                host,
                [expected_path],
                program_slug=slug,
            )
        select_program(slug)
        result = runner.invoke(app, ["triage", "1", "--dry-run"])
        assert result.exit_code == 0, result.output

    alpha_payload = json.loads(
        Path(".bb/programs/alpha/runs/1/llm/flow-map-input-0001.json").read_text()
    )
    beta_payload = json.loads(
        Path(".bb/programs/beta/runs/1/llm/flow-map-input-0001.json").read_text()
    )
    assert alpha_payload["items"][0]["unknown_dynamic_paths"] == ["/alpha"]
    assert beta_payload["items"][0]["unknown_dynamic_paths"] == ["/beta"]
    assert load_program("alpha").database_path != load_program("beta").database_path


def test_cli_dry_run_end_to_end(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()

    def refuse_network(*args, **kwargs):
        pytest.fail("CLI de triage tentou acessar a rede")

    monkeypatch.setattr(socket, "socket", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    monkeypatch.setattr(services.subprocess, "run", refuse_network)
    monkeypatch.setattr(services.shutil, "which", refuse_network)
    monkeypatch.chdir(tmp_path)
    create_program("test-program", "Test Program")
    select_program("test-program")
    Path("scope.txt").write_text("example.com\n*.example.com\n", encoding="utf-8")
    Path("assets.jsonl").write_text(
        '{"domain":"example.com"}\n{"domain":"api.example.com"}\n',
        encoding="utf-8",
    )
    env = {"BB_DB_PATH": str(tmp_path / "cli.db")}

    assert runner.invoke(app, ["scope", "import", "scope.txt"], env=env).exit_code == 0
    assert runner.invoke(app, ["run", "ingest", "assets.jsonl"], env=env).exit_code == 0
    assert runner.invoke(app, ["candidates", "approve", "1", "--all"], env=env).exit_code == 0
    assert runner.invoke(app, ["sanitize", "1"], env=env).exit_code == 0
    result = runner.invoke(app, ["triage", "1", "--dry-run"], env=env)

    assert result.exit_code == 0, result.output
    assert (
        "assets=2, sinais determinísticos=0, paths desconhecidos=0, "
        "fluxos CONTEXT_REQUIRED=0, lotes=1"
    ) in result.output
    output_path = tmp_path / ".bb/programs/test-program/runs/1/llm/flow-map-input-0001.json"
    payload = json.loads(output_path.read_text())
    assert len(payload["items"]) == 2
    assert payload["selection_policy"] == "route-priority-v1"
    assert payload["mapping_policy"] == "flow-signal-policy-v1"
    assert set(payload["items"][0]) == {
        "asset_id",
        "host",
        "deterministic_flow_signals",
        "unknown_dynamic_paths",
        "unknown_dynamic_paths_total",
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
