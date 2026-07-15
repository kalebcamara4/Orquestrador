import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from typer.testing import CliRunner

import bb_orchestrator.services as services
from bb_orchestrator.cli import app
from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.flow_policies import (
    FLOW_ALIASES_POLICY,
    MINIMUM_CONTEXT_GAPS,
    FlowAliasEntry,
    FlowAliasPolicy,
    FlowType,
    classify_flow_paths,
    empty_flow_alias_policy,
    load_flow_alias_policy,
    save_flow_alias_policy,
)
from bb_orchestrator.llm import (
    FLOW_PROMPT_VERSION,
    FLOW_SYSTEM_PROMPT,
    LlmError,
    build_flow_mapping_request,
    configure_ollama,
    flow_mapping_response_schema,
    inspect_flow_mapping,
    load_flow_mapping_batches,
    run_flow_mapping,
    validate_flow_mapping_response,
    verify_ollama_compatibility,
)
from bb_orchestrator.models import (
    AssetModel,
    CandidateModel,
    CrawlPathModel,
    ExecutionPolicySnapshotModel,
    FlowMappingAttemptModel,
    FlowMappingResultModel,
    HttpVerificationAttemptModel,
    ProgramModel,
    QueueItemModel,
    RunModel,
    ScopeRuleModel,
)
from bb_orchestrator.programs import create_program, select_program
from bb_orchestrator.schemas import (
    AssetStatus,
    DeterministicFlowSignal,
    FlowMappingAsset,
    FlowMappingRequest,
    QueueStatus,
    RunStatus,
)
from bb_orchestrator.services import prepare_flow_mapping


class FakeAdapter:
    def __init__(self, responses: list[str]) -> None:
        self.responses = responses
        self.calls: list[tuple[dict[str, object], int]] = []

    def chat(self, payload, *, timeout_seconds: int) -> str:
        self.calls.append((payload, timeout_seconds))
        return self.responses[len(self.calls) - 1]


def _request(paths: list[str]) -> FlowMappingRequest:
    classification = classify_flow_paths(paths)
    signals = [
        DeterministicFlowSignal(
            flow_type=signal.flow_type,
            basis=signal.basis,
            relevance=signal.relevance,
            evidence_paths=list(signal.evidence_paths),
            evidence_paths_total=signal.evidence_paths_total,
            required_context=list(signal.required_context),
        )
        for signal in classification.signals
    ]
    return FlowMappingRequest(
        batch_id="0001",
        mapping_policy="flow-signal-policy-v1",
        selection_policy="route-priority-v1",
        items=[
            FlowMappingAsset(
                asset_id="asset-" + "a" * 64,
                host="app.example.test",
                deterministic_flow_signals=signals,
                unknown_dynamic_paths=list(classification.unknown_dynamic_paths),
                unknown_dynamic_paths_total=len(classification.unknown_dynamic_paths),
            )
        ],
    )


def _valid_output(request: FlowMappingRequest) -> dict[str, object]:
    item = request.items[0]
    mappings: list[dict[str, object]] = [
        {
            "flow_type": signal.flow_type.value,
            "basis": signal.basis.value,
            "evidence_paths": signal.evidence_paths,
            "context_gaps": [gap.value for gap in signal.required_context],
        }
        for signal in item.deterministic_flow_signals
    ]
    mappings.extend(
        {
            "flow_type": "UNKNOWN_DYNAMIC",
            "basis": "UNKNOWN_DYNAMIC",
            "evidence_paths": [path],
            "context_gaps": ["OTHER_CONTEXT_NOT_OBSERVED"],
        }
        for path in item.unknown_dynamic_paths
    )
    context_required = [mapping for mapping in mappings if mapping["flow_type"] != "CONTENT_PUBLIC"]
    questions: list[dict[str, object]] = []
    if context_required:
        flows = list(dict.fromkeys(str(mapping["flow_type"]) for mapping in context_required))
        gaps = list(
            dict.fromkeys(
                str(gap)
                for mapping in context_required
                for gap in mapping["context_gaps"]  # type: ignore[union-attr]
            )
        )[:2]
        questions.append(
            {
                "applies_to_flows": flows,
                "required_context": gaps,
                "question": "Quais contextos dos fluxos devem ser observados na revisão manual?",
            }
        )
    return {
        "items": [
            {
                "asset_id": item.asset_id,
                "flow_mappings": mappings,
                "review_questions": questions,
            }
        ]
    }


def _serialized_output(request: FlowMappingRequest) -> str:
    return json.dumps(_valid_output(request), ensure_ascii=False)


def _seed_run(session, *, program_id: str, paths: list[str]) -> int:
    if session.scalar(select(ProgramModel).where(ProgramModel.slug == program_id)) is None:
        session.add(ProgramModel(slug=program_id, name=program_id.title()))
    if session.scalar(select(ScopeRuleModel.id).limit(1)) is None:
        session.add(ScopeRuleModel(pattern="example.test", kind="exact"))
    run = RunModel(
        source_sha256="0" * 64,
        status=RunStatus.SANITIZED.value,
        accepted_count=1,
        rejected_count=0,
        duplicate_count=0,
    )
    session.add(run)
    session.flush()
    candidate = CandidateModel(
        run_id=run.id,
        host="example.test",
        source="test",
        status="approved",
        approved_at=datetime.now(UTC),
    )
    asset = AssetModel(
        run_id=run.id,
        domain="example.test",
        status=AssetStatus.SANITIZED.value,
        sanitized_at=datetime.now(UTC),
    )
    session.add_all([candidate, asset])
    session.flush()
    session.add(QueueItemModel(run_id=run.id, asset_id=asset.id, status=QueueStatus.PENDING.value))
    snapshot = ExecutionPolicySnapshotModel(
        run_id=run.id,
        program_slug=program_id,
        step="katana",
        snapshot={"name": "conservative", "version": "2", "parameters": {}},
    )
    session.add(snapshot)
    session.flush()
    session.add_all(
        CrawlPathModel(
            run_id=run.id,
            host="example.test",
            path=path,
            source="katana",
            observed_at=datetime.now(UTC),
            policy_snapshot_id=snapshot.id,
        )
        for path in paths
    )
    session.add(
        HttpVerificationAttemptModel(
            run_id=run.id,
            candidate_id=candidate.id,
            program_slug=program_id,
            host="example.test",
            reachability="reachable",
            status_code=302,
            scheme="https",
            title="Cloudflare dashboard",
            technologies=["Cloudflare", "JavaScript"],
            verified_at=datetime.now(UTC),
        )
    )
    session.commit()
    return run.id


def test_general_multilingual_signals_unknowns_static_and_substrings() -> None:
    classification = classify_flow_paths(
        [
            "/account",
            "/perfil",
            "/orders",
            "/pedido",
            "/wallet",
            "/cupom",
            "/checkout",
            "/admin",
            "/graphql",
            "/products",
            "/api/products",
            "/accounting",
            "/workspace",
            "/x7/portal",
            "/assets/app.css",
            "/assets/application.js",
        ]
    )

    assert [signal.flow_type for signal in classification.signals] == [
        FlowType.IDENTITY_ACCESS,
        FlowType.USER_DATA_RESOURCE,
        FlowType.TRANSACTION_ORDER,
        FlowType.MONEY_VALUE,
        FlowType.BENEFIT_ENTITLEMENT,
        FlowType.STATE_WORKFLOW,
        FlowType.ADMIN_PRIVILEGED,
        FlowType.INTEGRATION_API,
        FlowType.CONTENT_PUBLIC,
    ]
    assert classification.unknown_dynamic_paths == (
        "/accounting",
        "/workspace",
        "/x7/portal",
    )
    integration = classification.signals[-2]
    content = classification.signals[-1]
    assert integration.evidence_paths == ("/api/products", "/graphql")
    assert content.evidence_paths == ("/api/products", "/products")


def test_pizzaria_is_only_a_regression_fixture_for_general_categories() -> None:
    classification = classify_flow_paths(
        ["/minha-conta", "/meus-pedidos", "/cupons", "/area-de-entrega", "/cardapio"]
    )
    assert [signal.flow_type for signal in classification.signals] == [
        FlowType.USER_DATA_RESOURCE,
        FlowType.TRANSACTION_ORDER,
        FlowType.BENEFIT_ENTITLEMENT,
        FlowType.STATE_WORKFLOW,
        FlowType.CONTENT_PUBLIC,
    ]


def test_evidence_is_lexical_ordered_limited_and_keeps_total() -> None:
    paths = [f"/orders/{index}" for index in reversed(range(7))]
    signal = classify_flow_paths(paths).signals[0]

    assert signal.evidence_paths == tuple(f"/orders/{index}" for index in range(5))
    assert signal.evidence_paths_total == 7


def test_manual_aliases_are_versioned_and_isolated_by_program(tmp_path: Path) -> None:
    alpha = tmp_path / "alpha"
    beta = tmp_path / "beta"
    entry = FlowAliasEntry(
        program_id="alpha",
        origin="manual",
        version="1",
        timestamp=datetime.now(UTC),
        match_type="segment",
        value="workspace",
        flow_type=FlowType.USER_DATA_RESOURCE,
    )
    save_flow_alias_policy(
        alpha,
        FlowAliasPolicy(program_id="alpha", aliases=[entry]),
        program_id="alpha",
    )

    alpha_policy = load_flow_alias_policy(alpha, program_id="alpha")
    beta_policy = load_flow_alias_policy(beta, program_id="beta")
    alpha_result = classify_flow_paths(["/workspace"], aliases=alpha_policy.aliases)
    beta_result = classify_flow_paths(["/workspace"], aliases=beta_policy.aliases)

    assert alpha_result.signals[0].flow_type is FlowType.USER_DATA_RESOURCE
    assert alpha_result.signals[0].basis.value == "MANUAL_PROGRAM_ALIAS"
    assert beta_result.unknown_dynamic_paths == ("/workspace",)
    assert not (beta / f"{FLOW_ALIASES_POLICY}.json").exists()
    with pytest.raises(ValueError, match="outro programa"):
        load_flow_alias_policy(alpha, program_id="beta")


def test_manual_alias_cannot_redefine_lexical_signal() -> None:
    with pytest.raises(ValueError, match="redefinir"):
        FlowAliasPolicy(
            program_id="alpha",
            aliases=[
                FlowAliasEntry(
                    program_id="alpha",
                    origin="manual",
                    version="1",
                    timestamp=datetime.now(UTC),
                    match_type="segment",
                    value="account",
                    flow_type=FlowType.MONEY_VALUE,
                )
            ],
        )


def test_llm_loader_does_not_reopen_manual_alias_configuration(tmp_path: Path) -> None:
    entry = FlowAliasEntry(
        program_id="alpha",
        origin="manual",
        version="1",
        timestamp=datetime.now(UTC),
        match_type="segment",
        value="workspace",
        flow_type=FlowType.USER_DATA_RESOURCE,
    )
    classification = classify_flow_paths(["/workspace"], aliases=[entry])
    signal = classification.signals[0]
    request = FlowMappingRequest(
        batch_id="0001",
        mapping_policy="flow-signal-policy-v1",
        selection_policy="route-priority-v1",
        items=[
            FlowMappingAsset(
                asset_id="asset-" + "a" * 64,
                host="app.example.test",
                deterministic_flow_signals=[
                    DeterministicFlowSignal(
                        flow_type=signal.flow_type,
                        basis=signal.basis,
                        relevance=signal.relevance,
                        evidence_paths=list(signal.evidence_paths),
                        evidence_paths_total=signal.evidence_paths_total,
                        required_context=list(signal.required_context),
                    )
                ],
                unknown_dynamic_paths=[],
                unknown_dynamic_paths_total=0,
            )
        ],
    )
    input_directory = tmp_path / "runs" / "1" / "llm"
    input_directory.mkdir(parents=True)
    (input_directory / "flow-map-input-0001.json").write_text(
        json.dumps(request.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    batches = load_flow_mapping_batches(
        1,
        tmp_path / "runs",
        program_id="alpha",
        program_directory=tmp_path / "missing-alias-directory",
    )

    assert batches[0].request.items[0].deterministic_flow_signals[0].basis.value == (
        "MANUAL_PROGRAM_ALIAS"
    )
    assert not (tmp_path / "missing-alias-directory").exists()


def test_prepare_flow_mapping_excludes_http_metadata_and_preserves_legacy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    engine = create_sqlite_engine(tmp_path / "flow.db")
    initialize_database(engine)
    session = create_session_factory(engine)()
    run_id = _seed_run(
        session,
        program_id="alpha",
        paths=["/orders", "/workspace", "/x7/portal", "/assets/app.css"]
        + [f"/opaque/{index:02d}" for index in range(60)],
    )
    runs_path = tmp_path / "runs"
    legacy = runs_path / str(run_id) / "llm" / "triage-input-0001.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy-must-remain\n", encoding="utf-8")

    def refuse_external(*args, **kwargs):
        pytest.fail("flow mapping tentou usar rede ou subprocesso")

    monkeypatch.setattr(socket, "socket", refuse_external)
    monkeypatch.setattr(socket, "create_connection", refuse_external)
    monkeypatch.setattr(services.subprocess, "run", refuse_external)
    first = prepare_flow_mapping(
        run_id,
        session,
        program_id="alpha",
        program_directory=tmp_path / "alpha",
        runs_path=runs_path,
    )
    first_bytes = first.paths[0].read_bytes()
    second = prepare_flow_mapping(
        run_id,
        session,
        program_id="alpha",
        program_directory=tmp_path / "alpha",
        runs_path=runs_path,
    )
    payload = json.loads(second.paths[0].read_text(encoding="utf-8"))
    item = payload["items"][0]

    assert first_bytes == second.paths[0].read_bytes()
    assert legacy.read_text(encoding="utf-8") == "legacy-must-remain\n"
    assert second.paths[0].name == "flow-map-input-0001.json"
    assert set(item) == {
        "asset_id",
        "host",
        "deterministic_flow_signals",
        "unknown_dynamic_paths",
        "unknown_dynamic_paths_total",
    }
    assert len(item["unknown_dynamic_paths"]) == 62
    assert {"/workspace", "/x7/portal", "/opaque/59"} <= set(item["unknown_dynamic_paths"])
    serialized = second.paths[0].read_text(encoding="utf-8").lower()
    for forbidden in ("cloudflare", "javascript", "status", "title", "technologies"):
        assert forbidden not in serialized
    session.close()
    engine.dispose()


def test_response_accepts_unknown_or_tentative_without_persisting_alias(tmp_path: Path) -> None:
    request = _request(["/workspace"])
    unknown = validate_flow_mapping_response(_serialized_output(request), request)
    tentative = _valid_output(request)
    mapping = tentative["items"][0]["flow_mappings"][0]  # type: ignore[index]
    mapping.update(  # type: ignore[union-attr]
        {
            "flow_type": "USER_DATA_RESOURCE",
            "basis": "TENTATIVE_PATH_SEMANTIC_INFERENCE",
            "context_gaps": [gap.value for gap in MINIMUM_CONTEXT_GAPS[FlowType.USER_DATA_RESOURCE]]
            + ["OTHER_CONTEXT_NOT_OBSERVED"],
        }
    )
    tentative["items"][0]["review_questions"][0]["applies_to_flows"] = [  # type: ignore[index]
        "USER_DATA_RESOURCE"
    ]
    inferred = validate_flow_mapping_response(json.dumps(tentative), request)

    assert unknown.items[0].flow_mappings[0].flow_type is FlowType.UNKNOWN_DYNAMIC
    assert inferred.items[0].flow_mappings[0].basis.value == ("TENTATIVE_PATH_SEMANTIC_INFERENCE")
    assert load_flow_alias_policy(tmp_path, program_id="alpha") == empty_flow_alias_policy("alpha")


@pytest.mark.parametrize(
    "mutation",
    [
        "omit_signal",
        "omit_unknown",
        "invent_unknown",
        "missing_gap",
        "missing_question",
        "extra_field",
    ],
)
def test_flow_output_policy_fails_closed_for_semantic_mutations(mutation: str) -> None:
    request = _request(["/orders", "/workspace"])
    output = _valid_output(request)
    item = output["items"][0]  # type: ignore[index]
    mappings = item["flow_mappings"]  # type: ignore[index]
    if mutation == "omit_signal":
        mappings.pop(0)  # type: ignore[union-attr]
    elif mutation == "omit_unknown":
        mappings.pop()  # type: ignore[union-attr]
    elif mutation == "invent_unknown":
        mappings[-1]["evidence_paths"] = ["/invented"]  # type: ignore[index]
    elif mutation == "missing_gap":
        mappings[0]["context_gaps"] = []  # type: ignore[index]
    elif mutation == "missing_question":
        item["review_questions"] = []  # type: ignore[index]
    else:
        item["decision"] = "IGNORE"  # type: ignore[index]

    with pytest.raises(LlmError, match="flow-output-policy-v1"):
        validate_flow_mapping_response(json.dumps(output), request)


@pytest.mark.parametrize(
    "question",
    [
        "Existe IDOR confirmado neste fluxo?",
        "O fluxo está vulnerável e possui impacto confirmado?",
        "A aplicação não verifica autorização entre usuários?",
        "A regra de negócio foi burlada neste fluxo?",
        "Qual payload deve ser enviado contra o fluxo?",
        "Quais dados devem ser observados em https://example.test?",
        "Quais credenciais do usuário devem ser observadas no fluxo?",
        "Quais cookies do usuário devem ser observados no fluxo?",
        "Quais contextos do fluxo devem ser observados no IP 192.0.2.10?",
        "Quais contextos do fluxo devem ser observados na porta 8443?",
        "Quais contextos do fluxo devem ser enviados a user@example.test?",
        "- Quais contextos do fluxo devem ser observados?",
        "Quais contextos do fluxo devem ser observados\nem revisão?",
    ],
)
def test_flow_output_policy_rejects_conclusive_or_unsafe_questions(question: str) -> None:
    request = _request(["/orders"])
    output = _valid_output(request)
    output["items"][0]["review_questions"][0]["question"] = question  # type: ignore[index]

    with pytest.raises(LlmError, match="pergunta"):
        validate_flow_mapping_response(json.dumps(output, ensure_ascii=False), request)


@pytest.mark.parametrize(
    "serialized",
    [
        "not json",
        "```json\n{}\n```",
        '{"items":[]} trailing',
        '{"items":[],"items":[]}',
    ],
)
def test_flow_response_rejects_invalid_json_markdown_and_extra_text(serialized: str) -> None:
    with pytest.raises(LlmError):
        validate_flow_mapping_response(serialized, _request(["/orders"]))


def test_content_public_alone_and_empty_asset_may_have_no_question() -> None:
    public_request = _request(["/catalog"])
    empty_request = _request(["/assets/app.css"])

    public = validate_flow_mapping_response(_serialized_output(public_request), public_request)
    empty = validate_flow_mapping_response(_serialized_output(empty_request), empty_request)

    assert public.items[0].review_questions == []
    assert empty.items[0].flow_mappings == []
    assert empty.items[0].review_questions == []


def test_defensive_question_about_unobserved_context_is_accepted() -> None:
    request = _request(["/orders"])
    output = _valid_output(request)
    question = "O fluxo exige contexto sobre isolamento entre usuários autorizados?"
    output["items"][0]["review_questions"][0]["question"] = question  # type: ignore[index]

    validated = validate_flow_mapping_response(json.dumps(output, ensure_ascii=False), request)

    assert validated.items[0].review_questions[0].question == question


def test_prompt_schema_and_ollama_format_have_one_source(tmp_path: Path) -> None:
    config = configure_ollama(tmp_path, "local-model:7b")
    request = _request(["/orders", "/workspace"])
    directory = tmp_path / "runs" / "1" / "llm"
    directory.mkdir(parents=True)
    (directory / "flow-map-input-0001.json").write_text(
        json.dumps(request.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    batch = load_flow_mapping_batches(
        1,
        tmp_path / "runs",
        program_id="alpha",
        program_directory=tmp_path,
    )[0]
    payload = build_flow_mapping_request(config, batch)
    compact_schema = json.dumps(
        flow_mapping_response_schema(), separators=(",", ":"), sort_keys=True
    )

    assert payload["format"] == flow_mapping_response_schema()
    assert compact_schema in payload["messages"][0]["content"]
    assert "missing context is not a missing control" in FLOW_SYSTEM_PROMPT.lower()
    assert "never claim idor" in FLOW_SYSTEM_PROMPT.lower()
    assert "tools" not in payload
    assert "status" not in batch.serialized


def test_run_flow_mapping_persists_only_validated_projection(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "flow-run.db")
    initialize_database(engine)
    session = create_session_factory(engine)()
    program_directory = tmp_path / "alpha"
    runs_path = tmp_path / "runs"
    run_id = _seed_run(
        session,
        program_id="alpha",
        paths=["/orders", "/workspace"],
    )
    prepare_flow_mapping(
        run_id,
        session,
        program_id="alpha",
        program_directory=program_directory,
        runs_path=runs_path,
    )
    legacy_result = runs_path / str(run_id) / "llm" / "results" / "triage-results.json"
    legacy_result.parent.mkdir(parents=True)
    legacy_result.write_text("legacy-result-must-remain\n", encoding="utf-8")
    configure_ollama(program_directory, "local-model:7b")
    verify_ollama_compatibility(
        session,
        program_slug="alpha",
        program_directory=program_directory,
        adapter=FakeAdapter(['{"ok":true}']),
    )
    batch = load_flow_mapping_batches(
        run_id,
        runs_path,
        program_id="alpha",
        program_directory=program_directory,
    )[0]
    adapter = FakeAdapter([_serialized_output(batch.request)])

    result = run_flow_mapping(
        run_id,
        session,
        program_id="alpha",
        program_directory=program_directory,
        runs_path=runs_path,
        adapter=adapter,
    )
    row = session.scalar(select(FlowMappingResultModel))
    attempt = session.scalar(select(FlowMappingAttemptModel))
    artifact = json.loads(result.result_path.read_text(encoding="utf-8"))

    assert (result.batch_count, result.item_count) == (1, 1)
    assert adapter.calls[0][1] == 90
    assert row is not None and row.analysis_type == "flow_mapping"
    assert attempt is not None and attempt.status == "validated"
    assert row.prompt_version == FLOW_PROMPT_VERSION
    assert row.mapping_policy == "flow-signal-policy-v1"
    assert row.output_policy == "flow-output-policy-v1"
    assert len(row.schema_fingerprint) == 64
    assert result.result_path.name == "flow-mapping-results.json"
    assert legacy_result.read_text(encoding="utf-8") == "legacy-result-must-remain\n"
    assert artifact["analysis_type"] == "flow_mapping"
    serialized_artifact = result.result_path.read_text(encoding="utf-8").lower()
    for forbidden in (
        "raw_response",
        "message.thinking",
        "chain-of-thought",
        "cloudflare",
    ):
        assert forbidden not in serialized_artifact
    assert session.scalar(select(func.count(FlowMappingResultModel.id))) == 1
    session.close()
    engine.dispose()


def test_inspection_counts_without_connection(tmp_path: Path, monkeypatch) -> None:
    engine = create_sqlite_engine(tmp_path / "inspect.db")
    initialize_database(engine)
    session = create_session_factory(engine)()
    program_directory = tmp_path / "alpha"
    runs_path = tmp_path / "runs"
    run_id = _seed_run(
        session,
        program_id="alpha",
        paths=["/orders", "/workspace"],
    )
    prepare_flow_mapping(
        run_id,
        session,
        program_id="alpha",
        program_directory=program_directory,
        runs_path=runs_path,
    )
    configure_ollama(program_directory, "local-model:7b")

    def refuse_network(*args, **kwargs):
        pytest.fail("inspect tentou abrir conexão")

    monkeypatch.setattr(socket, "socket", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    plan = inspect_flow_mapping(
        run_id,
        program_id="alpha",
        program_directory=program_directory,
        runs_path=runs_path,
    )

    assert plan.batch_count == plan.item_count == 1
    assert plan.deterministic_signal_count == 1
    assert plan.unknown_dynamic_path_count == 1
    assert plan.context_required_flow_count == 2
    assert plan.mapping_policy == "flow-signal-policy-v1"
    assert plan.output_policy == "flow-output-policy-v1"
    session.close()
    engine.dispose()


def test_results_cli_uses_new_columns_without_mixing_legacy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    program = create_program("alpha", "Alpha")
    select_program("alpha")
    engine = create_sqlite_engine(program.database_path)
    initialize_database(engine)
    session = create_session_factory(engine)()
    run_id = _seed_run(session, program_id="alpha", paths=["/orders", "/workspace"])
    prepare_flow_mapping(
        run_id,
        session,
        program_id="alpha",
        program_directory=program.database_path.parent,
        runs_path=program.runs_path,
    )
    configure_ollama(program.database_path.parent, "local-model:7b")
    verify_ollama_compatibility(
        session,
        program_slug="alpha",
        program_directory=program.database_path.parent,
        adapter=FakeAdapter(['{"ok":true}']),
    )
    batch = load_flow_mapping_batches(
        run_id,
        program.runs_path,
        program_id="alpha",
        program_directory=program.database_path.parent,
    )[0]

    def refuse_network(*args, **kwargs):
        pytest.fail("llm triage --dry-run tentou abrir conexão")

    monkeypatch.setattr(socket, "socket", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    dry_run = CliRunner().invoke(app, ["llm", "triage", str(run_id), "--dry-run"])

    assert dry_run.exit_code == 0
    assert "Prompt: local-flow-mapping-v1" in dry_run.stdout
    assert "Mapping policy: flow-signal-policy-v1" in dry_run.stdout
    assert "Output policy: flow-output-policy-v1" in dry_run.stdout
    assert "sinais determinísticos=1" in dry_run.stdout
    assert "paths desconhecidos=1" in dry_run.stdout
    run_flow_mapping(
        run_id,
        session,
        program_id="alpha",
        program_directory=program.database_path.parent,
        runs_path=program.runs_path,
        adapter=FakeAdapter([_serialized_output(batch.request)]),
    )

    result = CliRunner().invoke(app, ["llm", "results", str(run_id)])

    assert result.exit_code == 0
    assert result.stdout.splitlines()[0] == "HOST | FLUXOS | LACUNAS | PERGUNTAS"
    assert "example.test | TRANSACTION_ORDER, UNKNOWN_DYNAMIC |" in result.stdout
    for forbidden in ("DECISÃO", "CONFIANÇA", "NEEDS_REVIEW", "Cloudflare", "local-model"):
        assert forbidden not in result.stdout
    session.close()
    engine.dispose()
