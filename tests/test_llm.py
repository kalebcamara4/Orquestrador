import json
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler

import pytest
from sqlalchemy import delete, func, inspect, select
from typer.testing import CliRunner

import bb_orchestrator.llm as llm
from bb_orchestrator.cli import app
from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.llm import (
    ADAPTER_PROTOCOL_VERSION,
    COMPATIBILITY_SCHEMA,
    OLLAMA_CHAT_ENDPOINT,
    OLLAMA_TIMEOUT_SECONDS,
    SYSTEM_PROMPT,
    LlmError,
    OllamaChatAdapter,
    OllamaProfileName,
    build_compatibility_request,
    build_ollama_request,
    configure_ollama,
    current_schema_version,
    inspect_llm_triage,
    load_ollama_config,
    load_triage_batches,
    ollama_compatibility_state,
    run_llm_triage,
    validate_llm_response,
    validate_model_id,
    validate_profile,
    verify_ollama_compatibility,
)
from bb_orchestrator.models import (
    LlmTriageAttemptModel,
    LlmTriageResultModel,
    OllamaCompatibilityVerificationModel,
    RunModel,
)
from bb_orchestrator.programs import ProgramInfo, create_program, select_program
from bb_orchestrator.schemas import RunStatus, TriageAsset, TriageRequest


@dataclass
class LlmContext:
    program: ProgramInfo
    session: Any
    run_id: int


@pytest.fixture
def llm_context(tmp_path: Path, monkeypatch) -> LlmContext:
    monkeypatch.chdir(tmp_path)
    program = create_program("acme", "Acme")
    select_program(program.slug)
    engine = create_sqlite_engine(program.database_path)
    initialize_database(engine)
    session = create_session_factory(engine)()
    run = RunModel(
        source_sha256="0" * 64,
        status=RunStatus.SANITIZED.value,
        accepted_count=1,
        rejected_count=0,
        duplicate_count=0,
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    _write_batches(program, run.id, [[_asset("a", "a.example.com")]])
    configure_ollama(program.database_path.parent, "qwen2.5:7b")
    verify_ollama_compatibility(
        session,
        program_slug=program.slug,
        program_directory=program.database_path.parent,
        adapter=FakeAdapter(['{"ok":true}']),
    )
    yield LlmContext(program=program, session=session, run_id=run.id)
    session.close()
    engine.dispose()


def _asset(seed: str, host: str) -> TriageAsset:
    return TriageAsset(
        asset_id=f"asset-{seed * 64}",
        host=host,
        status=200,
        title="Safe title",
        technologies=["nginx"],
        paths=["/", "/login"],
        paths_total=2,
        paths_included=2,
        paths_omitted_by_policy=0,
        paths_omitted_by_limit=0,
    )


def _write_batches(program: ProgramInfo, run_id: int, batches: list[list[TriageAsset]]) -> None:
    directory = program.runs_path / str(run_id) / "llm"
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.glob("triage-input-*.json"):
        stale.unlink()
    for index, items in enumerate(batches, start=1):
        request = TriageRequest(
            batch_id=f"{index:04d}",
            selection_policy="route-priority-v1",
            items=items,
        )
        serialized = (
            json.dumps(
                request.model_dump(mode="json"),
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        (directory / f"triage-input-{index:04d}.json").write_text(
            serialized,
            encoding="utf-8",
        )


def _decision(asset: TriageAsset, *, question: str | None = None) -> dict[str, object]:
    return {
        "asset_id": asset.asset_id,
        "decision": "NEEDS_REVIEW",
        "confidence": "MEDIUM",
        "evidence": [
            {"kind": "PATH", "value": "/login"},
            {"kind": "HTTP_STATUS", "value": "200"},
            {"kind": "TECHNOLOGY", "value": "nginx"},
        ],
        "missing_context": ["USER_ROLE", "RESPONSE_BEHAVIOR"],
        "manual_review_question": question,
    }


def _response(*items: dict[str, object]) -> str:
    return json.dumps({"items": list(items)}, ensure_ascii=False)


class FakeAdapter:
    def __init__(self, responses: list[str | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[dict[str, Any], int]] = []
        self.in_call = False

    def chat(self, payload, *, timeout_seconds: int) -> str:
        assert not self.in_call
        self.in_call = True
        try:
            self.calls.append((payload, timeout_seconds))
            response = self.responses[len(self.calls) - 1]
            if isinstance(response, Exception):
                raise response
            return response
        finally:
            self.in_call = False


@pytest.mark.parametrize(
    "model_id",
    ["qwen2.5:7b", "llama3.2", "library/model-name:latest", "Org_Name/model.v1"],
)
def test_model_id_accepts_safe_local_names(model_id: str) -> None:
    assert validate_model_id(model_id) == model_id


@pytest.mark.parametrize(
    "model_id",
    [
        "",
        " model",
        "model ",
        "http://remote.example/model",
        "../model",
        "model?key=value",
        "model@remote",
        "gpt-oss:120b-cloud",
        "cloud/model:latest",
        "a" * 129,
        "modelo\nnovo",
    ],
)
def test_model_id_rejects_unsafe_or_oversized_values(model_id: str) -> None:
    with pytest.raises(LlmError, match="model_id inválido"):
        validate_model_id(model_id)


def test_unknown_profile_is_rejected_without_model_name_detection(tmp_path: Path) -> None:
    with pytest.raises(LlmError, match="profile Ollama inválido"):
        validate_profile("unknown_profile")
    with pytest.raises(LlmError, match="profile Ollama inválido"):
        configure_ollama(tmp_path, "gpt-oss:20b", "auto")


def test_profiles_are_explicit_and_do_not_depend_on_model_name(tmp_path: Path) -> None:
    generic = configure_ollama(
        tmp_path,
        "gpt-oss:20b",
        OllamaProfileName.GENERIC_OLLAMA_JSON,
    )
    gpt_profile = configure_ollama(
        tmp_path,
        "unrelated-local-model:7b",
        OllamaProfileName.GPT_OSS_JSON,
    )

    generic_request = build_compatibility_request(generic)
    gpt_request = build_compatibility_request(gpt_profile)
    assert "think" not in generic_request
    assert gpt_request["think"] == "low"
    assert set(gpt_request) == {"model", "messages", "stream", "format", "options", "think"}


def test_profiles_cli_lists_only_fixed_capabilities() -> None:
    result = CliRunner().invoke(app, ["llm", "ollama", "profiles"])

    assert result.exit_code == 0
    assert "generic_ollama_json  required  omitted  false  0" in result.stdout
    assert "gpt_oss_json  required  low  false  0" in result.stdout
    assert "auto" not in result.stdout


def test_configuration_persists_only_provider_and_model(llm_context: LlmContext) -> None:
    config_path = llm_context.program.database_path.parent / "llm-config.json"

    assert json.loads(config_path.read_text(encoding="utf-8")) == {
        "model_id": "qwen2.5:7b",
        "profile": "generic_ollama_json",
        "provider": "ollama_local",
    }
    assert load_ollama_config(llm_context.program.database_path.parent).model_id == "qwen2.5:7b"


def test_configuration_rejects_extra_fields(llm_context: LlmContext) -> None:
    config_path = llm_context.program.database_path.parent / "llm-config.json"
    config_path.write_text(
        json.dumps(
            {
                "provider": "ollama_local",
                "model_id": "qwen2.5:7b",
                "profile": "generic_ollama_json",
                "url": "http://remote.example",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(LlmError, match="configuração local da LLM inválida"):
        load_ollama_config(llm_context.program.database_path.parent)


def test_legacy_configuration_without_profile_fails_closed(llm_context: LlmContext) -> None:
    config_path = llm_context.program.database_path.parent / "llm-config.json"
    config_path.write_text(
        json.dumps({"provider": "ollama_local", "model_id": "qwen2.5:7b"}),
        encoding="utf-8",
    )

    with pytest.raises(LlmError, match="configuração local da LLM inválida"):
        load_ollama_config(llm_context.program.database_path.parent)


def test_legacy_llm_tables_receive_safe_idempotent_additive_migration(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "legacy-llm.db")
    initialize_database(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE llm_triage_results")
        connection.exec_driver_sql("DROP TABLE llm_triage_attempts")
        connection.exec_driver_sql(
            """
            CREATE TABLE llm_triage_attempts (
                id INTEGER PRIMARY KEY,
                run_id INTEGER NOT NULL,
                program_slug VARCHAR(64) NOT NULL,
                batch_id VARCHAR(80) NOT NULL,
                status VARCHAR(16) NOT NULL,
                provider VARCHAR(32) NOT NULL,
                model_id VARCHAR(128) NOT NULL,
                prompt_version VARCHAR(32) NOT NULL,
                limits JSON NOT NULL,
                created_at DATETIME NOT NULL,
                completed_at DATETIME
            )
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TABLE llm_triage_results (
                id INTEGER PRIMARY KEY,
                attempt_id INTEGER NOT NULL,
                run_id INTEGER NOT NULL,
                program_slug VARCHAR(64) NOT NULL,
                batch_id VARCHAR(80) NOT NULL,
                asset_id VARCHAR(80) NOT NULL,
                decision VARCHAR(16) NOT NULL,
                confidence VARCHAR(8) NOT NULL,
                evidence JSON NOT NULL,
                missing_context JSON NOT NULL,
                manual_review_question VARCHAR(280),
                provider VARCHAR(32) NOT NULL,
                model_id VARCHAR(128) NOT NULL,
                prompt_version VARCHAR(32) NOT NULL,
                limits JSON NOT NULL,
                created_at DATETIME NOT NULL
            )
            """
        )
        connection.exec_driver_sql(
            """
            INSERT INTO llm_triage_attempts
                (id, run_id, program_slug, batch_id, status, provider, model_id,
                 prompt_version, limits, created_at)
            VALUES
                (1, 1, 'legacy', '0001', 'validated', 'ollama_local', 'old-model',
                 'local-triage-v1', '{}', '2026-01-01 00:00:00')
            """
        )

    initialize_database(engine)
    initialize_database(engine)

    attempt_columns = {
        column["name"] for column in inspect(engine).get_columns("llm_triage_attempts")
    }
    result_columns = {
        column["name"] for column in inspect(engine).get_columns("llm_triage_results")
    }
    expected = {"profile", "adapter_protocol_version", "schema_version"}
    assert expected <= attempt_columns
    assert expected <= result_columns
    with engine.connect() as connection:
        migrated = connection.exec_driver_sql(
            "SELECT profile, adapter_protocol_version, schema_version "
            "FROM llm_triage_attempts WHERE id = 1"
        ).one()
    assert migrated == ("legacy_unprofiled", "legacy", "legacy")
    engine.dispose()


def test_configure_cli_accepts_valid_and_rejects_invalid_model(llm_context: LlmContext) -> None:
    runner = CliRunner()

    valid = runner.invoke(
        app,
        ["llm", "ollama", "configure", "--model", "llama3.2:latest"],
    )
    invalid = runner.invoke(
        app,
        ["llm", "ollama", "configure", "--model", "https://remote.example/model"],
    )
    invalid_profile = runner.invoke(
        app,
        [
            "llm",
            "ollama",
            "configure",
            "--model",
            "llama3.2:latest",
            "--profile",
            "unknown_profile",
        ],
    )

    assert valid.exit_code == 0
    assert "Provider: ollama_local" in valid.stdout
    assert "Model: llama3.2:latest" in valid.stdout
    assert "Profile: generic_ollama_json" in valid.stdout
    assert invalid.exit_code == 1
    assert "model_id inválido" in invalid.stderr
    assert invalid_profile.exit_code != 0
    assert load_ollama_config(llm_context.program.database_path.parent).model_id == (
        "llama3.2:latest"
    )


def test_dry_run_and_status_make_no_network_calls(llm_context: LlmContext, monkeypatch) -> None:
    def refuse_network(*args, **kwargs):
        pytest.fail("dry-run/status tentou acessar a rede")

    monkeypatch.setattr(socket, "socket", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    monkeypatch.setattr(OllamaChatAdapter, "chat", refuse_network)

    verification_count_before = llm_context.session.scalar(
        select(func.count(OllamaCompatibilityVerificationModel.id))
    )
    plan = inspect_llm_triage(
        llm_context.run_id,
        program_directory=llm_context.program.database_path.parent,
        runs_path=llm_context.program.runs_path,
    )
    status = CliRunner().invoke(app, ["llm", "status"])
    dry_run = CliRunner().invoke(
        app,
        ["llm", "triage", str(llm_context.run_id), "--dry-run"],
    )
    verify_dry_run = CliRunner().invoke(app, ["llm", "ollama", "verify", "--dry-run"])

    assert (plan.batch_count, plan.item_count) == (1, 1)
    assert plan.batch_ids == ("0001",)
    assert status.exit_code == verify_dry_run.exit_code == 0
    assert dry_run.exit_code == 1
    assert "Provider: ollama_local" in status.stdout
    assert "Profile: generic_ollama_json" in status.stdout
    assert "Compatibility: validated" in status.stdout
    assert "Execute bb triage 1 --dry-run para gerar flow-map-input v1" in dry_run.stderr
    assert "Verificação local: sem conexão" in verify_dry_run.stdout
    assert llm_context.session.scalar(select(func.count(LlmTriageAttemptModel.id))) == 0
    assert (
        llm_context.session.scalar(select(func.count(OllamaCompatibilityVerificationModel.id)))
        == verification_count_before
    )


def test_cli_requires_exactly_one_triage_gate(llm_context: LlmContext) -> None:
    runner = CliRunner()

    absent = runner.invoke(app, ["llm", "triage", str(llm_context.run_id)])
    both = runner.invoke(
        app,
        ["llm", "triage", str(llm_context.run_id), "--dry-run", "--confirm"],
    )
    verify_absent = runner.invoke(app, ["llm", "ollama", "verify"])
    verify_both = runner.invoke(
        app,
        ["llm", "ollama", "verify", "--dry-run", "--confirm"],
    )

    assert (
        absent.exit_code == both.exit_code == verify_absent.exit_code == verify_both.exit_code == 1
    )
    assert "escolha exatamente uma opção" in absent.stderr
    assert "escolha exatamente uma opção" in both.stderr
    assert "escolha exatamente uma opção" in verify_absent.stderr
    assert "escolha exatamente uma opção" in verify_both.stderr


def test_real_adapter_builds_only_fixed_loopback_post_without_proxy_or_redirect(
    monkeypatch,
) -> None:
    observed: dict[str, Any] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return OLLAMA_CHAT_ENDPOINT

        def getcode(self):
            return 200

        def read(self, limit):
            observed["read_limit"] = limit
            return json.dumps(
                {
                    "message": {
                        "role": "assistant",
                        "content": '{"items":[]}',
                        "thinking": "NEVER-PARSE-OR-LEAK-THIS",
                    },
                    "done": True,
                }
            ).encode()

    class Opener:
        def open(self, request, *, timeout):
            observed["request"] = request
            observed["timeout"] = timeout
            return Response()

    def fake_build_opener(*handlers):
        observed["handlers"] = handlers
        return Opener()

    monkeypatch.setattr(llm, "build_opener", fake_build_opener)

    content = OllamaChatAdapter().chat(
        {"model": "local-model", "stream": False},
        timeout_seconds=OLLAMA_TIMEOUT_SECONDS,
    )

    request = observed["request"]
    handlers = observed["handlers"]
    assert content == '{"items":[]}'
    assert "NEVER-PARSE" not in content
    assert request.full_url == "http://127.0.0.1:11434/api/chat"
    assert request.method == "POST"
    assert not request.has_header("Authorization")
    assert observed["timeout"] == 90
    assert isinstance(handlers[0], ProxyHandler) and handlers[0].proxies == {}
    assert any(isinstance(handler, HTTPRedirectHandler) for handler in handlers)
    with pytest.raises(TypeError):
        OllamaChatAdapter("http://remote.example")


def test_request_uses_structured_output_zero_temperature_and_no_tools(
    llm_context: LlmContext,
) -> None:
    config = load_ollama_config(llm_context.program.database_path.parent)
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]

    payload = build_ollama_request(config, batch)

    assert payload["stream"] is False
    assert "think" not in payload
    assert payload["options"] == {"temperature": 0}
    assert payload["format"]["type"] == "object"
    assert "tools" not in payload
    assert payload["model"] == "qwen2.5:7b"
    assert batch.serialized in payload["messages"][1]["content"]
    compact_schema = json.dumps(
        payload["format"],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert compact_schema in payload["messages"][0]["content"]


def test_gpt_oss_profile_sends_exactly_low_thinking_for_real_triage(
    llm_context: LlmContext,
) -> None:
    config = configure_ollama(
        llm_context.program.database_path.parent,
        "ordinary-model-name:20b",
        OllamaProfileName.GPT_OSS_JSON,
    )
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]

    payload = build_ollama_request(config, batch)

    assert payload["think"] == "low"
    assert payload["stream"] is False
    assert payload["options"] == {"temperature": 0}


def test_compatibility_request_uses_only_fixed_harmless_prompt_and_minimal_schema(
    llm_context: LlmContext,
) -> None:
    config = load_ollama_config(llm_context.program.database_path.parent)

    payload = build_compatibility_request(config)
    prompt = payload["messages"][0]["content"]
    compact_schema = json.dumps(
        COMPATIBILITY_SCHEMA,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )

    assert payload["format"] == COMPATIBILITY_SCHEMA
    assert compact_schema in prompt
    assert '{"ok":true}' in prompt
    assert payload["stream"] is False
    assert payload["options"] == {"temperature": 0}
    assert "think" not in payload
    assert len(payload["messages"]) == 1
    for forbidden in ("example.com", "asset-", "/login", "batch_id", "run_id"):
        assert forbidden not in json.dumps(payload)


def test_verify_valid_json_persists_only_safe_compatibility_metadata(
    llm_context: LlmContext,
) -> None:
    adapter = FakeAdapter(['{"ok":true}'])
    result = verify_ollama_compatibility(
        llm_context.session,
        program_slug=llm_context.program.slug,
        program_directory=llm_context.program.database_path.parent,
        adapter=adapter,
    )
    latest = llm_context.session.scalar(
        select(OllamaCompatibilityVerificationModel)
        .order_by(OllamaCompatibilityVerificationModel.id.desc())
        .limit(1)
    )

    assert result.status == "validated"
    assert len(adapter.calls) == 1
    assert adapter.calls[0][1] == 90
    assert latest is not None
    assert (
        latest.provider,
        latest.model_id,
        latest.profile,
        latest.prompt_version,
        latest.adapter_protocol_version,
        latest.schema_version,
        latest.status,
    ) == (
        "ollama_local",
        "qwen2.5:7b",
        "generic_ollama_json",
        "ollama-compat-v1",
        ADAPTER_PROTOCOL_VERSION,
        current_schema_version(),
        "validated",
    )
    assert set(latest.__table__.columns.keys()) == {
        "id",
        "program_slug",
        "provider",
        "model_id",
        "profile",
        "prompt_version",
        "adapter_protocol_version",
        "schema_version",
        "status",
        "verified_at",
    }


@pytest.mark.parametrize(
    ("content", "expected_code"),
    [
        ("", "EMPTY"),
        ("   \n", "EMPTY"),
        ("not-json-sensitive-value", "JSON_DECODE_ERROR"),
        ('```json\n{"ok":true}\n```', "JSON_DECODE_ERROR"),
        ('before {"ok":true}', "JSON_DECODE_ERROR"),
        ('{"ok":true} after', "JSON_DECODE_ERROR"),
        ('{"ok":true,"ok":true}', "JSON_STRICT_ERROR"),
        ('{"ok":false}', "SCHEMA_MISMATCH"),
        ('{"ok":1}', "SCHEMA_MISMATCH"),
        ("[]", "SCHEMA_MISMATCH"),
        ('{"ok":true,"secret":"DO-NOT-LEAK"}', "SCHEMA_MISMATCH"),
    ],
)
def test_verify_invalid_content_fails_with_structural_diagnostic_only(
    llm_context: LlmContext,
    content: str,
    expected_code: str,
) -> None:
    adapter = FakeAdapter([content])

    with pytest.raises(LlmError) as captured:
        verify_ollama_compatibility(
            llm_context.session,
            program_slug=llm_context.program.slug,
            program_directory=llm_context.program.database_path.parent,
            adapter=adapter,
        )

    message = str(captured.value)
    assert f"code={expected_code}" in message
    assert f"content_length={len(content)}" in message
    assert "first_non_whitespace=" in message
    assert "starts_with_brace=" in message
    assert "ends_with_brace=" in message
    for forbidden in ("sensitive-value", "DO-NOT-LEAK", '"ok"', "```json", "before"):
        assert forbidden not in message
    state = ollama_compatibility_state(
        llm_context.session,
        program_slug=llm_context.program.slug,
        config=load_ollama_config(llm_context.program.database_path.parent),
    )
    assert state.state == "failed"


def test_verify_confirm_cli_uses_mockable_adapter_without_run_data(
    llm_context: LlmContext,
    monkeypatch,
) -> None:
    fake = FakeAdapter(['{"ok":true}'])
    monkeypatch.setattr(llm, "DEFAULT_OLLAMA_ADAPTER", fake)

    result = CliRunner().invoke(app, ["llm", "ollama", "verify", "--confirm"])

    assert result.exit_code == 0
    assert "Compatibilidade: validated" in result.stdout
    assert len(fake.calls) == 1
    serialized_request = json.dumps(fake.calls[0][0])
    assert "example.com" not in serialized_request
    assert "asset-" not in serialized_request
    assert "/login" not in serialized_request


def test_adapter_http_failure_is_clear_and_does_not_leak_remote_text(monkeypatch) -> None:
    class Opener:
        def open(self, request, *, timeout):
            raise HTTPError(request.full_url, 404, "raw-secret-model-error", {}, None)

    monkeypatch.setattr(llm, "build_opener", lambda *handlers: Opener())

    with pytest.raises(LlmError) as captured:
        OllamaChatAdapter().chat(
            {"model": "missing-model", "stream": False},
            timeout_seconds=90,
        )

    assert "HTTP 404" in str(captured.value)
    assert "raw-secret" not in str(captured.value)


def test_message_thinking_is_ignored_by_parser_diagnostic_and_persistence(
    llm_context: LlmContext,
    monkeypatch,
) -> None:
    secret_thinking = "THINKING-MUST-NEVER-LEAK"

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return OLLAMA_CHAT_ENDPOINT

        def getcode(self):
            return 200

        def read(self, limit):
            return json.dumps(
                {
                    "message": {
                        "role": "assistant",
                        "content": "not-json",
                        "thinking": secret_thinking,
                    },
                    "done": True,
                }
            ).encode()

    class Opener:
        def open(self, request, *, timeout):
            return Response()

    monkeypatch.setattr(llm, "build_opener", lambda *handlers: Opener())

    with pytest.raises(LlmError) as captured:
        verify_ollama_compatibility(
            llm_context.session,
            program_slug=llm_context.program.slug,
            program_directory=llm_context.program.database_path.parent,
            adapter=OllamaChatAdapter(),
        )

    latest = llm_context.session.scalar(
        select(OllamaCompatibilityVerificationModel)
        .order_by(OllamaCompatibilityVerificationModel.id.desc())
        .limit(1)
    )
    assert secret_thinking not in str(captured.value)
    assert latest is not None and latest.status == "failed"
    persisted = " ".join(
        (
            latest.provider,
            latest.model_id,
            latest.profile,
            latest.prompt_version,
            latest.adapter_protocol_version,
            latest.schema_version,
            latest.status,
        )
    )
    assert secret_thinking not in persisted


def test_prompt_is_classifier_only_and_does_not_request_hidden_reasoning() -> None:
    prompt = SYSTEM_PROMPT.lower()

    assert "ignore, low_priority, or needs_review" in prompt
    assert "no tools" in prompt
    assert "internal reasoning" in prompt
    assert "chain-of-thought" not in prompt
    assert "step-by-step" not in prompt
    assert "curl" not in prompt
    assert "http://" not in prompt


@pytest.mark.parametrize(
    "mutate",
    [
        lambda valid, asset: "not-json",
        lambda valid, asset: valid + " trailing",
        lambda valid, asset: json.dumps({"items": []}),
        lambda valid, asset: json.dumps(
            {
                "items": [
                    {key: value for key, value in _decision(asset).items() if key != "decision"}
                ]
            }
        ),
        lambda valid, asset: json.dumps({"items": [{**_decision(asset), "unexpected": "field"}]}),
        lambda valid, asset: _response(
            _decision(asset),
            {**_decision(asset), "asset_id": "asset-" + "f" * 64},
        ),
    ],
    ids=[
        "invalid-json",
        "extra-text",
        "incomplete-items",
        "missing-field",
        "extra-field",
        "extra-id",
    ],
)
def test_response_validation_fails_closed_for_malformed_or_incomplete_output(
    llm_context: LlmContext,
    mutate,
) -> None:
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]
    asset = batch.request.items[0]
    valid = _response(_decision(asset))

    with pytest.raises(LlmError):
        validate_llm_response(mutate(valid, asset), batch.request)


def test_response_rejects_duplicate_id_and_invented_evidence(llm_context: LlmContext) -> None:
    request = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0].request
    asset = request.items[0]
    duplicate = _response(_decision(asset), _decision(asset))
    invented = _decision(asset)
    invented["evidence"] = [{"kind": "PATH", "value": "/invented"}]

    with pytest.raises(LlmError, match="asset_ids"):
        validate_llm_response(duplicate, request)
    with pytest.raises(LlmError, match="evidência"):
        validate_llm_response(_response(invented), request)


def test_response_rejects_forbidden_claims_even_inside_a_question(llm_context: LlmContext) -> None:
    request = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0].request
    asset = request.items[0]

    for forbidden in ("CONFIRMED", "CVE-2026-12345", "exploit", "PoC", "payload"):
        with pytest.raises(LlmError, match="pergunta manual"):
            validate_llm_response(
                _response(_decision(asset, question=f"Isto seria {forbidden}?")),
                request,
            )


@pytest.mark.parametrize(
    "question",
    [
        "A revisão deve usar https://example.com/private?",
        "O comportamento muda em /login?next=admin?",
        "Qual regra se aplica a /login?",
        "O endereço mailto:user@example.com deve ser revisado?",
        "O host 192.0.2.10 deveria responder?",
        "A porta :8443 deveria estar acessível?",
        "Quais credenciais devem ser usadas?",
        "O token precisa ser renovado?",
        "Qual header deve ser enviado?",
        "Qual cookie deve ser usado?",
        "Qual payload deve ser testado?",
        "O valor X-Test: abc deveria ser usado?",
        "O valor eyJabc.def.ghi deveria ser usado?",
        "Execute o comando indicado?",
        "Pergunta com controle\nindevido?",
    ],
)
def test_response_rejects_unsafe_manual_questions(
    llm_context: LlmContext,
    question: str,
) -> None:
    request = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0].request
    asset = request.items[0]

    with pytest.raises(LlmError, match="pergunta manual"):
        validate_llm_response(_response(_decision(asset, question=question)), request)


def test_response_accepts_short_defensive_question_with_question_mark(
    llm_context: LlmContext,
) -> None:
    request = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0].request
    asset = request.items[0]
    question = "Qual papel de usuário deveria acessar este caminho?"

    response = validate_llm_response(_response(_decision(asset, question=question)), request)

    assert response.items[0].manual_review_question == question


def test_triage_is_blocked_without_current_compatibility_verification(
    llm_context: LlmContext,
) -> None:
    llm_context.session.execute(delete(OllamaCompatibilityVerificationModel))
    llm_context.session.commit()
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]
    adapter = FakeAdapter([_response(_decision(batch.request.items[0]))])

    with pytest.raises(LlmError, match="bb llm ollama verify --confirm"):
        run_llm_triage(
            llm_context.run_id,
            llm_context.session,
            program_slug=llm_context.program.slug,
            program_directory=llm_context.program.database_path.parent,
            runs_path=llm_context.program.runs_path,
            adapter=adapter,
        )

    assert adapter.calls == []
    assert llm_context.session.scalar(select(func.count(LlmTriageAttemptModel.id))) == 0


@pytest.mark.parametrize(
    "change",
    ["model", "profile", "adapter_protocol", "schema", "compatibility_prompt"],
)
def test_model_profile_schema_or_protocol_change_invalidates_compatibility(
    llm_context: LlmContext,
    monkeypatch,
    change: str,
) -> None:
    if change == "model":
        configure_ollama(llm_context.program.database_path.parent, "another-model:7b")
    elif change == "profile":
        configure_ollama(
            llm_context.program.database_path.parent,
            "qwen2.5:7b",
            OllamaProfileName.GPT_OSS_JSON,
        )
    elif change == "adapter_protocol":
        monkeypatch.setattr(llm, "ADAPTER_PROTOCOL_VERSION", "ollama-chat-json-next")
    elif change == "schema":
        monkeypatch.setattr(
            llm,
            "COMPATIBILITY_SCHEMA",
            {**COMPATIBILITY_SCHEMA, "title": "changed"},
        )
    else:
        monkeypatch.setattr(llm, "COMPATIBILITY_PROMPT_VERSION", "ollama-compat-next")

    config = load_ollama_config(llm_context.program.database_path.parent)
    state = ollama_compatibility_state(
        llm_context.session,
        program_slug=llm_context.program.slug,
        config=config,
    )
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]
    adapter = FakeAdapter([_response(_decision(batch.request.items[0]))])

    assert state.state == "stale"
    with pytest.raises(LlmError, match="verify --confirm"):
        run_llm_triage(
            llm_context.run_id,
            llm_context.session,
            program_slug=llm_context.program.slug,
            program_directory=llm_context.program.database_path.parent,
            runs_path=llm_context.program.runs_path,
            adapter=adapter,
        )
    assert adapter.calls == []


def test_latest_failed_verification_blocks_older_validated_combination(
    llm_context: LlmContext,
) -> None:
    with pytest.raises(LlmError):
        verify_ollama_compatibility(
            llm_context.session,
            program_slug=llm_context.program.slug,
            program_directory=llm_context.program.database_path.parent,
            adapter=FakeAdapter(["invalid-json"]),
        )
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]
    triage_adapter = FakeAdapter([_response(_decision(batch.request.items[0]))])

    with pytest.raises(LlmError, match="verify --confirm"):
        run_llm_triage(
            llm_context.run_id,
            llm_context.session,
            program_slug=llm_context.program.slug,
            program_directory=llm_context.program.database_path.parent,
            runs_path=llm_context.program.runs_path,
            adapter=triage_adapter,
        )

    assert triage_adapter.calls == []


def test_triage_is_released_after_exact_gpt_oss_profile_verification(
    llm_context: LlmContext,
) -> None:
    configure_ollama(
        llm_context.program.database_path.parent,
        "ordinary-model:20b",
        OllamaProfileName.GPT_OSS_JSON,
    )
    verify_adapter = FakeAdapter(['{"ok":true}'])
    verify_ollama_compatibility(
        llm_context.session,
        program_slug=llm_context.program.slug,
        program_directory=llm_context.program.database_path.parent,
        adapter=verify_adapter,
    )
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]
    triage_adapter = FakeAdapter([_response(_decision(batch.request.items[0]))])

    result = run_llm_triage(
        llm_context.run_id,
        llm_context.session,
        program_slug=llm_context.program.slug,
        program_directory=llm_context.program.database_path.parent,
        runs_path=llm_context.program.runs_path,
        adapter=triage_adapter,
    )

    assert result.item_count == 1
    assert verify_adapter.calls[0][0]["think"] == "low"
    assert triage_adapter.calls[0][0]["think"] == "low"


def test_batches_are_processed_serially_once_with_fixed_timeout(llm_context: LlmContext) -> None:
    first = _asset("a", "a.example.com")
    second = _asset("b", "b.example.com")
    _write_batches(llm_context.program, llm_context.run_id, [[first], [second]])
    adapter = FakeAdapter([_response(_decision(first)), _response(_decision(second))])

    result = run_llm_triage(
        llm_context.run_id,
        llm_context.session,
        program_slug=llm_context.program.slug,
        program_directory=llm_context.program.database_path.parent,
        runs_path=llm_context.program.runs_path,
        adapter=adapter,
    )

    assert (result.batch_count, result.item_count) == (2, 2)
    assert len(adapter.calls) == 2
    assert [timeout for _, timeout in adapter.calls] == [90, 90]
    assert [payload["messages"][1]["content"].count("asset-") for payload, _ in adapter.calls] == [
        1,
        1,
    ]


def test_no_retry_and_no_results_are_persisted_after_adapter_failure(
    llm_context: LlmContext,
) -> None:
    first = _asset("a", "a.example.com")
    second = _asset("b", "b.example.com")
    _write_batches(llm_context.program, llm_context.run_id, [[first], [second]])
    adapter = FakeAdapter([LlmError("Ollama local indisponível")])

    with pytest.raises(LlmError, match="indisponível"):
        run_llm_triage(
            llm_context.run_id,
            llm_context.session,
            program_slug=llm_context.program.slug,
            program_directory=llm_context.program.database_path.parent,
            runs_path=llm_context.program.runs_path,
            adapter=adapter,
        )

    assert len(adapter.calls) == 1
    attempt = llm_context.session.scalar(select(LlmTriageAttemptModel))
    assert attempt is not None and attempt.status == "failed"
    assert llm_context.session.scalar(select(func.count(LlmTriageResultModel.id))) == 0


def test_partial_validation_persists_attempts_but_no_results_or_artifact(
    llm_context: LlmContext,
) -> None:
    first = _asset("a", "a.example.com")
    second = _asset("b", "b.example.com")
    _write_batches(llm_context.program, llm_context.run_id, [[first], [second]])
    adapter = FakeAdapter([_response(_decision(first)), "invalid response"])

    with pytest.raises(LlmError):
        run_llm_triage(
            llm_context.run_id,
            llm_context.session,
            program_slug=llm_context.program.slug,
            program_directory=llm_context.program.database_path.parent,
            runs_path=llm_context.program.runs_path,
            adapter=adapter,
        )

    attempts = list(
        llm_context.session.scalars(
            select(LlmTriageAttemptModel).order_by(LlmTriageAttemptModel.id)
        )
    )
    assert [attempt.status for attempt in attempts] == ["validated", "failed"]
    assert llm_context.session.scalar(select(func.count(LlmTriageResultModel.id))) == 0
    assert not (
        llm_context.program.runs_path / str(llm_context.run_id) / "llm/results/triage-results.json"
    ).exists()


def test_validated_results_snapshot_and_artifact_are_safe_and_deterministic(
    llm_context: LlmContext,
) -> None:
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]
    asset = batch.request.items[0]
    question = "Qual papel de usuário deveria acessar este caminho?"
    response = _response(_decision(asset, question=question))
    input_path = (
        llm_context.program.runs_path / str(llm_context.run_id) / "llm/triage-input-0001.json"
    )
    input_before = input_path.read_bytes()

    first = run_llm_triage(
        llm_context.run_id,
        llm_context.session,
        program_slug=llm_context.program.slug,
        program_directory=llm_context.program.database_path.parent,
        runs_path=llm_context.program.runs_path,
        adapter=FakeAdapter([response]),
    )
    first_bytes = first.result_path.read_bytes()
    second = run_llm_triage(
        llm_context.run_id,
        llm_context.session,
        program_slug=llm_context.program.slug,
        program_directory=llm_context.program.database_path.parent,
        runs_path=llm_context.program.runs_path,
        adapter=FakeAdapter([response]),
    )

    row = llm_context.session.scalar(select(LlmTriageResultModel))
    attempts = list(llm_context.session.scalars(select(LlmTriageAttemptModel)))
    artifact = json.loads(second.result_path.read_text(encoding="utf-8"))
    assert first_bytes == second.result_path.read_bytes()
    assert input_path.read_bytes() == input_before
    assert llm_context.session.scalar(select(func.count(LlmTriageResultModel.id))) == 1
    assert len(attempts) == 2
    assert row is not None
    assert (row.provider, row.model_id, row.prompt_version) == (
        "ollama_local",
        "qwen2.5:7b",
        "local-triage-v1",
    )
    assert row.profile == "generic_ollama_json"
    assert row.adapter_protocol_version == ADAPTER_PROTOCOL_VERSION
    assert row.schema_version == current_schema_version()
    assert row.limits["timeout_seconds"] == 90
    assert artifact["items"][0]["manual_review_question"] == question
    assert "host" not in artifact["items"][0]
    assert "raw_response" not in artifact
    assert "thinking" not in artifact
    assert artifact["profile"] == "generic_ollama_json"
    assert artifact["adapter_protocol_version"] == ADAPTER_PROTOCOL_VERSION
    assert artifact["schema_version"] == current_schema_version()


def test_results_cli_shows_only_allowed_columns(llm_context: LlmContext) -> None:
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]
    asset = batch.request.items[0]
    run_llm_triage(
        llm_context.run_id,
        llm_context.session,
        program_slug=llm_context.program.slug,
        program_directory=llm_context.program.database_path.parent,
        runs_path=llm_context.program.runs_path,
        adapter=FakeAdapter([_response(_decision(asset))]),
    )

    result = CliRunner().invoke(app, ["llm", "results", str(llm_context.run_id)])

    assert result.exit_code == 0
    assert result.stdout.splitlines()[0] == "Analysis: legacy_triage"
    assert result.stdout.splitlines()[1] == "HOST  DECISÃO  CONFIANÇA  PERGUNTA"
    assert "a.example.com  NEEDS_REVIEW  MEDIUM  -" in result.stdout
    assert "asset-" not in result.stdout
    assert "nginx" not in result.stdout
    assert "qwen2.5" not in result.stdout
    assert "Provider" not in result.stdout


def test_confirm_cli_uses_mockable_adapter_and_writes_validated_artifact(
    llm_context: LlmContext,
    monkeypatch,
) -> None:
    batch = load_triage_batches(llm_context.run_id, llm_context.program.runs_path)[0]
    fake = FakeAdapter([_response(_decision(batch.request.items[0]))])
    monkeypatch.setattr(llm, "DEFAULT_OLLAMA_ADAPTER", fake)

    result = CliRunner().invoke(
        app,
        ["llm", "triage", str(llm_context.run_id), "--confirm"],
    )

    assert result.exit_code == 1
    assert "Execute bb triage 1 --dry-run para gerar flow-map-input v1" in result.stderr
    assert fake.calls == []


def test_llm_tables_and_artifacts_are_isolated_by_program_and_run(
    llm_context: LlmContext,
) -> None:
    beta = create_program("beta", "Beta")
    beta_engine = create_sqlite_engine(beta.database_path)
    initialize_database(beta_engine)
    beta_session = create_session_factory(beta_engine)()
    beta_run = RunModel(
        source_sha256="1" * 64,
        status=RunStatus.SANITIZED.value,
        accepted_count=1,
        rejected_count=0,
        duplicate_count=0,
    )
    beta_session.add(beta_run)
    beta_session.commit()
    beta_session.refresh(beta_run)
    beta_asset = _asset("b", "b.example.com")
    _write_batches(beta, beta_run.id, [[beta_asset]])
    configure_ollama(beta.database_path.parent, "beta-model:1b")
    beta_config = load_ollama_config(beta.database_path.parent)
    assert (
        ollama_compatibility_state(
            beta_session,
            program_slug=beta.slug,
            config=beta_config,
        ).state
        == "not_verified"
    )
    blocked_adapter = FakeAdapter([_response(_decision(beta_asset))])
    with pytest.raises(LlmError, match="verify --confirm"):
        run_llm_triage(
            beta_run.id,
            beta_session,
            program_slug=beta.slug,
            program_directory=beta.database_path.parent,
            runs_path=beta.runs_path,
            adapter=blocked_adapter,
        )
    assert blocked_adapter.calls == []
    verify_ollama_compatibility(
        beta_session,
        program_slug=beta.slug,
        program_directory=beta.database_path.parent,
        adapter=FakeAdapter(['{"ok":true}']),
    )

    beta_result = run_llm_triage(
        beta_run.id,
        beta_session,
        program_slug=beta.slug,
        program_directory=beta.database_path.parent,
        runs_path=beta.runs_path,
        adapter=FakeAdapter([_response(_decision(beta_asset))]),
    )
    assert beta_run.id == llm_context.run_id == 1
    assert llm_context.session.scalar(select(func.count(LlmTriageResultModel.id))) == 0
    assert beta_session.scalar(select(func.count(LlmTriageResultModel.id))) == 1

    acme_asset = load_triage_batches(
        llm_context.run_id,
        llm_context.program.runs_path,
    )[0].request.items[0]
    acme_result = run_llm_triage(
        llm_context.run_id,
        llm_context.session,
        program_slug=llm_context.program.slug,
        program_directory=llm_context.program.database_path.parent,
        runs_path=llm_context.program.runs_path,
        adapter=FakeAdapter([_response(_decision(acme_asset))]),
    )

    acme_run_two = RunModel(
        source_sha256="2" * 64,
        status=RunStatus.SANITIZED.value,
        accepted_count=1,
        rejected_count=0,
        duplicate_count=0,
    )
    llm_context.session.add(acme_run_two)
    llm_context.session.commit()
    llm_context.session.refresh(acme_run_two)
    acme_asset_two = _asset("c", "c.example.com")
    _write_batches(llm_context.program, acme_run_two.id, [[acme_asset_two]])
    acme_result_two = run_llm_triage(
        acme_run_two.id,
        llm_context.session,
        program_slug=llm_context.program.slug,
        program_directory=llm_context.program.database_path.parent,
        runs_path=llm_context.program.runs_path,
        adapter=FakeAdapter([_response(_decision(acme_asset_two))]),
    )

    assert acme_result.result_path != beta_result.result_path
    assert acme_result.result_path != acme_result_two.result_path
    assert llm_context.session.scalar(select(func.count(LlmTriageResultModel.id))) == 2
    assert (
        llm_context.session.scalar(
            select(func.count(LlmTriageResultModel.id)).where(
                LlmTriageResultModel.run_id == llm_context.run_id
            )
        )
        == 1
    )
    assert beta_session.scalar(select(func.count(LlmTriageResultModel.id))) == 1
    assert json.loads(acme_result.result_path.read_text())["model_id"] == "qwen2.5:7b"
    assert json.loads(beta_result.result_path.read_text())["model_id"] == "beta-model:1b"
    beta_session.close()
    beta_engine.dispose()
