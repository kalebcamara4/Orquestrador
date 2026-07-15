import json
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler

import pytest
from sqlalchemy import func, select
from typer.testing import CliRunner

import bb_orchestrator.llm as llm
from bb_orchestrator.cli import app
from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.llm import (
    OLLAMA_CHAT_ENDPOINT,
    OLLAMA_TIMEOUT_SECONDS,
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    LlmError,
    OllamaChatAdapter,
    build_ollama_request,
    configure_ollama,
    inspect_llm_triage,
    load_ollama_config,
    load_triage_batches,
    run_llm_triage,
    validate_llm_response,
    validate_model_id,
)
from bb_orchestrator.models import LlmTriageAttemptModel, LlmTriageResultModel, RunModel
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


def test_configuration_persists_only_provider_and_model(llm_context: LlmContext) -> None:
    config_path = llm_context.program.database_path.parent / "llm-config.json"

    assert json.loads(config_path.read_text(encoding="utf-8")) == {
        "model_id": "qwen2.5:7b",
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
                "url": "http://remote.example",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(LlmError, match="configuração local da LLM inválida"):
        load_ollama_config(llm_context.program.database_path.parent)


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

    assert valid.exit_code == 0
    assert "Provider: ollama_local" in valid.stdout
    assert "Model: llama3.2:latest" in valid.stdout
    assert invalid.exit_code == 1
    assert "model_id inválido" in invalid.stderr
    assert load_ollama_config(llm_context.program.database_path.parent).model_id == (
        "llama3.2:latest"
    )


def test_dry_run_and_status_make_no_network_calls(llm_context: LlmContext, monkeypatch) -> None:
    def refuse_network(*args, **kwargs):
        pytest.fail("dry-run/status tentou acessar a rede")

    monkeypatch.setattr(socket, "socket", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    monkeypatch.setattr(OllamaChatAdapter, "chat", refuse_network)

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

    assert (plan.batch_count, plan.item_count) == (1, 1)
    assert plan.batch_ids == ("0001",)
    assert status.exit_code == dry_run.exit_code == 0
    assert "Provider: ollama_local" in status.stdout
    assert f"Prompt: {PROMPT_VERSION}" in dry_run.stdout
    assert "Lotes: 0001" in dry_run.stdout
    assert "lotes=1; itens=1; sem conexão" in dry_run.stdout
    assert llm_context.session.scalar(select(func.count(LlmTriageAttemptModel.id))) == 0


def test_cli_requires_exactly_one_triage_gate(llm_context: LlmContext) -> None:
    runner = CliRunner()

    absent = runner.invoke(app, ["llm", "triage", str(llm_context.run_id)])
    both = runner.invoke(
        app,
        ["llm", "triage", str(llm_context.run_id), "--dry-run", "--confirm"],
    )

    assert absent.exit_code == both.exit_code == 1
    assert "escolha exatamente uma opção" in absent.stderr
    assert "escolha exatamente uma opção" in both.stderr


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
                    "message": {"role": "assistant", "content": '{"items":[]}'},
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
    assert payload["think"] is False
    assert payload["options"] == {"temperature": 0}
    assert payload["format"]["type"] == "object"
    assert "tools" not in payload
    assert payload["model"] == "qwen2.5:7b"
    assert batch.serialized in payload["messages"][1]["content"]


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
    assert row.limits["timeout_seconds"] == 90
    assert artifact["items"][0]["manual_review_question"] == question
    assert "host" not in artifact["items"][0]
    assert "raw_response" not in artifact
    assert "thinking" not in artifact


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
    assert result.stdout.splitlines()[0] == "HOST  DECISÃO  CONFIANÇA  PERGUNTA"
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

    assert result.exit_code == 0
    assert "lotes validados=1; itens validados=1" in result.stdout
    assert len(fake.calls) == 1
    assert (
        llm_context.program.runs_path / str(llm_context.run_id) / "llm/results/triage-results.json"
    ).is_file()


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
