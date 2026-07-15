"""Schemas Pydantic usados nas fronteiras do orquestrador."""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from bb_orchestrator.domain import ScopeKind, normalize_domain, parse_scope_pattern
from bb_orchestrator.flow_policies import (
    ContextGap,
    DeterministicFlowBasis,
    FlowOutputBasis,
    FlowRelevance,
    FlowType,
)
from bb_orchestrator.triage_selection import (
    MAX_SELECTED_PATHS,
    RouteSelectionPolicyName,
    select_triage_paths,
)


def utc_now() -> datetime:
    return datetime.now(UTC)


class RunStatus(StrEnum):
    INGESTED = "ingested"
    DISCOVERED = "discovered"
    SANITIZED = "sanitized"


class AssetStatus(StrEnum):
    INGESTED = "ingested"
    SANITIZED = "sanitized"


class QueueStatus(StrEnum):
    PENDING = "pending"


class CandidateStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class DnsStatus(StrEnum):
    PENDING = "pending"
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


class HttpReachability(StrEnum):
    PENDING = "pending"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"


class SurfaceStage(StrEnum):
    PENDING = "pending"
    DNS_RESOLVED = "dns_resolved"
    HTTP_REACHABLE = "http_reachable"
    PORTS_OBSERVED = "ports_observed"
    PATHS_OBSERVED = "paths_observed"


class Schema(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ScopeRule(Schema):
    id: int | None = None
    pattern: str
    kind: ScopeKind | None = None
    created_at: datetime | None = None

    @model_validator(mode="after")
    def normalize_rule(self) -> ScopeRule:
        parsed_kind, parsed_pattern = parse_scope_pattern(self.pattern)
        if self.kind is not None and self.kind is not parsed_kind:
            raise ValueError("o tipo da regra não corresponde ao padrão")
        self.pattern = parsed_pattern
        self.kind = parsed_kind
        return self


class Asset(Schema):
    id: int | None = None
    run_id: int
    domain: str
    status: AssetStatus = AssetStatus.INGESTED
    created_at: datetime | None = None
    sanitized_at: datetime | None = None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return normalize_domain(value)


class Run(Schema):
    id: int | None = None
    source_sha256: str
    status: RunStatus = RunStatus.INGESTED
    accepted_count: int = 0
    rejected_count: int = 0
    duplicate_count: int = 0
    created_at: datetime | None = None


class QueueItem(Schema):
    id: int | None = None
    run_id: int
    asset_id: int
    status: QueueStatus = QueueStatus.PENDING
    created_at: datetime | None = None


class IngestRecord(Schema):
    """Formato intencionalmente estreito: dados brutos extras são recusados."""

    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return normalize_domain(value)


SurfaceTechnology = Annotated[str, Field(min_length=1, max_length=80)]


class SurfaceRecord(Schema):
    """Projeção local e estrita dos estados seguros de um candidato."""

    model_config = ConfigDict(extra="forbid", frozen=True, from_attributes=True)

    host: str
    approval_status: CandidateStatus
    dns_status: DnsStatus
    http_reachability: HttpReachability
    http_status_code: int | None = Field(default=None, ge=100, le=599)
    http_title: str | None = Field(default=None, max_length=200)
    http_technologies: tuple[SurfaceTechnology, ...] = Field(
        default_factory=tuple,
        max_length=20,
    )
    open_ports: tuple[StrictInt, ...] = Field(default_factory=tuple)
    path_count: StrictInt = Field(default=0, ge=0, le=100)
    stage: SurfaceStage

    @field_validator("host")
    @classmethod
    def validate_surface_host(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("open_ports")
    @classmethod
    def validate_open_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(isinstance(port, bool) or not 1 <= port <= 65535 for port in value):
            raise ValueError("porta inválida na superfície")
        if value != tuple(sorted(set(value))):
            raise ValueError("portas da superfície devem ser únicas e ordenadas")
        return value


class TriageSchema(BaseModel):
    """Base estrita para tudo que pode cruzar a futura fronteira de LLM."""

    model_config = ConfigDict(extra="forbid", strict=True)


class TriageAsset(TriageSchema):
    """Allowlist mínima de um ativo preparado para triagem."""

    asset_id: StrictStr = Field(min_length=1, max_length=80)
    host: StrictStr = Field(min_length=1, max_length=253)
    status: StrictInt | None = Field(ge=100, le=599)
    title: StrictStr | None = Field(max_length=500)
    technologies: list[StrictStr] = Field(max_length=50)
    paths: list[Annotated[StrictStr, Field(min_length=1, max_length=512)]] = Field(
        max_length=MAX_SELECTED_PATHS
    )
    paths_total: StrictInt = Field(ge=0)
    paths_included: StrictInt = Field(ge=0, le=MAX_SELECTED_PATHS)
    paths_omitted_by_policy: StrictInt = Field(ge=0)
    paths_omitted_by_limit: StrictInt = Field(ge=0)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("paths devem ser únicos")
        for path in value:
            if not path.startswith("/") or path.startswith("//"):
                raise ValueError("path relativo inválido")
            if "?" in path or "#" in path:
                raise ValueError("query string ou fragmento não permitido")
            if any(unicodedata.category(character).startswith("C") for character in path):
                raise ValueError("caractere de controle não permitido")
        selection = select_triage_paths(value)
        if list(selection.paths) != value or selection.paths_omitted_by_policy:
            raise ValueError("paths não correspondem à ordenação da política de seleção")
        return value

    @model_validator(mode="after")
    def validate_path_counts(self) -> TriageAsset:
        if self.paths_included != len(self.paths):
            raise ValueError("paths_included deve corresponder aos paths incluídos")
        accounted_paths = (
            self.paths_included + self.paths_omitted_by_policy + self.paths_omitted_by_limit
        )
        if self.paths_total != accounted_paths:
            raise ValueError("os contadores de paths devem corresponder a paths_total")
        return self


class _TriageItems(TriageSchema):
    batch_id: StrictStr = Field(min_length=1, max_length=80)
    selection_policy: RouteSelectionPolicyName
    items: list[TriageAsset] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def refuse_duplicate_asset_ids(self) -> _TriageItems:
        asset_ids = [item.asset_id for item in self.items]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("asset_id duplicado no lote de triagem")
        return self


class TriageBatch(_TriageItems):
    """Lote determinístico, limitado a vinte ativos."""


class TriageRequest(_TriageItems):
    """Payload serializado de uma requisição local de triagem."""


class TriageEvidence(TriageSchema):
    kind: Literal["PATH", "HTTP_STATUS", "TECHNOLOGY"]
    value: StrictStr = Field(min_length=1, max_length=512)


class TriageDecision(TriageSchema):
    asset_id: StrictStr = Field(min_length=1, max_length=80)
    decision: Literal["IGNORE", "LOW_PRIORITY", "NEEDS_REVIEW"]
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    evidence: list[TriageEvidence] = Field(max_length=3)
    missing_context: list[
        Literal["AUTHORIZATION", "USER_ROLE", "RESPONSE_BEHAVIOR", "BUSINESS_RULE", "OTHER"]
    ] = Field(max_length=5)
    manual_review_question: StrictStr | None = Field(max_length=280)

    @model_validator(mode="after")
    def refuse_duplicate_values(self) -> TriageDecision:
        evidence = [(item.kind, item.value) for item in self.evidence]
        if len(evidence) != len(set(evidence)):
            raise ValueError("evidência duplicada")
        if len(self.missing_context) != len(set(self.missing_context)):
            raise ValueError("missing_context duplicado")
        return self


class TriageResponse(TriageSchema):
    items: list[TriageDecision]


class FlowSchema(BaseModel):
    """Schema fechado da nova fronteira de mapeamento de fluxos."""

    # Enums vindas de JSON precisam ser materializadas como ``StrEnum``; os escalares que não
    # podem sofrer coerção usam explicitamente StrictStr/StrictInt.
    model_config = ConfigDict(extra="forbid")


FlowPath = Annotated[StrictStr, Field(min_length=1, max_length=512)]


def _validate_flow_paths(value: list[str]) -> list[str]:
    if len(value) != len(set(value)) or value != sorted(value):
        raise ValueError("paths de fluxo devem ser únicos e ordenados")
    for path in value:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path relativo de fluxo inválido")
        if "?" in path or "#" in path or "\\" in path:
            raise ValueError("query string, fragmento ou separador inválido")
        if any(unicodedata.category(character).startswith("C") for character in path):
            raise ValueError("caractere de controle não permitido")
    return value


class DeterministicFlowSignal(FlowSchema):
    flow_type: FlowType
    basis: DeterministicFlowBasis
    relevance: FlowRelevance
    evidence_paths: list[FlowPath] = Field(min_length=1, max_length=5)
    evidence_paths_total: StrictInt = Field(ge=1)
    required_context: list[ContextGap] = Field(max_length=len(ContextGap))

    @field_validator("evidence_paths")
    @classmethod
    def validate_evidence_paths(cls, value: list[str]) -> list[str]:
        return _validate_flow_paths(value)

    @field_validator("required_context")
    @classmethod
    def validate_required_context(cls, value: list[ContextGap]) -> list[ContextGap]:
        if len(value) != len(set(value)):
            raise ValueError("lacuna determinística duplicada")
        return value

    @model_validator(mode="after")
    def validate_evidence_total(self) -> DeterministicFlowSignal:
        if self.evidence_paths_total < len(self.evidence_paths):
            raise ValueError("evidence_paths_total menor que as evidências incluídas")
        return self


class FlowMappingAsset(FlowSchema):
    asset_id: StrictStr = Field(pattern=r"^asset-[0-9a-f]{64}$")
    host: StrictStr = Field(min_length=1, max_length=253)
    deterministic_flow_signals: list[DeterministicFlowSignal] = Field(max_length=20)
    unknown_dynamic_paths: list[FlowPath] = Field(max_length=100)
    unknown_dynamic_paths_total: StrictInt = Field(ge=0, le=100)

    @field_validator("host")
    @classmethod
    def validate_flow_host(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("unknown_dynamic_paths")
    @classmethod
    def validate_unknown_paths(cls, value: list[str]) -> list[str]:
        return _validate_flow_paths(value)

    @model_validator(mode="after")
    def validate_unknown_total(self) -> FlowMappingAsset:
        if self.unknown_dynamic_paths_total != len(self.unknown_dynamic_paths):
            raise ValueError("unknown_dynamic_paths_total não corresponde aos paths")
        coordinates = [
            (signal.flow_type, signal.basis) for signal in self.deterministic_flow_signals
        ]
        if len(coordinates) != len(set(coordinates)):
            raise ValueError("sinal determinístico duplicado")
        return self


class FlowMappingRequest(FlowSchema):
    batch_id: StrictStr = Field(pattern=r"^\d{4}$")
    mapping_policy: Literal["flow-signal-policy-v1"]
    selection_policy: RouteSelectionPolicyName
    items: list[FlowMappingAsset] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def refuse_duplicate_flow_asset_ids(self) -> FlowMappingRequest:
        asset_ids = [item.asset_id for item in self.items]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("asset_id duplicado no lote de mapeamento")
        return self


class FlowMapping(FlowSchema):
    flow_type: FlowType
    basis: FlowOutputBasis
    evidence_paths: list[FlowPath] = Field(min_length=1, max_length=100)
    context_gaps: list[ContextGap] = Field(max_length=len(ContextGap))

    @field_validator("evidence_paths")
    @classmethod
    def validate_mapping_paths(cls, value: list[str]) -> list[str]:
        return _validate_flow_paths(value)

    @field_validator("context_gaps")
    @classmethod
    def refuse_duplicate_context_gaps(cls, value: list[ContextGap]) -> list[ContextGap]:
        if len(value) != len(set(value)):
            raise ValueError("context_gap duplicado")
        return value


class FlowReviewQuestion(FlowSchema):
    applies_to_flows: list[FlowType] = Field(min_length=1, max_length=len(FlowType))
    required_context: list[ContextGap] = Field(min_length=1, max_length=len(ContextGap))
    question: StrictStr = Field(min_length=20, max_length=280)

    @model_validator(mode="after")
    def refuse_duplicate_question_coordinates(self) -> FlowReviewQuestion:
        if len(self.applies_to_flows) != len(set(self.applies_to_flows)):
            raise ValueError("flow duplicado na pergunta")
        if len(self.required_context) != len(set(self.required_context)):
            raise ValueError("contexto duplicado na pergunta")
        return self


class FlowMappingItem(FlowSchema):
    asset_id: StrictStr = Field(pattern=r"^asset-[0-9a-f]{64}$")
    flow_mappings: list[FlowMapping] = Field(max_length=200)
    review_questions: list[FlowReviewQuestion] = Field(max_length=3)


class FlowMappingResponse(FlowSchema):
    items: list[FlowMappingItem] = Field(max_length=20)
