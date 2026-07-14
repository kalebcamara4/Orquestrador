"""Schemas Pydantic usados nas fronteiras do orquestrador."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

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
    paths: list[StrictStr] = Field(max_length=100)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        return normalize_domain(value)


class _TriageItems(TriageSchema):
    batch_id: StrictStr = Field(min_length=1, max_length=80)
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
    """Payload serializado de uma futura requisição de triagem."""


class TriageDecision(TriageSchema):
    asset_id: StrictStr = Field(min_length=1, max_length=80)
    decision: Literal["IGNORE", "LOW_PRIORITY", "NEEDS_REVIEW"]
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    evidence: list[StrictStr] = Field(max_length=50)
    missing_context: list[StrictStr] = Field(max_length=50)
    manual_review_question: StrictStr | None = Field(max_length=500)


class TriageResponse(TriageSchema):
    items: list[TriageDecision]
