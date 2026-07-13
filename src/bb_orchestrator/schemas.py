"""Schemas Pydantic usados nas fronteiras do orquestrador."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from bb_orchestrator.domain import ScopeKind, normalize_domain, parse_scope_pattern


def utc_now() -> datetime:
    return datetime.now(UTC)


class RunStatus(StrEnum):
    INGESTED = "ingested"
    SANITIZED = "sanitized"


class AssetStatus(StrEnum):
    INGESTED = "ingested"
    SANITIZED = "sanitized"


class QueueStatus(StrEnum):
    PENDING = "pending"


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
