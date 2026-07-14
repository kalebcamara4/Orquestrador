"""Modelos SQLAlchemy persistidos no SQLite local."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class ScopeRuleModel(Base):
    __tablename__ = "scope_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    pattern: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)


class ProgramModel(Base):
    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(nullable=True)


class ProgramPolicyModel(Base):
    __tablename__ = "program_policies"

    program_slug: Mapped[str] = mapped_column(
        String(64), ForeignKey("programs.slug"), primary_key=True
    )
    policy_name: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )


class RunModel(Base):
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    accepted_count: Mapped[int] = mapped_column(default=0, nullable=False)
    rejected_count: Mapped[int] = mapped_column(default=0, nullable=False)
    duplicate_count: Mapped[int] = mapped_column(default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)


class AssetModel(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("run_id", "domain", name="uq_asset_run_domain"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    sanitized_at: Mapped[datetime | None] = mapped_column(nullable=True)


class CandidateModel(Base):
    __tablename__ = "candidates"
    __table_args__ = (
        UniqueConstraint("run_id", "host", name="uq_candidate_run_host"),
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected')",
            name="ck_candidate_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(nullable=True)


class DnsVerificationAttemptModel(Base):
    __tablename__ = "dns_verification_attempts"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'resolved', 'unresolved')",
            name="ck_dns_verification_status",
        ),
        Index("ix_dns_attempt_candidate_latest", "candidate_id", "id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    candidate_id: Mapped[int] = mapped_column(
        ForeignKey("candidates.id"), nullable=False, index=True
    )
    program_slug: Mapped[str] = mapped_column(
        String(64), ForeignKey("programs.slug"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(nullable=False)
    dnsx_version: Mapped[str | None] = mapped_column(String(64), nullable=True)


class HttpVerificationAttemptModel(Base):
    __tablename__ = "http_verification_attempts"
    __table_args__ = (
        CheckConstraint(
            "reachability IN ('pending', 'reachable', 'unreachable')",
            name="ck_http_verification_reachability",
        ),
        CheckConstraint(
            "status_code IS NULL OR status_code BETWEEN 100 AND 599",
            name="ck_http_verification_status_code",
        ),
        Index("ix_http_attempt_candidate_latest", "candidate_id", "id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    candidate_id: Mapped[int] = mapped_column(
        ForeignKey("candidates.id"), nullable=False, index=True
    )
    program_slug: Mapped[str] = mapped_column(
        String(64), ForeignKey("programs.slug"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    reachability: Mapped[str] = mapped_column(String(16), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    technologies: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    verified_at: Mapped[datetime] = mapped_column(nullable=False)


class ExecutionPolicySnapshotModel(Base):
    __tablename__ = "execution_policy_snapshots"
    __table_args__ = (
        CheckConstraint("step IN ('dns', 'http', 'ports')", name="ck_policy_snapshot_step"),
        Index("ix_policy_snapshot_run_step", "run_id", "step", "id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    program_slug: Mapped[str] = mapped_column(
        String(64), ForeignKey("programs.slug"), nullable=False, index=True
    )
    step: Mapped[str] = mapped_column(String(16), nullable=False)
    snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)


class PortObservationModel(Base):
    __tablename__ = "port_observations"
    __table_args__ = (
        CheckConstraint("status = 'open'", name="ck_port_observation_status"),
        CheckConstraint("port IN (80, 443, 8080, 8443)", name="ck_port_observation_port"),
        UniqueConstraint("run_id", "host", "port", name="uq_port_observation_run_host_port"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(8), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("execution_policy_snapshots.id"), nullable=False, index=True
    )


class QueueItemModel(Base):
    __tablename__ = "queue_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id"), unique=True, nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
