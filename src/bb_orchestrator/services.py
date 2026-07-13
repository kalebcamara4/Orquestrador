"""Casos de uso locais, determinísticos e sem acesso à rede."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from bb_orchestrator.domain import InvalidDomain, is_domain_in_scope
from bb_orchestrator.models import AssetModel, QueueItemModel, RunModel, ScopeRuleModel
from bb_orchestrator.schemas import (
    AssetStatus,
    IngestRecord,
    QueueStatus,
    RunStatus,
    ScopeRule,
)


class InputError(ValueError):
    """Erro seguro e apresentável de entrada local."""


@dataclass(frozen=True)
class ImportResult:
    imported: int
    duplicates: int


@dataclass(frozen=True)
class SanitizeResult:
    sanitized: int
    queued: int


def import_scope_file(path: Path, session: Session) -> ImportResult:
    rules: list[ScopeRule] = []
    seen_in_file: set[str] = set()
    duplicate_count = 0

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise InputError(f"não foi possível ler o arquivo: {exc}") from exc

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rule = ScopeRule(pattern=line)
        except (InvalidDomain, ValidationError, ValueError) as exc:
            raise InputError(f"regra inválida na linha {line_number}: {exc}") from exc
        if rule.pattern in seen_in_file:
            duplicate_count += 1
            continue
        seen_in_file.add(rule.pattern)
        rules.append(rule)

    existing = set(session.scalars(select(ScopeRuleModel.pattern)).all())
    imported_count = 0
    for rule in rules:
        if rule.pattern in existing:
            duplicate_count += 1
            continue
        session.add(ScopeRuleModel(pattern=rule.pattern, kind=rule.kind.value))
        existing.add(rule.pattern)
        imported_count += 1

    session.commit()
    return ImportResult(imported=imported_count, duplicates=duplicate_count)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise InputError(f"não foi possível ler o arquivo: {exc}") from exc
    return digest.hexdigest()


def _load_ingest_records(path: Path) -> list[IngestRecord]:
    records: list[IngestRecord] = []
    try:
        with path.open(encoding="utf-8") as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                if not raw_line.strip():
                    continue
                try:
                    payload = json.loads(raw_line)
                    records.append(IngestRecord.model_validate(payload))
                except (json.JSONDecodeError, ValidationError, InvalidDomain, ValueError) as exc:
                    raise InputError(f"JSONL inválido na linha {line_number}: {exc}") from exc
    except (OSError, UnicodeError) as exc:
        raise InputError(f"não foi possível ler o arquivo: {exc}") from exc
    return records


def ingest_jsonl(path: Path, session: Session) -> RunModel:
    patterns = list(session.scalars(select(ScopeRuleModel.pattern)).all())
    if not patterns:
        raise InputError("nenhuma regra de escopo importada; ingestão recusada por segurança")

    records = _load_ingest_records(path)
    unique_domains: list[str] = []
    seen_domains: set[str] = set()
    rejected_count = 0
    duplicate_count = 0

    for record in records:
        if not is_domain_in_scope(record.domain, patterns):
            rejected_count += 1
            continue
        if record.domain in seen_domains:
            duplicate_count += 1
            continue
        seen_domains.add(record.domain)
        unique_domains.append(record.domain)

    run = RunModel(
        source_sha256=_sha256_file(path),
        status=RunStatus.INGESTED.value,
        accepted_count=len(unique_domains),
        rejected_count=rejected_count,
        duplicate_count=duplicate_count,
    )
    session.add(run)
    session.flush()
    session.add_all(
        AssetModel(run_id=run.id, domain=domain, status=AssetStatus.INGESTED.value)
        for domain in unique_domains
    )
    session.commit()
    return run


def sanitize_run(run_id: int, session: Session) -> SanitizeResult:
    run = session.get(RunModel, run_id)
    if run is None:
        raise InputError(f"run {run_id} não encontrada")

    assets = list(
        session.scalars(
            select(AssetModel).where(AssetModel.run_id == run_id).order_by(AssetModel.id)
        )
    )
    queued_asset_ids = set(
        session.scalars(select(QueueItemModel.asset_id).where(QueueItemModel.run_id == run_id))
    )
    now = datetime.now(UTC)
    sanitized_count = 0
    queued_count = 0

    for asset in assets:
        if asset.status != AssetStatus.SANITIZED.value:
            # O valor já foi validado na ingestão; esta etapa só promove dados canônicos.
            asset.status = AssetStatus.SANITIZED.value
            asset.sanitized_at = now
            sanitized_count += 1
        if asset.id not in queued_asset_ids:
            session.add(
                QueueItemModel(
                    run_id=run_id,
                    asset_id=asset.id,
                    status=QueueStatus.PENDING.value,
                )
            )
            queued_count += 1

    run.status = RunStatus.SANITIZED.value
    session.commit()
    return SanitizeResult(sanitized=sanitized_count, queued=queued_count)


def list_queue(session: Session) -> list[QueueItemModel]:
    return list(session.scalars(select(QueueItemModel).order_by(QueueItemModel.id)).all())
