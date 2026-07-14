"""Casos de uso seguros, sem requests aos hosts descobertos."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from bb_orchestrator.domain import (
    InvalidDomain,
    ScopeKind,
    is_domain_in_scope,
    normalize_domain,
    parse_scope_pattern,
)
from bb_orchestrator.models import (
    AssetModel,
    CandidateModel,
    QueueItemModel,
    RunModel,
    ScopeRuleModel,
)
from bb_orchestrator.schemas import (
    AssetStatus,
    CandidateStatus,
    IngestRecord,
    QueueStatus,
    RunStatus,
    ScopeRule,
    TriageAsset,
    TriageBatch,
    TriageRequest,
)

DEFAULT_TRIAGE_BATCH_SIZE = 10
MAX_TRIAGE_BATCH_SIZE = 20
DEFAULT_RUNS_PATH = Path("runs")
SUBFINDER_TIMEOUT_SECONDS = 300

_URL_PATTERN = re.compile(r"(?i)(?:\b[a-z][a-z0-9+.-]{1,20}://|\b(?:[a-z0-9-]+\.)+[a-z]{2,63}/\S*)")
_QUERY_PATTERN = re.compile(r"(?i)(?:\?|%3f|(?:^|&)\s*[^&=\s]{1,64}=[^&\s]*)")
_PORT_PATTERN = re.compile(r":\d{1,5}\b")
_RAW_HTTP_PATTERN = re.compile(
    r"(?im)(?:^|\r?\n)(?:HTTP/\d(?:\.\d)?\s+\d{3}|[A-Za-z0-9-]{2,40}:\s*\S)"
)
_SENSITIVE_PATTERN = re.compile(
    r"(?i)\b(?:authorization|bearer|cookie|set-cookie|token|api[-_ ]?key|secret|"
    r"password|passwd|session[-_ ]?(?:id|token)?|private[-_ ]?key)\b"
)
_SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(?:\beyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+\b|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[a-z0-9]{20,}\b|"
    r"\bxox[baprs]-[a-z0-9-]{10,}\b|\bsk-[a-z0-9_-]{8,}\b|"
    r"\b(?:sk|pk)_(?:live|test)_[a-z0-9]{8,}\b|\bAIza[a-z0-9_-]{35}\b|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_EMAIL_PATTERN = re.compile(r"(?i)(?<![a-z0-9._%+-])[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
_PHONE_PATTERN = re.compile(r"(?<![A-Za-z0-9])(?:\+?\d[\s().-]*){8,15}(?![A-Za-z0-9])")
_CPF_PATTERN = re.compile(r"(?<![A-Za-z0-9])\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?![A-Za-z0-9])")
_IP_CANDIDATE_PATTERN = re.compile(r"(?<![A-Za-z0-9])[\[\]0-9A-Fa-f:.%]+(?![A-Za-z0-9])")


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


@dataclass(frozen=True)
class TriagePreparationResult:
    item_count: int
    batch_count: int
    paths: tuple[Path, ...]


@dataclass(frozen=True)
class PassiveReconResult:
    run_id: int
    accepted: int
    rejected: int
    duplicates: int
    raw_path: Path | None


@dataclass(frozen=True)
class CandidateTransitionResult:
    changed: int
    unchanged: int


@dataclass(frozen=True)
class AssetExportResult:
    exported: int
    path: Path


class PolicyViolation(InputError):
    """Indica que o gate default-deny recusou um payload de triagem."""


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


def _scope_patterns(session: Session) -> list[str]:
    return list(session.scalars(select(ScopeRuleModel.pattern)).all())


def passive_recon_roots(session: Session) -> list[str]:
    """Retorna somente raízes explicitamente autorizadas por regras wildcard."""
    roots: set[str] = set()
    patterns = session.scalars(
        select(ScopeRuleModel.pattern).where(ScopeRuleModel.kind == ScopeKind.WILDCARD.value)
    )
    for pattern in patterns:
        try:
            kind, normalized_pattern = parse_scope_pattern(pattern)
        except (InvalidDomain, ValueError):
            continue
        if kind is ScopeKind.WILDCARD:
            roots.add(normalized_pattern[2:])
    return sorted(roots)


def exact_scope_hosts(session: Session) -> list[str]:
    """Retorna regras exatas como hosts candidatos, sem autorizar enumeração."""
    hosts: set[str] = set()
    patterns = session.scalars(
        select(ScopeRuleModel.pattern).where(ScopeRuleModel.kind == ScopeKind.EXACT.value)
    )
    for pattern in patterns:
        try:
            kind, normalized_pattern = parse_scope_pattern(pattern)
        except (InvalidDomain, ValueError):
            continue
        if kind is ScopeKind.EXACT:
            hosts.add(normalized_pattern)
    return sorted(hosts)


def _is_safely_in_scope(host: str, patterns: Sequence[str]) -> bool:
    try:
        return is_domain_in_scope(host, patterns)
    except (InvalidDomain, ValueError):
        return False


def _write_atomic(path: Path, content: str, error_context: str) -> None:
    temporary_path = path.with_suffix(f"{path.suffix}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            temporary_path.write_text(content, encoding="utf-8")
            temporary_path.replace(path)
        finally:
            temporary_path.unlink(missing_ok=True)
    except OSError as exc:
        raise InputError(f"não foi possível gravar {error_context}: {exc}") from exc


def _filter_subfinder_output(
    stdout: str,
    patterns: Sequence[str],
) -> tuple[str, list[str], int, int]:
    """Aplica validação, escopo default-deny e deduplicação a cada linha recebida."""
    unique_hosts: list[str] = []
    seen_hosts: set[str] = set()
    rejected_count = 0
    duplicate_count = 0

    for raw_line in stdout.splitlines():
        observed = raw_line.strip()
        if not observed:
            continue
        try:
            host = normalize_domain(observed)
        except (InvalidDomain, ValueError):
            rejected_count += 1
            continue
        if not _is_safely_in_scope(host, patterns):
            rejected_count += 1
            continue
        if host in seen_hosts:
            duplicate_count += 1
            continue
        seen_hosts.add(host)
        unique_hosts.append(host)

    raw_content = "".join(f"{host}\n" for host in unique_hosts)
    return raw_content, unique_hosts, rejected_count, duplicate_count


def run_passive_recon(
    session: Session,
    *,
    runs_path: Path = DEFAULT_RUNS_PATH,
) -> PassiveReconResult:
    """Executa exclusivamente subfinder; não resolve nem contata os hosts retornados."""
    roots = passive_recon_roots(session)
    exact_hosts = exact_scope_hosts(session)
    if not roots and not exact_hosts:
        raise InputError("nenhuma regra de escopo importada para descoberta passiva")

    subfinder_path: str | None = None
    if roots:
        subfinder_path = shutil.which("subfinder")
        if subfinder_path is None:
            raise InputError(
                "subfinder não está instalado; instale-o manualmente e adicione o binário ao PATH"
            )

    run = RunModel(
        source_sha256="0" * 64,
        status=RunStatus.DISCOVERED.value,
        accepted_count=0,
        rejected_count=0,
        duplicate_count=0,
    )
    session.add(run)
    session.flush()

    patterns = _scope_patterns(session)
    raw_content = ""
    observed_hosts: list[str] = []
    rejected_count = 0
    duplicate_count = 0
    raw_path: Path | None = None
    if roots:
        command = [subfinder_path, "-silent", "-duc"]
        for root in roots:
            command.extend(("-d", root))
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                encoding="utf-8",
                errors="replace",
                stdin=subprocess.DEVNULL,
                shell=False,
                text=True,
                timeout=SUBFINDER_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            session.rollback()
            raise InputError("não foi possível executar o subfinder") from exc

        if completed.returncode != 0:
            session.rollback()
            raise InputError(f"subfinder terminou com código {completed.returncode}")

        raw_content, observed_hosts, rejected_count, duplicate_count = _filter_subfinder_output(
            completed.stdout or "", patterns
        )
        raw_path = runs_path / str(run.id) / "raw" / "subfinder.txt"
        try:
            _write_atomic(raw_path, raw_content, "a saída segura do subfinder")
        except InputError:
            session.rollback()
            raise

    exact_host_set = set(exact_hosts)
    discovered_hosts: list[str] = []
    for host in observed_hosts:
        if host in exact_host_set:
            duplicate_count += 1
        else:
            discovered_hosts.append(host)

    session.add_all(
        CandidateModel(
            run_id=run.id,
            host=host,
            source="scope_exact",
            status=CandidateStatus.PENDING.value,
        )
        for host in exact_hosts
    )
    session.add_all(
        CandidateModel(
            run_id=run.id,
            host=host,
            source="subfinder",
            status=CandidateStatus.PENDING.value,
        )
        for host in discovered_hosts
    )
    source_content = "".join(f"scope_exact:{host}\n" for host in exact_hosts) + raw_content
    run.source_sha256 = hashlib.sha256(source_content.encode("utf-8")).hexdigest()
    run.accepted_count = len(exact_hosts) + len(discovered_hosts)
    run.rejected_count = rejected_count
    run.duplicate_count = duplicate_count
    session.commit()
    return PassiveReconResult(
        run_id=run.id,
        accepted=run.accepted_count,
        rejected=rejected_count,
        duplicates=duplicate_count,
        raw_path=raw_path,
    )


def ingest_jsonl(path: Path, session: Session) -> RunModel:
    patterns = _scope_patterns(session)
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
        CandidateModel(
            run_id=run.id,
            host=domain,
            source="ingest",
            status=CandidateStatus.PENDING.value,
        )
        for domain in unique_domains
    )
    session.commit()
    return run


def _require_run(run_id: int, session: Session) -> RunModel:
    run = session.get(RunModel, run_id)
    if run is None:
        raise InputError(f"run {run_id} não encontrada")
    return run


def list_candidates(run_id: int, session: Session) -> list[CandidateModel]:
    """Lista somente pendentes que continuam cobertos pelo escopo autorizado."""
    _require_run(run_id, session)
    patterns = _scope_patterns(session)

    candidates = session.scalars(
        select(CandidateModel)
        .where(
            CandidateModel.run_id == run_id,
            CandidateModel.status == CandidateStatus.PENDING.value,
        )
        .order_by(CandidateModel.host, CandidateModel.id)
    )
    return [candidate for candidate in candidates if _is_safely_in_scope(candidate.host, patterns)]


def _normalize_requested_hosts(hosts: Sequence[str]) -> list[str]:
    normalized_hosts: list[str] = []
    seen: set[str] = set()
    for observed in hosts:
        try:
            host = normalize_domain(observed)
        except (InvalidDomain, ValueError) as exc:
            raise InputError(f"host inválido: {exc}") from exc
        if host not in seen:
            seen.add(host)
            normalized_hosts.append(host)
    return normalized_hosts


def _transition_candidates(
    run_id: int,
    session: Session,
    *,
    status: CandidateStatus,
    hosts: Sequence[str] | None = None,
    all_pending: bool = False,
) -> CandidateTransitionResult:
    _require_run(run_id, session)
    patterns = _scope_patterns(session)

    if all_pending and hosts:
        raise InputError("use todos os pendentes ou uma seleção explícita, mas não ambos")

    if all_pending:
        candidates = list(
            session.scalars(
                select(CandidateModel)
                .where(
                    CandidateModel.run_id == run_id,
                    CandidateModel.status == CandidateStatus.PENDING.value,
                )
                .order_by(CandidateModel.host)
            )
        )
        candidates = [
            candidate for candidate in candidates if _is_safely_in_scope(candidate.host, patterns)
        ]
    else:
        requested_hosts = _normalize_requested_hosts(hosts or ())
        if not requested_hosts:
            raise InputError("selecione ao menos um candidato")
        outside_scope = [
            host for host in requested_hosts if not _is_safely_in_scope(host, patterns)
        ]
        if outside_scope:
            raise InputError(f"host fora do escopo: {outside_scope[0]}")
        candidates_by_host = {
            candidate.host: candidate
            for candidate in session.scalars(
                select(CandidateModel).where(
                    CandidateModel.run_id == run_id,
                    CandidateModel.host.in_(requested_hosts),
                )
            )
        }
        missing = [host for host in requested_hosts if host not in candidates_by_host]
        if missing:
            raise InputError(f"candidato não encontrado na run {run_id}: {missing[0]}")
        candidates = [candidates_by_host[host] for host in requested_hosts]

    opposite = (
        CandidateStatus.REJECTED if status is CandidateStatus.APPROVED else CandidateStatus.APPROVED
    )
    for candidate in candidates:
        if candidate.status == opposite.value:
            raise InputError(
                f"candidato {candidate.host} já está {opposite.value}; estado terminal preservado"
            )
        if candidate.status not in (status.value, CandidateStatus.PENDING.value):
            raise InputError(f"estado inválido para o candidato {candidate.host}")

    changed = 0
    unchanged = 0
    now = datetime.now(UTC)
    for candidate in candidates:
        if candidate.status == status.value:
            unchanged += 1
            continue
        candidate.status = status.value
        if status is CandidateStatus.APPROVED:
            candidate.approved_at = now
        changed += 1

    session.commit()
    return CandidateTransitionResult(changed=changed, unchanged=unchanged)


def approve_candidates(
    run_id: int,
    session: Session,
    *,
    hosts: Sequence[str] | None = None,
    approve_all: bool = False,
) -> CandidateTransitionResult:
    return _transition_candidates(
        run_id,
        session,
        status=CandidateStatus.APPROVED,
        hosts=hosts,
        all_pending=approve_all,
    )


def reject_candidates(
    run_id: int,
    session: Session,
    *,
    hosts: Sequence[str],
) -> CandidateTransitionResult:
    return _transition_candidates(
        run_id,
        session,
        status=CandidateStatus.REJECTED,
        hosts=hosts,
    )


def export_assets(
    run_id: int,
    session: Session,
    *,
    runs_path: Path = DEFAULT_RUNS_PATH,
) -> AssetExportResult:
    """Sobrescreve deterministicamente apenas o assets.jsonl da run informada."""
    _require_run(run_id, session)
    patterns = _scope_patterns(session)
    approved_hosts = {
        candidate.host
        for candidate in session.scalars(
            select(CandidateModel).where(
                CandidateModel.run_id == run_id,
                CandidateModel.status == CandidateStatus.APPROVED.value,
            )
        )
        if _is_safely_in_scope(candidate.host, patterns)
    }
    content = "".join(
        f"{json.dumps({'domain': host}, ensure_ascii=True, separators=(',', ':'))}\n"
        for host in sorted(approved_hosts)
    )
    output_path = runs_path / str(run_id) / "assets.jsonl"
    _write_atomic(output_path, content, "assets.jsonl")
    return AssetExportResult(exported=len(approved_hosts), path=output_path)


def sanitize_run(run_id: int, session: Session) -> SanitizeResult:
    run = _require_run(run_id, session)

    patterns = _scope_patterns(session)
    approved_hosts = {
        host
        for host in session.scalars(
            select(CandidateModel.host).where(
                CandidateModel.run_id == run_id,
                CandidateModel.status == CandidateStatus.APPROVED.value,
            )
        )
        if _is_safely_in_scope(host, patterns)
    }
    existing_domains = set(
        session.scalars(select(AssetModel.domain).where(AssetModel.run_id == run_id))
    )
    session.add_all(
        AssetModel(run_id=run_id, domain=host, status=AssetStatus.INGESTED.value)
        for host in approved_hosts
        if host not in existing_domains
    )
    session.flush()

    assets = list(
        session.scalars(
            select(AssetModel)
            .where(
                AssetModel.run_id == run_id,
                AssetModel.domain.in_(approved_hosts),
            )
            .order_by(AssetModel.id)
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
            # O conjunto elegível deriva exclusivamente de candidatos aprovados.
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


def _stable_asset_id(host: str) -> str:
    return f"asset-{hashlib.sha256(host.encode('ascii')).hexdigest()}"


def _contains_ip_address(value: str) -> bool:
    for match in _IP_CANDIDATE_PATTERN.finditer(value):
        candidate = match.group().strip("[]().,;")
        if not candidate or ("." not in candidate and ":" not in candidate):
            continue
        candidate = candidate.split("%", maxsplit=1)[0]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


def _forbidden_reason(value: str) -> str | None:
    checks = (
        (_URL_PATTERN, "URL completa"),
        (_QUERY_PATTERN, "query string"),
        (_PORT_PATTERN, "porta"),
        (_RAW_HTTP_PATTERN, "header ou conteúdo HTTP bruto"),
        (_SENSITIVE_PATTERN, "dado sensível"),
        (_SECRET_VALUE_PATTERN, "token ou chave"),
        (_EMAIL_PATTERN, "PII"),
        (_PHONE_PATTERN, "PII"),
        (_CPF_PATTERN, "PII"),
    )
    for pattern, reason in checks:
        if pattern.search(value):
            return reason
    if _contains_ip_address(value):
        return "endereço IP"
    return None


def _iter_string_values(value: Any, path: str = "$"):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_string_values(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_string_values(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyViolation("policy gate recusou chave JSON duplicada")
        result[key] = value
    return result


def enforce_triage_policy(serialized: str) -> None:
    """Valida o JSON final por estrutura allowlist e padrões proibidos."""
    try:
        payload = json.loads(serialized, object_pairs_hook=_object_without_duplicate_keys)
    except PolicyViolation:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise PolicyViolation("policy gate recusou JSON inválido") from exc

    try:
        request = TriageRequest.model_validate(payload)
    except (ValidationError, ValueError) as exc:
        raise PolicyViolation("policy gate recusou campos ou tipos não permitidos") from exc

    if payload != request.model_dump(mode="json"):
        raise PolicyViolation("policy gate recusou payload não canônico")

    for field_path, value in _iter_string_values(payload):
        reason = _forbidden_reason(value)
        if reason is not None:
            raise PolicyViolation(f"policy gate recusou {reason} no campo permitido {field_path}")


def _serialize_triage_request(request: TriageRequest) -> str:
    return (
        json.dumps(
            request.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _write_triage_batches(
    run_id: int,
    serialized_batches: list[tuple[str, str]],
    runs_path: Path,
) -> tuple[Path, ...]:
    output_dir = runs_path / str(run_id) / "llm"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        for stale_path in output_dir.glob("triage-input-*.json"):
            stale_path.unlink()

        written_paths: list[Path] = []
        for batch_id, serialized in serialized_batches:
            output_path = output_dir / f"triage-input-{batch_id}.json"
            temporary_path = output_path.with_suffix(".json.tmp")
            try:
                temporary_path.write_text(serialized, encoding="utf-8")
                temporary_path.replace(output_path)
            finally:
                temporary_path.unlink(missing_ok=True)
            written_paths.append(output_path)
    except OSError as exc:
        raise InputError(f"não foi possível gravar os lotes de triagem: {exc}") from exc
    return tuple(written_paths)


def prepare_triage(
    run_id: int,
    session: Session,
    *,
    batch_size: int = DEFAULT_TRIAGE_BATCH_SIZE,
    runs_path: Path = DEFAULT_RUNS_PATH,
) -> TriagePreparationResult:
    """Prepara lotes locais e determinísticos; não contém qualquer acesso à rede."""
    if isinstance(batch_size, bool) or not isinstance(batch_size, int):
        raise InputError("o tamanho do lote deve ser um número inteiro")
    if not 1 <= batch_size <= MAX_TRIAGE_BATCH_SIZE:
        raise InputError(f"o tamanho do lote deve estar entre 1 e {MAX_TRIAGE_BATCH_SIZE}")

    run = session.get(RunModel, run_id)
    if run is None:
        raise InputError(f"run {run_id} não encontrada")

    assets = list(
        session.scalars(
            select(AssetModel)
            .join(QueueItemModel, QueueItemModel.asset_id == AssetModel.id)
            .join(
                CandidateModel,
                and_(
                    CandidateModel.run_id == AssetModel.run_id,
                    CandidateModel.host == AssetModel.domain,
                ),
            )
            .where(
                QueueItemModel.run_id == run_id,
                QueueItemModel.status == QueueStatus.PENDING.value,
                AssetModel.run_id == run_id,
                AssetModel.status == AssetStatus.SANITIZED.value,
                AssetModel.sanitized_at.is_not(None),
                CandidateModel.status == CandidateStatus.APPROVED.value,
            )
        ).all()
    )
    patterns = _scope_patterns(session)
    assets = [asset for asset in assets if _is_safely_in_scope(asset.domain, patterns)]
    if not assets:
        raise InputError(f"run {run_id} não possui itens sanitizados e pendentes")

    try:
        triage_assets = [
            TriageAsset(
                asset_id=_stable_asset_id(asset.domain),
                host=asset.domain,
                status=None,
                title=None,
                technologies=[],
                paths=[],
            )
            for asset in assets
        ]
    except (ValidationError, ValueError) as exc:
        raise PolicyViolation("policy gate recusou um asset persistido") from exc
    triage_assets.sort(key=lambda asset: asset.asset_id)

    asset_ids = [asset.asset_id for asset in triage_assets]
    if len(asset_ids) != len(set(asset_ids)):
        raise PolicyViolation("policy gate recusou IDs de asset duplicados")

    serialized_batches: list[tuple[str, str]] = []
    for offset in range(0, len(triage_assets), batch_size):
        batch_id = f"{offset // batch_size + 1:04d}"
        batch = TriageBatch(
            batch_id=batch_id,
            items=triage_assets[offset : offset + batch_size],
        )
        request = TriageRequest.model_validate(batch.model_dump(mode="json"))
        serialized = _serialize_triage_request(request)
        enforce_triage_policy(serialized)
        serialized_batches.append((batch_id, serialized))

    paths = _write_triage_batches(run_id, serialized_batches, runs_path)
    return TriagePreparationResult(
        item_count=len(triage_assets),
        batch_count=len(serialized_batches),
        paths=paths,
    )
