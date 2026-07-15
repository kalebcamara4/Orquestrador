"""Casos de uso seguros, sem requests aos hosts descobertos."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from bb_orchestrator.adapters import DEFAULT_SUBPROCESS_ADAPTER, SubprocessAdapter
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
    DnsVerificationAttemptModel,
    HttpVerificationAttemptModel,
    PortObservationModel,
    QueueItemModel,
    RunModel,
    ScopeRuleModel,
)
from bb_orchestrator.policies import (
    DnsParameters,
    ExecutionPolicy,
    HttpParameters,
    PolicyError,
    PortParameters,
    get_program_policy,
    persist_policy_snapshot,
)
from bb_orchestrator.schemas import (
    AssetStatus,
    CandidateStatus,
    DnsStatus,
    HttpReachability,
    IngestRecord,
    QueueStatus,
    RunStatus,
    ScopeRule,
    SurfaceRecord,
    SurfaceStage,
    TriageAsset,
    TriageBatch,
    TriageRequest,
)

DEFAULT_TRIAGE_BATCH_SIZE = 10
MAX_TRIAGE_BATCH_SIZE = 20
DEFAULT_RUNS_PATH = Path("runs")
SUBFINDER_TIMEOUT_SECONDS = 300
HTTP_TITLE_MAX_LENGTH = 200
HTTP_TECHNOLOGY_MAX_LENGTH = 80
HTTP_TECHNOLOGIES_MAX_COUNT = 20

_HTTPX_BLOCKED_ENVIRONMENT = frozenset(
    {
        "ALL_PROXY",
        "ENABLE_CLOUD_UPLOAD",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    }
)

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
_DNSX_VERSION_PATTERN = re.compile(r"(?i)\bversion\s*:?\s*(v?\d+\.\d+\.\d+)\b")
_NAABU_VERSION_PATTERN = re.compile(
    r"(?i)(?:\bversion\b[^0-9v]{0,20}|\bnaabu\s+)"
    r"(v?\d+\.\d+(?:\.\d+)?)(?!\.)\b"
)

_NAABU_BLOCKED_ENVIRONMENT = frozenset(
    {
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    }
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


@dataclass(frozen=True)
class DnsVerificationPlan:
    host_count: int
    threads: int
    rate_limit: int
    command: tuple[str, ...]
    input_path: Path
    resolved_path: Path
    policy_name: str
    policy_version: str
    parameters: DnsParameters


@dataclass(frozen=True)
class DnsVerificationResult:
    attempted: int
    resolved: int
    unresolved: int
    input_path: Path
    resolved_path: Path
    dnsx_version: str | None


@dataclass(frozen=True)
class HttpVerificationPlan:
    host_count: int
    threads: int
    rate_limit: int
    request_timeout: int
    attempts: int
    command: tuple[str, ...]
    input_path: Path
    policy_name: str
    policy_version: str
    parameters: HttpParameters


@dataclass(frozen=True)
class HttpVerificationResult:
    attempted: int
    reachable: int
    unreachable: int
    input_path: Path


@dataclass(frozen=True)
class PortVerificationPlan:
    host_count: int
    workers: int
    rate_limit: int
    timeout_milliseconds: int
    retries: int
    ports: tuple[int, ...]
    scan_type: str
    command: tuple[str, ...]
    input_path: Path
    output_path: Path
    policy_name: str
    policy_version: str
    parameters: PortParameters


@dataclass(frozen=True)
class PortVerificationResult:
    attempted: int
    open_ports: int
    input_path: Path
    output_path: Path


@dataclass(frozen=True)
class SurfaceExportResult:
    exported: int
    path: Path


@dataclass(frozen=True)
class OpenPort:
    host: str
    port: int
    status: str


@dataclass(frozen=True)
class _ParsedOpenPort:
    host: str
    port: int


@dataclass(frozen=True)
class AssetDnsState:
    host: str
    approval_status: str
    dns_status: str
    http_reachability: str
    http_status_code: int | None


@dataclass(frozen=True)
class _HttpObservation:
    reachability: str
    status_code: int | None
    title: str | None
    technologies: list[str] | None


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


def _approved_dns_candidates(run_id: int, session: Session) -> list[CandidateModel]:
    _require_run(run_id, session)
    patterns = _scope_patterns(session)
    candidates = list(
        session.scalars(
            select(CandidateModel)
            .where(
                CandidateModel.run_id == run_id,
                CandidateModel.status == CandidateStatus.APPROVED.value,
            )
            .order_by(CandidateModel.host, CandidateModel.id)
        )
    )
    approved = [
        candidate for candidate in candidates if _is_safely_in_scope(candidate.host, patterns)
    ]
    if not approved:
        raise InputError(f"run {run_id} não possui candidatos aprovados em escopo")
    return approved


def _dns_verification_plan(
    run_id: int,
    candidates: Sequence[CandidateModel],
    runs_path: Path,
    policy: ExecutionPolicy,
) -> DnsVerificationPlan:
    parameters = policy.dns
    dns_path = runs_path / str(run_id) / "dns"
    input_path = dns_path / "input-hosts.txt"
    resolved_path = dns_path / "resolved-hosts.txt"
    command = (
        "dnsx",
        "-l",
        str(input_path),
        "-silent",
        "-t",
        str(parameters.threads),
        "-rl",
        str(parameters.rate_limit_per_second),
    )
    return DnsVerificationPlan(
        host_count=len(candidates),
        threads=parameters.threads,
        rate_limit=parameters.rate_limit_per_second,
        command=command,
        input_path=input_path,
        resolved_path=resolved_path,
        policy_name=policy.name.value,
        policy_version=policy.version,
        parameters=parameters,
    )


def plan_dns_verification(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
    runs_path: Path = DEFAULT_RUNS_PATH,
) -> DnsVerificationPlan:
    """Planeja a execução sem consultar binários, executar processos ou gravar arquivos."""
    candidates = _approved_dns_candidates(run_id, session)
    try:
        policy = get_program_policy(session, program_slug=program_slug)
    except PolicyError as exc:
        raise InputError(str(exc)) from exc
    return _dns_verification_plan(run_id, candidates, runs_path, policy)


def _resolved_hosts_from_dnsx(stdout: str, approved_hosts: set[str]) -> list[str]:
    resolved: set[str] = set()
    for raw_line in stdout.splitlines():
        try:
            host = normalize_domain(raw_line)
        except (InvalidDomain, ValueError):
            continue
        if host in approved_hosts:
            resolved.add(host)
    return sorted(resolved)


def _dnsx_version(stderr: str) -> str | None:
    match = _DNSX_VERSION_PATTERN.search(stderr)
    return match.group(1) if match is not None else None


def verify_dns(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
    runs_path: Path = DEFAULT_RUNS_PATH,
) -> DnsVerificationResult:
    """Executa somente dnsx e persiste uma tentativa mínima por candidato aprovado."""
    candidates = _approved_dns_candidates(run_id, session)
    try:
        policy = get_program_policy(session, program_slug=program_slug)
    except PolicyError as exc:
        raise InputError(str(exc)) from exc
    plan = _dns_verification_plan(run_id, candidates, runs_path, policy)
    dnsx_path = shutil.which("dnsx")
    if dnsx_path is None:
        raise InputError(
            "dnsx não está instalado; instale-o manualmente e adicione o binário ao PATH"
        )

    input_content = "".join(f"{candidate.host}\n" for candidate in candidates)
    _write_atomic(plan.input_path, input_content, "a lista de entrada do dnsx")

    started_at = datetime.now(UTC)
    attempts = [
        DnsVerificationAttemptModel(
            run_id=run_id,
            candidate_id=candidate.id,
            program_slug=program_slug,
            host=candidate.host,
            status=DnsStatus.PENDING.value,
            verified_at=started_at,
            dnsx_version=None,
        )
        for candidate in candidates
    ]
    session.add_all(attempts)
    try:
        persist_policy_snapshot(
            session,
            run_id=run_id,
            program_slug=program_slug,
            step="dns",
            policy=policy,
        )
    except PolicyError as exc:
        session.rollback()
        raise InputError(str(exc)) from exc
    session.commit()

    command = [dnsx_path, *plan.command[1:]]
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
            timeout=plan.parameters.process_timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InputError("não foi possível executar o dnsx") from exc

    if completed.returncode != 0:
        raise InputError(f"dnsx terminou com código {completed.returncode}")

    approved_hosts = {candidate.host for candidate in candidates}
    resolved_hosts = _resolved_hosts_from_dnsx(completed.stdout or "", approved_hosts)
    resolved_set = set(resolved_hosts)
    resolved_content = "".join(f"{host}\n" for host in resolved_hosts)
    _write_atomic(plan.resolved_path, resolved_content, "a saída segura do dnsx")

    checked_at = datetime.now(UTC)
    version = _dnsx_version(completed.stderr or "")
    for attempt in attempts:
        attempt.status = (
            DnsStatus.RESOLVED.value if attempt.host in resolved_set else DnsStatus.UNRESOLVED.value
        )
        attempt.verified_at = checked_at
        attempt.dnsx_version = version
    session.commit()

    return DnsVerificationResult(
        attempted=len(attempts),
        resolved=len(resolved_hosts),
        unresolved=len(attempts) - len(resolved_hosts),
        input_path=plan.input_path,
        resolved_path=plan.resolved_path,
        dnsx_version=version,
    )


def _latest_dns_attempts(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
) -> dict[int, DnsVerificationAttemptModel]:
    latest_attempt_ids = (
        select(func.max(DnsVerificationAttemptModel.id))
        .where(
            DnsVerificationAttemptModel.run_id == run_id,
            DnsVerificationAttemptModel.program_slug == program_slug,
        )
        .group_by(DnsVerificationAttemptModel.candidate_id)
    )
    return {
        attempt.candidate_id: attempt
        for attempt in session.scalars(
            select(DnsVerificationAttemptModel).where(
                DnsVerificationAttemptModel.id.in_(latest_attempt_ids)
            )
        )
    }


def _approved_resolved_http_candidates(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
) -> list[CandidateModel]:
    _require_run(run_id, session)
    patterns = _scope_patterns(session)
    latest_dns = _latest_dns_attempts(run_id, session, program_slug=program_slug)
    candidates = list(
        session.scalars(
            select(CandidateModel)
            .where(
                CandidateModel.run_id == run_id,
                CandidateModel.status == CandidateStatus.APPROVED.value,
            )
            .order_by(CandidateModel.host, CandidateModel.id)
        )
    )
    eligible = [
        candidate
        for candidate in candidates
        if _is_safely_in_scope(candidate.host, patterns)
        and candidate.id in latest_dns
        and latest_dns[candidate.id].status == DnsStatus.RESOLVED.value
    ]
    if not eligible:
        raise InputError(f"run {run_id} não possui candidatos aprovados com último DNS resolved")
    return eligible


def _http_verification_plan(
    run_id: int,
    candidates: Sequence[CandidateModel],
    runs_path: Path,
    policy: ExecutionPolicy,
) -> HttpVerificationPlan:
    parameters = policy.http
    input_path = runs_path / str(run_id) / "http" / "input-hosts.txt"
    command = (
        "httpx",
        "-l",
        str(input_path),
        "-json",
        "-silent",
        "-probe",
        "-sc",
        "-title",
        "-td",
        "-ob",
        "-t",
        str(parameters.threads),
        "-rl",
        str(parameters.rate_limit_per_second),
        "-timeout",
        str(parameters.timeout_seconds),
        "-retries",
        str(parameters.retries),
        "-path",
        "/",
        "-config",
        "/dev/null",
        "-duc",
        "-no-stdin",
    )
    return HttpVerificationPlan(
        host_count=len(candidates),
        threads=parameters.threads,
        rate_limit=parameters.rate_limit_per_second,
        request_timeout=parameters.timeout_seconds,
        attempts=parameters.retries + 1,
        command=command,
        input_path=input_path,
        policy_name=policy.name.value,
        policy_version=policy.version,
        parameters=parameters,
    )


def plan_http_verification(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
    runs_path: Path = DEFAULT_RUNS_PATH,
) -> HttpVerificationPlan:
    """Planeja o httpx sem consultar binários, executar processos ou gravar arquivos."""
    candidates = _approved_resolved_http_candidates(
        run_id,
        session,
        program_slug=program_slug,
    )
    try:
        policy = get_program_policy(session, program_slug=program_slug)
    except PolicyError as exc:
        raise InputError(str(exc)) from exc
    return _http_verification_plan(run_id, candidates, runs_path, policy)


def _sanitize_http_text(value: Any, *, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    without_controls = "".join(
        character for character in value if not unicodedata.category(character).startswith("C")
    )
    sanitized = " ".join(without_controls.split())
    if not sanitized or len(sanitized) > max_length:
        return None
    if _forbidden_reason(sanitized) is not None:
        return None
    return sanitized


def _sanitize_http_technologies(value: Any) -> list[str] | None:
    if not isinstance(value, list) or not value or len(value) > HTTP_TECHNOLOGIES_MAX_COUNT:
        return None
    sanitized: list[str] = []
    seen: set[str] = set()
    for technology in value:
        item = _sanitize_http_text(technology, max_length=HTTP_TECHNOLOGY_MAX_LENGTH)
        if item is None:
            return None
        normalized_item = item.casefold()
        if normalized_item not in seen:
            seen.add(normalized_item)
            sanitized.append(item)
    return sorted(sanitized, key=str.casefold) or None


def _http_observations(stdout: str, allowed_hosts: set[str]) -> dict[str, _HttpObservation]:
    observations = {
        host: _HttpObservation(
            reachability=HttpReachability.UNREACHABLE.value,
            status_code=None,
            title=None,
            technologies=None,
        )
        for host in allowed_hosts
    }
    for raw_line in stdout.splitlines():
        try:
            payload = json.loads(raw_line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        try:
            host = normalize_domain(payload.get("input"))
        except (InvalidDomain, TypeError, ValueError):
            continue
        if host not in allowed_hosts:
            continue
        status_code = payload.get("status_code")
        if (
            isinstance(status_code, bool)
            or not isinstance(status_code, int)
            or not 100 <= status_code <= 599
            or observations[host].reachability == HttpReachability.REACHABLE.value
        ):
            continue
        observations[host] = _HttpObservation(
            reachability=HttpReachability.REACHABLE.value,
            status_code=status_code,
            title=_sanitize_http_text(payload.get("title"), max_length=HTTP_TITLE_MAX_LENGTH),
            technologies=_sanitize_http_technologies(payload.get("tech")),
        )
    return observations


def _httpx_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if name.upper() not in _HTTPX_BLOCKED_ENVIRONMENT
        and not name.upper().startswith(("HTTPX_", "PDCP_"))
    }


def verify_http(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
    runs_path: Path = DEFAULT_RUNS_PATH,
) -> HttpVerificationResult:
    """Executa somente httpx e persiste metadados HTTP mínimos e sanitizados."""
    candidates = _approved_resolved_http_candidates(
        run_id,
        session,
        program_slug=program_slug,
    )
    try:
        policy = get_program_policy(session, program_slug=program_slug)
    except PolicyError as exc:
        raise InputError(str(exc)) from exc
    plan = _http_verification_plan(run_id, candidates, runs_path, policy)
    httpx_path = shutil.which("httpx")
    if httpx_path is None:
        raise InputError(
            "httpx não está instalado; instale-o manualmente e adicione o binário ao PATH"
        )

    input_content = "".join(f"{candidate.host}\n" for candidate in candidates)
    _write_atomic(plan.input_path, input_content, "a lista de entrada do httpx")

    started_at = datetime.now(UTC)
    attempts = [
        HttpVerificationAttemptModel(
            run_id=run_id,
            candidate_id=candidate.id,
            program_slug=program_slug,
            host=candidate.host,
            reachability=HttpReachability.PENDING.value,
            status_code=None,
            title=None,
            technologies=None,
            verified_at=started_at,
        )
        for candidate in candidates
    ]
    session.add_all(attempts)
    try:
        persist_policy_snapshot(
            session,
            run_id=run_id,
            program_slug=program_slug,
            step="http",
            policy=policy,
        )
    except PolicyError as exc:
        session.rollback()
        raise InputError(str(exc)) from exc
    session.commit()

    command = [httpx_path, *plan.command[1:]]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            encoding="utf-8",
            env=_httpx_environment(),
            errors="replace",
            stdin=subprocess.DEVNULL,
            shell=False,
            text=True,
            timeout=plan.parameters.process_timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InputError("não foi possível executar o httpx") from exc

    if completed.returncode != 0:
        raise InputError(f"httpx terminou com código {completed.returncode}")

    observations = _http_observations(
        completed.stdout or "",
        {candidate.host for candidate in candidates},
    )
    checked_at = datetime.now(UTC)
    for attempt in attempts:
        observation = observations[attempt.host]
        attempt.reachability = observation.reachability
        attempt.status_code = observation.status_code
        attempt.title = observation.title
        attempt.technologies = observation.technologies
        attempt.verified_at = checked_at
    session.commit()

    reachable = sum(
        attempt.reachability == HttpReachability.REACHABLE.value for attempt in attempts
    )
    return HttpVerificationResult(
        attempted=len(attempts),
        reachable=reachable,
        unreachable=len(attempts) - reachable,
        input_path=plan.input_path,
    )


def _latest_http_attempts(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
) -> dict[int, HttpVerificationAttemptModel]:
    latest_attempt_ids = (
        select(func.max(HttpVerificationAttemptModel.id))
        .where(
            HttpVerificationAttemptModel.run_id == run_id,
            HttpVerificationAttemptModel.program_slug == program_slug,
        )
        .group_by(HttpVerificationAttemptModel.candidate_id)
    )
    return {
        attempt.candidate_id: attempt
        for attempt in session.scalars(
            select(HttpVerificationAttemptModel).where(
                HttpVerificationAttemptModel.id.in_(latest_attempt_ids)
            )
        )
    }


def _approved_resolved_reachable_port_candidates(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
) -> list[CandidateModel]:
    _require_run(run_id, session)
    patterns = _scope_patterns(session)
    latest_dns = _latest_dns_attempts(run_id, session, program_slug=program_slug)
    latest_http = _latest_http_attempts(run_id, session, program_slug=program_slug)
    candidates = list(
        session.scalars(
            select(CandidateModel)
            .where(
                CandidateModel.run_id == run_id,
                CandidateModel.status == CandidateStatus.APPROVED.value,
            )
            .order_by(CandidateModel.host, CandidateModel.id)
        )
    )
    eligible = [
        candidate
        for candidate in candidates
        if _is_safely_in_scope(candidate.host, patterns)
        and candidate.id in latest_dns
        and latest_dns[candidate.id].status == DnsStatus.RESOLVED.value
        and candidate.id in latest_http
        and latest_http[candidate.id].reachability == HttpReachability.REACHABLE.value
    ]
    if not eligible:
        raise InputError(
            f"run {run_id} não possui candidatos approved, DNS resolved e HTTP reachable"
        )
    return eligible


def _port_verification_plan(
    run_id: int,
    candidates: Sequence[CandidateModel],
    runs_path: Path,
    policy: ExecutionPolicy,
) -> PortVerificationPlan:
    parameters = policy.ports
    ports_path = runs_path / str(run_id) / "ports"
    input_path = ports_path / "input-hosts.txt"
    output_path = ports_path / "ports.jsonl"
    command = (
        "naabu",
        "-l",
        str(input_path),
        "-p",
        ",".join(str(port) for port in parameters.ports),
        "-scan-type",
        "c",
        "-c",
        str(parameters.workers),
        "-rate",
        str(parameters.rate_limit_per_second),
        "-timeout",
        str(parameters.timeout_milliseconds),
        "-retries",
        str(parameters.retries),
        "-json",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-no-stdin",
        "-config",
        "/dev/null",
    )
    return PortVerificationPlan(
        host_count=len(candidates),
        workers=parameters.workers,
        rate_limit=parameters.rate_limit_per_second,
        timeout_milliseconds=parameters.timeout_milliseconds,
        retries=parameters.retries,
        ports=parameters.ports,
        scan_type=parameters.scan_type,
        command=command,
        input_path=input_path,
        output_path=output_path,
        policy_name=policy.name.value,
        policy_version=policy.version,
        parameters=parameters,
    )


def plan_port_verification(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
    runs_path: Path = DEFAULT_RUNS_PATH,
) -> PortVerificationPlan:
    """Planeja o Naabu sem consultar PATH, criar arquivos, executar processo ou usar rede."""
    candidates = _approved_resolved_reachable_port_candidates(
        run_id,
        session,
        program_slug=program_slug,
    )
    try:
        policy = get_program_policy(session, program_slug=program_slug)
    except PolicyError as exc:
        raise InputError(str(exc)) from exc
    return _port_verification_plan(run_id, candidates, runs_path, policy)


def _naabu_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if name.upper() not in _NAABU_BLOCKED_ENVIRONMENT
        and name.upper() != "ENABLE_CLOUD_UPLOAD"
        and not name.upper().startswith(("NAABU_", "PDCP_"))
    }


def _safe_subprocess_error(stderr: str, *, tool: str, returncode: int) -> str:
    without_controls = "".join(
        character
        for character in stderr
        if character in "\n\t" or not unicodedata.category(character).startswith("C")
    )
    lines = [" ".join(line.split()) for line in without_controls.splitlines() if line.strip()]
    detail = lines[0][:160] if lines else "falha reportada pela ferramenta"
    if _forbidden_reason(detail) is not None:
        detail = "falha reportada pela ferramenta"
    return f"{tool} falhou (código {returncode}): {detail}"


def _naabu_version(
    executable: str,
    adapter: SubprocessAdapter,
    *,
    environment: dict[str, str],
    timeout_seconds: int,
) -> str:
    command = (executable, "-version", "-disable-update-check", "-no-color")
    try:
        completed = adapter.run(
            command,
            timeout_seconds=timeout_seconds,
            environment=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InputError("não foi possível consultar a versão do naabu") from exc
    if completed.returncode != 0:
        raise InputError(
            _safe_subprocess_error(
                completed.stderr or "",
                tool="naabu",
                returncode=completed.returncode,
            )
        )
    match = _NAABU_VERSION_PATTERN.search(f"{completed.stdout or ''}\n{completed.stderr or ''}")
    if match is None:
        raise InputError("naabu não informou uma versão válida")
    version = match.group(1).lower()
    if _contains_ip_address(version):
        raise InputError("naabu não informou uma versão válida")
    return version


def _parse_naabu_output(
    stdout: str,
    *,
    allowed_hosts: set[str],
    allowed_ports: set[int],
) -> list[_ParsedOpenPort]:
    observations: set[tuple[str, int]] = set()
    for raw_line in stdout.splitlines():
        try:
            payload = json.loads(raw_line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        try:
            host = normalize_domain(payload.get("host"))
        except (InvalidDomain, TypeError, ValueError):
            continue
        port = payload.get("port")
        if (
            host not in allowed_hosts
            or isinstance(port, bool)
            or not isinstance(port, int)
            or port not in allowed_ports
        ):
            continue
        observations.add((host, port))
    return [_ParsedOpenPort(host=host, port=port) for host, port in sorted(observations)]


def _port_jsonl_content(
    run_id: int,
    session: Session,
) -> str:
    records = session.scalars(
        select(PortObservationModel)
        .where(PortObservationModel.run_id == run_id)
        .order_by(PortObservationModel.host, PortObservationModel.port)
    )
    lines: list[str] = []
    for record in records:
        timestamp = record.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        payload = {
            "host": record.host,
            "port": record.port,
            "status": record.status,
            "timestamp": timestamp,
            "tool_version": record.tool_version,
            "run_id": record.run_id,
            "policy_snapshot_id": record.policy_snapshot_id,
        }
        lines.append(json.dumps(payload, ensure_ascii=True, separators=(",", ":")))
    return "".join(f"{line}\n" for line in lines)


def verify_ports(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
    runs_path: Path = DEFAULT_RUNS_PATH,
    adapter: SubprocessAdapter | None = None,
) -> PortVerificationResult:
    """Executa Naabu em TCP CONNECT e retém somente host e porta aberta permitidos."""
    adapter = adapter or DEFAULT_SUBPROCESS_ADAPTER
    candidates = _approved_resolved_reachable_port_candidates(
        run_id,
        session,
        program_slug=program_slug,
    )
    try:
        policy = get_program_policy(session, program_slug=program_slug)
    except PolicyError as exc:
        raise InputError(str(exc)) from exc
    plan = _port_verification_plan(run_id, candidates, runs_path, policy)
    executable = adapter.find_executable("naabu")
    if executable is None:
        raise InputError(
            "naabu não está instalado; instale-o manualmente e adicione o binário ao PATH"
        )

    environment = _naabu_environment()
    version = _naabu_version(
        executable,
        adapter,
        environment=environment,
        timeout_seconds=plan.parameters.process_timeout_seconds,
    )
    input_content = "".join(f"{candidate.host}\n" for candidate in candidates)
    _write_atomic(plan.input_path, input_content, "a lista de entrada do naabu")
    try:
        snapshot = persist_policy_snapshot(
            session,
            run_id=run_id,
            program_slug=program_slug,
            step="ports",
            policy=policy,
        )
    except PolicyError as exc:
        session.rollback()
        raise InputError(str(exc)) from exc
    session.commit()

    command = (executable, *plan.command[1:])
    try:
        completed = adapter.run(
            command,
            timeout_seconds=plan.parameters.process_timeout_seconds,
            environment=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InputError("não foi possível executar o naabu") from exc
    if completed.returncode != 0:
        raise InputError(
            _safe_subprocess_error(
                completed.stderr or "",
                tool="naabu",
                returncode=completed.returncode,
            )
        )

    parsed = _parse_naabu_output(
        completed.stdout or "",
        allowed_hosts={candidate.host for candidate in candidates},
        allowed_ports=set(plan.ports),
    )
    existing = {
        (record.host, record.port)
        for record in session.scalars(
            select(PortObservationModel).where(PortObservationModel.run_id == run_id)
        )
    }
    observed_at = datetime.now(UTC)
    session.add_all(
        PortObservationModel(
            run_id=run_id,
            host=observation.host,
            port=observation.port,
            status="open",
            observed_at=observed_at,
            tool_version=version,
            policy_snapshot_id=snapshot.id,
        )
        for observation in parsed
        if (observation.host, observation.port) not in existing
    )
    session.flush()
    try:
        _write_atomic(
            plan.output_path,
            _port_jsonl_content(run_id, session),
            "ports.jsonl",
        )
    except InputError:
        session.rollback()
        raise
    session.commit()
    return PortVerificationResult(
        attempted=len(candidates),
        open_ports=len(parsed),
        input_path=plan.input_path,
        output_path=plan.output_path,
    )


def list_open_ports(run_id: int, session: Session) -> list[OpenPort]:
    _require_run(run_id, session)
    return [
        OpenPort(host=record.host, port=record.port, status=record.status)
        for record in session.scalars(
            select(PortObservationModel)
            .where(PortObservationModel.run_id == run_id)
            .order_by(PortObservationModel.host, PortObservationModel.port)
        )
    ]


def _surface_stage(
    dns_status: str,
    http_reachability: str,
    open_ports: tuple[int, ...],
) -> SurfaceStage:
    if dns_status != DnsStatus.RESOLVED.value:
        return SurfaceStage.PENDING
    if http_reachability != HttpReachability.REACHABLE.value:
        return SurfaceStage.DNS_RESOLVED
    if open_ports:
        return SurfaceStage.PORTS_OBSERVED
    return SurfaceStage.HTTP_REACHABLE


def build_surface_map(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
) -> list[SurfaceRecord]:
    """Consolida somente dados locais, reduzidos e autorizados da run informada."""
    _require_run(run_id, session)
    candidates = list(
        session.scalars(
            select(CandidateModel)
            .where(CandidateModel.run_id == run_id)
            .order_by(CandidateModel.host, CandidateModel.id)
        )
    )
    latest_dns = _latest_dns_attempts(run_id, session, program_slug=program_slug)
    latest_http = _latest_http_attempts(run_id, session, program_slug=program_slug)
    ports_by_host: dict[str, set[int]] = {}
    candidate_hosts = {candidate.host for candidate in candidates}
    for observation in session.scalars(
        select(PortObservationModel)
        .where(
            PortObservationModel.run_id == run_id,
            PortObservationModel.status == "open",
        )
        .order_by(PortObservationModel.host, PortObservationModel.port)
    ):
        if observation.host in candidate_hosts:
            ports_by_host.setdefault(observation.host, set()).add(observation.port)

    surface: list[SurfaceRecord] = []
    for candidate in candidates:
        dns_status = DnsStatus.PENDING.value
        http_reachability = HttpReachability.PENDING.value
        status_code: int | None = None
        title: str | None = None
        technologies: tuple[str, ...] = ()
        open_ports: tuple[int, ...] = ()

        if candidate.status == CandidateStatus.APPROVED.value:
            dns_attempt = latest_dns.get(candidate.id)
            if dns_attempt is not None:
                dns_status = dns_attempt.status

            if dns_status == DnsStatus.RESOLVED.value:
                http_attempt = latest_http.get(candidate.id)
                if http_attempt is not None:
                    http_reachability = http_attempt.reachability

                if http_reachability == HttpReachability.REACHABLE.value:
                    observed_status_code = http_attempt.status_code
                    if (
                        not isinstance(observed_status_code, bool)
                        and isinstance(observed_status_code, int)
                        and 100 <= observed_status_code <= 599
                    ):
                        status_code = observed_status_code
                    title = _sanitize_http_text(
                        http_attempt.title,
                        max_length=HTTP_TITLE_MAX_LENGTH,
                    )
                    sanitized_technologies = _sanitize_http_technologies(http_attempt.technologies)
                    technologies = tuple(sanitized_technologies or ())
                    open_ports = tuple(sorted(ports_by_host.get(candidate.host, set())))

        surface.append(
            SurfaceRecord(
                host=candidate.host,
                approval_status=candidate.status,
                dns_status=dns_status,
                http_reachability=http_reachability,
                http_status_code=status_code,
                http_title=title,
                http_technologies=technologies,
                open_ports=open_ports,
                stage=_surface_stage(dns_status, http_reachability, open_ports),
            )
        )
    return surface


def export_surface_map(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
    runs_path: Path = DEFAULT_RUNS_PATH,
) -> SurfaceExportResult:
    """Exporta atomicamente a mesma projeção segura usada pela listagem local."""
    records = build_surface_map(run_id, session, program_slug=program_slug)
    content = "".join(
        json.dumps(
            record.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
        for record in records
    )
    output_path = runs_path / str(run_id) / "surface" / "surface.jsonl"
    _write_atomic(output_path, content, "surface.jsonl")
    return SurfaceExportResult(exported=len(records), path=output_path)


def list_assets_with_dns(
    run_id: int,
    session: Session,
    *,
    program_slug: str,
) -> list[AssetDnsState]:
    """Lista candidatos com os estados DNS e HTTP mais recentes, sem materializar assets."""
    _require_run(run_id, session)
    candidates = list(
        session.scalars(
            select(CandidateModel)
            .where(CandidateModel.run_id == run_id)
            .order_by(CandidateModel.host, CandidateModel.id)
        )
    )
    latest_dns = _latest_dns_attempts(run_id, session, program_slug=program_slug)
    latest_http = _latest_http_attempts(run_id, session, program_slug=program_slug)
    return [
        AssetDnsState(
            host=candidate.host,
            approval_status=candidate.status,
            dns_status=(
                latest_dns[candidate.id].status
                if candidate.id in latest_dns
                else DnsStatus.PENDING.value
            ),
            http_reachability=(
                latest_http[candidate.id].reachability
                if candidate.id in latest_http
                else HttpReachability.PENDING.value
            ),
            http_status_code=(
                latest_http[candidate.id].status_code if candidate.id in latest_http else None
            ),
        )
        for candidate in candidates
    ]


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
