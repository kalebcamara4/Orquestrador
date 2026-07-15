"""Políticas de execução tipadas, versionadas e associadas a programas."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from bb_orchestrator.models import (
    ExecutionPolicySnapshotModel,
    ProgramModel,
    ProgramPolicyModel,
    RunModel,
)


class PolicyError(ValueError):
    """Indica uma seleção de política inválida ou inconsistente."""


class PolicyName(StrEnum):
    CONSERVATIVE = "conservative"


class _PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class DnsParameters(_PolicyModel):
    threads: int = Field(ge=1)
    rate_limit_per_second: int = Field(ge=1)
    process_timeout_seconds: int = Field(ge=1)


class HttpParameters(_PolicyModel):
    threads: int = Field(ge=1)
    rate_limit_per_second: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)
    retries: int = Field(ge=0)
    process_timeout_seconds: int = Field(ge=1)


class PortParameters(_PolicyModel):
    workers: int = Field(ge=1)
    rate_limit_per_second: int = Field(ge=1)
    timeout_milliseconds: int = Field(ge=1)
    retries: int = Field(ge=0)
    ports: tuple[Literal[80], Literal[443], Literal[8080], Literal[8443]]
    scan_type: Literal["tcp_connect"]
    process_timeout_seconds: int = Field(ge=1)


class KatanaParameters(_PolicyModel):
    mode: Literal["standard"]
    headless: Literal[False]
    javascript: Literal[False]
    concurrency: int = Field(ge=1)
    parallelism: int = Field(ge=1)
    rate_limit_per_second: int = Field(ge=1)
    depth: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)
    retries: int = Field(ge=0)
    max_duration_seconds: int = Field(ge=1)
    max_response_read_bytes: int = Field(ge=1)
    max_paths_per_host: int = Field(ge=1)
    scope: Literal["fqdn"]
    output_field: Literal["path"]
    methods: tuple[Literal["GET"]]


class ExecutionPolicy(_PolicyModel):
    name: PolicyName
    version: str = Field(pattern=r"^[1-9][0-9]*(?:\.[0-9]+)*$")
    dns: DnsParameters
    http: HttpParameters
    ports: PortParameters
    katana: KatanaParameters


class PolicySnapshot(_PolicyModel):
    name: PolicyName
    version: str
    parameters: dict[str, object]


CONSERVATIVE_POLICY = ExecutionPolicy(
    name=PolicyName.CONSERVATIVE,
    version="2",
    dns=DnsParameters(
        threads=5,
        rate_limit_per_second=5,
        process_timeout_seconds=300,
    ),
    http=HttpParameters(
        threads=2,
        rate_limit_per_second=2,
        timeout_seconds=10,
        retries=0,
        process_timeout_seconds=300,
    ),
    ports=PortParameters(
        workers=2,
        rate_limit_per_second=4,
        timeout_milliseconds=1000,
        retries=0,
        ports=(80, 443, 8080, 8443),
        scan_type="tcp_connect",
        process_timeout_seconds=300,
    ),
    katana=KatanaParameters(
        mode="standard",
        headless=False,
        javascript=False,
        concurrency=1,
        parallelism=1,
        rate_limit_per_second=1,
        depth=1,
        timeout_seconds=10,
        retries=0,
        max_duration_seconds=60,
        max_response_read_bytes=1024 * 1024,
        max_paths_per_host=100,
        scope="fqdn",
        output_field="path",
        methods=("GET",),
    ),
)

DEFAULT_POLICY_NAME = PolicyName.CONSERVATIVE
POLICY_REGISTRY: dict[PolicyName, ExecutionPolicy] = {
    PolicyName.CONSERVATIVE: CONSERVATIVE_POLICY,
}


def available_policies() -> tuple[ExecutionPolicy, ...]:
    return tuple(POLICY_REGISTRY[name] for name in PolicyName)


def _registered_policy(name: str | PolicyName) -> ExecutionPolicy:
    try:
        policy_name = PolicyName(name)
        return POLICY_REGISTRY[policy_name]
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyError(f"política não disponível: {name}") from exc


def get_program_policy(session: Session, *, program_slug: str) -> ExecutionPolicy:
    if session.scalar(select(ProgramModel.id).where(ProgramModel.slug == program_slug)) is None:
        raise PolicyError(f"programa não encontrado: {program_slug}")
    selection = session.get(ProgramPolicyModel, program_slug)
    if selection is None:
        return POLICY_REGISTRY[DEFAULT_POLICY_NAME]
    return _registered_policy(selection.policy_name)


def set_program_policy(
    session: Session,
    *,
    program_slug: str,
    name: str | PolicyName,
) -> ExecutionPolicy:
    policy = _registered_policy(name)
    if session.scalar(select(ProgramModel.id).where(ProgramModel.slug == program_slug)) is None:
        raise PolicyError(f"programa não encontrado: {program_slug}")
    selection = session.get(ProgramPolicyModel, program_slug)
    if selection is None:
        selection = ProgramPolicyModel(program_slug=program_slug, policy_name=policy.name.value)
        session.add(selection)
    else:
        selection.policy_name = policy.name.value
    session.commit()
    return policy


def policy_snapshot(
    policy: ExecutionPolicy,
    step: Literal["dns", "http", "ports", "katana"],
) -> PolicySnapshot:
    parameters = getattr(policy, step)
    return PolicySnapshot(
        name=policy.name,
        version=policy.version,
        parameters=parameters.model_dump(mode="json"),
    )


def persist_policy_snapshot(
    session: Session,
    *,
    run_id: int,
    program_slug: str,
    step: Literal["dns", "http", "ports", "katana"],
    policy: ExecutionPolicy,
) -> ExecutionPolicySnapshotModel:
    if session.get(RunModel, run_id) is None:
        raise PolicyError(f"run {run_id} não encontrada")
    if session.scalar(select(ProgramModel.id).where(ProgramModel.slug == program_slug)) is None:
        raise PolicyError(f"programa não encontrado: {program_slug}")
    snapshot = policy_snapshot(policy, step)
    model = ExecutionPolicySnapshotModel(
        run_id=run_id,
        program_slug=program_slug,
        step=step,
        snapshot=snapshot.model_dump(mode="json"),
    )
    session.add(model)
    session.flush()
    return model
