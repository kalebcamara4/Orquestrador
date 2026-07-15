"""Políticas locais e versionadas para sinais gerais de fluxo."""

from __future__ import annotations

import json
import posixpath
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError, field_validator

from bb_orchestrator.triage_selection import RouteCategory, classify_triage_path

FLOW_SIGNAL_POLICY = "flow-signal-policy-v1"
FLOW_OUTPUT_POLICY = "flow-output-policy-v1"
FLOW_ALIASES_POLICY = "flow-aliases-v1"


class FlowType(StrEnum):
    """Taxonomia ordenada de recursos e operações, nunca de vulnerabilidades."""

    IDENTITY_ACCESS = "IDENTITY_ACCESS"
    USER_DATA_RESOURCE = "USER_DATA_RESOURCE"
    TRANSACTION_ORDER = "TRANSACTION_ORDER"
    MONEY_VALUE = "MONEY_VALUE"
    BENEFIT_ENTITLEMENT = "BENEFIT_ENTITLEMENT"
    STATE_WORKFLOW = "STATE_WORKFLOW"
    ADMIN_PRIVILEGED = "ADMIN_PRIVILEGED"
    INTEGRATION_API = "INTEGRATION_API"
    CONTENT_PUBLIC = "CONTENT_PUBLIC"
    UNKNOWN_DYNAMIC = "UNKNOWN_DYNAMIC"


class ContextGap(StrEnum):
    AUTHENTICATION_STATE_NOT_OBSERVED = "AUTHENTICATION_STATE_NOT_OBSERVED"
    AUTHORIZATION_BEHAVIOR_NOT_OBSERVED = "AUTHORIZATION_BEHAVIOR_NOT_OBSERVED"
    RESOURCE_OWNERSHIP_NOT_OBSERVED = "RESOURCE_OWNERSHIP_NOT_OBSERVED"
    USER_ROLES_NOT_OBSERVED = "USER_ROLES_NOT_OBSERVED"
    RESPONSE_BEHAVIOR_NOT_OBSERVED = "RESPONSE_BEHAVIOR_NOT_OBSERVED"
    STATE_TRANSITIONS_NOT_OBSERVED = "STATE_TRANSITIONS_NOT_OBSERVED"
    BUSINESS_RULES_NOT_OBSERVED = "BUSINESS_RULES_NOT_OBSERVED"
    OBJECT_IDENTIFIERS_NOT_OBSERVED = "OBJECT_IDENTIFIERS_NOT_OBSERVED"
    SESSION_BEHAVIOR_NOT_OBSERVED = "SESSION_BEHAVIOR_NOT_OBSERVED"
    INPUT_CONSTRAINTS_NOT_OBSERVED = "INPUT_CONSTRAINTS_NOT_OBSERVED"
    OTHER_CONTEXT_NOT_OBSERVED = "OTHER_CONTEXT_NOT_OBSERVED"


class FlowRelevance(StrEnum):
    CONTEXT_REQUIRED = "CONTEXT_REQUIRED"
    INFORMATIONAL = "INFORMATIONAL"


class DeterministicFlowBasis(StrEnum):
    DETERMINISTIC_LEXICAL_SIGNAL = "DETERMINISTIC_LEXICAL_SIGNAL"
    MANUAL_PROGRAM_ALIAS = "MANUAL_PROGRAM_ALIAS"


class FlowOutputBasis(StrEnum):
    DETERMINISTIC_LEXICAL_SIGNAL = "DETERMINISTIC_LEXICAL_SIGNAL"
    MANUAL_PROGRAM_ALIAS = "MANUAL_PROGRAM_ALIAS"
    TENTATIVE_PATH_SEMANTIC_INFERENCE = "TENTATIVE_PATH_SEMANTIC_INFERENCE"
    UNKNOWN_DYNAMIC = "UNKNOWN_DYNAMIC"


FLOW_TYPE_ORDER = {flow_type: index for index, flow_type in enumerate(FlowType)}
CONTEXT_GAP_ORDER = {gap: index for index, gap in enumerate(ContextGap)}

CONTEXT_REQUIRED_FLOW_TYPES = frozenset(
    flow_type for flow_type in FlowType if flow_type is not FlowType.CONTENT_PUBLIC
)

MINIMUM_CONTEXT_GAPS: dict[FlowType, tuple[ContextGap, ...]] = {
    FlowType.IDENTITY_ACCESS: (
        ContextGap.AUTHENTICATION_STATE_NOT_OBSERVED,
        ContextGap.SESSION_BEHAVIOR_NOT_OBSERVED,
        ContextGap.RESPONSE_BEHAVIOR_NOT_OBSERVED,
    ),
    FlowType.USER_DATA_RESOURCE: (
        ContextGap.AUTHENTICATION_STATE_NOT_OBSERVED,
        ContextGap.AUTHORIZATION_BEHAVIOR_NOT_OBSERVED,
        ContextGap.RESOURCE_OWNERSHIP_NOT_OBSERVED,
        ContextGap.RESPONSE_BEHAVIOR_NOT_OBSERVED,
    ),
    FlowType.TRANSACTION_ORDER: (
        ContextGap.AUTHORIZATION_BEHAVIOR_NOT_OBSERVED,
        ContextGap.RESOURCE_OWNERSHIP_NOT_OBSERVED,
        ContextGap.STATE_TRANSITIONS_NOT_OBSERVED,
        ContextGap.BUSINESS_RULES_NOT_OBSERVED,
    ),
    FlowType.MONEY_VALUE: (
        ContextGap.AUTHORIZATION_BEHAVIOR_NOT_OBSERVED,
        ContextGap.STATE_TRANSITIONS_NOT_OBSERVED,
        ContextGap.BUSINESS_RULES_NOT_OBSERVED,
        ContextGap.INPUT_CONSTRAINTS_NOT_OBSERVED,
    ),
    FlowType.BENEFIT_ENTITLEMENT: (
        ContextGap.USER_ROLES_NOT_OBSERVED,
        ContextGap.STATE_TRANSITIONS_NOT_OBSERVED,
        ContextGap.BUSINESS_RULES_NOT_OBSERVED,
        ContextGap.INPUT_CONSTRAINTS_NOT_OBSERVED,
    ),
    FlowType.STATE_WORKFLOW: (
        ContextGap.STATE_TRANSITIONS_NOT_OBSERVED,
        ContextGap.BUSINESS_RULES_NOT_OBSERVED,
        ContextGap.INPUT_CONSTRAINTS_NOT_OBSERVED,
    ),
    FlowType.ADMIN_PRIVILEGED: (
        ContextGap.AUTHENTICATION_STATE_NOT_OBSERVED,
        ContextGap.AUTHORIZATION_BEHAVIOR_NOT_OBSERVED,
        ContextGap.USER_ROLES_NOT_OBSERVED,
    ),
    FlowType.INTEGRATION_API: (
        ContextGap.AUTHENTICATION_STATE_NOT_OBSERVED,
        ContextGap.AUTHORIZATION_BEHAVIOR_NOT_OBSERVED,
        ContextGap.RESPONSE_BEHAVIOR_NOT_OBSERVED,
    ),
    FlowType.CONTENT_PUBLIC: (),
    FlowType.UNKNOWN_DYNAMIC: (ContextGap.OTHER_CONTEXT_NOT_OBSERVED,),
}


def flow_relevance(flow_type: FlowType) -> FlowRelevance:
    if flow_type is FlowType.CONTENT_PUBLIC:
        return FlowRelevance.INFORMATIONAL
    return FlowRelevance.CONTEXT_REQUIRED


# Segmentos completos e explícitos. A fixture da pizzaria usa algumas destas pistas, mas
# nenhum nome de programa, host ou produto participa da política.
FLOW_LEXICAL_ALIASES: dict[FlowType, frozenset[str]] = {
    FlowType.IDENTITY_ACCESS: frozenset(
        {
            "account",
            "auth",
            "authentication",
            "cadastro",
            "conta",
            "entrar",
            "login",
            "log-in",
            "logout",
            "oauth",
            "password",
            "register",
            "registration",
            "reset",
            "senha",
            "sign-in",
            "sign-up",
            "signin",
            "signup",
            "sso",
        }
    ),
    FlowType.USER_DATA_RESOURCE: frozenset(
        {
            "meus-dados",
            "minha-conta",
            "perfil",
            "profile",
            "user",
            "users",
            "usuario",
            "usuarios",
        }
    ),
    FlowType.TRANSACTION_ORDER: frozenset(
        {
            "booking",
            "bookings",
            "meu-pedido",
            "meus-pedidos",
            "order",
            "orders",
            "pedido",
            "pedidos",
            "reservation",
            "reservations",
            "reserva",
            "reservas",
        }
    ),
    FlowType.MONEY_VALUE: frozenset(
        {
            "billing",
            "carteira",
            "cobranca",
            "deposit",
            "deposito",
            "fatura",
            "invoice",
            "invoices",
            "pagamento",
            "pagamentos",
            "payment",
            "payments",
            "saque",
            "wallet",
            "wallets",
            "withdraw",
            "withdrawal",
        }
    ),
    FlowType.BENEFIT_ENTITLEMENT: frozenset(
        {
            "beneficio",
            "beneficios",
            "benefit",
            "benefits",
            "coupon",
            "coupons",
            "cupom",
            "cupons",
            "entitlement",
            "promotion",
            "promotions",
            "promocao",
            "promocoes",
        }
    ),
    FlowType.STATE_WORKFLOW: frozenset(
        {
            "approval",
            "approvals",
            "aprovacao",
            "area-de-entrega",
            "cancel",
            "cancelar",
            "cancellation",
            "carrinho",
            "cart",
            "checkout",
            "delivery",
            "entrega",
        }
    ),
    FlowType.ADMIN_PRIVILEGED: frozenset(
        {
            "admin",
            "administracao",
            "administrativo",
            "administrator",
            "backoffice",
            "dashboard",
            "painel",
        }
    ),
    FlowType.INTEGRATION_API: frozenset(
        {
            "api",
            "api-docs",
            "graphql",
            "integracao",
            "integracoes",
            "integration",
            "integrations",
            "openapi",
            "openapi.json",
            "openapi.yaml",
            "openapi.yml",
            "swagger",
            "swagger.json",
            "swagger.yaml",
            "swagger.yml",
            "swagger-ui",
            "webhook",
            "webhooks",
        }
    ),
    FlowType.CONTENT_PUBLIC: frozenset(
        {
            "cardapio",
            "catalog",
            "catalogs",
            "catalogue",
            "menu",
            "product",
            "products",
            "produto",
            "produtos",
        }
    ),
    FlowType.UNKNOWN_DYNAMIC: frozenset(),
}


class _AliasSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FlowAliasEntry(_AliasSchema):
    program_id: StrictStr = Field(min_length=1, max_length=64)
    origin: Literal["manual"]
    version: StrictStr = Field(min_length=1, max_length=32)
    timestamp: datetime
    match_type: Literal["segment", "path"]
    value: StrictStr = Field(min_length=1, max_length=512)
    flow_type: FlowType

    @field_validator("flow_type")
    @classmethod
    def refuse_unknown_alias(cls, value: FlowType) -> FlowType:
        if value is FlowType.UNKNOWN_DYNAMIC:
            raise ValueError("alias manual deve apontar para uma categoria geral conhecida")
        return value

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp do alias deve possuir timezone")
        return value

    @field_validator("timestamp", mode="before")
    @classmethod
    def refuse_numeric_timestamp(cls, value: object) -> object:
        if not isinstance(value, (str, datetime)):
            raise ValueError("timestamp do alias deve ser datetime ISO 8601")
        return value

    @field_validator("value")
    @classmethod
    def validate_alias_value(cls, value: str, info) -> str:
        if value != value.lower() or any(character.isspace() for character in value):
            raise ValueError("alias deve estar em lowercase e não pode conter espaços")
        match_type = info.data.get("match_type")
        if match_type == "segment":
            if "/" in value or value in {".", ".."}:
                raise ValueError("alias de segmento inválido")
        elif match_type == "path" and not _is_safe_relative_path(value):
            raise ValueError("alias de path inválido")
        return value


class FlowAliasPolicy(_AliasSchema):
    policy: Literal["flow-aliases-v1"] = FLOW_ALIASES_POLICY
    program_id: StrictStr = Field(min_length=1, max_length=64)
    aliases: list[FlowAliasEntry] = Field(default_factory=list, max_length=500)

    @field_validator("aliases")
    @classmethod
    def validate_aliases(cls, value: list[FlowAliasEntry], info) -> list[FlowAliasEntry]:
        program_id = info.data.get("program_id")
        coordinates = [(entry.match_type, entry.value) for entry in value]
        if len(coordinates) != len(set(coordinates)):
            raise ValueError("alias manual duplicado")
        if any(entry.program_id != program_id for entry in value):
            raise ValueError("alias manual pertence a outro programa")
        lexical_segments = set().union(*FLOW_LEXICAL_ALIASES.values())
        manual_segments = {entry.value for entry in value if entry.match_type == "segment"}
        if manual_segments.intersection(lexical_segments):
            raise ValueError("alias manual não pode redefinir um sinal lexical versionado")
        for entry in value:
            if entry.match_type != "path":
                continue
            path_segments = {segment for segment in entry.value.split("/") if segment}
            if path_segments.intersection(lexical_segments | manual_segments):
                raise ValueError("alias manual de path sobrepõe um segmento explícito")
        return value


@dataclass(frozen=True)
class ClassifiedFlowSignal:
    flow_type: FlowType
    basis: DeterministicFlowBasis
    evidence_paths: tuple[str, ...]
    evidence_paths_total: int

    @property
    def relevance(self) -> FlowRelevance:
        return flow_relevance(self.flow_type)

    @property
    def required_context(self) -> tuple[ContextGap, ...]:
        return MINIMUM_CONTEXT_GAPS[self.flow_type]


@dataclass(frozen=True)
class FlowClassification:
    signals: tuple[ClassifiedFlowSignal, ...]
    unknown_dynamic_paths: tuple[str, ...]


def _is_safe_relative_path(value: str) -> bool:
    return (
        value.startswith("/")
        and not value.startswith("//")
        and "?" not in value
        and "#" not in value
        and "\\" not in value
        and "\x00" not in value
        and not any(unicodedata.category(character).startswith("C") for character in value)
        and posixpath.normpath(value) == value
    )


def flow_aliases_path(program_directory: Path) -> Path:
    return program_directory / f"{FLOW_ALIASES_POLICY}.json"


def empty_flow_alias_policy(program_id: str) -> FlowAliasPolicy:
    return FlowAliasPolicy(program_id=program_id, aliases=[])


def _strict_alias_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("chave duplicada em flow-aliases-v1")
        value[key] = item
    return value


def load_flow_alias_policy(program_directory: Path, *, program_id: str) -> FlowAliasPolicy:
    """Carrega aliases apenas do diretório do programa informado; ausência equivale a vazio."""
    path = flow_aliases_path(program_directory)
    if not path.exists():
        return empty_flow_alias_policy(program_id)
    if path.is_symlink() or not path.is_file():
        raise ValueError("caminho da política de aliases é inseguro")
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_alias_object
        )
        policy = FlowAliasPolicy.model_validate(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise ValueError("política flow-aliases-v1 inválida") from exc
    if policy.program_id != program_id:
        raise ValueError("política flow-aliases-v1 pertence a outro programa")
    return policy


def save_flow_alias_policy(
    program_directory: Path,
    policy: FlowAliasPolicy,
    *,
    program_id: str,
) -> Path:
    """Persiste somente uma política manual já revisada no diretório do próprio programa."""
    if policy.program_id != program_id:
        raise ValueError("política flow-aliases-v1 pertence a outro programa")
    path = flow_aliases_path(program_directory)
    temporary_path = path.with_suffix(".json.tmp")
    serialized = (
        json.dumps(policy.model_dump(mode="json"), ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    )
    try:
        if program_directory.is_symlink() or path.is_symlink() or temporary_path.is_symlink():
            raise ValueError("caminho da política de aliases é inseguro")
        program_directory.mkdir(parents=True, exist_ok=True)
        try:
            temporary_path.write_text(serialized, encoding="utf-8")
            temporary_path.replace(path)
        finally:
            temporary_path.unlink(missing_ok=True)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("não foi possível persistir flow-aliases-v1") from exc
    return path


def _matched_lexical_flows(segments: tuple[str, ...]) -> set[FlowType]:
    return {
        flow_type
        for flow_type, aliases in FLOW_LEXICAL_ALIASES.items()
        if aliases.intersection(segments)
    }


def _matched_manual_flows(
    path: str,
    segments: tuple[str, ...],
    aliases: Iterable[FlowAliasEntry],
) -> set[FlowType]:
    lowercase_path = path.lower()
    return {
        alias.flow_type
        for alias in aliases
        if (alias.match_type == "path" and alias.value == lowercase_path)
        or (alias.match_type == "segment" and alias.value in segments)
    }


def classify_flow_paths(
    paths: Iterable[str],
    *,
    aliases: Iterable[FlowAliasEntry] = (),
) -> FlowClassification:
    """Classifica paths deduplicados sem rede, LLM, decodificação ou substring matching."""
    evidence: dict[tuple[FlowType, DeterministicFlowBasis], set[str]] = {}
    unknown: list[str] = []
    for path in sorted(set(paths)):
        category = classify_triage_path(path)
        if path == "/" or category in {
            RouteCategory.JAVASCRIPT_REFERENCE,
            RouteCategory.STATIC_LIKELY,
        }:
            continue
        segments = tuple(segment.lower() for segment in path.split("/") if segment)
        lexical_flows = _matched_lexical_flows(segments)
        manual_flows = _matched_manual_flows(path, segments, aliases)
        if not lexical_flows and not manual_flows:
            unknown.append(path)
            continue
        for flow_type in lexical_flows:
            evidence.setdefault(
                (flow_type, DeterministicFlowBasis.DETERMINISTIC_LEXICAL_SIGNAL), set()
            ).add(path)
        for flow_type in manual_flows:
            evidence.setdefault(
                (flow_type, DeterministicFlowBasis.MANUAL_PROGRAM_ALIAS), set()
            ).add(path)

    signals = []
    for (flow_type, basis), paths_for_signal in sorted(
        evidence.items(),
        key=lambda item: (FLOW_TYPE_ORDER[item[0][0]], item[0][1].value),
    ):
        ordered_paths = sorted(paths_for_signal)
        signals.append(
            ClassifiedFlowSignal(
                flow_type=flow_type,
                basis=basis,
                evidence_paths=tuple(ordered_paths[:5]),
                evidence_paths_total=len(ordered_paths),
            )
        )
    return FlowClassification(signals=tuple(signals), unknown_dynamic_paths=tuple(unknown))
