"""Validação determinística e segura de domínios e regras de escopo."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from enum import StrEnum

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FORBIDDEN_DOMAIN_CHARS = frozenset("/:?#@")


class ScopeKind(StrEnum):
    EXACT = "exact"
    WILDCARD = "wildcard"


class InvalidDomain(ValueError):
    """Indica um domínio ou padrão de escopo inválido."""


def normalize_domain(value: str) -> str:
    """Normaliza um hostname DNS ASCII sem fazer resolução de rede."""
    if not isinstance(value, str):
        raise InvalidDomain("o domínio deve ser texto")

    domain = value.strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]

    if not domain:
        raise InvalidDomain("o domínio não pode ser vazio")
    if any(char in domain for char in _FORBIDDEN_DOMAIN_CHARS):
        raise InvalidDomain("informe somente o domínio, sem URL, porta ou credenciais")
    if "*" in domain:
        raise InvalidDomain("wildcard não é permitido em um domínio observado")
    if len(domain) > 253:
        raise InvalidDomain("o domínio excede 253 caracteres")

    try:
        domain.encode("ascii")
    except UnicodeEncodeError as exc:
        raise InvalidDomain("use a forma ASCII/punycode para domínios internacionalizados") from exc

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise InvalidDomain("endereços IP não são aceitos como domínio")

    labels = domain.split(".")
    if len(labels) < 2:
        raise InvalidDomain("o domínio deve ter ao menos dois rótulos DNS")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise InvalidDomain("o domínio contém um rótulo DNS inválido")

    return domain


def parse_scope_pattern(value: str) -> tuple[ScopeKind, str]:
    """Valida uma regra e retorna seu tipo e sua forma canônica."""
    if not isinstance(value, str):
        raise InvalidDomain("a regra de escopo deve ser texto")

    pattern = value.strip().lower()
    if pattern.startswith("*."):
        base_domain = normalize_domain(pattern[2:])
        return ScopeKind.WILDCARD, f"*.{base_domain}"
    if "*" in pattern:
        raise InvalidDomain("o wildcard só pode aparecer no início como '*.'")

    return ScopeKind.EXACT, normalize_domain(pattern)


def domain_matches_pattern(domain: str, pattern: str) -> bool:
    """Compara por limites de rótulo, nunca por substring."""
    normalized_domain = normalize_domain(domain)
    kind, normalized_pattern = parse_scope_pattern(pattern)

    if kind is ScopeKind.EXACT:
        return normalized_domain == normalized_pattern

    base_domain = normalized_pattern[2:]
    return normalized_domain.endswith(f".{base_domain}")


def is_domain_in_scope(domain: str, patterns: Iterable[str]) -> bool:
    """Retorna verdadeiro se ao menos uma regra autorizar o domínio."""
    normalized_domain = normalize_domain(domain)
    return any(domain_matches_pattern(normalized_domain, pattern) for pattern in patterns)
