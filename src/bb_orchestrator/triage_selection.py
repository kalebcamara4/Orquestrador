"""Política local e determinística de seleção de paths para triagem."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

type RouteSelectionPolicyName = Literal["route-priority-v1"]

ROUTE_SELECTION_POLICY: RouteSelectionPolicyName = "route-priority-v1"
MAX_SELECTED_PATHS = 50
MAX_JAVASCRIPT_REFERENCES = 5


class RouteCategory(StrEnum):
    """Categorias ordenadas da política ``route-priority-v1``."""

    ROOT = "root"
    APPLICATION_LIKELY = "application_likely"
    API_OR_DYNAMIC_FILE = "api_or_dynamic_file"
    DYNAMIC_LIKELY = "dynamic_likely"
    JAVASCRIPT_REFERENCE = "javascript_reference"
    STATIC_LIKELY = "static_likely"


_CATEGORY_ORDER = {
    RouteCategory.ROOT: 0,
    RouteCategory.APPLICATION_LIKELY: 1,
    RouteCategory.API_OR_DYNAMIC_FILE: 2,
    RouteCategory.DYNAMIC_LIKELY: 3,
    RouteCategory.JAVASCRIPT_REFERENCE: 4,
    RouteCategory.STATIC_LIKELY: 5,
}

_APPLICATION_SEGMENTS = frozenset(
    {
        "account",
        "admin",
        "api",
        "callback",
        "carrinho",
        "checkout",
        "conta",
        "coupon",
        "cupom",
        "dashboard",
        "deposit",
        "graphql",
        "login",
        "logout",
        "meu-pedido",
        "meus-pedidos",
        "oauth",
        "pagamento",
        "password",
        "payment",
        "pedido",
        "pedidos",
        "perfil",
        "profile",
        "promocoes",
        "register",
        "reset",
        "saque",
        "signin",
        "signup",
        "sso",
        "user",
        "users",
        "webhook",
        "withdraw",
    }
)

_API_DOCUMENTATION_FILES = frozenset(
    {
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "swagger.json",
        "swagger.yaml",
        "swagger.yml",
    }
)
_API_DOCUMENTATION_SEGMENTS = frozenset({"api-docs", "openapi", "swagger", "swagger-ui"})
_DYNAMIC_FILE_EXTENSIONS = frozenset({".aspx", ".do", ".jsp", ".php"})
_STATIC_FILE_EXTENSIONS = frozenset(
    {
        ".7z",
        ".avif",
        ".bmp",
        ".css",
        ".eot",
        ".gif",
        ".gz",
        ".ico",
        ".jpeg",
        ".jpg",
        ".map",
        ".mkv",
        ".mov",
        ".mp3",
        ".mp4",
        ".ogg",
        ".otf",
        ".png",
        ".rar",
        ".svg",
        ".tar",
        ".tgz",
        ".tif",
        ".tiff",
        ".ttf",
        ".wav",
        ".webm",
        ".webp",
        ".woff",
        ".woff2",
        ".zip",
    }
)
_MANIFEST_FILENAMES = frozenset(
    {
        "asset-manifest.json",
        "manifest.json",
        "manifest.webmanifest",
        "site.webmanifest",
        "webmanifest.json",
    }
)
_LIBRARY_PATH_SEGMENTS = frozenset({"node_modules", "vendor", "vendors"})
_JAVASCRIPT_LIBRARY_PATTERN = re.compile(
    r"(?:^|[._-])(?:angular|axios|bootstrap|jquery|lodash|moment|onesignal(?:sdk)?|polyfill|"
    r"react|sweetalert|underscore|vue)(?:[._-]|$)",
    re.IGNORECASE,
)
_MINIFIED_JAVASCRIPT_PATTERN = re.compile(r"(?:^|[._-])min(?:[._-]|\.js$)", re.IGNORECASE)
_MANIFEST_PATTERN = re.compile(r"(?:^|[._-])manifest(?:[._-]|$)", re.IGNORECASE)


@dataclass(frozen=True)
class RouteSelection:
    """Resultado auditável da aplicação de ``route-priority-v1`` a um asset."""

    paths: tuple[str, ...]
    paths_total: int
    paths_included: int
    paths_omitted_by_policy: int
    paths_omitted_by_limit: int


def _path_parts(path: str) -> tuple[tuple[str, ...], str, str]:
    segments = tuple(segment.lower() for segment in path.split("/") if segment)
    filename = segments[-1] if segments else ""
    extension = posixpath.splitext(filename)[1]
    return segments, filename, extension


def _is_manifest(filename: str) -> bool:
    return (
        filename in _MANIFEST_FILENAMES
        or filename.endswith(".webmanifest")
        or (filename.endswith(".json") and _MANIFEST_PATTERN.search(filename) is not None)
    )


def _is_evident_javascript_library(segments: tuple[str, ...], filename: str) -> bool:
    return (
        bool(_LIBRARY_PATH_SEGMENTS.intersection(segments))
        or _MINIFIED_JAVASCRIPT_PATTERN.search(filename) is not None
        or any(_JAVASCRIPT_LIBRARY_PATTERN.search(segment) is not None for segment in segments)
    )


def classify_triage_path(path: str) -> RouteCategory:
    """Classifica um path normalizado sem consultar rede, arquivos ou processos externos."""
    if path == "/":
        return RouteCategory.ROOT

    segments, filename, extension = _path_parts(path)

    # Extensões inequivocamente estáticas vencem palavras presentes em diretórios, por exemplo
    # ``/api/assets/style.css``. A política seleciona rotas, não arquivos de apresentação.
    if extension in _STATIC_FILE_EXTENSIONS or _is_manifest(filename):
        return RouteCategory.STATIC_LIKELY
    if extension == ".js":
        if _is_evident_javascript_library(segments, filename):
            return RouteCategory.STATIC_LIKELY
        return RouteCategory.JAVASCRIPT_REFERENCE

    if _APPLICATION_SEGMENTS.intersection(segments):
        return RouteCategory.APPLICATION_LIKELY
    if (
        filename in _API_DOCUMENTATION_FILES
        or _API_DOCUMENTATION_SEGMENTS.intersection(segments)
        or extension in _DYNAMIC_FILE_EXTENSIONS
    ):
        return RouteCategory.API_OR_DYNAMIC_FILE
    if not extension:
        return RouteCategory.DYNAMIC_LIKELY
    return RouteCategory.STATIC_LIKELY


def route_priority_key(path: str) -> tuple[int, str]:
    """Chave pública da ordenação versionada e estável da política."""
    return _CATEGORY_ORDER[classify_triage_path(path)], path


def select_triage_paths(paths: list[str] | tuple[str, ...]) -> RouteSelection:
    """Deduplica, prioriza e limita paths conforme ``route-priority-v1``."""
    unique_paths = sorted(set(paths))
    by_category: dict[RouteCategory, list[str]] = {category: [] for category in RouteCategory}
    for path in unique_paths:
        by_category[classify_triage_path(path)].append(path)

    javascript = by_category[RouteCategory.JAVASCRIPT_REFERENCE]
    policy_eligible = [
        *by_category[RouteCategory.ROOT],
        *by_category[RouteCategory.APPLICATION_LIKELY],
        *by_category[RouteCategory.API_OR_DYNAMIC_FILE],
        *by_category[RouteCategory.DYNAMIC_LIKELY],
        *javascript[:MAX_JAVASCRIPT_REFERENCES],
    ]
    selected = tuple(policy_eligible[:MAX_SELECTED_PATHS])
    omitted_by_policy = len(by_category[RouteCategory.STATIC_LIKELY]) + max(
        0, len(javascript) - MAX_JAVASCRIPT_REFERENCES
    )
    omitted_by_limit = max(0, len(policy_eligible) - MAX_SELECTED_PATHS)

    return RouteSelection(
        paths=selected,
        paths_total=len(unique_paths),
        paths_included=len(selected),
        paths_omitted_by_policy=omitted_by_policy,
        paths_omitted_by_limit=omitted_by_limit,
    )
