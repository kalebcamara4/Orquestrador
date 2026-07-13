import pytest

from bb_orchestrator.domain import (
    InvalidDomain,
    ScopeKind,
    domain_matches_pattern,
    is_domain_in_scope,
    normalize_domain,
    parse_scope_pattern,
)


@pytest.mark.parametrize(
    ("domain", "pattern"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM.", "example.com"),
        ("api.example.com", "*.example.com"),
        ("deep.api.example.com", "*.example.com"),
    ],
)
def test_allowed_domain_matches_on_dns_label_boundaries(domain: str, pattern: str) -> None:
    assert domain_matches_pattern(domain, pattern)


@pytest.mark.parametrize(
    ("domain", "pattern"),
    [
        ("api.example.com", "example.com"),
        ("example.com", "*.example.com"),
        ("example.com.attacker.test", "example.com"),
        ("example.com.attacker.test", "*.example.com"),
        ("notexample.com", "example.com"),
        ("notexample.com", "*.example.com"),
        ("example.net", "*.example.com"),
    ],
)
def test_third_parties_and_suffix_tricks_are_rejected(domain: str, pattern: str) -> None:
    assert not domain_matches_pattern(domain, pattern)


def test_scope_is_default_deny() -> None:
    assert not is_domain_in_scope("example.com", [])


def test_scope_accepts_any_explicit_matching_rule() -> None:
    patterns = ["unrelated.test", "*.example.com"]
    assert is_domain_in_scope("api.example.com", patterns)
    assert not is_domain_in_scope("third-party.test", patterns)


def test_patterns_are_normalized_and_typed() -> None:
    assert parse_scope_pattern("  *.EXAMPLE.COM. ") == (
        ScopeKind.WILDCARD,
        "*.example.com",
    )
    assert parse_scope_pattern("EXAMPLE.COM.") == (ScopeKind.EXACT, "example.com")


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "user@example.com",
        "127.0.0.1",
        "localhost",
        "example..com",
        "-example.com",
        "example.com..",
        "exämple.com",
    ],
)
def test_invalid_or_non_domain_values_are_rejected(value: str) -> None:
    with pytest.raises(InvalidDomain):
        normalize_domain(value)


@pytest.mark.parametrize(
    "pattern",
    ["*example.com", "api.*.example.com", "**.example.com", "*", "*.127.0.0.1"],
)
def test_unsafe_wildcard_patterns_are_rejected(pattern: str) -> None:
    with pytest.raises(InvalidDomain):
        parse_scope_pattern(pattern)
