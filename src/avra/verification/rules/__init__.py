"""Built-in verification rules and the default registry (M8.4, ADR 0009)."""

from __future__ import annotations

from avra.verification.rules.base import (
    RuleEvaluation,
    RuleRegistry,
    SuggestContext,
    Suggestion,
    VerificationRule,
)
from avra.verification.rules.http_headers import MissingNosniffRule
from avra.verification.rules.observation import HttpServiceObservedRule, TcpPortOpenRule

__all__ = [
    "HttpServiceObservedRule",
    "MissingNosniffRule",
    "RuleEvaluation",
    "RuleRegistry",
    "SuggestContext",
    "Suggestion",
    "TcpPortOpenRule",
    "VerificationRule",
    "default_registry",
]


def default_registry() -> RuleRegistry:
    """A fresh registry with every built-in rule. Add plugins with ``register``.

    Unchanged since M8.4: the research loop, ``avra verify`` and attested
    reports keep their established verdicts. Extra rule packs are opt-in."""
    return RuleRegistry([TcpPortOpenRule(), HttpServiceObservedRule(), MissingNosniffRule()])


def m84_registry() -> RuleRegistry:
    """The original M8.4 rule set, by name (pinned inputs such as the model benchmark)."""
    return default_registry()


def web_registry() -> RuleRegistry:
    """Opt-in: the default rules plus the passive web-header pack (CSP, framing, CORS
    wildcard, version disclosure). Used by ``avra assess`` and ``verify session --web-rules``."""
    from avra.verification.rules.web_headers import WEB_HEADER_RULES

    reg = default_registry()
    for rule in WEB_HEADER_RULES:
        reg.register(rule())
    return reg


def validation_registry() -> RuleRegistry:
    """M10.4 (ADR 0017), opt-in with ``avra research --web-research``: the web pack plus the
    passive validation rules (CORS wildcard + credentials, cookies without HttpOnly). The
    ``--web-rules`` registry is unchanged."""
    from avra.verification.rules.web_validation import WEB_VALIDATION_RULES

    reg = web_registry()
    for rule in WEB_VALIDATION_RULES:
        reg.register(rule())
    return reg
