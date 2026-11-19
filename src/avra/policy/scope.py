"""Load and enforce scope files (docs/architecture.md §8, §4.9).

This module is the Policy layer's scope half. Both the Orchestrator and,
later, the Tool Runner are expected to hold their own ``ScopeChecker`` and
check independently — never trust that "the other side already checked."
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from avra.schemas.scope import ActionTier, Scope


class ScopeError(Exception):
    """A scope file is missing, malformed, invalid, or expired."""


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


def load_scope(path: str | Path) -> Scope:
    """Load, parse and validate a scope YAML file.

    Raises ScopeError (never a bare parsing exception) for every failure
    mode, so callers can show the owner one clear message.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ScopeError(f"scope file not found: {file_path}")

    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScopeError(f"invalid YAML in {file_path}: {exc}") from exc

    if raw is None:
        raise ScopeError(f"scope file is empty: {file_path}")

    try:
        scope = Scope.model_validate(raw)
    except ValidationError as exc:
        raise ScopeError(f"invalid scope file {file_path}:\n{exc}") from exc

    if scope.is_expired:
        raise ScopeError(
            f"scope '{scope.session_name}' expired at "
            f"{scope.expires_at.isoformat()}"
        )

    return scope


class ScopeChecker:
    """Default-deny authorization check against one loaded Scope."""

    def __init__(self, scope: Scope) -> None:
        self._scope = scope

    @property
    def scope(self) -> Scope:
        return self._scope

    def check(
        self, *, host: str, port: int, tool: str, tier: ActionTier,
        path: str | None = None,
    ) -> ScopeDecision:
        if self._scope.is_expired:
            return ScopeDecision(
                False,
                f"scope expired at {self._scope.expires_at.isoformat()}",
            )

        for target in self._scope.targets:
            if target.host != host:
                continue
            # Default-deny: an empty list matches nothing — never "any".
            # The schema already rejects empty lists; this guards scopes
            # built without validation (e.g. model_construct).
            if port not in target.ports:
                continue
            if tier not in target.allowed_tiers:
                continue
            if tool not in target.allowed_tools:
                continue
            if path is not None and not path_allowed(path, target.http_paths):
                continue  # M10.5: path-scoped tools need an explicit prefix match
            return ScopeDecision(True, f"allowed by target {target.host}")

        return ScopeDecision(
            False,
            f"{host}:{port} tool={tool} tier={tier.value}"
            + (f" path={path[:100]}" if path is not None else "") + " is not in scope",
        )


def path_allowed(path: str, prefixes: list[str]) -> bool:
    """M10.5: ``path`` is allowed if it equals a prefix, or the prefix ends with '/' and
    the path starts with it, or the path continues the prefix with '/'. So ``/api`` allows
    ``/api`` and ``/api/x`` but never ``/apix``. An empty list allows nothing."""
    for prefix in prefixes:
        if path == prefix or (prefix.endswith("/") and path.startswith(prefix)) \
                or path.startswith(prefix + "/"):
            return True
    return False
