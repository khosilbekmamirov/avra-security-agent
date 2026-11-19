"""Pydantic models for a scope file (docs/architecture.md §8, §4.9).

A scope file is the only thing that can authorize AVRA to touch a target.
Default is deny: anything not explicitly listed here is out of scope.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class ActionTier(str, Enum):
    """Escalating risk levels for an action against a target.

    See docs/security.md for what each tier means. ``DESTRUCTIVE`` exists
    in this enum only so a scope file that lists it fails validation with
    a clear message — the MVP never grants it (ADR 0001, item 7).
    """

    PASSIVE = "passive"
    ACTIVE_SAFE = "active-safe"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


class Target(BaseModel):
    """One authorized target inside a scope file.

    ``ports`` and ``allowed_tools`` are required and must be non-empty:
    authorization is only ever what's explicitly listed. (Before this was
    enforced, an omitted or empty list meant "any port" / "any tool".)
    """

    host: str
    description: str = ""
    ports: list[int] = Field(min_length=1)
    allowed_tiers: list[ActionTier]
    allowed_tools: list[str] = Field(min_length=1)
    # M10.5 (ADR 0018): path prefixes ``http_get_path`` may fetch on this target. Empty =
    # no path may be fetched (default deny). Other tools ignore it.
    http_paths: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("http_paths")
    @classmethod
    def http_paths_valid(cls, paths: list[str]) -> list[str]:
        from avra.runner.schemas import validate_http_path

        for path in paths:
            validate_http_path(path)
        return paths

    @field_validator("allowed_tools")
    @classmethod
    def tool_names_not_blank(cls, tools: list[str]) -> list[str]:
        if any(not tool.strip() for tool in tools):
            raise ValueError("allowed_tools must not contain blank names")
        return tools

    @field_validator("allowed_tiers")
    @classmethod
    def reject_destructive(cls, tiers: list[ActionTier]) -> list[ActionTier]:
        if ActionTier.DESTRUCTIVE in tiers:
            raise ValueError(
                "the 'destructive' tier is not permitted in the MVP "
                "(docs/security.md) — remove it from allowed_tiers"
            )
        if not tiers:
            raise ValueError("allowed_tiers must not be empty")
        return tiers

    @field_validator("ports")
    @classmethod
    def ports_in_range(cls, ports: list[int]) -> list[int]:
        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid port: {port}")
        return ports


class Scope(BaseModel):
    """A full scope file: a named session with its list of targets."""

    session_name: str
    expires_at: datetime
    # Free-text, owner-written note describing the authorized environment
    # (e.g. "home VirtualBox lab, intentionally-vulnerable training targets
    # only"). Passed to the model as factual context; it is descriptive DATA
    # and is never consulted by the ScopeChecker, so it can neither grant nor
    # widen authorization. Bounded so it can't bloat the cached prompt.
    description: str = Field(default="", max_length=2000)
    targets: list[Target]

    @field_validator("targets")
    @classmethod
    def at_least_one_target(cls, targets: list[Target]) -> list[Target]:
        if not targets:
            raise ValueError("scope must list at least one target")
        return targets

    @property
    def is_expired(self) -> bool:
        now = datetime.now(UTC)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return now >= expires
