"""Runner-side, independent scope enforcement (ADR 0003, M2.2a).

The Runner never trusts that the Windows core already checked a request.
It loads its own scope file from its own local configuration (env var
``AVRA_RUNNER_SCOPE_FILE`` on the Kali VM) — a request can't carry a scope
(the schemas forbid unknown fields) — and checks every request against it
with the existing default-deny ``ScopeChecker``.

``authorize_request`` is the single gate: unknown tool, invalid request,
or anything out of scope returns ``Denied`` and the tool's executor is
never called. Only ``Authorized`` carries a built command.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ValidationError

from avra.policy.scope import ScopeChecker, ScopeDecision, ScopeError, load_scope
from avra.runner.registry import (
    ToolCommand,
    ToolSpec,
    UnknownToolError,
    parse_request,
)
from avra.runner.schemas import validate_ipv4_target
from avra.schemas.scope import Scope

SCOPE_FILE_ENV = "AVRA_RUNNER_SCOPE_FILE"
_MAX_REASON = 500


class RunnerScopeError(Exception):
    """The Runner's own scope configuration is missing or unacceptable.

    The Runner must refuse to start (fail closed) when this is raised.
    """


@dataclass(frozen=True)
class Authorized:
    spec: ToolSpec
    request: BaseModel
    command: ToolCommand


@dataclass(frozen=True)
class Denied:
    stage: Literal["unknown_tool", "invalid_request", "scope"]
    reason: str


def _check_runner_scope(scope: Scope) -> None:
    """Extra rules the Runner applies on top of the shared scope schema.

    ScopeChecker treats an empty ``ports`` or ``allowed_tools`` list as
    "no restriction". The Runner refuses such scopes outright so an
    omission can never widen what it may touch.
    """
    for target in scope.targets:
        try:
            validate_ipv4_target(target.host)
        except ValueError as exc:
            raise RunnerScopeError(
                f"scope target {target.host!r}: {exc}"
            ) from None
        if not target.ports:
            raise RunnerScopeError(
                f"scope target {target.host}: 'ports' must list explicit ports"
            )
        if not target.allowed_tools:
            raise RunnerScopeError(
                f"scope target {target.host}: 'allowed_tools' must list "
                "explicit tools"
            )


class RunnerPolicy:
    """Default-deny authorization for one Runner, from its own scope."""

    def __init__(self, scope: Scope) -> None:
        _check_runner_scope(scope)
        self._checker = ScopeChecker(scope)

    @property
    def is_expired(self) -> bool:
        return self._checker.scope.is_expired

    @classmethod
    def from_scope_file(cls, path: str | Path) -> RunnerPolicy:
        try:
            scope = load_scope(path)
        except ScopeError as exc:
            raise RunnerScopeError(str(exc)) from exc
        return cls(scope)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RunnerPolicy:
        env = os.environ if env is None else env
        path = env.get(SCOPE_FILE_ENV, "").strip()
        if not path:
            raise RunnerScopeError(
                f"{SCOPE_FILE_ENV} is not set — the Runner has no scope and "
                "will not run anything"
            )
        return cls.from_scope_file(path)

    def check(self, spec: ToolSpec, request: BaseModel) -> ScopeDecision:
        """Every (host, port) the request touches must be in scope for this
        tool at the tool's registry-fixed tier."""
        targets = spec.scope_targets(request)
        if not targets:
            return ScopeDecision(False, "request declares no targets")
        path = spec.scope_path(request) if spec.scope_path is not None else None
        for host, port in targets:
            decision = self._checker.check(
                host=host, port=port, tool=spec.name.value, tier=spec.tier, path=path
            )
            if not decision.allowed:
                return decision
        return ScopeDecision(True, f"{len(targets)} target(s) in scope")

    def authorize_request(self, payload: object) -> Authorized | Denied:
        """The single gate in front of every executor."""
        try:
            spec, request = parse_request(payload)
        except UnknownToolError as exc:
            return Denied("unknown_tool", str(exc)[:_MAX_REASON])
        except ValidationError as exc:
            return Denied(
                "invalid_request",
                f"{exc.error_count()} validation error(s): "
                + "; ".join(
                    f"{'.'.join(map(str, e['loc']))}: {e['msg']}"
                    for e in exc.errors()
                )[:_MAX_REASON],
            )

        decision = self.check(spec, request)
        if not decision.allowed:
            return Denied("scope", decision.reason[:_MAX_REASON])

        return Authorized(spec, request, spec.build_command(request))
