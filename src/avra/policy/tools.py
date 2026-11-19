"""Windows-side authorization of a typed tool request (ADR 0003, M6.3).

The Orchestrator checks every request against ITS OWN scope file before
anything leaves Windows; the Runner checks again against its own scope on
Kali. Neither trusts the other (docs/architecture.md §8).

The tool's tier and the (host, port) pairs it touches come from the same
static Tool Registry the Runner uses, so the two sides can't disagree about
what a request *is* — only about whether it's allowed, and then it's denied.
"""

from __future__ import annotations

from pydantic import BaseModel

from avra.policy.scope import ScopeChecker, ScopeDecision
from avra.runner.registry import UnknownToolError, get_tool


def authorize_tool_request(checker: ScopeChecker, request: BaseModel) -> ScopeDecision:
    """Default deny: every (host, port) must be in scope for this tool at
    the registry-fixed tier, and the scope must not be expired."""
    tool = getattr(request, "tool", None)
    try:
        spec = get_tool(getattr(tool, "value", tool))
    except UnknownToolError as exc:
        return ScopeDecision(False, str(exc))
    if type(request) is not spec.request_model:
        return ScopeDecision(False, f"request type does not match tool {spec.name.value}")
    targets = spec.scope_targets(request)
    if not targets:
        return ScopeDecision(False, "request declares no targets")
    path = spec.scope_path(request) if spec.scope_path is not None else None
    for host, port in targets:
        decision = checker.check(host=host, port=port, tool=spec.name.value, tier=spec.tier,
                                 path=path)
        if not decision.allowed:
            return decision
    return ScopeDecision(True, f"{len(targets)} target(s) in scope at tier {spec.tier.value}")
