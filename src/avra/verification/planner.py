"""Investigation planning from verification feedback (M8.5 Stage 2, ADR 0010).

Candidate actions are NOT scripted: they come only from the rules'
``next_actions`` for hypotheses that are currently INCONCLUSIVE for lack of
evidence. Each candidate is scored by expected information gain over cost:

* gain   = sum of weights of the open hypotheses on that target whose rule
           consumes the evidence kind the action would produce (observation
           rule 1; vulnerability rule by severity) + 0.5 for every registered
           rule of that evidence kind not yet checked on the target (follow-up
           checks the new evidence would enable);
* cost   = the action's tier cost (passive probe 1, active-safe scan 2);
* gating = the scope must allow the tool on that target (checked with the
           same policy function the pipelines use); whether the research
           agent may request it itself or only the owner can run it; whether
           tool runs remain in the session budget.

Blocked actions are kept (score 0) with the reason, so the model and the
report can explain why a gap stays open. Nothing here executes anything.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from avra.policy.scope import ScopeChecker
from avra.policy.tools import authorize_tool_request
from avra.runner.schemas import HttpProbeRequest, NmapConnectScanRequest
from avra.verification.models import (
    EvidenceKind,
    ProposedAction,
    RuleKind,
    Target,
    Verdict,
    VerificationResult,
)
from avra.verification.rules import RuleRegistry

TOOL_EVIDENCE = {"nmap_connect_scan": EvidenceKind.NMAP_XML,
                 "http_probe": EvidenceKind.HTTP_ENVELOPE}
TOOL_COST = {"http_probe": 1.0, "nmap_connect_scan": 2.0}
SEVERITY_WEIGHT = {"none": 1.0, "informational": 1.0, "low": 2.0, "medium": 3.0, "high": 4.0}
RESOLVABLE = frozenset({"no_evidence", "insufficient_evidence", "ambiguous_state",
                        "no_usable_response"})
_NIL = uuid.UUID(int=0)


@dataclass(frozen=True)
class PlannedAction:
    action: ProposedAction
    score: float
    gain: float
    resolves: tuple[str, ...]   # hypothesis ids this evidence could decide
    enables: tuple[str, ...]    # rule ids that could then be checked on the target
    executor: str               # "agent" (the research model may request it) | "owner_only"
    allowed_by_scope: bool
    blocked_reason: str = ""

    def as_dict(self) -> dict:
        return {"tool": self.action.tool, "target": self.action.target.label(),
                "reason": self.action.reason, "score": round(self.score, 3),
                "resolves": list(self.resolves), "enables": list(self.enables),
                "executor": self.executor, "allowed_by_scope": self.allowed_by_scope,
                "blocked_reason": self.blocked_reason,
                "requires_owner_approval": self.action.requires_owner_approval}


def _scope_allows(checker: ScopeChecker | None, tool: str, target: Target) -> bool:
    if checker is None:
        return False
    if tool == "http_probe":
        req = HttpProbeRequest(request_id=_NIL, session_id=_NIL, host=target.host,
                               port=target.port)
    elif tool == "nmap_connect_scan":
        req = NmapConnectScanRequest(request_id=_NIL, session_id=_NIL, host=target.host,
                                     ports=[target.port])
    else:
        return False
    return authorize_tool_request(checker, req).allowed


def plan(results: Iterable[tuple[str, VerificationResult]], actions: Iterable[ProposedAction],
         registry: RuleRegistry, *, checker: ScopeChecker | None,
         agent_tools: frozenset[str], tool_runs_left: int) -> list[PlannedAction]:
    """``results``: (hypothesis_id, latest result); ``actions``: candidate
    ProposedActions from the rules. Returns the ranked plan (best first)."""
    results = list(results)
    checked = {(r.rule_id, r.target) for _, r in results}
    planned: dict[tuple[str, str], PlannedAction] = {}
    for a in actions:
        kind = TOOL_EVIDENCE.get(a.tool)
        if kind is None or a.key() in planned:
            continue
        resolves, gain = [], 0.0
        for hid, r in results:
            rule = registry.get(r.rule_id)
            if (r.target == a.target and r.verdict is Verdict.INCONCLUSIVE and rule
                    and r.reason_code in RESOLVABLE and kind in rule.evidence_kinds):
                resolves.append(hid)
                gain += (SEVERITY_WEIGHT.get(rule.severity, 1.0)
                         if rule.kind is RuleKind.VULNERABILITY else 1.0)
        enables = sorted(r.id for r in registry.rules()
                         if kind in r.evidence_kinds and (r.id, a.target) not in checked)
        gain += 0.5 * len(enables)
        allowed = _scope_allows(checker, a.tool, a.target)
        if a.tool not in agent_tools:
            executor, why = "owner_only", "only the owner can run this tool (e.g. avra probe http)"
        elif tool_runs_left <= 0:
            executor, why = "agent", "the session's tool-run budget is used up"
        else:
            executor, why = "agent", ""
        if not allowed:
            why = "the scope does not allow this tool on this target"
        if not resolves and not enables:
            why = why or "no open hypothesis would be decided by it"
        score = 0.0 if (not allowed or not (resolves or enables)
                        or (executor == "agent" and tool_runs_left <= 0)) \
            else gain / TOOL_COST.get(a.tool, 2.0)
        planned[a.key()] = PlannedAction(a, score, gain, tuple(sorted(resolves)),
                                         tuple(enables), executor, allowed, why)
    return sorted(planned.values(),
                  key=lambda p: (-p.score, p.action.tool, p.action.target.label()))
