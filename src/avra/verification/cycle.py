"""Bounded offline research cycle (M8.4 Stage 2, ADR 0009).

    evidence -> proposals -> admission -> deterministic verification
             -> feedback (state, next actions) -> next proposals ...

The cycle runs without operator confirmation: it only READS evidence and
calls the engine. It never sends a network request. When a hypothesis
needs new evidence, the rule's ``next_actions`` become ``ProposedAction``s
that a human must approve through the normal scoped tool path (M8.3).

Proposers (``HypothesisProposer``) may be the deterministic rule generator,
an owner/AI-supplied list, or the LLM (``ModelProposer``). Whatever they
propose goes through the same admission and the same engine; no proposer
can set a verdict.

Termination is guaranteed: at most ``max_iterations`` rounds, at most
``max_hypotheses`` verified in total; hypotheses are identified by
(rule, target, params) so a repeat is never re-verified; a round with no
new admissible hypothesis ends the cycle (``evidence_exhausted``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from avra.verification.engine import VerificationEngine
from avra.verification.evidence import SessionEvidence
from avra.verification.models import (
    Hypothesis,
    Origin,
    ProposedAction,
    RuleKind,
    Target,
    Verdict,
    VerificationResult,
)
from avra.verification.rules import RuleRegistry, SuggestContext


class Status(str, Enum):
    CONFIRMED = "confirmed"        # verified (a finding if the rule is a vulnerability rule)
    REJECTED = "rejected"          # reliable evidence says the condition is false
    INCONCLUSIVE = "inconclusive"  # open question: see missing_evidence / next actions


class StopReason(str, Enum):
    EVIDENCE_EXHAUSTED = "evidence_exhausted"  # a round produced nothing new to verify
    MAX_ITERATIONS = "max_iterations"
    MAX_HYPOTHESES = "max_hypotheses"


@dataclass(frozen=True)
class Budget:
    max_iterations: int = 5
    max_hypotheses: int = 50

    def __post_init__(self) -> None:
        if not 1 <= self.max_iterations <= 50 or not 1 <= self.max_hypotheses <= 500:
            raise ValueError("budget out of range (iterations 1-50, hypotheses 1-500)")


@dataclass
class Entry:
    hypothesis: Hypothesis
    iteration: int
    proposed_by: str
    result: VerificationResult

    @property
    def status(self) -> Status:
        return Status(self.result.verdict.value.lower())

    @property
    def explanation(self) -> str:
        r = self.result
        if r.verdict is Verdict.REJECTED:
            return f"Discarded: {r.reason}"
        if r.verdict is Verdict.INCONCLUSIVE:
            need = "; ".join(r.missing_evidence) or "no rule can decide this with any evidence"
            return f"Open: {r.reason} Needed: {need}."
        return f"Verified: {r.reason}"


@dataclass(frozen=True)
class Dropped:
    proposer: str
    iteration: int
    reason: str
    detail: str


@dataclass(frozen=True)
class IterationLog:
    number: int
    proposed: int
    admitted: int
    repeats: int
    dropped: int
    confirmed: int
    rejected: int
    inconclusive: int


@dataclass
class CycleState:
    session_id: str
    entries: dict[str, Entry] = field(default_factory=dict)
    dropped: list[Dropped] = field(default_factory=list)
    next_actions: dict[tuple[str, str], ProposedAction] = field(default_factory=dict)
    iterations: list[IterationLog] = field(default_factory=list)
    stop_reason: StopReason | None = None
    proposer_notes: list[str] = field(default_factory=list)

    def verdicts(self) -> dict[tuple[str, Target], Verdict]:
        return {(e.hypothesis.rule_id, e.hypothesis.target): e.result.verdict
                for e in self.entries.values()}

    def by_status(self, status: Status) -> list[Entry]:
        return sorted((e for e in self.entries.values() if e.status is status),
                      key=lambda e: (e.iteration, e.hypothesis.id))

    def findings(self) -> list[Entry]:
        return [e for e in self.by_status(Status.CONFIRMED) if e.result.is_finding]

    def verified_observations(self) -> list[Entry]:
        return [e for e in self.by_status(Status.CONFIRMED)
                if e.result.rule_kind is RuleKind.OBSERVATION]


@dataclass(frozen=True)
class CycleContext:
    """What a proposer sees: trusted evidence, the rule catalogue and the
    state so far (feedback). Read-only."""

    evidence: SessionEvidence
    registry: RuleRegistry
    state: CycleState
    iteration: int


class HypothesisProposer(Protocol):
    name: str

    def propose(self, ctx: CycleContext) -> list[Hypothesis]: ...


class RuleBasedProposer:
    """Deterministic generator: each rule suggests follow-ups from the
    current evidence and verdicts (e.g. HTTP verified -> check headers)."""

    name = "rules"

    def propose(self, ctx: CycleContext) -> list[Hypothesis]:
        sctx = SuggestContext(evidence=ctx.evidence, verdicts=ctx.state.verdicts())
        out = []
        for rule in ctx.registry.rules():
            for s in rule.suggest(sctx):
                out.append(Hypothesis.create(rule_id=rule.id, host=s.target.host,
                                             port=s.target.port, origin=Origin.GENERATOR,
                                             params=dict(s.params), rationale=s.rationale))
        return out


class StaticProposer:
    """Hypotheses supplied up front (an owner file, or AI-style proposals
    recorded elsewhere). Offered once, in the first round."""

    def __init__(self, hypotheses: list[Hypothesis], name: str = "supplied") -> None:
        self._hypotheses, self.name = list(hypotheses), name

    def propose(self, ctx: CycleContext) -> list[Hypothesis]:
        return list(self._hypotheses) if ctx.iteration == 1 else []


class ResearchCycle:
    def __init__(self, engine: VerificationEngine, proposers: list[HypothesisProposer],
                 budget: Budget | None = None,
                 on_result: Callable[[Entry], None] | None = None) -> None:
        if not proposers:
            raise ValueError("at least one proposer is required")
        self.engine, self.proposers = engine, list(proposers)
        self.budget = budget or Budget()
        self.on_result = on_result

    def run(self, evidence: SessionEvidence) -> CycleState:
        state = CycleState(session_id=evidence.session_id)
        hosts = {t.host for t in evidence.targets()}
        for n in range(1, self.budget.max_iterations + 1):
            ctx = CycleContext(evidence, self.engine.registry, state, n)
            fresh: dict[str, tuple[Hypothesis, str]] = {}
            proposed = repeats = dropped = 0
            for proposer in self.proposers:
                for h in proposer.propose(ctx):
                    proposed += 1
                    if h.target.host not in hosts:
                        dropped += 1
                        state.dropped.append(Dropped(proposer.name, n, "unknown_host",
                                                     f"{h.rule_id} @ {h.target.label()}: no "
                                                     "evidence exists for this host"))
                    elif h.id in state.entries or h.id in fresh:
                        repeats += 1
                    else:
                        fresh[h.id] = (h, proposer.name)
            if not fresh:
                state.iterations.append(IterationLog(n, proposed, 0, repeats, dropped, 0, 0, 0))
                state.stop_reason = StopReason.EVIDENCE_EXHAUSTED
                return state
            counts = {v: 0 for v in Verdict}
            admitted = 0
            for hid in sorted(fresh):
                if len(state.entries) >= self.budget.max_hypotheses:
                    state.stop_reason = StopReason.MAX_HYPOTHESES
                    break
                h, who = fresh[hid]
                result = self.engine.verify(h, evidence)
                entry = Entry(h, n, who, result)
                state.entries[h.id] = entry
                admitted += 1
                counts[result.verdict] += 1
                self._feedback(state, entry)
            state.iterations.append(IterationLog(
                n, proposed, admitted, repeats, dropped, counts[Verdict.CONFIRMED],
                counts[Verdict.REJECTED], counts[Verdict.INCONCLUSIVE]))
            if state.stop_reason is StopReason.MAX_HYPOTHESES:
                return state
        state.stop_reason = StopReason.MAX_ITERATIONS
        return state

    def _feedback(self, state: CycleState, entry: Entry) -> None:
        """CONFIRMED is kept with its proof, REJECTED is discarded with the
        reason (never re-proposed: same id), INCONCLUSIVE yields the next
        evidence-gathering actions (proposed, never executed)."""
        if entry.result.verdict is Verdict.INCONCLUSIVE:
            rule = self.engine.registry.get(entry.hypothesis.rule_id)
            if rule is not None:
                for action in rule.next_actions(entry.hypothesis, entry.result):
                    state.next_actions.setdefault(action.key(), action)
        if self.on_result is not None:
            self.on_result(entry)


def observation_summary(evidence: SessionEvidence) -> list[dict[str, Any]]:
    """Structured, bounded facts for a proposer (no server-controlled text)."""
    from avra.verification.evidence import HttpObservation, TcpPortObservation

    out = []
    for o in evidence.observations:
        item: dict[str, Any] = {"target": o.target.label(), "evidence": o.ref.request_id,
                                "kind": o.ref.kind.value}
        if isinstance(o, TcpPortObservation):
            item.update(state=o.state, reason=o.reason)
        elif isinstance(o, HttpObservation):
            item.update(outcome=o.outcome, complete=o.complete, truncated=o.truncated)
            if o.facts is not None:
                item.update(protocol_observed=o.facts.protocol_observed,
                            status=o.facts.status_code,
                            header_names=sorted({h.name for h in o.facts.headers})[:60])
        out.append(item)
    return out
