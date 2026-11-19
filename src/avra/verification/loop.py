"""Verification inside the live research loop (M8.5, ADR 0010).

``VerificationLoop`` is the research state the agent carries across steps:
every hypothesis it has examined, its latest verdict and its verdict
history, the session's trusted evidence, and the ranked next actions.

It is driven by ``ResearchSession`` (core/research.py):

* ``start``           — at session start: verify what existing evidence
                        supports (e.g. an owner-run probe in this session);
* ``submit``          — the model's ``verify_hypothesis`` tool call;
* ``refresh``         — after each executed tool: reload evidence, RE-VERIFY
                        every known hypothesis (verdicts can be revised by
                        new evidence) and let the rules propose follow-ups;
* ``feedback``        — the bounded, structured digest returned to the model;
* ``progress_marker`` — what changes when research makes progress.

Everything here is offline and deterministic: it reads the session's own
audit/evidence, calls the engine, and audits every hypothesis and verdict
INSIDE the research run (``verification_hypothesis`` /
``verification_verdict``), which report replay ignores and verification
reports rebuild from. It never contacts a target and never sets a verdict
itself; model text cannot reach a verdict.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path

from avra.policy.scope import ScopeChecker
from avra.storage.audit import AuditLog
from avra.verification.cycle import CycleContext, CycleState, Entry, RuleBasedProposer
from avra.verification.engine import VerificationEngine
from avra.verification.evidence import SessionEvidence, load_session_evidence
from avra.verification.models import (
    ENGINE_VERSION,
    Hypothesis,
    Origin,
    RuleKind,
    Verdict,
    VerificationResult,
)
from avra.verification.planner import PlannedAction, plan
from avra.verification.rules import RuleRegistry

FEEDBACK_ITEMS = 12
AGENT_TOOLS = frozenset({"nmap_connect_scan"})  # what the research model can propose itself


@dataclass(frozen=True)
class LoopConfig:
    evidence_root: Path
    max_verifications: int = 40     # distinct hypotheses verified per session
    max_rule_rounds: int = 5        # rule-chaining rounds per refresh
    no_progress_steps: int = 3      # consecutive model steps without progress -> stop

    def __post_init__(self) -> None:
        if not 1 <= self.max_verifications <= 500 or not 1 <= self.max_rule_rounds <= 20 \
                or not 1 <= self.no_progress_steps <= 20:
            raise ValueError("verification loop limits out of range")


@dataclass
class LoopEntry:
    hypothesis: Hypothesis
    proposed_by: str          # "model" | "rules"
    step: int                 # model step at which it was first examined (0 = start)
    result: VerificationResult
    history: list[tuple[int, str, str]] = field(default_factory=list)  # (step, verdict, code)
    repeats: int = 0


@dataclass(frozen=True)
class Submission:
    ok: bool
    status: str  # verified | repeat | rejected_repeat | invalid | out_of_scope | budget
    message: str
    entry: LoopEntry | None = None


class VerificationLoop:
    def __init__(self, config: LoopConfig, registry: RuleRegistry | None = None) -> None:
        self.config = config
        self.engine = VerificationEngine(registry)
        self.registry = self.engine.registry
        self.entries: dict[str, LoopEntry] = {}
        self.evidence: SessionEvidence | None = None
        self.audit: AuditLog | None = None
        self.session_id = ""
        self.checker: ScopeChecker | None = None
        self.tool_runs_left = 0
        self.feedback_rounds = 0
        self.repeat_submissions = 0
        self.engine_version = ENGINE_VERSION
        # What the research model may propose itself. ResearchSession widens it only
        # when it really offers a matching tool (M9.1 --allow-http-probe).
        self.agent_tools: frozenset[str] = AGENT_TOOLS

    # --- binding / evidence ------------------------------------------------------------

    def bind(self, *, audit: AuditLog, session_id: uuid.UUID, checker: ScopeChecker,
             tool_runs_left: int) -> None:
        self.audit, self.session_id, self.checker = audit, str(session_id), checker
        self.tool_runs_left = tool_runs_left

    def _reload(self) -> bool:
        """Reload the session's trusted evidence; True if it changed."""
        before = self._evidence_key()
        self.evidence = load_session_evidence(self.audit.path.parent,
                                              self.config.evidence_root, self.session_id)
        return self._evidence_key() != before

    def _evidence_key(self) -> tuple:
        if self.evidence is None:
            return ()
        return (self.evidence.trusted,
                tuple(sorted(o.ref.request_id for o in self.evidence.observations)),
                tuple(sorted((i.label, i.code) for i in self.evidence.issues)))

    def evidence_summary(self) -> list[str]:
        """Plain counts of trusted evidence, e.g. '1 http_probe result for
        10.66.7.103:3000' (no content from the target)."""
        if self.evidence is None or not self.evidence.trusted:
            return []
        counts: dict[tuple[str, str], int] = {}
        for o in self.evidence.observations:
            key = (o.ref.tool, o.target.label())
            counts[key] = counts.get(key, 0) + 1
        return [f"{n} {tool} result{'s' if n > 1 else ''} for {target}"
                for (tool, target), n in sorted(counts.items())]

    def catalogue(self) -> list[dict]:
        return [{"rule_id": r.id, "kind": r.kind.value, "title": r.title,
                 "severity": r.severity, "evidence_needed": sorted(k.value for k in r.evidence_kinds),
                 "confirmed_requires": r.confirmed_requires} for r in self.registry.rules()]

    # --- verification ------------------------------------------------------------------

    def _record(self, entry: LoopEntry, step: int, trigger: str) -> None:
        r = entry.result
        last = entry.history[-1] if entry.history else None
        if last is not None and (last[1], last[2]) == (r.verdict.value, r.reason_code):
            return  # unchanged verdict: nothing new to record
        entry.history.append((step, r.verdict.value, r.reason_code))
        self.audit.record("verification_verdict", {
            "step": step, "trigger": trigger, "hypothesis_id": entry.hypothesis.id,
            "rule_id": r.rule_id, "rule_version": r.rule_version,
            "target": r.target.label(), "verdict": r.verdict.value,
            "reason_code": r.reason_code, "revised_from": last[1] if last else None,
            "evidence": [e.request_id for e in r.evidence_used],
            "result_sha256": r.sha256(), "engine_version": ENGINE_VERSION})

    def _add(self, h: Hypothesis, proposed_by: str, step: int, trigger: str) -> LoopEntry:
        self.audit.record("verification_hypothesis", {
            "step": step, "hypothesis_id": h.id, "rule_id": h.rule_id,
            "target": h.target.label(), "origin": h.origin.value, "proposed_by": proposed_by,
            "rationale": h.rationale})
        entry = LoopEntry(h, proposed_by, step, self.engine.verify(h, self.evidence))
        self.entries[h.id] = entry
        self._record(entry, step, trigger)
        return entry

    def _rule_rounds(self, step: int, trigger: str) -> list[LoopEntry]:
        added, proposer = [], RuleBasedProposer()
        for _ in range(self.config.max_rule_rounds):
            state = CycleState(session_id=self.session_id)
            for e in self.entries.values():  # feed current verdicts to the rules
                state.entries[e.hypothesis.id] = Entry(e.hypothesis, e.step, e.proposed_by,
                                                       e.result)
            hosts = {t.host for t in self.evidence.targets()}
            fresh = [h for h in proposer.propose(CycleContext(self.evidence, self.registry,
                                                              state, 1))
                     if h.id not in self.entries and h.target.host in hosts]
            fresh = sorted({h.id: h for h in fresh}.values(), key=lambda h: h.id)
            if not fresh:
                break
            for h in fresh:
                if len(self.entries) >= self.config.max_verifications:
                    return added
                added.append(self._add(h, "rules", step, trigger))
        return added

    def start(self) -> None:
        self._reload()
        self._rule_rounds(0, "session_start")

    def refresh(self, step: int, *, tool_runs_left: int) -> bool:
        """After new evidence. Returns True if anything changed."""
        self.tool_runs_left = tool_runs_left
        if not self._reload():
            return False
        for e in self.entries.values():  # revise: every verdict against the new evidence
            e.result = self.engine.verify(e.hypothesis, self.evidence)
            self._record(e, step, "new_evidence")
        self._rule_rounds(step, "new_evidence")
        return True

    def submit(self, *, step: int, rule_id: str, host: str, port: int,
               rationale: str) -> Submission:
        """The model's verify_hypothesis call. The engine decides; repeats and
        already-rejected claims are answered from state, not re-verified."""
        if not self._in_scope(host, port):
            self._refused(step, "out_of_scope", rule_id, host, port,
                          "target is not in this session's scope")
            return Submission(False, "out_of_scope",
                              f"{host}:{port} is not a target in this session's scope; "
                              "nothing was verified.")
        try:
            h = Hypothesis.create(rule_id=rule_id, host=host, port=port, origin=Origin.MODEL,
                                  rationale=rationale)
        except ValueError as exc:
            self._refused(step, "invalid", rule_id, host, port,
                          f"hypothesis rejected by validation ({type(exc).__name__})")
            return Submission(False, "invalid", f"Invalid hypothesis: {str(exc)[:200]}")
        known = self.entries.get(h.id)
        if known is not None:
            known.repeats += 1
            self.repeat_submissions += 1
            self.audit.record("verification_repeat", {"step": step, "hypothesis_id": h.id,
                                                      "verdict": known.result.verdict.value})
            if known.result.verdict is Verdict.REJECTED:
                return Submission(True, "rejected_repeat",
                                  "Already REJECTED by the evidence: "
                                  f"{known.result.reason} Do not propose it again.", known)
            return Submission(True, "repeat", f"Already examined: "
                              f"{known.result.verdict.value} ({known.result.reason_code}); "
                              "the evidence has not changed since.", known)
        if len(self.entries) >= self.config.max_verifications:
            self._refused(step, "budget", rule_id, host, port,
                          f"verification budget of {self.config.max_verifications} used up")
            return Submission(False, "budget", "The session's verification budget is used up.")
        entry = self._add(h, "model", step, "model_request")
        return Submission(True, "verified", f"{entry.result.verdict.value}: "
                                            f"{entry.result.reason}", entry)

    def _refused(self, step: int, status: str, rule_id: str, host: str, port: int,
                 reason: str) -> None:
        """M8.6 (G3b): every refused model request is audited. Bounded
        identifiers and a fixed reason only - no rationale or other free text."""
        self.audit.record("verification_request_refused", {
            "step": step, "status": status, "rule_id": str(rule_id)[:80],
            "host": str(host)[:64], "port": port if isinstance(port, int) else None,
            "reason": reason[:200], "verifications_used": len(self.entries),
            "max_verifications": self.config.max_verifications})

    def _in_scope(self, host: str, port: int) -> bool:
        return any(t.host == host and port in t.ports for t in self.checker.scope.targets)

    # --- feedback / planning -----------------------------------------------------------

    def plan(self) -> list[PlannedAction]:
        latest = [(hid, e.result) for hid, e in sorted(self.entries.items())]
        actions = []
        for hid, e in sorted(self.entries.items()):
            rule = self.registry.get(e.hypothesis.rule_id)
            if rule is not None and e.result.verdict is Verdict.INCONCLUSIVE:
                actions.extend(rule.next_actions(e.hypothesis, e.result))
        return plan(latest, actions, self.registry, checker=self.checker,
                    agent_tools=self.agent_tools, tool_runs_left=self.tool_runs_left)

    def feedback(self, focus: str | None = None) -> dict:
        """Bounded, structured; no server-controlled text (only reasons the
        rules wrote, ids, verdicts and evidence request ids)."""
        self.feedback_rounds += 1
        ordered = sorted(self.entries.values(), key=lambda e: (e.step, e.hypothesis.id))

        def item(e: LoopEntry) -> dict:
            return {"hypothesis_id": e.hypothesis.id, "rule_id": e.hypothesis.rule_id,
                    "target": e.hypothesis.target.label(), "verdict": e.result.verdict.value,
                    "reason": e.result.reason, "proposed_by": e.proposed_by}

        confirmed = [e for e in ordered if e.result.verdict is Verdict.CONFIRMED]
        out = {
            "engine": f"AVRA Verification Engine v{ENGINE_VERSION} (deterministic)",
            "evidence_trusted": bool(self.evidence and self.evidence.trusted),
            "verified_observations": [
                {**item(e), "proof": [r.request_id for r in e.result.evidence_used]}
                for e in confirmed if e.result.rule_kind is RuleKind.OBSERVATION
            ][:FEEDBACK_ITEMS],
            "confirmed_findings": [
                {**item(e), "severity": self.registry.get(e.hypothesis.rule_id).severity,
                 "proof": [r.request_id for r in e.result.evidence_used]}
                for e in confirmed if e.result.rule_kind is RuleKind.VULNERABILITY
            ][:FEEDBACK_ITEMS],
            "rejected": [item(e) for e in ordered
                         if e.result.verdict is Verdict.REJECTED][:FEEDBACK_ITEMS],
            "inconclusive": [{**item(e), "missing_evidence": list(e.result.missing_evidence)}
                             for e in ordered
                             if e.result.verdict is Verdict.INCONCLUSIVE][:FEEDBACK_ITEMS],
            "next_actions": [p.as_dict() for p in self.plan()][:5],
            "verifications_left": self.config.max_verifications - len(self.entries),
        }
        if focus is not None and focus in self.entries:
            e = self.entries[focus]
            out["this_hypothesis"] = {
                **item(e), "reason_code": e.result.reason_code,
                "criteria": [c.model_dump() for c in e.result.checks],
                "missing_evidence": list(e.result.missing_evidence),
                "history": [{"step": s, "verdict": v, "reason_code": c}
                            for s, v, c in e.history]}
        return out

    def progress_marker(self) -> tuple:
        return (self._evidence_key(),
                tuple(sorted((hid, e.result.verdict.value) for hid, e in self.entries.items())))

    def summary(self) -> dict:
        by = {v.value: 0 for v in Verdict}
        for e in self.entries.values():
            by[e.result.verdict.value] += 1
        findings = sum(1 for e in self.entries.values() if e.result.is_finding)
        planned = self.plan()
        return {"hypotheses": len(self.entries), "verdicts": by, "confirmed_findings": findings,
                "repeat_submissions": self.repeat_submissions,
                "feedback_rounds": self.feedback_rounds,
                # kept for older records: actions with a positive score (any executor)
                "open_next_actions": len([p for p in planned if p.score > 0]),
                # M8.6 (G2): every candidate (as in the verification report) vs
                # what the research agent itself could still run in this session
                "proposed_next_actions": len(planned),
                "agent_actionable_next_actions": len([
                    p for p in planned if p.executor == "agent" and p.score > 0])}
