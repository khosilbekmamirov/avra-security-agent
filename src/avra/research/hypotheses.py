"""Evidence-driven hypothesis planning (M10.2, ADR 0017).

The ``HypothesisBoard`` is the research agent's structured working memory. It
keeps six things strictly apart:

* **observed facts**        - verified observations (engine CONFIRMED observation
                              rules) and endpoint references seen in recorded
                              responses (M10.1 web surface: referenced, not fetched);
* **potential weaknesses**  - CONFIRMED configuration-weakness rules (hardening
                              gaps, not proven exploitable);
* **verified findings**     - CONFIRMED vulnerability rules that are not mere
                              configuration weaknesses;
* **untested hypotheses**   - research hypotheses no deterministic check has decided;
* **rejected hypotheses**   - REJECTED by the engine;
* **missing evidence**      - what would decide an open hypothesis.

A ``ResearchHypothesis`` is a *proposal* (from the model or the rules). Its
``state`` is NEVER taken from the proposer: it is derived from the Verification
Engine's verdict for the linked rule (``confirmed``/``rejected`` only from the
engine), or from what is missing (``needs_evidence``) or not available yet
(``needs_capability``). Model-cited evidence ids are checked against the
session's trusted evidence; unknown ids are kept apart as ``unverified_refs``.
An endpoint the model names is marked ``endpoint_observed`` only if it occurs in
the recorded web surface - the model cannot introduce an endpoint as a fact.

The priority score orders RESEARCH WORK (evidence quality x impact / cost of the
next check). It is not a likelihood of exploitability.

Pure and deterministic: no I/O except the audit records it writes, no clock.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from avra.verification.models import (
    Hypothesis,
    RuleKind,
    Target,
    Verdict,
    canonical_json,
    sha256_hex,
)

if TYPE_CHECKING:
    from avra.recon.web_surface import WebSurface
    from avra.storage.audit import AuditLog
    from avra.verification.loop import VerificationLoop

PRIORITY_NOTE = "research-planning priority (what to examine next), not exploitability"
MAX_BOARD = 60
MAX_REFS = 10
MAX_REQUIRED = 5
MAX_TEXT = 500
_PATH = re.compile(r"^/[A-Za-z0-9\-._~!$&'()*+,;=:@%/#?]{0,299}$")
_REF = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")


class VulnClass(str, Enum):
    MISSING_SECURITY_HEADER = "missing_security_header"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    INFORMATION_DISCLOSURE = "information_disclosure"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    SENSITIVE_ENDPOINT_EXPOSURE = "sensitive_endpoint_exposure"
    BROKEN_ACCESS_CONTROL = "broken_access_control"   # incl. IDOR
    AUTHENTICATION_WEAKNESS = "authentication_weakness"
    INJECTION = "injection"
    XSS = "xss"
    NETWORK_EXPOSURE = "network_exposure"
    OTHER = "other"


class State(str, Enum):
    UNTESTED = "untested"                  # a check exists but has not run
    NEEDS_EVIDENCE = "needs_evidence"      # engine INCONCLUSIVE: evidence missing
    NEEDS_CAPABILITY = "needs_capability"  # no deterministic check (or not authorized yet)
    CONFIRMED = "confirmed"                # engine CONFIRMED - never set by a proposer
    REJECTED = "rejected"                  # engine REJECTED - never set by a proposer


RESOLVED = frozenset({State.CONFIRMED, State.REJECTED})

# Impact weights for ordering research work (not severity ratings of findings).
IMPACT = {VulnClass.INJECTION: 4.0, VulnClass.BROKEN_ACCESS_CONTROL: 4.0,
          VulnClass.AUTHENTICATION_WEAKNESS: 3.5, VulnClass.XSS: 3.0,
          VulnClass.SENSITIVE_ENDPOINT_EXPOSURE: 2.5, VulnClass.CORS_MISCONFIGURATION: 2.0,
          VulnClass.SECURITY_MISCONFIGURATION: 1.5, VulnClass.INFORMATION_DISCLOSURE: 1.5,
          VulnClass.MISSING_SECURITY_HEADER: 1.0, VulnClass.NETWORK_EXPOSURE: 1.0,
          VulnClass.OTHER: 1.0}
CONFIDENCE = {"low": 0.7, "medium": 0.85, "high": 1.0}
# Cost of the next step: an offline check is cheap; new evidence costs a tool run.
ACTION_COST = {"verify_rule": 0.25, "validation_check": 0.25, "http_probe": 1.0,
               "http_get_path": 1.0, "nmap_connect_scan": 2.0}

# Which verification rules can decide a class (rule ids in the catalogue).
CLASS_RULES: dict[VulnClass, tuple[str, ...]] = {
    VulnClass.MISSING_SECURITY_HEADER: ("http.missing_content_security_policy",
                                        "http.missing_clickjacking_protection",
                                        "http.missing_x_content_type_options"),
    VulnClass.CORS_MISCONFIGURATION: ("http.cors_wildcard_origin",
                                      "http.cors_wildcard_with_credentials"),
    VulnClass.INFORMATION_DISCLOSURE: ("http.version_disclosure",),
    VulnClass.SECURITY_MISCONFIGURATION: ("http.cookie_missing_httponly",),
    VulnClass.NETWORK_EXPOSURE: ("net.tcp_port_open",),
}
RULE_CLASS: dict[str, VulnClass] = {r: c for c, rules in CLASS_RULES.items() for r in rules}
RULE_CLASS["http.service_observed"] = VulnClass.NETWORK_EXPOSURE


@dataclass(frozen=True)
class NextAction:
    kind: str           # verify_rule | validation_check | http_probe | nmap_connect_scan | none
    available: bool     # can the research agent take it in this session?
    reason: str
    rule_id: str = ""

    def as_dict(self) -> dict:
        return {"kind": self.kind, "available": self.available, "reason": self.reason,
                **({"rule_id": self.rule_id} if self.rule_id else {})}


@dataclass(frozen=True)
class ResearchHypothesis:
    id: str
    vuln_class: VulnClass
    target: Target
    endpoint: str                    # "" = the service as a whole
    statement: str
    origin: str                      # model | rules
    evidence_refs: tuple[str, ...]   # cited AND found in trusted evidence
    unverified_refs: tuple[str, ...]  # cited but NOT found (possible hallucination)
    endpoint_observed: bool | None   # None when no endpoint was named
    confidence: str                  # the proposer's own claim: low | medium | high
    uncertainty: str
    required_evidence: tuple[str, ...]
    verification_rule: str           # "" when no rule applies

    @staticmethod
    def make_id(vuln_class: VulnClass, target: Target, endpoint: str, rule: str) -> str:
        key = canonical_json({"class": vuln_class.value, "target": target.label(),
                              "endpoint": endpoint, "rule": rule})
        return "RH-" + sha256_hex(key)[:16]


@dataclass
class BoardEntry:
    hypothesis: ResearchHypothesis
    state: State
    step: int
    verdict: dict | None = None          # engine verdict this state came from
    missing: tuple[str, ...] = ()
    next_action: NextAction = field(default_factory=lambda: NextAction("none", False, ""))
    priority: dict = field(default_factory=dict)
    history: list[tuple[int, str]] = field(default_factory=list)
    repeats: int = 0


@dataclass(frozen=True)
class Proposal:
    ok: bool
    status: str        # recorded | duplicate | already_resolved | invalid | out_of_scope | budget
    message: str
    entry: BoardEntry | None = None


class HypothesisBoard:
    def __init__(self, *, loop: VerificationLoop, audit: AuditLog,
                 surfaces: list[WebSurface] | None = None,
                 agent_tools: frozenset[str] = frozenset(),
                 max_entries: int = MAX_BOARD) -> None:
        self.loop, self.audit = loop, audit
        self.surfaces = list(surfaces or [])
        self.agent_tools = agent_tools
        self.max_entries = max_entries
        self.entries: dict[str, BoardEntry] = {}

    # --- inputs ---------------------------------------------------------------------------

    def set_surfaces(self, surfaces: list[WebSurface]) -> None:
        self.surfaces = list(surfaces)

    def _observed(self, target: Target, endpoint: str) -> bool:
        base = endpoint.split("?", 1)[0]
        return any(s.host == target.host and s.port == target.port
                   and (endpoint in s.paths() or base in s.paths()) for s in self.surfaces)

    def fetch_info(self, target: Target, endpoint: str) -> dict | None:
        """M12.2: AVRA's own fetches of exactly this path (status + evidence ids), or None.
        A fetch is an observed fact about the endpoint, never a verdict on a weakness."""
        for s in self.surfaces:
            if (s.host, s.port) != (target.host, target.port):
                continue
            for e in s.endpoints:
                if e.path == endpoint and e.fetches:
                    return {"http_status": [st for _, st in e.fetches],
                            "evidence": [rid for rid, _ in e.fetches]}
        return None

    def _fetched(self, target: Target, endpoint: str) -> bool:
        return any(e.path == endpoint and e.status == "fetched" for s in self.surfaces
                   if (s.host, s.port) == (target.host, target.port) for e in s.endpoints)

    def _in_scope(self, host: str, port: int) -> bool:
        checker = self.loop.checker
        return checker is not None and any(
            t.host == host and port in t.ports for t in checker.scope.targets)

    def propose(self, *, step: int, vuln_class: str, host: str, port: int, endpoint: str,
                statement: str, supporting_evidence: list[str], confidence: str,
                uncertainty: str, required_evidence: list[str], verification_rule: str,
                origin: str = "model") -> Proposal:
        """Validate and record a structured hypothesis. Never decides its truth."""
        try:
            vc = VulnClass(vuln_class)
        except ValueError:
            return self._refuse(step, "invalid", f"unknown vuln_class {str(vuln_class)[:40]!r}; "
                                f"use one of: {', '.join(c.value for c in VulnClass)}")
        if not self._in_scope(host, port):
            return self._refuse(step, "out_of_scope",
                                f"{str(host)[:64]}:{port} is not a target in this session's scope")
        endpoint = (endpoint or "").strip()
        if endpoint and not _PATH.fullmatch(endpoint):
            return self._refuse(step, "invalid", "endpoint must be a same-origin path such as "
                                "/rest/products (no scheme, host or spaces)")
        if confidence not in CONFIDENCE:
            return self._refuse(step, "invalid", "confidence must be low, medium or high")
        rule = (verification_rule or "").strip()
        if rule and self.loop.registry.get(rule) is None:
            return self._refuse(step, "invalid", f"verification_rule {rule[:80]!r} is not in "
                                "the rule catalogue; leave it empty if no rule applies")
        if rule and endpoint:
            # every current rule examines GET / of the service, not a specific path
            return self._refuse(step, "invalid", "catalogue rules check the service's GET / "
                                "response; use endpoint \"\" with a verification_rule")
        target = Target(host=host, port=port)
        hid = ResearchHypothesis.make_id(vc, target, endpoint, rule)
        known = self.entries.get(hid)
        if known is not None:
            known.repeats += 1
            self.audit.record("research_hypothesis_repeat", {
                "step": step, "hypothesis_id": hid, "state": known.state.value})
            if known.state in RESOLVED:
                return Proposal(True, "already_resolved",
                                f"Already {known.state.value} by the engine; not re-examined.",
                                known)
            return Proposal(True, "duplicate", f"Already on the board ({known.state.value}).",
                            known)
        if len(self.entries) >= self.max_entries:
            return self._refuse(step, "budget", f"the board holds at most {self.max_entries} "
                                "hypotheses")
        known_refs = set(self.loop.evidence.refs()) if self.loop.evidence else set()
        cited = list(dict.fromkeys(str(r)[:64] for r in supporting_evidence))[:MAX_REFS]
        h = ResearchHypothesis(
            id=hid, vuln_class=vc, target=target, endpoint=endpoint,
            statement=statement[:MAX_TEXT], origin=origin,
            evidence_refs=tuple(r for r in cited if r in known_refs),
            unverified_refs=tuple(r for r in cited if r not in known_refs),
            endpoint_observed=self._observed(target, endpoint) if endpoint else None,
            confidence=confidence, uncertainty=uncertainty[:MAX_TEXT],
            required_evidence=tuple(str(x)[:200] for x in required_evidence)[:MAX_REQUIRED],
            verification_rule=rule)
        entry = BoardEntry(h, State.UNTESTED, step)
        self.entries[hid] = entry
        self.audit.record("research_hypothesis", {
            "step": step, "hypothesis_id": hid, "vuln_class": vc.value,
            "target": target.label(), "endpoint": endpoint, "origin": origin,
            "evidence_refs": list(h.evidence_refs), "unverified_refs": list(h.unverified_refs),
            "endpoint_observed": h.endpoint_observed, "confidence": confidence,
            "verification_rule": rule, "statement": h.statement})
        self._update(entry, step)
        msg = f"Recorded {hid} ({entry.state.value})."
        if h.unverified_refs:
            msg += (f" {len(h.unverified_refs)} cited evidence id(s) do not exist in this "
                    "session's trusted evidence and support nothing.")
        if h.endpoint_observed is False:
            msg += (" The endpoint does not occur in any recorded response: it is your "
                    "guess, not an observed fact.")
        return Proposal(True, "recorded", msg, entry)

    def _refuse(self, step: int, status: str, reason: str) -> Proposal:
        self.audit.record("research_hypothesis_refused", {"step": step, "status": status,
                                                          "reason": reason[:300]})
        return Proposal(False, status, f"Not recorded: {reason}.")

    # --- state ----------------------------------------------------------------------------

    def _engine_entry(self, rule_id: str, target: Target):
        return self.loop.entries.get(Hypothesis.make_id(rule_id, target, {}))

    def _update(self, e: BoardEntry, step: int) -> None:
        h = e.hypothesis
        rule = h.verification_rule
        candidates = (rule,) if rule else tuple(
            r for r in CLASS_RULES.get(h.vuln_class, ()) if self.loop.registry.get(r)) \
            if not h.endpoint else ()
        state, verdict, missing, action = State.NEEDS_CAPABILITY, None, (), NextAction(
            "none", False, "no deterministic check for this class and endpoint exists yet; "
            "an active check would need a separate owner authorization")
        decided = [(r, self._engine_entry(r, h.target)) for r in candidates]
        decided = [(r, x) for r, x in decided if x is not None]
        if rule and decided:
            x = decided[0][1]
            state, verdict, missing = _from_verdict(x)
        elif not rule and decided:
            # class-level hypothesis: CONFIRMED if any applicable rule confirms; REJECTED
            # only if every applicable rule was decided and all rejected
            verdicts = [x.result.verdict for _, x in decided]
            if Verdict.CONFIRMED in verdicts:
                x = next(x for _, x in decided if x.result.verdict is Verdict.CONFIRMED)
                state, verdict, missing = _from_verdict(x)
            elif len(decided) == len(candidates) and all(v is Verdict.REJECTED for v in verdicts):
                x = decided[0][1]
                state, verdict, missing = _from_verdict(x)
            else:
                state = State.UNTESTED if any(v is not Verdict.INCONCLUSIVE for v in verdicts) \
                    or len(decided) < len(candidates) else State.NEEDS_EVIDENCE
                missing = tuple(m for _, x in decided for m in x.result.missing_evidence)[:5]
        elif candidates:
            state = State.UNTESTED
        elif (h.endpoint and h.endpoint_observed and "http_get_path" in self.agent_tools
              and not h.endpoint.startswith("/#") and not self._fetched(h.target, h.endpoint)):
            # M10.5: the referenced endpoint can be fetched read-only to collect evidence
            action = NextAction("http_get_path", True, "fetch the referenced path (one "
                                "read-only GET) to confirm it exists and collect evidence")
        else:
            from avra.verification.validation import CLASS_CHECKS, live_authorization

            check_id = CLASS_CHECKS.get(h.vuln_class.value)
            if check_id is not None:  # M10.4: a fixture-only check exists; live is refused
                _ok, why = live_authorization(check_id)
                action = NextAction("validation_check", False,
                                    f"deterministic check {check_id} exists for fixtures; "
                                    + why, check_id)
        if state is State.UNTESTED:
            todo = next((r for r in candidates if self._engine_entry(r, h.target) is None),
                        candidates[0] if candidates else "")
            action = NextAction("verify_rule", True, "an offline deterministic check of the "
                                "recorded evidence can decide this", todo)
        elif state is State.NEEDS_EVIDENCE:
            action = self._evidence_action(h.target)
        elif state in RESOLVED:
            action = NextAction("none", False, f"decided by the engine ({state.value})")
        if (state.value, (verdict or {}).get("reason_code")) != (
                e.state.value, (e.verdict or {}).get("reason_code")) or not e.history:
            e.history.append((step, state.value))
            if len(e.history) > 1 or state is not State.UNTESTED:
                self.audit.record("research_hypothesis_state", {
                    "step": step, "hypothesis_id": h.id, "state": state.value,
                    "previous": e.state.value if len(e.history) > 1 else None,
                    "verdict": verdict})
        e.state, e.verdict, e.missing, e.next_action = state, verdict, missing, action
        e.priority = self._priority(e)

    def _evidence_action(self, target: Target) -> NextAction:
        for p in self.loop.plan():
            if p.action.target == target:
                ok = p.executor == "agent" and p.score > 0 and p.action.tool in self.agent_tools
                return NextAction(p.action.tool, ok,
                                  p.blocked_reason or p.action.reason
                                  if not ok else p.action.reason)
        return NextAction("none", False, "no permitted tool would produce the missing evidence")

    def _priority(self, e: BoardEntry) -> dict:
        h = e.hypothesis
        quality = 0.2 + (0.3 if h.evidence_refs else 0.0) - (0.1 if h.unverified_refs else 0.0)
        quality += {True: 0.2, False: -0.1, None: 0.1}[h.endpoint_observed]
        fetched = self.fetch_info(h.target, h.endpoint) if h.endpoint else None
        if fetched and any(st is not None and 200 <= st < 300 for st in fetched["http_status"]):
            quality += 0.2  # M12.2: the endpoint really answered (fetched evidence)
        svc = self._engine_entry("http.service_observed", h.target)
        if svc is not None and svc.result.verdict is Verdict.CONFIRMED:
            quality += 0.3
        quality = round(min(1.0, max(0.1, quality)), 3)
        impact = IMPACT[h.vuln_class]
        act = e.next_action
        cost = ACTION_COST.get(act.kind)
        if e.state in RESOLVED or not act.available or cost is None:
            score = 0.0
        else:
            score = round(quality * impact * CONFIDENCE[h.confidence] / cost, 3)
        return {"score": score, "evidence_quality": quality, "impact": impact,
                "next_step_cost": cost, "note": PRIORITY_NOTE}

    def sync(self, step: int) -> None:
        """Re-derive every state from the engine (after new evidence or verdicts) and
        mirror engine-decided rule hypotheses onto the board (origin ``rules``)."""
        for le in sorted(self.loop.entries.values(), key=lambda x: x.hypothesis.id):
            rule_id = le.hypothesis.rule_id
            vc = RULE_CLASS.get(rule_id)
            if vc is None:
                continue
            t = le.hypothesis.target
            hid = ResearchHypothesis.make_id(vc, t, "", rule_id)
            if hid not in self.entries and len(self.entries) < self.max_entries:
                rule = self.loop.registry.get(rule_id)
                self.entries[hid] = BoardEntry(ResearchHypothesis(
                    id=hid, vuln_class=vc, target=t, endpoint="", statement=rule.title,
                    origin="rules", evidence_refs=(), unverified_refs=(),
                    endpoint_observed=None, confidence="medium", uncertainty="",
                    required_evidence=tuple(sorted(k.value for k in rule.evidence_kinds)),
                    verification_rule=rule_id), State.UNTESTED, step)
        for e in self.entries.values():
            self._update(e, step)

    # --- views ----------------------------------------------------------------------------

    def ranked(self) -> list[BoardEntry]:
        return sorted(self.entries.values(),
                      key=lambda e: (-e.priority.get("score", 0.0), e.hypothesis.id))

    def ledger(self, limit: int = 8) -> dict:
        """The six categories, bounded. No server-controlled text except URL-safe paths."""
        from avra.assessment import CONFIG_WEAKNESS_RULES

        def item(e: BoardEntry) -> dict:
            h = e.hypothesis
            out = {"id": h.id, "class": h.vuln_class.value, "target": h.target.label(),
                   "state": e.state.value, "origin": h.origin}
            if h.endpoint:
                out.update(endpoint=h.endpoint, endpoint_observed=h.endpoint_observed)
            if h.verification_rule:
                out["rule"] = h.verification_rule
            if h.unverified_refs:
                out["unverified_refs"] = len(h.unverified_refs)
            if h.endpoint:
                fetched = self.fetch_info(h.target, h.endpoint)
                out["endpoint_fetched"] = fetched or False
            return out

        facts, weak, found = [], [], []
        for le in sorted(self.loop.entries.values(), key=lambda x: x.hypothesis.id):
            r = le.result
            if r.verdict is not Verdict.CONFIRMED:
                continue
            row = {"rule": r.rule_id, "target": r.target.label(),
                   "proof": [x.request_id for x in r.evidence_used][:3]}
            if r.rule_kind is RuleKind.OBSERVATION:
                facts.append(row)
            elif r.rule_id in CONFIG_WEAKNESS_RULES:
                weak.append(row)
            else:
                found.append(row)
        for s in self.surfaces:
            for e in [e for e in s.endpoints if e.fetches][:limit]:
                facts.append({"fetched_endpoint": f"{s.origin}{e.path}",
                              "http_status": [st for _, st in e.fetches],
                              "evidence": [rid for rid, _ in e.fetches],
                              "status": "fetched (exists/answers; nothing about weaknesses)"})
            facts.append({"web_surface": s.origin, "endpoint_references": len(s.endpoints),
                          "forms": len(s.forms), "status": "referenced_not_fetched"})
        ranked = self.ranked()
        missing = sorted({m for e in ranked if e.state is State.NEEDS_EVIDENCE for m in e.missing}
                         | {r for e in ranked if e.state is State.NEEDS_CAPABILITY
                            for r in e.hypothesis.required_evidence})
        return {
            "observed_facts": facts[:limit],
            "potential_weaknesses": weak[:limit],
            "verified_findings": found[:limit],
            "untested_hypotheses": [
                {**item(e), "priority": e.priority.get("score", 0.0),
                 "next_action": e.next_action.as_dict()}
                for e in ranked if e.state not in RESOLVED][:limit],
            "rejected_hypotheses": [item(e) for e in ranked
                                    if e.state is State.REJECTED][:limit],
            "missing_evidence": missing[:limit],
            "priority_note": PRIORITY_NOTE,
        }

    def summary(self) -> dict:
        by = {s.value: 0 for s in State}
        for e in self.entries.values():
            by[e.state.value] += 1
        return {"hypotheses": len(self.entries), "states": by,
                "model_proposed": sum(1 for e in self.entries.values()
                                      if e.hypothesis.origin == "model"),
                "unverified_citations": sum(len(e.hypothesis.unverified_refs)
                                            for e in self.entries.values()),
                "unobserved_endpoints": sum(1 for e in self.entries.values()
                                            if e.hypothesis.endpoint_observed is False)}

    def marker(self) -> tuple:
        return tuple(sorted((hid, e.state.value) for hid, e in self.entries.items()))


def _from_verdict(x: Any) -> tuple[State, dict, tuple[str, ...]]:
    r = x.result
    state = {Verdict.CONFIRMED: State.CONFIRMED, Verdict.REJECTED: State.REJECTED,
             Verdict.INCONCLUSIVE: State.NEEDS_EVIDENCE}[r.verdict]
    return state, {"engine_hypothesis": x.hypothesis.id, "rule": r.rule_id,
                   "verdict": r.verdict.value, "reason_code": r.reason_code}, \
        tuple(r.missing_evidence)[:5]
