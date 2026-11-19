"""The Verification Engine (M8.4, ADR 0009).

``VerificationEngine.verify(hypothesis, evidence)`` is the ONLY place a
``VerificationResult`` (and so a verdict) is created. It is deterministic:
no I/O beyond what ``SessionEvidence`` already loaded, no clock, no model.

Fail-closed order of checks:

1. unknown rule                        -> INCONCLUSIVE ``unsupported_rule``
2. invalid parameters                  -> INCONCLUSIVE ``invalid_hypothesis``
3. untrusted session (missing/broken audit chain)
                                       -> INCONCLUSIVE ``untrusted_evidence``
4. the rule evaluates ONLY trusted observations of its evidence kinds for
   the hypothesis' exact target;
5. invariant: CONFIRMED/REJECTED must cite >= 1 observation, all of which
   belong to that trusted, target-filtered set — otherwise the decision is
   downgraded to INCONCLUSIVE ``rule_invariant_violation``.

Evidence a hypothesis *cites* is never trusted because it is cited: a
citation that does not resolve to trusted evidence for the target is
listed under ``evidence_excluded`` (``unresolved_citation``).
"""

from __future__ import annotations

from avra.verification.evidence import SessionEvidence
from avra.verification.models import (
    EvidenceIssue,
    Hypothesis,
    Verdict,
    VerificationResult,
)
from avra.verification.rules import RuleRegistry, default_registry


class VerificationEngine:
    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or default_registry()

    def verify(self, hypothesis: Hypothesis, evidence: SessionEvidence) -> VerificationResult:
        rule = self.registry.get(hypothesis.rule_id)
        base = {"hypothesis_id": hypothesis.id, "rule_id": hypothesis.rule_id,
                "target": hypothesis.target}
        if rule is None:
            return VerificationResult(**base, rule_version="", rule_kind=None,
                                      verdict=Verdict.INCONCLUSIVE,
                                      reason_code="unsupported_rule",
                                      reason=f"No verification rule {hypothesis.rule_id!r} "
                                             "is registered; nothing can be decided.")
        base.update(rule_version=rule.version, rule_kind=rule.kind)
        limitations = tuple(sorted(set(rule.limitations)
                                   | set(evidence.provenance_limitations())))
        try:
            rule.validate_params(hypothesis.params)
        except ValueError as exc:
            return VerificationResult(**base, verdict=Verdict.INCONCLUSIVE,
                                      reason_code="invalid_hypothesis", reason=str(exc)[:300],
                                      limitations=limitations)
        excluded = list(evidence.issues)
        if not evidence.trusted:
            return VerificationResult(**base, verdict=Verdict.INCONCLUSIVE,
                                      reason_code="untrusted_evidence",
                                      reason="The session audit log is missing or its chain "
                                             "does not verify; no evidence is trusted.",
                                      evidence_excluded=_sorted_issues(excluded),
                                      limitations=limitations)

        observations = [o for o in evidence.for_target(hypothesis.target)
                        if o.ref.kind in rule.evidence_kinds]
        allowed = {o.ref.request_id for o in observations}
        for cited in hypothesis.cited_evidence:
            if cited not in allowed:
                excluded.append(EvidenceIssue(label=cited[:64], code="unresolved_citation",
                                              detail="cited evidence is not trusted evidence "
                                                     "of this rule's kind for the target"))
        ev = rule.evaluate(hypothesis, observations)
        verdict, code, reason = ev.verdict, ev.reason_code, ev.reason
        used = {o.ref.request_id: o.ref for o in ev.used}
        if verdict is not Verdict.INCONCLUSIVE and (not used or not set(used) <= allowed):
            verdict, code = Verdict.INCONCLUSIVE, "rule_invariant_violation"
            reason = "The rule's decision did not rest on trusted evidence for this target."
            used = {k: v for k, v in used.items() if k in allowed}
        return VerificationResult(
            **base, verdict=verdict, reason_code=code, reason=reason[:500],
            checks=ev.checks,
            evidence_used=tuple(sorted(used.values(), key=lambda r: (r.audit_seq, r.request_id))),
            evidence_excluded=_sorted_issues(excluded),
            missing_evidence=tuple(sorted(set(ev.missing_evidence))),
            limitations=tuple(sorted(set(limitations) | set(ev.limitations))))


def _sorted_issues(issues: list[EvidenceIssue]) -> tuple[EvidenceIssue, ...]:
    uniq = {(i.label, i.code, i.detail): i for i in issues}
    return tuple(uniq[k] for k in sorted(uniq))
