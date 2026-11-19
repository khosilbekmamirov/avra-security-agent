"""Vulnerability rule: missing ``X-Content-Type-Options: nosniff`` (M8.4).

Narrow, byte-verifiable security weakness (OWASP Secure Headers; CWE-693
Protection Mechanism Failure). Without ``nosniff`` a browser may MIME-sniff
the response and treat it as a different content type. Severity: low — a
hardening gap, not exploitable on its own.

Eligible evidence (all must hold; otherwise the observation is unusable):

* a trusted http_probe observation for this exact host:port;
* the response is complete (connection closed by the server), not
  truncated, and its header section is terminated;
* no header line was dropped (<= the parser's header limit) and none was
  malformed — a dropped or malformed line could BE the header in question;
* the status is 2xx (the page was actually served) with a non-empty body;
* at most one ``X-Content-Type-Options`` header (duplicates are ambiguous).

CONFIRMED: >= 1 eligible response without an effective ``nosniff`` (header
absent, or value not exactly ``nosniff`` case-insensitively), and no
eligible response with it. REJECTED: every eligible response sends
``nosniff``. Mixed or no eligible evidence: INCONCLUSIVE.

Only ``GET /`` is ever examined, so a CONFIRMED result is about THAT
response; other paths may differ. A generic 200, a banner or a title never
satisfies any criterion here.
"""

from __future__ import annotations

from avra.recon.http_probe import MAX_HEADERS
from avra.verification.evidence import HttpObservation
from avra.verification.models import (
    Criterion,
    EvidenceKind,
    Hypothesis,
    ProposedAction,
    RuleKind,
    Verdict,
    VerificationResult,
)
from avra.verification.rules.base import (
    RuleEvaluation,
    SuggestContext,
    Suggestion,
    VerificationRule,
    check,
)
from avra.verification.rules.observation import HttpServiceObservedRule

HEADER = "x-content-type-options"


def _ineligible_reason(o: HttpObservation) -> str | None:
    f = o.facts
    if f is None or not f.protocol_observed:
        return "no HTTP response"
    if not o.complete or o.truncated:
        return "response incomplete or truncated"
    if f.header_section_bytes is None:
        return "header section not terminated"
    if f.header_lines_total > MAX_HEADERS:
        return "header lines were dropped by the parser limit"
    if any("malformed header" in m for m in f.malformed):
        return "malformed header line(s) present"
    if f.status_code is None or not 200 <= f.status_code < 300:
        return f"status {f.status_code} is not 2xx"
    if f.body_bytes == 0:
        return "empty body"
    if sum(1 for h in f.headers if h.name == HEADER) > 1:
        return "duplicate X-Content-Type-Options headers"
    return None


def _has_nosniff(o: HttpObservation) -> bool:
    values = [h.value for h in o.facts.headers if h.name == HEADER]
    return bool(values) and values[0].strip().lower() == "nosniff"


class MissingNosniffRule(VerificationRule):
    id = "http.missing_x_content_type_options"
    version = "1"
    kind = RuleKind.VULNERABILITY
    severity = "low"
    title = "Response lacks X-Content-Type-Options: nosniff"
    description = ("The served response does not tell browsers to stop MIME-sniffing "
                   "(missing or ineffective X-Content-Type-Options header).")
    evidence_kinds = frozenset({EvidenceKind.HTTP_ENVELOPE})
    references = ("CWE-693", "OWASP Secure Headers Project: X-Content-Type-Options")
    criteria = (
        Criterion(id="eligible_response", polarity="positive",
                  description="A trusted, complete, untruncated 2xx response with a fully "
                              "parsed header section and a body exists."),
        Criterion(id="nosniff_absent", polarity="positive",
                  description="That response has no X-Content-Type-Options header, or its "
                              "value is not exactly 'nosniff'."),
        Criterion(id="nosniff_present", polarity="negative",
                  description="An eligible response sends X-Content-Type-Options: nosniff."),
    )
    confirmed_requires = (
        "At least one trusted http_probe response for this host:port that is complete, "
        "not truncated, 2xx with a body, has a terminated header section with no dropped "
        "or malformed header lines and at most one X-Content-Type-Options header, and does "
        "not send an effective 'nosniff'; and no eligible response that does.")
    limitations = (
        "Only the response to GET / was examined; other paths and content types may differ.",
        "Low-severity hardening weakness; not exploitable on its own.",
        "True for the time the evidence was collected.",
    )

    def evaluate(self, hypothesis: Hypothesis, observations: list) -> RuleEvaluation:
        obs = [o for o in observations if isinstance(o, HttpObservation)]
        c_elig, c_absent, c_present = self.criteria
        missing = (f"a complete, untruncated 2xx http_probe response for "
                   f"{hypothesis.target.label()}"),
        eligible, skipped = [], []
        for o in obs:
            why = _ineligible_reason(o)
            (skipped if why else eligible).append((o, why))
        if not eligible:
            detail = "; ".join(sorted({w for _, w in skipped})) or "no http_probe evidence"
            return RuleEvaluation(
                Verdict.INCONCLUSIVE, "no_evidence" if not obs else "insufficient_evidence",
                f"No eligible response ({detail}).",
                (check(c_elig, False, detail), check(c_absent, None), check(c_present, None)),
                missing_evidence=missing)
        lacking = [o for o, _ in eligible if not _has_nosniff(o)]
        having = [o for o, _ in eligible if _has_nosniff(o)]
        checks = (check(c_elig, True, f"{len(eligible)} eligible response(s)"),
                  check(c_absent, bool(lacking)), check(c_present, bool(having)))
        if lacking and having:
            return RuleEvaluation(Verdict.INCONCLUSIVE, "contradictory_evidence",
                                  "Some eligible responses send nosniff and some do not.",
                                  checks, used=tuple(lacking + having))
        if lacking:
            vals = sorted({h.value for o in lacking for h in o.facts.headers if h.name == HEADER})
            how = f"value {vals[0]!r} is not 'nosniff'" if vals else "header absent"
            return RuleEvaluation(Verdict.CONFIRMED, "nosniff_missing",
                                  f"The served 2xx response lacks an effective nosniff "
                                  f"({how}).", checks, used=tuple(lacking))
        return RuleEvaluation(Verdict.REJECTED, "nosniff_present",
                              "Every eligible response sends X-Content-Type-Options: nosniff.",
                              checks, used=tuple(having))

    def suggest(self, ctx: SuggestContext):
        for t in ctx.confirmed(HttpServiceObservedRule.id):
            yield Suggestion(t, "an HTTP service is verified; check its security headers")

    def next_actions(self, hypothesis: Hypothesis, result: VerificationResult):
        if result.verdict is Verdict.INCONCLUSIVE and result.reason_code in (
                "no_evidence", "insufficient_evidence"):
            yield ProposedAction(tool="http_probe", target=hypothesis.target,
                                 reason="a complete 2xx response to GET / is needed")
