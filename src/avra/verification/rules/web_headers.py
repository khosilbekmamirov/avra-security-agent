"""Passive web-security rules on recorded HTTP responses (ADR 0015 sprint).

Same evidence discipline as ``MissingNosniffRule`` (M8.4): only a trusted,
complete, untruncated 2xx ``GET /`` response with a body, a terminated header
section, no dropped and no malformed header lines is eligible. A duplicate of a
header a rule depends on makes that response ineligible (ambiguous). Mixed
eligible evidence is INCONCLUSIVE. Nothing here sends traffic: the rules read
recorded, hash-checked envelopes only.

Rules (all about the response to ``GET /`` at collection time):
- ``http.missing_content_security_policy`` (low): no ``Content-Security-Policy``
  header (``-Report-Only`` does not enforce anything, so it does not count).
- ``http.missing_clickjacking_protection`` (low): neither ``X-Frame-Options``
  ``DENY``/``SAMEORIGIN`` nor a CSP ``frame-ancestors`` directive.
- ``http.cors_wildcard_origin`` (info): ``Access-Control-Allow-Origin: *``.
- ``http.version_disclosure`` (info): ``Server`` or ``X-Powered-By`` reveals a
  version number.
"""

from __future__ import annotations

import re

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

_VERSION = re.compile(r"\d+\.\d+")


def _values(o: HttpObservation, name: str) -> list[str]:
    return [h.value for h in o.facts.headers if h.name == name]


class _HeaderRule(VerificationRule):
    """Shared eligibility, verdict logic and follow-up for one-response header checks."""

    kind = RuleKind.VULNERABILITY
    version = "1"
    evidence_kinds = frozenset({EvidenceKind.HTTP_ENVELOPE})
    depends_on: tuple[str, ...] = ()  # header names whose duplicates make a response ambiguous
    finding_code = "weakness_present"
    clean_code = "weakness_absent"
    base_limitations = (
        "Only the response to GET / was examined; other paths and content types may differ.",
        "True for the time the evidence was collected.",
    )

    def weak(self, o: HttpObservation) -> tuple[bool, str]:  # -> (weakness present?, detail)
        raise NotImplementedError

    def _ineligible(self, o: HttpObservation) -> str | None:
        f = o.facts
        if getattr(o, "path", "/") != "/":
            return "not the GET / response (M10.5 path fetches are judged separately)"
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
        for name in self.depends_on:
            if len(_values(o, name)) > 1:
                return f"duplicate {name} headers"
        return None

    def evaluate(self, hypothesis: Hypothesis, observations: list) -> RuleEvaluation:
        obs = [o for o in observations if isinstance(o, HttpObservation)]
        c_elig, c_weak, c_ok = self.criteria
        missing = (f"a complete, untruncated 2xx http_probe response for {hypothesis.target.label()}",)
        eligible, skipped = [], []
        for o in obs:
            why = self._ineligible(o)
            (skipped if why else eligible).append((o, why))
        if not eligible:
            detail = "; ".join(sorted({w for _, w in skipped})) or "no http_probe evidence"
            return RuleEvaluation(
                Verdict.INCONCLUSIVE, "no_evidence" if not obs else "insufficient_evidence",
                f"No eligible response ({detail}).",
                (check(c_elig, False, detail), check(c_weak, None), check(c_ok, None)),
                missing_evidence=missing)
        judged = [(o, *self.weak(o)) for o, _ in eligible]
        bad = [(o, d) for o, w, d in judged if w]
        good = [(o, d) for o, w, d in judged if not w]
        checks = (check(c_elig, True, f"{len(eligible)} eligible response(s)"),
                  check(c_weak, bool(bad), bad[0][1] if bad else ""),
                  check(c_ok, bool(good), good[0][1] if good else ""))
        used = tuple(o for o, _ in bad + good)
        if bad and good:
            return RuleEvaluation(Verdict.INCONCLUSIVE, "contradictory_evidence",
                                  "Eligible responses disagree.", checks, used=used)
        if bad:
            return RuleEvaluation(Verdict.CONFIRMED, self.finding_code,
                                  f"The served 2xx response: {bad[0][1]}.", checks,
                                  used=tuple(o for o, _ in bad))
        return RuleEvaluation(Verdict.REJECTED, self.clean_code,
                              f"Every eligible response: {good[0][1]}.", checks,
                              used=tuple(o for o, _ in good))

    def suggest(self, ctx: SuggestContext):
        for t in ctx.confirmed(HttpServiceObservedRule.id):
            yield Suggestion(t, "an HTTP service is verified; check its response headers")

    def next_actions(self, hypothesis: Hypothesis, result: VerificationResult):
        if result.verdict is Verdict.INCONCLUSIVE and result.reason_code in (
                "no_evidence", "insufficient_evidence"):
            yield ProposedAction(tool="http_probe", target=hypothesis.target,
                                 reason="a complete 2xx response to GET / is needed")


def _criteria(weak: str, ok: str) -> tuple[Criterion, Criterion, Criterion]:
    return (Criterion(id="eligible_response", polarity="positive",
                      description="A trusted, complete, untruncated 2xx response with a fully "
                                  "parsed header section and a body exists."),
            Criterion(id="weakness_present", polarity="positive", description=weak),
            Criterion(id="weakness_absent", polarity="negative", description=ok))


_CONFIRMED_BASE = ("At least one trusted http_probe response for this host:port that is "
                   "complete, not truncated, 2xx with a body, has a terminated header section "
                   "with no dropped or malformed header lines and no duplicate of the relevant "
                   "header(s), and ")


class MissingCspRule(_HeaderRule):
    id = "http.missing_content_security_policy"
    severity = "low"
    title = "Response lacks a Content-Security-Policy"
    description = ("The served page sends no enforcing Content-Security-Policy, so the browser "
                   "has no policy limiting script sources (reduced XSS mitigation).")
    references = ("CWE-693", "OWASP Secure Headers Project: Content-Security-Policy")
    depends_on = ("content-security-policy",)
    finding_code, clean_code = "csp_missing", "csp_present"
    criteria = _criteria("The response has no Content-Security-Policy header.",
                         "The response sends a Content-Security-Policy header.")
    confirmed_requires = _CONFIRMED_BASE + ("has no Content-Security-Policy header "
                                            "(Report-Only does not count); and none that has one.")
    limitations = (*_HeaderRule.base_limitations,
                   "Hardening gap, not a vulnerability on its own; a policy's quality is not judged.")

    def weak(self, o):
        v = _values(o, "content-security-policy")
        return (not v, "no Content-Security-Policy header" if not v
                else "Content-Security-Policy present")


class MissingClickjackingProtectionRule(_HeaderRule):
    id = "http.missing_clickjacking_protection"
    severity = "low"
    title = "Response does not restrict framing (clickjacking)"
    description = ("Neither X-Frame-Options (DENY or SAMEORIGIN) nor a CSP frame-ancestors "
                   "directive restricts who may frame the page.")
    references = ("CWE-1021", "OWASP Clickjacking Defense Cheat Sheet")
    depends_on = ("x-frame-options", "content-security-policy")
    finding_code, clean_code = "framing_unrestricted", "framing_restricted"
    criteria = _criteria("No X-Frame-Options DENY/SAMEORIGIN and no CSP frame-ancestors.",
                         "X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors is sent.")
    confirmed_requires = _CONFIRMED_BASE + ("sends neither X-Frame-Options DENY/SAMEORIGIN nor a "
                                            "CSP frame-ancestors directive; and none that does.")
    limitations = (*_HeaderRule.base_limitations,
                   "Only matters for pages with state-changing UI; not exploitable on its own.")

    def weak(self, o):
        xfo = [v.strip().lower() for v in _values(o, "x-frame-options")]
        csp = " ".join(_values(o, "content-security-policy")).lower()
        if xfo and xfo[0] in ("deny", "sameorigin"):
            return False, f"X-Frame-Options: {xfo[0].upper()}"
        if "frame-ancestors" in csp:
            return False, "CSP frame-ancestors present"
        return True, ("X-Frame-Options value not DENY/SAMEORIGIN" if xfo
                      else "no X-Frame-Options and no CSP frame-ancestors")


class CorsWildcardRule(_HeaderRule):
    id = "http.cors_wildcard_origin"
    severity = "informational"
    title = "Response allows any origin to read it (CORS *)"
    description = ("Access-Control-Allow-Origin: * lets scripts on any web origin read this "
                   "response. Fine for public content; risky if the same policy covers APIs "
                   "with user data.")
    references = ("CWE-942", "OWASP Testing Guide: Testing Cross Origin Resource Sharing")
    depends_on = ("access-control-allow-origin",)
    finding_code, clean_code = "cors_wildcard", "cors_not_wildcard"
    criteria = _criteria("The response sends Access-Control-Allow-Origin: *.",
                         "The response sends no wildcard Access-Control-Allow-Origin.")
    confirmed_requires = _CONFIRMED_BASE + ("sends Access-Control-Allow-Origin: *; and none "
                                            "that does not.")
    limitations = (*_HeaderRule.base_limitations,
                   ("Only GET / was examined: whether API endpoints share this policy, and "
                    "whether credentials are allowed, is not shown by this evidence."))

    def weak(self, o):
        v = [x.strip() for x in _values(o, "access-control-allow-origin")]
        return (bool(v) and v[0] == "*",
                "Access-Control-Allow-Origin: *" if v and v[0] == "*"
                else f"Access-Control-Allow-Origin: {v[0]}" if v else "no CORS header")


class VersionDisclosureRule(_HeaderRule):
    id = "http.version_disclosure"
    severity = "informational"
    title = "Server software version disclosed in headers"
    description = ("Server or X-Powered-By reveals a version number, which helps an attacker "
                   "match known vulnerabilities. The value is a server claim, not proof of "
                   "the version.")
    references = ("CWE-200", "OWASP WSTG-INFO-02 Fingerprint Web Server")
    depends_on = ("server", "x-powered-by")
    finding_code, clean_code = "version_disclosed", "no_version_disclosed"
    criteria = _criteria("Server or X-Powered-By contains a version number.",
                         "Neither header contains a version number.")
    confirmed_requires = _CONFIRMED_BASE + ("has a Server or X-Powered-By value containing a "
                                            "version number (digits.digits); and none without.")
    limitations = (*_HeaderRule.base_limitations,
                   "Header values are server-controlled claims; the real version may differ.")

    def weak(self, o):
        for name in self.depends_on:
            for v in _values(o, name):
                if _VERSION.search(v):
                    return True, f"{name}: {v[:80]}"
        return False, "no version number in Server / X-Powered-By"


WEB_HEADER_RULES = (MissingCspRule, MissingClickjackingProtectionRule, CorsWildcardRule,
                    VersionDisclosureRule)
