"""Observation rules: verified network/protocol FACTS, never vulnerabilities.

A CONFIRMED observation ("TCP 3000 was open", "something spoke HTTP on
3000") is a fact about the target at collection time. It is reported as a
verified observation, never as a finding, and says nothing about product,
version or weakness.
"""

from __future__ import annotations

from avra.verification.evidence import HttpObservation, TcpPortObservation
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

POINT_IN_TIME = ("A network observation is true for the time the evidence was "
                 "collected; the target may have changed since.")


class TcpPortOpenRule(VerificationRule):
    id = "net.tcp_port_open"
    version = "1"
    kind = RuleKind.OBSERVATION
    title = "TCP port accepts connections"
    description = ("The target accepted a full TCP connection on the port "
                   "(nmap -sT state 'open').")
    evidence_kinds = frozenset({EvidenceKind.NMAP_XML})
    criteria = (
        Criterion(id="open_seen", polarity="positive",
                  description="A trusted nmap_connect_scan result reports state 'open'."),
        Criterion(id="closed_seen", polarity="negative",
                  description="A trusted nmap_connect_scan result reports state 'closed' "
                              "(the target actively refused the connection)."),
    )
    confirmed_requires = ("At least one trusted nmap_connect_scan result for this exact "
                          "host:port with state 'open', and none with state 'closed'.")
    limitations = (POINT_IN_TIME,
                   "'filtered' and similar states are not evidence either way.")

    def evaluate(self, hypothesis: Hypothesis, observations: list) -> RuleEvaluation:
        obs = [o for o in observations if isinstance(o, TcpPortObservation)]
        opened = [o for o in obs if o.state == "open"]
        closed = [o for o in obs if o.state == "closed"]
        c_open, c_closed = self.criteria
        checks = (check(c_open, bool(opened) if obs else None),
                  check(c_closed, bool(closed) if obs else None))
        missing = (f"a trusted nmap_connect_scan result for {hypothesis.target.label()}",)
        if not obs:
            return RuleEvaluation(Verdict.INCONCLUSIVE, "no_evidence",
                                  "No trusted nmap evidence covers this port.",
                                  checks, missing_evidence=missing)
        if opened and closed:
            return RuleEvaluation(Verdict.INCONCLUSIVE, "contradictory_evidence",
                                  f"{len(opened)} scan(s) saw 'open' and {len(closed)} saw "
                                  "'closed'; the port state changed or the evidence conflicts.",
                                  checks, used=tuple(opened + closed))
        if opened:
            return RuleEvaluation(Verdict.CONFIRMED, "port_open",
                                  f"{len(opened)} trusted scan(s) report the port open "
                                  f"({opened[0].reason or 'no reason recorded'}).",
                                  checks, used=tuple(opened))
        if closed:
            return RuleEvaluation(Verdict.REJECTED, "port_closed",
                                  f"{len(closed)} trusted scan(s) report the port closed "
                                  f"({closed[0].reason or 'no reason recorded'}).",
                                  checks, used=tuple(closed))
        states = ", ".join(sorted({o.state for o in obs}))
        return RuleEvaluation(Verdict.INCONCLUSIVE, "ambiguous_state",
                              f"Trusted scans only report non-decisive state(s): {states}.",
                              checks, missing_evidence=missing)

    def suggest(self, ctx: SuggestContext):
        for t in ctx.evidence.targets():
            if any(isinstance(o, TcpPortObservation) for o in ctx.evidence.for_target(t)):
                yield Suggestion(t, "nmap evidence exists for this port")

    def next_actions(self, hypothesis: Hypothesis, result: VerificationResult):
        if result.verdict is Verdict.INCONCLUSIVE and result.reason_code in (
                "no_evidence", "ambiguous_state"):
            yield ProposedAction(tool="nmap_connect_scan", target=hypothesis.target,
                                 reason="a TCP connect scan would establish the port state")


class HttpServiceObservedRule(VerificationRule):
    id = "http.service_observed"
    version = "1"
    kind = RuleKind.OBSERVATION
    title = "An HTTP server answers on the port"
    description = ("The fixed http_probe request received a syntactically valid HTTP "
                   "status line. Protocol level only: no product or version.")
    evidence_kinds = frozenset({EvidenceKind.HTTP_ENVELOPE})
    criteria = (
        Criterion(id="http_status_line", polarity="positive",
                  description="A trusted http_probe response starts with a valid HTTP "
                              "status line (protocol_observed)."),
        Criterion(id="refused_or_not_http", polarity="negative",
                  description="A trusted http_probe was refused, or received a complete "
                              "response that is not HTTP."),
    )
    confirmed_requires = ("At least one trusted http_probe result for this host:port whose "
                          "response has a valid HTTP status line, and no trusted result "
                          "showing the port refused or answering with non-HTTP data.")
    limitations = (POINT_IN_TIME,
                   ("Server, X-Powered-By and <title> are server-controlled claims and "
                    "never identify a product."))

    def evaluate(self, hypothesis: Hypothesis, observations: list) -> RuleEvaluation:
        obs = [o for o in observations if isinstance(o, HttpObservation)]
        pos = [o for o in obs if o.facts is not None and o.facts.protocol_observed]
        neg = [o for o in obs if o.outcome == "connection_refused"
               or (o.facts is not None and not o.facts.protocol_observed and o.complete)]
        c_pos, c_neg = self.criteria
        checks = (check(c_pos, bool(pos) if obs else None),
                  check(c_neg, bool(neg) if obs else None))
        missing = (f"a trusted http_probe result for {hypothesis.target.label()}",)
        if not obs:
            return RuleEvaluation(Verdict.INCONCLUSIVE, "no_evidence",
                                  "No trusted http_probe evidence covers this port.",
                                  checks, missing_evidence=missing)
        if pos and neg:
            return RuleEvaluation(Verdict.INCONCLUSIVE, "contradictory_evidence",
                                  "Some probes saw HTTP, others were refused or saw non-HTTP.",
                                  checks, used=tuple(pos + neg))
        if pos:
            f = pos[0].facts
            return RuleEvaluation(Verdict.CONFIRMED, "http_observed",
                                  f"HTTP/{f.http_version} status {f.status_code} received "
                                  f"({len(pos)} trusted probe(s)).", checks, used=tuple(pos))
        if neg:
            why = ("connection refused" if neg[0].outcome == "connection_refused"
                   else "complete response without an HTTP status line")
            return RuleEvaluation(Verdict.REJECTED, "not_http",
                                  f"Trusted probe evidence: {why}.", checks, used=tuple(neg))
        outcomes = ", ".join(sorted({o.outcome for o in obs}))
        return RuleEvaluation(Verdict.INCONCLUSIVE, "no_usable_response",
                              f"Probes ended without a usable answer ({outcomes}).",
                              checks, missing_evidence=missing)

    def suggest(self, ctx: SuggestContext):
        seen = set()
        for t in ctx.evidence.targets():
            if any(isinstance(o, HttpObservation) for o in ctx.evidence.for_target(t)):
                seen.add(t)
                yield Suggestion(t, "http_probe evidence exists for this port")
        for t in ctx.confirmed(TcpPortOpenRule.id):
            if t not in seen:
                yield Suggestion(t, "the TCP port is verified open; is it an HTTP service?")

    def next_actions(self, hypothesis: Hypothesis, result: VerificationResult):
        if result.verdict is Verdict.INCONCLUSIVE and result.reason_code in (
                "no_evidence", "no_usable_response"):
            yield ProposedAction(tool="http_probe", target=hypothesis.target,
                                 reason="one fixed GET / would show whether HTTP answers")
