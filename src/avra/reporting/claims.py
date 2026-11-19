"""Deterministic checks on model-written free text (M7.9.4, D3; report schema 4).

The model's notes and summary are untrusted prose. These checks look only for
EXPLICIT, mechanically checkable things and never interpret meaning:

* References (all model text, hypotheses included) — request UUIDs, evidence
  SHA-256 hashes (full, abbreviated ``prefix...suffix``, or a hex prefix
  right after a word like "sha256"/"hash"/"request"), IPv4 addresses and
  IP:port pairs. Each must resolve to this run's recorded requests, verified
  evidence or the owner's scope. A reference that does not resolve is a
  mismatch (the validator turns that into INCOMPLETE). A prefix that fits
  several known values is ambiguous: recorded, never treated as resolved.
* Assertions (observations and the summary only; hypotheses may speculate) —
  explicit port-state claims, "service confirmed/identified" claims and
  "vulnerability proven/exploited" claims, skipped in any sentence with
  negation, hedging, conditionals or examples. These are INFORMATIONAL only.

Nothing here can strengthen anything: no field derived from evidence reads
these results. Passing them never means the prose is true (CLAIM_CHECK_NOTE).
Pure functions; same inputs -> same output, so replay reproduces them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict

CLAIM_CHECK_NOTE = (
    "Only explicit references (request IDs, evidence hashes, IPv4 addresses, IP:port) and a "
    "few explicit assertion patterns were checked mechanically. Passing these checks does NOT "
    "mean the model's free text is true or verified."
)
EXCERPT_CHARS = 200


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ReferenceIssue(_Model):
    field: str   # e.g. "model_summary", "model_observations[0]", "hypotheses[1]"
    kind: str    # request_id | sha256 | sha256_abbrev | hex_prefix | ipv4 | ipv4_port
    token: str   # exactly as normalized for checking (lower-case hex, "ip:port")
    reason: str


class SuspiciousAssertion(_Model):
    field: str
    category: str  # port_state | service_identity | vulnerability
    excerpt: str
    reason: str


class ClaimChecks(_Model):
    references_checked: int
    reference_mismatches: tuple[ReferenceIssue, ...] = ()
    ambiguous_references: tuple[ReferenceIssue, ...] = ()
    suspicious_assertions: tuple[SuspiciousAssertion, ...] = ()
    note: str = CLAIM_CHECK_NOTE


# --- patterns (ASCII hex/digits; \w is Unicode, so letters of any script bound tokens) ---

_HEX = "[0-9A-Fa-f]"
_UUID = re.compile(rf"(?<![\w-])({_HEX}{{8}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{12}})"
                   r"(?![\w-])")
_SHA = re.compile(rf"(?<![\w])({_HEX}{{64}})(?![\w])")
_ABBR = re.compile(rf"(?<![\w])({_HEX}{{6,62}})(?:\.\.\.|…)({_HEX}{{2,62}})(?![\w])")
_BARE = re.compile(rf"(?<![\w-])({_HEX}{{8,63}})(?![\w-])")
_HEX_CONTEXT = re.compile(r"(?i)\b(?:sha-?256|hash|digest|request(?:[ _-]?id)?|evidence|id)"
                          r"[\s:=#(\"'`]*$")
_OCT = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IP = rf"{_OCT}(?:\.{_OCT}){{3}}"
_IPV4 = re.compile(rf"(?<![\w.])({_IP})(?::([0-9]{{1,6}}))?(?![\w])(?!\.[0-9])(?!/[0-9])")

_CODE = re.compile(r"`[^`\n]*`")
_QUOTED = re.compile(r"\"[^\"\n]*\"|“[^”\n]*”")
_ABBREVIATIONS = re.compile(r"(?i)\b(e\.g\.|i\.e\.)")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+|\n+")
_EXAMPLE = re.compile(r"(?i)\b(?:e_g_|for example|for instance|such as|example)")
_HEDGE = re.compile(
    r"(?i)\b(?:not|no|never|none|cannot|without|unverified|unconfirmed|unproven|untested|"
    r"unknown|if|could|would|might|may|maybe|likely|unlikely|probably|possibly|perhaps|"
    r"hypothes\w*|suppose\w*|assum\w*|unless|whether|guess\w*|appears?|seems?|suggests?|"
    r"e_g_|i_e_|for example|for instance|such as|example)\b|\w+n['’]t\b")

_PORT_STATE = (
    re.compile(r"(?i)(?<![\w])([0-9]{1,5})/tcp\s+(open|closed|filtered)\b"),
    re.compile(r"(?i)\b(?:port|tcp)\s+([0-9]{1,5})\s+(?:is|was)\s+(open|closed|filtered)\b"),
    re.compile(rf"(?i)(?<![\w.]){_IP}:([0-9]{{1,5}})\s+(?:is|was)\s+(open|closed|filtered)\b"),
)
_IDENTITY_ASSERT = re.compile(r"(?i)\b(?:identified|confirmed|verified|definitely|certainly|"
                              r"clearly|is running|runs)\b")
_SERVICE_TERM = re.compile(r"(?i)\b(?:service|server|software|application|app|framework|"
                           r"version|daemon|express|node(?:\.js)?|nginx|apache|iis|tomcat|"
                           r"juice shop)\b")
_VULN = re.compile(r"(?i)\b(?:exploit(?:ed|able|ation)?|compromised|vulnerab(?:le|ility|"
                   r"ilities)|rce|remote code execution|pwned|breached|backdoor(?:ed)?)\b")
_VULN_EXEMPT = re.compile(r"(?i)\b(?:intentionally|deliberately)[\s-]+vulnerable\b|"
                          r"\bvulnerable[\s-]+(?:training|by design)\b")


# --- context from trusted inputs ------------------------------------------------------

class _Context:
    def __init__(self, result, *, session_id: str, targets: Iterable,
                 prior: tuple | None = None) -> None:
        verified = [o for o in result.outcomes if o.ok and o.report is not None]
        self.request_ids = {str(o.request.request_id).lower() for o in result.outcomes}
        # Schema 5: AVRA-verified evidence recorded earlier in this session.
        # None = schema-4 semantics (this run only, original wording).
        self.prior = prior
        for p in prior or ():
            self.request_ids.add(p.request_id.lower())
        self.session_id = str(session_id).lower()
        self.hashes = set()
        for o in result.outcomes:
            if o.evidence is not None:
                self.hashes.add(o.evidence.sha256.lower())
            if o.result is not None and o.result.output_sha256:
                self.hashes.add(o.result.output_sha256.lower())
        for p in prior or ():
            self.hashes.add(p.sha256.lower())
        self.scope_pairs = {(t.host, int(p)) for t in targets for p in t.ports}
        self.ips = {t.host for t in targets} | {h.address for o in verified
                                               for h in o.report.hosts}
        self.port_states: dict[int, set[str]] = {}
        open_ports = []
        for o in verified:
            for h in o.report.hosts:
                for p in h.ports:
                    self.port_states.setdefault(p.port, set()).add(p.state)
                    if p.state == "open":
                        open_ports.append(p)
        self.identity_identified = bool(open_ports) and all(p.service_identified
                                                            for p in open_ports)


def _texts(result) -> list[tuple[str, str, bool]]:
    """(field, text, assertion-checked). Same strings the report shows."""
    out = [("model_summary", result.final_summary or "", True)]
    out += [(f"model_observations[{i}]", o.get("summary", "") or "", True)
            for i, o in enumerate(result.observations)]
    out += [(f"hypotheses[{i}]", f"{h.get('statement', '')} | basis: {h.get('basis', '')}",
             False) for i, h in enumerate(result.hypotheses)]
    return out


def _mask(text: str, pattern: re.Pattern) -> str:
    """Blank out matches (same length, so positions stay valid)."""
    return pattern.sub(lambda m: " " * len(m.group(0)), text)


def _sentences(text: str) -> list[tuple[int, int]]:
    spans, start = [], 0
    for m in _SENTENCE_END.finditer(text):
        spans.append((start, m.start()))
        start = m.end()
    spans.append((start, len(text)))
    return [(a, b) for a, b in spans if b > a]


def _sentence_at(spans, pos) -> tuple[int, int]:
    return next(((a, b) for a, b in spans if a <= pos < b), (pos, pos))


# --- references -----------------------------------------------------------------------

def _resolve_prefix(token: str, ctx: _Context) -> tuple[str, int]:
    ids = {i.replace("-", "") for i in ctx.request_ids | {ctx.session_id}}
    hits = {i for i in ids if i.startswith(token)} | {h for h in ctx.hashes
                                                      if h.startswith(token)}
    return ("resolved", 1) if len(hits) == 1 else (("ambiguous", len(hits)) if hits
                                                    else ("mismatch", 0))


def _check_references(field: str, text: str, ctx: _Context, seen: set, out: dict) -> None:
    norm = _ABBREVIATIONS.sub(lambda m: m.group(0).replace(".", "_"), text)
    sentences = _sentences(norm)
    quoted = [m.span() for m in _CODE.finditer(norm)] + [m.span() for m in
                                                         _QUOTED.finditer(norm)]
    taken: list[tuple[int, int]] = []

    def free(span):
        return not any(span[0] < b and a < span[1] for a, b in taken)

    def add(kind, token, status, reason):
        key = (field, kind, token)
        if key in seen:
            return  # the same reference twice in one field counts once
        seen.add(key)
        out["checked"] += 1
        if status == "mismatch":
            out["mismatches"].append(ReferenceIssue(field=field, kind=kind, token=token,
                                                    reason=reason))
        elif status == "ambiguous":
            out["ambiguous"].append(ReferenceIssue(field=field, kind=kind, token=token,
                                                   reason=reason))

    for m in _UUID.finditer(norm):
        taken.append(m.span())
        token = m.group(1).lower()
        ok = token in ctx.request_ids or token == ctx.session_id
        add("request_id", token, "resolved" if ok else "mismatch",
            "not a request or session ID of this run" if ctx.prior is None else
            "not a request or session ID of this run, nor verified earlier evidence "
            "of this session")
    for m in _SHA.finditer(norm):
        if not free(m.span()):
            continue
        taken.append(m.span())
        token = m.group(1).lower()
        add("sha256", token, "resolved" if token in ctx.hashes else "mismatch",
            "not a recorded evidence/output hash of this run" if ctx.prior is None else
            "not a recorded evidence/output hash of this run or of verified earlier "
            "evidence of this session")
    for m in _ABBR.finditer(norm):
        if not free(m.span()):
            continue
        taken.append(m.span())
        pre, suf = m.group(1).lower(), m.group(2).lower()
        hits = [h for h in ctx.hashes if h.startswith(pre) and h.endswith(suf)
                and len(pre) + len(suf) <= 64]
        status = "resolved" if len(hits) == 1 else ("ambiguous" if hits else "mismatch")
        add("sha256_abbrev", f"{pre}...{suf}", status,
            f"matches {len(hits)} recorded hashes" if hits
            else "no recorded hash has this prefix and suffix")
    for m in _BARE.finditer(norm):
        if not free(m.span()) or not _HEX_CONTEXT.search(norm[max(0, m.start() - 32):
                                                               m.start()]):
            continue  # arbitrary hex without a reference word before it: not a reference
        taken.append(m.span())
        token = m.group(1).lower()
        status, n = _resolve_prefix(token, ctx)
        add("hex_prefix", token, status,
            f"prefix of {n} recorded IDs/hashes" if status == "ambiguous"
            else "not the start of any recorded request ID or hash")
    for m in _IPV4.finditer(norm):
        if not free(m.span()):
            continue
        a, b = _sentence_at(sentences, m.start())
        if any(qa <= m.start() < qb for qa, qb in quoted) or _EXAMPLE.search(norm[a:b]):
            continue  # an example or a quotation, not an explicit claim about this lab
        ip, port = m.group(1), m.group(2)
        if port is None:
            add("ipv4", ip, "resolved" if ip in ctx.ips else "mismatch",
                "IP is neither in scope nor in the verified evidence")
        else:
            pair_ok = 1 <= int(port) <= 65535 and (ip, int(port)) in ctx.scope_pairs
            add("ipv4_port", f"{ip}:{int(port)}", "resolved" if pair_ok else "mismatch",
                "IP:port is not in the authorized scope")


# --- assertions (informational) -------------------------------------------------------

def _check_assertions(field: str, text: str, ctx: _Context, seen: set, out: list) -> None:
    norm = _ABBREVIATIONS.sub(lambda m: m.group(0).replace(".", "_"), text)
    norm = _mask(_mask(norm, _CODE), _QUOTED)

    def add(category, sentence, reason):
        excerpt = " ".join(sentence.split())[:EXCERPT_CHARS]
        key = (field, category, excerpt)
        if key not in seen:
            seen.add(key)
            out.append(SuspiciousAssertion(field=field, category=category, excerpt=excerpt,
                                           reason=reason))

    for a, b in _sentences(norm):
        sentence = norm[a:b]
        if _HEDGE.search(sentence):
            continue  # negated, hedged, conditional or an example: not an assertion
        for pattern in _PORT_STATE:
            for m in pattern.finditer(sentence):
                port, state = int(m.group(1)), m.group(2).lower()
                recorded = ctx.port_states.get(port)
                if not recorded:
                    add("port_state", sentence, f"port {port} has no verified scan result")
                elif state not in recorded:
                    add("port_state", sentence, f"port {port} is recorded as "
                                                f"{'/'.join(sorted(recorded))}, not {state}")
        if (not ctx.identity_identified and _IDENTITY_ASSERT.search(sentence)
                and _SERVICE_TERM.search(sentence)):
            add("service_identity", sentence,
                "asserts a service identity that no probe confirmed")
        if _VULN.search(sentence) and not _VULN_EXEMPT.search(sentence):
            add("vulnerability", sentence,
                "asserts a vulnerability or exploitation; AVRA ran no vulnerability test")


def check_claims(result, *, session_id: str, targets: Iterable,
                 prior: tuple | None = None) -> ClaimChecks:
    """Deterministic claim checks for one research run. ``targets`` are the
    scope targets (objects with ``.host`` and ``.ports``) the report shows.
    ``prior`` (schema 5): AVRA-verified evidence recorded earlier in the same
    session; its request ids and hashes also resolve. None = schema 4."""
    ctx = _Context(result, session_id=session_id, targets=list(targets), prior=prior)
    refs = {"checked": 0, "mismatches": [], "ambiguous": []}
    seen_refs: set = set()
    assertions: list[SuspiciousAssertion] = []
    seen_assertions: set = set()
    for field, text, check_assertions in _texts(result):
        _check_references(field, text, ctx, seen_refs, refs)
        if check_assertions:
            _check_assertions(field, text, ctx, seen_assertions, assertions)
    return ClaimChecks(references_checked=refs["checked"],
                       reference_mismatches=tuple(refs["mismatches"]),
                       ambiguous_references=tuple(refs["ambiguous"]),
                       suspicious_assertions=tuple(assertions))
