"""One-pass, AI-assisted lab assessment (``avra assess``, ADR 0015).

The vertical slice:

    scope check -> evidence (a fresh nmap scan through the Runner, or an existing
    session's hash-checked evidence) -> Verification Engine (deterministic) ->
    fact sheet -> ONE model call (local or Anthropic) -> validated analysis ->
    Markdown + JSON report, with its own hash-chained audit log.

Trust boundaries (unchanged from the rest of AVRA):
- Facts come only from recorded, hash-checked evidence; verdicts only from the
  Verification Engine. The model never decides a status.
- The model's analysis is validated (Pydantic) and every hypothesis it states is
  labelled UNVERIFIED. Hypotheses about a host:port that the evidence does not
  cover are dropped (and listed as dropped), so the model cannot introduce new
  targets.
- The model has no tools here: it cannot run anything.
- Every model call is audited (hashes of the exact request and response,
  usage, stop reason), as are the report files.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from avra.storage.audit import AuditLog

PROMPT_VERSION = "assess-v3"
# assess-v3 (2026-11-13): confirmed_weaknesses (header rules) are separated from
# confirmed_findings and must never be called exploitable or confirmed vulnerabilities.
# assess-v2 (2026-11-13): same instructions; the fact sheet is sent as a compact model
# view (model_view): no hashes, 8-char evidence ids, no indentation - fewer prompt
# tokens for local models. The facts themselves are unchanged.
REPORT_FORMAT = "avra-assessment/1"
AUDIT_NAME = "assessment-audit.jsonl"

SYSTEM_PROMPT = """\
You are the analysis component of AVRA, a vulnerability research assistant used in
the owner's AUTHORIZED, isolated home lab (intentionally vulnerable training targets).

You receive a JSON fact sheet produced by deterministic tools:
- "targets": per host:port, nmap TCP results and any HTTP probe facts;
- "verified": statements the Verification Engine CONFIRMED from hash-checked evidence;
- "confirmed_findings": vulnerabilities the engine confirmed (may be empty);
- "confirmed_weaknesses": configuration weaknesses the engine confirmed from recorded
  headers (e.g. a missing security header). They are facts about the configuration,
  NOT proven exploitable vulnerabilities - exploitability was never tested;
- "inconclusive" and "next_actions": what the evidence cannot decide yet.

Write a concise security analysis for the lab owner. Rules:
1. Facts in the sheet are facts. Anything else you say is a HYPOTHESIS: say why it
   is plausible and how it could be checked safely. Never call a hypothesis
   confirmed or verified; only the engine confirms.
2. Mention only hosts and ports that appear in "targets".
3. nmap service names marked method "table" are guesses from the port number.
4. No exploit code, payloads, credential attacks or destructive steps. Suggested
   checks must be safe, read-only observations (e.g. "fetch the page headers").
5. Remediation advice must be practical for the owner of the service.
6. Never describe a confirmed weakness as an exploitable or confirmed vulnerability;
   call it a configuration weakness / hardening gap.

Reply with ONE JSON object and nothing else, exactly this shape:
{"executive_summary": "<3-6 sentences>",
 "service_notes": [{"host": "<ip>", "port": <int>, "note": "<what the facts mean>"}],
 "hypotheses": [{"title": "<short>", "host": "<ip>", "port": <int>,
                 "rationale": "<why plausible, citing facts>",
                 "confidence": "low|medium|high",
                 "suggested_check": "<safe way to verify>"}],
 "remediation": ["<actionable recommendation>"]}
"""


# --------------------------------------------------------------------------- model output

class _Strict(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)


class ServiceNote(_Strict):
    host: str = Field(max_length=64)
    port: int = Field(ge=1, le=65535)
    note: str = Field(min_length=1, max_length=1500)


class AIHypothesis(_Strict):
    title: str = Field(min_length=1, max_length=200)
    host: str = Field(max_length=64)
    port: int = Field(ge=1, le=65535)
    rationale: str = Field(min_length=1, max_length=2000)
    confidence: Literal["low", "medium", "high"] = "low"
    suggested_check: str = Field(default="", max_length=1000)


class AIAnalysis(_Strict):
    executive_summary: str = Field(min_length=1, max_length=4000)
    service_notes: list[ServiceNote] = Field(default_factory=list, max_length=30)
    hypotheses: list[AIHypothesis] = Field(default_factory=list, max_length=15)
    remediation: list[str] = Field(default_factory=list, max_length=20)


_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def parse_analysis(text: str) -> AIAnalysis:
    """Model text -> AIAnalysis. Tolerates code fences / prose around ONE JSON
    object; anything that does not validate raises ``ValueError``."""
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw
    m = _JSON_OBJECT.search(raw)
    if not m:
        raise ValueError("the model reply contains no JSON object")
    try:
        data = json.loads(m.group(0))
    except ValueError as exc:
        raise ValueError(f"the model reply is not valid JSON ({exc})") from None
    if isinstance(data, dict):  # small models sometimes send remediation as objects
        data["remediation"] = [r if isinstance(r, str) else json.dumps(r, sort_keys=True)
                               for r in data.get("remediation") or []]
    try:
        return AIAnalysis.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"the model reply does not match the schema: "
                         f"{exc.error_count()} error(s), first: {exc.errors()[0]['msg']}") from None


# --------------------------------------------------------------------------- facts

def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_facts(verification_report: dict, evidence: Any, evidence_root: Path) -> dict:
    """Deterministic fact sheet from the Verification Engine's report and the
    session's hash-checked observations (``SessionEvidence``)."""
    from avra.recon.nmap_xml import NmapXmlError, parse_nmap_xml
    from avra.verification.evidence import HttpObservation, TcpPortObservation

    targets: dict[str, dict] = {}

    def slot(t) -> dict:
        return targets.setdefault(t.label(), {"host": t.host, "port": t.port, "tcp": [],
                                              "service": None, "http": []})

    parsed: dict[str, Any] = {}
    for obs in evidence.observations:
        ref = obs.ref
        cite = {"request_id": ref.request_id, "sha256": ref.sha256, "tool": ref.tool}
        if isinstance(obs, TcpPortObservation):
            slot(obs.target)["tcp"].append({"state": obs.state, "reason": obs.reason,
                                            "host_status": obs.host_status, "evidence": cite})
            if ref.request_id not in parsed:  # service label from the same verified file
                path = Path(evidence_root) / ref.session_id / f"{ref.request_id}.xml"
                try:
                    if _sha256_file(path) == ref.sha256:
                        parsed[ref.request_id] = parse_nmap_xml(path.read_text(encoding="utf-8"))
                except (OSError, NmapXmlError, UnicodeDecodeError):
                    parsed[ref.request_id] = None
            rep = parsed.get(ref.request_id)
            for h in (rep.hosts if rep else ()):
                for p in h.ports:
                    if h.address == obs.target.host and p.port == obs.target.port and p.service:
                        slot(obs.target)["service"] = {
                            "name": p.service, "method": p.service_method or "unknown",
                            "confidence": p.service_confidence,
                            "note": ("guess from the port number only" if p.service_method == "table"
                                     else "nmap service detection")}
        elif isinstance(obs, HttpObservation):
            f = obs.facts
            entry: dict[str, Any] = {"outcome": obs.outcome, "complete": obs.complete,
                                     "truncated": obs.truncated, "evidence": cite}
            if f is not None:
                headers = {h.name: h.value[:200] for h in f.headers}
                entry.update(status_code=f.status_code, reason=f.reason[:100],
                             content_type=f.content_type[:100], title=f.title[:200],
                             server=headers.get("server", ""), header_names=sorted(headers),
                             security_headers={k: headers.get(k, None) for k in (
                                 "x-content-type-options", "x-frame-options",
                                 "content-security-policy", "strict-transport-security",
                                 "access-control-allow-origin", "referrer-policy")},
                             note="banner/title are claims made by the server, not identification")
            slot(obs.target)["http"].append(entry)

    r = verification_report
    return {
        "format": "avra-assessment-facts/1",
        "session_id": r["session"]["session_id"],
        "session_trusted": bool(r["session"].get("audit_chain_valid")),
        "scope": r["session"].get("scope_session_name", ""),
        "targets": [targets[k] for k in sorted(targets)],
        "verified": [{"target": v["target"], "statement": v["title"], "reason": v["reason"],
                      "rule": v["rule_id"]} for v in r.get("verified_observations", [])],
        "confirmed_findings": [_finding(v) for v in r.get("confirmed_findings", [])
                               if v["rule_id"] not in CONFIG_WEAKNESS_RULES],
        "confirmed_weaknesses": [{**_finding(v), "exploitability": WEAKNESS_NOTE}
                                 for v in r.get("confirmed_findings", [])
                                 if v["rule_id"] in CONFIG_WEAKNESS_RULES],
        "inconclusive": [{"target": v["target"], "question": v["title"], "why": v["reason"],
                          "rule": v["rule_id"]} for v in r.get("inconclusive", [])],
        "next_actions": [{"tool": a["tool"], "target": f"{a['target']['host']}:{a['target']['port']}",
                          "why": a["reason"], "needs_owner_approval": a["requires_owner_approval"]}
                         for a in r.get("proposed_next_actions", [])],
    }


def _finding(v: dict) -> dict:
    return {"target": v["target"], "title": v["title"], "severity": v.get("severity", ""),
            "reason": v["reason"], "rule": v["rule_id"],
            "references": list(v.get("references", []))}


def merge_facts(sheets: list[dict]) -> dict:
    """Combine per-session fact sheets (each verified on its own) into one view.

    - per host:port, nmap and HTTP observations are concatenated (each keeps its
      own evidence citation, so provenance per session is preserved);
    - a question INCONCLUSIVE in one session but CONFIRMED/verified in another
      (same rule and target) is dropped from the open questions;
    - a proposed next action is dropped when another session already holds
      evidence from that tool for that target.
    A session whose evidence is not trusted makes the merged sheet untrusted."""
    if len(sheets) == 1:
        return sheets[0]
    targets: dict[str, dict] = {}
    for s in sheets:
        for t in s["targets"]:
            k = f"{t['host']}:{t['port']}"
            m = targets.setdefault(k, {"host": t["host"], "port": t["port"], "tcp": [],
                                       "service": None, "http": []})
            m["tcp"] += t["tcp"]
            m["http"] += t["http"]
            m["service"] = m["service"] or t["service"]

    def uniq(items: list[dict]) -> list[dict]:
        seen, out = set(), []
        for x in items:
            key = json.dumps(x, sort_keys=True)
            if key not in seen:
                seen.add(key)
                out.append(x)
        return out

    verified = uniq([v for s in sheets for v in s["verified"]])
    confirmed = uniq([v for s in sheets for v in s["confirmed_findings"]])
    weaknesses = uniq([v for s in sheets for v in s.get("confirmed_weaknesses", [])])
    decided = {(v["rule"], v["target"]) for v in verified + confirmed + weaknesses}
    inconclusive = uniq([v for s in sheets for v in s["inconclusive"]
                         if (v.get("rule"), v["target"]) not in decided])
    have = {(e["evidence"]["tool"], k) for k, t in targets.items() for e in t["tcp"] + t["http"]}
    actions = uniq([a for s in sheets for a in s["next_actions"]
                    if (a["tool"], a["target"]) not in have])
    return {"format": "avra-assessment-facts/1",
            "session_id": sheets[0]["session_id"],
            "sessions": [s["session_id"] for s in sheets],
            "session_trusted": all(s["session_trusted"] for s in sheets),
            "scope": sheets[0].get("scope", ""),
            "targets": [targets[k] for k in sorted(targets)],
            "verified": verified, "confirmed_findings": confirmed,
            "confirmed_weaknesses": weaknesses,
            "inconclusive": inconclusive, "next_actions": actions}


# --------------------------------------------------------------------------- analysis

@dataclass
class AnalysisOutcome:
    status: Literal["ok", "skipped", "failed", "refused", "invalid"]
    analysis: AIAnalysis | None = None
    detail: str = ""
    provider: str = ""
    model: str = ""
    dropped: list[str] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    cost_usd: float = 0.0
    seconds: float = 0.0


_DROP = frozenset({"sha256", "format", "host_status", "header_names"})


def model_view(facts: dict) -> Any:
    """What the model needs from a fact sheet: every fact, no integrity metadata.
    Evidence citations keep only an 8-char request id (the report keeps full hashes)."""
    def walk(o: Any, key: str = "") -> Any:
        if isinstance(o, dict):
            return {k: walk(v, k) for k, v in o.items() if k not in _DROP and k != "sessions"}
        if isinstance(o, list):
            return [walk(x) for x in o]
        if key in ("request_id", "session_id") and isinstance(o, str):
            return o[:8]
        return o
    return walk(facts)


def analysis_user_message(facts: dict) -> str:
    return ("Fact sheet (JSON, produced by AVRA's deterministic tools):\n"
            + json.dumps(model_view(facts), sort_keys=True, separators=(",", ":")))


def run_analysis(provider: Any, facts: dict, audit: AuditLog) -> AnalysisOutcome:
    """Exactly one model call, audited; never raises for model-side problems."""
    import time

    from avra.llm.provider import LLMProviderError

    cfg = provider.config
    out = AnalysisOutcome(status="failed", provider=cfg.provider, model=cfg.model)
    system = [{"type": "text", "text": SYSTEM_PROMPT}]
    messages = [{"role": "user", "content": analysis_user_message(facts)}]
    req_sha = hashlib.sha256(json.dumps([system, messages], sort_keys=True).encode()).hexdigest()
    audit.record("assessment_llm_request", {"provider": cfg.provider, "model": cfg.model,
                                            "prompt_version": PROMPT_VERSION,
                                            "request_sha256": req_sha})
    t0 = time.monotonic()
    try:
        resp = provider.complete(system=system, messages=messages, tools=[])
    except LLMProviderError as exc:
        out.seconds = round(time.monotonic() - t0, 2)
        out.detail = str(exc)[:500]
        audit.record("assessment_llm_failed", {"error": out.detail, "seconds": out.seconds})
        return out
    out.seconds = round(time.monotonic() - t0, 2)
    out.usage = resp.usage.as_dict()
    out.cost_usd = round(resp.usage.cost_usd(cfg.price), 6)
    audit.record("assessment_llm_response", {
        "stop_reason": resp.stop_reason, "model": resp.model, "usage": out.usage,
        "cost_usd": out.cost_usd, "seconds": out.seconds,
        "response_sha256": hashlib.sha256(resp.text.encode()).hexdigest(),
        "refusal_category": resp.refusal_category})
    if resp.stop_reason == "refusal":  # a normal outcome: recorded, never retried
        out.status, out.detail = "refused", f"model refused ({resp.refusal_category or 'n/a'})"
        return out
    try:
        analysis = parse_analysis(resp.text)
    except ValueError as exc:
        out.status, out.detail = "invalid", str(exc)[:500]
        if resp.stop_reason == "max_tokens":
            out.detail += " (the reply hit max_tokens)"
        audit.record("assessment_analysis_rejected", {"reason": out.detail})
        return out
    known = {(t["host"], t["port"]) for t in facts["targets"]}
    kept_h = [h for h in analysis.hypotheses if (h.host, h.port) in known]
    kept_n = [n for n in analysis.service_notes if (n.host, n.port) in known]
    out.dropped = [f"hypothesis about {h.host}:{h.port} (not in the evidence): {h.title}"
                   for h in analysis.hypotheses if (h.host, h.port) not in known]
    out.dropped += [f"service note about {n.host}:{n.port} (not in the evidence)"
                    for n in analysis.service_notes if (n.host, n.port) not in known]
    out.analysis = analysis.model_copy(update={"hypotheses": kept_h, "service_notes": kept_n})
    out.status = "ok"
    audit.record("assessment_analysis_accepted", {
        "hypotheses": len(kept_h), "service_notes": len(kept_n),
        "remediation": len(analysis.remediation), "dropped": out.dropped[:20]})
    return out


# --------------------------------------------------------------------------- report

# Deterministic, vetted fixes for engine-CONFIRMED findings (never model text).
RULE_REMEDIATION = {
    "http.missing_x_content_type_options":
        "Send `X-Content-Type-Options: nosniff` on every response.",
    "http.missing_content_security_policy":
        "Add a Content-Security-Policy (start with `default-src 'self'`; tighten script-src; "
        "roll out with Content-Security-Policy-Report-Only first).",
    "http.missing_clickjacking_protection":
        "Send `Content-Security-Policy: frame-ancestors 'self'` (or `X-Frame-Options: SAMEORIGIN`).",
    "http.cors_wildcard_origin":
        "Replace `Access-Control-Allow-Origin: *` with an explicit allow-list of trusted origins "
        "on any endpoint that returns user-specific data.",
    "http.version_disclosure":
        "Remove version numbers from `Server` / `X-Powered-By` (e.g. `app.disable('x-powered-by')` "
        "in Express, `server_tokens off` in nginx).",
    # M10.4 (ADR 0017) passive validation rules
    "http.cors_wildcard_with_credentials":
        "Never combine `Access-Control-Allow-Credentials: true` with a wildcard; allow-list "
        "trusted origins explicitly and never reflect the request's Origin.",
    "http.cookie_missing_httponly":
        "Set the `HttpOnly` flag (and `Secure`, `SameSite`) on session and other sensitive "
        "cookies.",
}


# Header/configuration rules: their CONFIRMED verdicts are configuration facts, not
# proven exploitable vulnerabilities (reported and prompted as such).
CONFIG_WEAKNESS_RULES = frozenset(RULE_REMEDIATION)
WEAKNESS_NOTE = "not assessed - configuration weakness, not a proven exploitable vulnerability"


def _md(text: Any) -> str:
    """Model or server text into Markdown table/inline context: no HTML, no pipes."""
    s = str(text if text is not None else "")
    return (s.replace("\r", " ").replace("\n", " ").replace("|", "\\|")
            .replace("<", "&lt;").replace(">", "&gt;"))


def render_markdown(meta: dict, facts: dict, vreport: dict, outcome: AnalysisOutcome) -> str:
    L: list[str] = []
    a = outcome.analysis
    L += [f"# AVRA assessment — {', '.join(t['host'] + ':' + str(t['port']) for t in facts['targets']) or 'no targets'}",
          "",
          f"- **Generated:** {meta['generated_at']}  ",
          (f"- **Session(s):** {', '.join(f'`{s}`' for s in facts.get('sessions') or [facts['session_id']])} "
           f"(evidence {'trusted: audit chains valid' if facts['session_trusted'] else '**NOT trusted**'})  "),
          f"- **Scope:** {_md(meta['scope_name'])} (`{_md(meta['scope_file'])}`, sha256 `{meta['scope_sha256'][:16]}…`)  ",
          f"- **Evidence source:** {_md(meta['evidence_source'])}  ",
          f"- **Verification report(s):** {', '.join(f'`{p}`' for p in meta['verification_reports'])}  ",
          f"- **AI analysis:** {_ai_line(outcome)}",
          "",
          ("> **How to read this report.** *Verified* statements were decided by AVRA's "
           "deterministic Verification Engine from hash-checked evidence. Everything in the "
           "*AI-assisted analysis* is a model's interpretation: hypotheses are **UNVERIFIED** "
           "until a rule confirms them. INCONCLUSIVE never means safe."),
          "", "## Executive summary", ""]
    weak = facts.get("confirmed_weaknesses", [])
    L.append(f"Deterministic result: **{len(facts['confirmed_findings'])} confirmed "
             f"vulnerability(ies)**, {len(weak)} confirmed configuration weakness(es) "
             f"(not proven exploitable), {len(facts['verified'])} verified observation(s), "
             f"{len(facts['inconclusive'])} open question(s).")
    L.append("")
    if a:
        L += [f"AI summary (unverified interpretation): {_md(a.executive_summary)}", ""]
    else:
        L += ["_No AI summary: " + _md(outcome.detail or "analysis not requested") + "_", ""]

    L += deterministic_sections(facts)

    L += ["## AI-assisted analysis (UNVERIFIED)", ""]
    if not a:
        L += [f"_Not available: {_md(outcome.detail or 'not requested')}_", ""]
    else:
        if a.service_notes:
            L += ["### Service interpretation", ""]
            L += [f"- {n.host}:{n.port} — {_md(n.note)}" for n in a.service_notes]
            L.append("")
        L += ["### Hypotheses", ""]
        if a.hypotheses:
            L += ["| # | Hypothesis | Target | Confidence (model's own) | Status | Safe check |",
                  "|---|---|---|---|---|---|"]
            for i, h in enumerate(a.hypotheses, 1):
                L.append(f"| H{i} | **{_md(h.title)}** — {_md(h.rationale)} | {h.host}:{h.port} | "
                         f"{h.confidence} | UNVERIFIED | {_md(h.suggested_check)} |")
        else:
            L.append("The model stated no hypotheses.")
        L.append("")
        if outcome.dropped:
            L += ["Dropped by AVRA validation (outside the evidence):", ""]
            L += [f"- {_md(d)}" for d in outcome.dropped]
            L.append("")

    L += ["## Recommendations", ""]
    L += deterministic_recommendations(facts, [f"(AI, unverified) {r}"
                                              for r in (a.remediation if a else [])])
    L.append("")

    L += ["## Limitations", ""]
    lims = list(dict.fromkeys(vreport.get("limitations", [])))[:10]
    L += [f"- {_md(x)}" for x in lims]
    L += [("- The AI analysis is generated text from one model call; it can be wrong or "
           "incomplete and is never evidence."), ""]
    L += ["---", (f"_AVRA {REPORT_FORMAT}, prompt `{PROMPT_VERSION}`. Audit: "
                  f"`{meta['audit_file']}`._"), ""]
    return "\n".join(L)


def deterministic_sections(facts: dict) -> list[str]:
    """Services, header observations and the engine's verdicts - no model text."""
    L: list[str] = []
    weak = facts.get("confirmed_weaknesses", [])
    L += ["## Discovered services", "",
          "| Target | TCP state (nmap) | Service label | HTTP | Evidence |",
          "|---|---|---|---|---|"]
    for t in facts["targets"]:
        tcp = "; ".join(f"{x['state']} ({x['reason']})" for x in t["tcp"]) or "—"
        svc = (f"{_md(t['service']['name'])} ({_md(t['service']['note'])})" if t["service"] else "—")
        http = "; ".join(
            (f"{h.get('status_code')} {_md(h.get('reason', ''))}, server header "
             f"{('“' + _md(h['server']) + '”') if h.get('server') else '—'}, "
             f"title “{_md(h.get('title', ''))}” (server claims)")
            if h.get("status_code") else _md(h["outcome"])
            for h in t["http"]) or "not probed"
        ev = ", ".join(f"`{e['evidence']['request_id'][:8]}` ({e['evidence']['tool']}, "
                       f"sha256 `{e['evidence']['sha256'][:12]}…`)" for e in t["tcp"] + t["http"])
        L.append(f"| {t['host']}:{t['port']} | {_md(tcp)} | {svc} | {http} | {ev} |")
    L.append("")
    L += _header_section(facts)

    L += ["## Verified by the Verification Engine", ""]
    def finding_lines(items: list[dict]) -> list[str]:
        out = []
        for f in items:
            refs = ", ".join(f.get("references", []))
            out.append(f"- **{_md(f['title'])}** — {f['target']} (severity {f['severity'] or 'n/a'}; "
                       f"rule `{f['rule']}`{'; ' + _md(refs) if refs else ''}): {_md(f['reason'])}")
            if RULE_REMEDIATION.get(f["rule"]):
                out.append(f"  - *Fix:* {RULE_REMEDIATION[f['rule']]}")
        return [*out, ""]

    if facts["confirmed_findings"]:
        L += ["### Confirmed vulnerabilities", "", *finding_lines(facts["confirmed_findings"])]
    else:
        L += ["No vulnerability was confirmed by a deterministic rule.", ""]
    if weak:
        L += ["### Confirmed configuration weaknesses (not proven exploitable)", "",
              ("The engine confirmed these from the recorded response headers. They are "
               "hardening gaps: whether any of them is exploitable was **not** tested."), "",
              *finding_lines(weak)]
    if facts["verified"]:
        L += ["### Verified observations", ""]
        L += [f"- {_md(v['statement'])} — {v['target']} (rule `{v['rule']}`): {_md(v['reason'])}"
              for v in facts["verified"]]
        L.append("")
    if facts["inconclusive"]:
        L += ["### Open questions (INCONCLUSIVE)", ""]
        L += [f"- {_md(v['question'])} — {v['target']}: {_md(v['why'])}" for v in facts["inconclusive"]]
        L.append("")

    return L


def deterministic_recommendations(facts: dict, extra: list[str] | None = None) -> list[str]:
    """Vetted fixes for confirmed results first, then ``extra`` (labelled model advice),
    then evidence gaps. Numbered Markdown lines."""
    weak = facts.get("confirmed_weaknesses", [])
    recs = [f"[{f['target']}] {RULE_REMEDIATION[f['rule']]} (confirmed: {f['title']})"
            for f in facts["confirmed_findings"] if f["rule"] in RULE_REMEDIATION]
    recs += [f"[{f['target']}] Hardening: {RULE_REMEDIATION[f['rule']]} ({f['title']})"
             for f in weak if f["rule"] in RULE_REMEDIATION]
    recs += list(extra or [])
    for act in facts["next_actions"]:
        recs.append(f"Evidence gap: run `{act['tool']}` on {act['target']} ({act['why']}); "
                    + ("needs owner approval." if act["needs_owner_approval"] else "allowed."))
    return [*([f"{i}. {_md(r)}" for i, r in enumerate(recs, 1)] or ["No recommendations."]), ""]


# --------------------------------------------------------------------------- M9.3 research report

def research_trace(records: list) -> dict:
    """The latest research run of a session, read back from its audit records."""
    starts = [i for i, r in enumerate(records) if r.event == "research_started"]
    if not starts:
        return {}
    run = records[starts[-1]:]
    st = run[0].data
    trace: dict = {"objective": st.get("objective", ""), "provider": st.get("provider", ""),
                   "model": st.get("model", ""), "prompt_version": st.get("prompt_version", ""),
                   "steps": [], "hypotheses": [], "observations": [], "finish": "",
                   "stop": {}, "calls": 0, "tokens_in": 0, "tokens_out": 0, "compactions": 0,
                   "board": {}, "surfaces": [], "board_summary": None}
    hyp: dict = {}
    for r in run[1:]:
        e, d = r.event, r.data if isinstance(r.data, dict) else {}
        target = f"{d.get('host', '')}:{','.join(map(str, d.get('ports') or []))}"
        if e == "llm_call":
            trace["calls"] += 1
            u = d.get("usage") or {}
            trace["tokens_in"] += u.get("input_tokens", 0)
            trace["tokens_out"] += u.get("output_tokens", 0)
        elif e == "llm_proposal":
            where = target + (d.get("path") or "")
            trace["steps"].append(f"Model proposed `{d.get('tool', 'nmap_connect_scan')}` on "
                                  f"{where}: {d.get('explanation', '')}")
        elif e == "owner_decision":
            trace["steps"].append("Owner " + ("**approved**" if d.get("approved") else "declined"))
        elif e in ("llm_proposal_denied", "llm_proposal_rejected"):
            trace["steps"].append(f"AVRA refused `{d.get('tool', 'nmap_connect_scan')}` on {target}: "
                                  f"{d.get('reason', '')}")
        elif e == "tool_result_received":
            where = (f"{d.get('host', '')}:{d.get('port') or ','.join(map(str, d.get('ports') or []))}"
                     + (d.get("path") or ""))
            code = (f", HTTP {d.get('http_status_code')}" if d.get("http_status_code") else "")
            trace["steps"].append(f"Ran `{d.get('tool')}` on {where}: {d.get('status')}{code}, "
                                  f"evidence sha256 `{(d.get('evidence_sha256') or '')[:12]}`")
        elif e == "verification_hypothesis":
            hyp[d.get("hypothesis_id")] = (d.get("rule_id"), d.get("target"))
            if d.get("proposed_by") not in ("rules",):
                trace["steps"].append(f"Model asked the engine to verify `{d.get('rule_id')}` on "
                                      f"{d.get('target')}")
        elif e == "verification_verdict":
            rule, tgt = hyp.get(d.get("hypothesis_id"), (d.get("rule_id"), ""))
            trace["steps"].append(f"Engine: `{rule}` on {tgt} -> {d.get('verdict')}"
                                  f" ({d.get('reason_code', '')})")
        elif e == "verification_repeat":
            rule, tgt = hyp.get(d.get("hypothesis_id"), ("?", "?"))
            trace["steps"].append(f"Model asked the engine to verify `{rule}` on {tgt}: already "
                                  f"decided ({d.get('verdict')})")
        elif e == "verification_request_refused":
            trace["steps"].append(f"Engine refused a verification request: {d.get('reason', '')}")
        elif e == "context_compacted":
            trace["compactions"] += 1
        elif e == "web_surface_built":  # M10.3
            trace["surfaces"].append(d)
            trace["steps"].append(f"AVRA derived the web surface of {d.get('origin')}: "
                                  f"{d.get('endpoints')} endpoint reference(s), {d.get('forms')} "
                                  "form(s) from recorded responses (not fetched)")
        elif e == "research_hypothesis":
            trace["board"][d.get("hypothesis_id")] = {**d, "state": "untested"}
            where = d.get("target", "") + (d.get("endpoint") or "")
            trace["steps"].append(f"Model recorded hypothesis `{d.get('vuln_class')}` on {where}")
        elif e == "research_hypothesis_state":
            if d.get("hypothesis_id") in trace["board"]:
                trace["board"][d["hypothesis_id"]]["state"] = d.get("state", "")
                trace["steps"].append(f"Board: hypothesis `{d['hypothesis_id']}` -> "
                                      f"{d.get('state')}")
        elif e == "research_hypothesis_repeat":
            trace["steps"].append(f"Model re-proposed `{d.get('hypothesis_id')}`: answered "
                                  f"from state ({d.get('state')}), not re-examined")
        elif e == "research_hypothesis_refused":
            trace["steps"].append(f"AVRA refused a research hypothesis: {d.get('reason', '')}")
        elif e == "tool_run_no_new_evidence":
            trace["steps"].append(f"`{d.get('tool')}` produced no new trusted evidence")
        elif e == "llm_hypothesis":
            trace["hypotheses"].append({"statement": d.get("statement", ""), "basis": d.get("basis", "")})
        elif e == "llm_observation":
            trace["observations"].append(d.get("summary", ""))
        elif e == "llm_finish":
            trace["finish"] = d.get("summary", "")
        elif e == "research_stopped":
            trace["stop"] = {"reason": d.get("stop_reason", ""), "detail": d.get("detail", "")}
            trace["board_summary"] = d.get("research_board")
    return trace


def render_research_markdown(meta: dict, facts: dict, vreport: dict, trace: dict) -> str:
    """One report for a research run: engine verdicts (facts) + what the agent did +
    the model's conclusions, kept strictly apart (the latter UNVERIFIED)."""
    weak = facts.get("confirmed_weaknesses", [])
    L = [f"# AVRA research report — {', '.join(t['host'] + ':' + str(t['port']) for t in facts['targets']) or 'no targets'}",
         "",
         f"- **Generated:** {meta['generated_at']}  ",
         (f"- **Session:** `{facts['session_id']}` (evidence "
          f"{'trusted: audit chain valid' if facts['session_trusted'] else '**NOT trusted**'})  "),
         f"- **Objective:** {_md(trace.get('objective', ''))}  ",
         f"- **Model:** {_md(trace.get('model', ''))} via {_md(trace.get('provider', ''))}, prompt "
         f"`{_md(trace.get('prompt_version', ''))}`; {trace.get('calls', 0)} call(s), "
         f"{trace.get('tokens_in', 0)} in / {trace.get('tokens_out', 0)} out tokens"
         + (f", {trace['compactions']} context compaction(s)" if trace.get("compactions") else "")
         + "  ",
         (f"- **Stopped:** {_md(trace.get('stop', {}).get('reason', ''))} — "
          f"{_md(trace.get('stop', {}).get('detail', ''))}  "),
         f"- **Verification report:** `{meta['verification_report']}`",
         "",
         ("> *Verified* statements come only from AVRA's deterministic Verification Engine on "
          "hash-checked evidence. The *research trace* is what happened, from the audit log. "
          "The *model's conclusions* are its own words and are **UNVERIFIED**."),
         "", "## Executive summary", "",
         (f"Deterministic result: **{len(facts['confirmed_findings'])} confirmed vulnerability(ies)**, "
          f"{len(weak)} confirmed configuration weakness(es) (not proven exploitable), "
          f"{len(facts['verified'])} verified observation(s), {len(facts['inconclusive'])} open "
          "question(s)."), ""]
    if trace.get("finish"):
        L += [f"Model's closing summary (unverified): {_md(trace['finish'])}", ""]
    L += deterministic_sections(facts)
    L += ["## Research trace", ""]
    L += [f"{i}. {_md(x)}" for i, x in enumerate(trace.get("steps", []), 1)] or [
        "No proposals, tool runs or verification requests in this run."]
    L.append("")
    L += _board_section(trace)
    L += ["## Model's conclusions (UNVERIFIED)", ""]
    if trace.get("hypotheses"):
        L += ["### Hypotheses recorded", ""]
        L += [f"- **{_md(h['statement'])}** — basis: {_md(h['basis'])} (UNVERIFIED)"
              for h in trace["hypotheses"]]
        L.append("")
    if trace.get("observations"):
        L += ["### Observations recorded", ""]
        L += [f"- {_md(o)} (unverified)" for o in trace["observations"]]
        L.append("")
    if not (trace.get("hypotheses") or trace.get("observations") or trace.get("finish")):
        L += ["_The model recorded no conclusions._", ""]
    L += ["## Recommendations", "", *deterministic_recommendations(facts)]
    L += ["## Limitations", ""]
    L += [f"- {_md(x)}" for x in list(dict.fromkeys(vreport.get("limitations", [])))[:10]]
    L += ["- Model text (summary, hypotheses, observations) is never evidence.", "", "---",
          f"_AVRA research report (M9.3). Session audit: `{meta['audit_file']}`._", ""]
    return "\n".join(L)


def _board_section(trace: dict) -> list[str]:
    """M10.3: the model's structured hypotheses. State comes from the engine; the
    statement is the model's own UNVERIFIED text."""
    board = trace.get("board") or {}
    if not board:
        return []
    L = ["## Research hypotheses (M10 board)", "",
         ("State is derived by AVRA from Verification Engine verdicts (`confirmed`/`rejected` "
          "only from the engine; `needs_capability` = no permitted deterministic check exists "
          "yet). The statement is the model's own text and is **UNVERIFIED**."), "",
         "| ID | Class | Target / endpoint | Endpoint observed | State | Statement (unverified) |",
         "|---|---|---|---|---|---|"]
    for hid, h in board.items():
        obs = {True: "yes", False: "**no (model guess)**", None: "—"}[h.get("endpoint_observed")]
        cite = (f" ({len(h['unverified_refs'])} cited id(s) not in evidence)"
                if h.get("unverified_refs") else "")
        L.append(f"| `{_md(hid)}` | {_md(h.get('vuln_class'))} | {_md(h.get('target'))}"
                 f"{_md(h.get('endpoint') or '')} | {obs} | **{_md(h.get('state'))}** | "
                 f"{_md(h.get('statement'))}{cite} |")
    summ = trace.get("board_summary") or {}
    if summ:
        L += ["", f"Board at the end: {summ.get('hypotheses', 0)} hypothesis(es); states "
              + ", ".join(f"{k} {v}" for k, v in (summ.get("states") or {}).items() if v)
              + f"; {summ.get('unverified_citations', 0)} unverified citation(s), "
              f"{summ.get('unobserved_endpoints', 0)} unobserved endpoint(s)."]
    return [*L, ""]


def write_research_report(out_dir: Path, meta: dict, facts: dict, vreport: dict,
                          trace: dict) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    base, n = f"research-{stamp}", 1
    while (out_dir / f"{base}.md").exists():
        n += 1
        base = f"research-{stamp}-{n}"
    path = out_dir / f"{base}.md"
    with open(path, "x", encoding="utf-8", newline="\n") as fh:
        fh.write(render_research_markdown(meta, facts, vreport, trace))
    return path


_HEADER_NOTES = {
    "content-security-policy": ("absent: no CSP in this response (limits XSS mitigation)", None),
    "x-frame-options": ("absent: framing not restricted by this header", None),
    "x-content-type-options": ("absent: MIME sniffing not disabled", "nosniff"),
    "referrer-policy": ("absent: browser default referrer behaviour", None),
    "strict-transport-security": ("absent (only meaningful over HTTPS; this probe used plain HTTP)", None),
    "access-control-allow-origin": ("absent: no CORS grant", None),
}


def _header_note(name: str, value: str | None) -> str:
    absent, good = _HEADER_NOTES[name]
    if value is None:
        return absent
    if name == "access-control-allow-origin" and value.strip() == "*":
        return "`*`: any web origin may read responses (fine for public content, risky for APIs)"
    if good and value.strip().lower() != good:
        return f"present with unexpected value `{_md(value)}`"
    return f"present: `{_md(value)}`"


def _header_section(facts: dict) -> list[str]:
    """Deterministic observations from recorded HTTP responses - NOT verdicts."""
    rows = []
    for t in facts["targets"]:
        for h in t["http"]:
            sec = h.get("security_headers")
            if not sec:
                continue
            for name in _HEADER_NOTES:
                rows.append(f"| {t['host']}:{t['port']} | `{name}` | {_header_note(name, sec.get(name))} "
                            f"| `{h['evidence']['request_id'][:8]}` |")
    if not rows:
        return []
    return ["### HTTP security headers (recorded response)", "",
            ("Raw observations from the recorded response(s), not verdicts. Rule-decided items "
             "appear under *Confirmed configuration weaknesses* (with `--rules web`: CSP, framing, "
             "CORS wildcard, version disclosure, nosniff); none of them is a proven exploitable "
             "vulnerability."),
            "", "| Target | Header | Observation | Evidence |", "|---|---|---|---|", *rows, ""]


def _ai_line(o: AnalysisOutcome) -> str:
    if o.status == "skipped":
        return "not requested"
    base = f"{o.provider} / `{_md(o.model)}`"
    if o.status != "ok":
        return f"{base} — **{o.status}**: {_md(o.detail)}"
    tok = o.usage.get("input_tokens", 0) + o.usage.get("output_tokens", 0)
    cost = "no API cost (local)" if o.cost_usd == 0 else f"${o.cost_usd:.4f}"
    return f"{base} — {tok} tokens, {o.seconds}s, {cost}"


@dataclass
class AssessmentFiles:
    markdown: Path
    json: Path
    audit: Path
    markdown_sha256: str


def write_assessment(out_dir: Path, audit: AuditLog, meta: dict, facts: dict, vreport: dict,
                     outcome: AnalysisOutcome) -> AssessmentFiles:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    base, n = f"assessment-{stamp}", 1
    while (out_dir / f"{base}.md").exists() or (out_dir / f"{base}.json").exists():
        n += 1  # two runs in the same second: never overwrite, never crash
        base = f"assessment-{stamp}-{n}"
    md_path, js_path = out_dir / f"{base}.md", out_dir / f"{base}.json"
    meta = {**meta, "audit_file": str(audit.path)}
    md = render_markdown(meta, facts, vreport, outcome)
    doc = {"format": REPORT_FORMAT, "prompt_version": PROMPT_VERSION, "meta": meta, "facts": facts,
           "analysis": {"status": outcome.status, "detail": outcome.detail,
                        "provider": outcome.provider, "model": outcome.model,
                        "usage": outcome.usage, "cost_usd": outcome.cost_usd,
                        "seconds": outcome.seconds, "dropped": outcome.dropped,
                        "result": outcome.analysis.model_dump() if outcome.analysis else None,
                        "label": "UNVERIFIED model output - never evidence"}}
    for p, data in ((md_path, md), (js_path, json.dumps(doc, indent=1, sort_keys=True) + "\n")):
        with open(p, "x", encoding="utf-8", newline="\n") as fh:  # never overwrite
            fh.write(data)
    md_sha = hashlib.sha256(md_path.read_bytes()).hexdigest()
    audit.record("assessment_written", {
        "markdown": md_path.name, "markdown_sha256": md_sha, "json": js_path.name,
        "json_sha256": hashlib.sha256(js_path.read_bytes()).hexdigest(),
        "analysis_status": outcome.status,
        "confirmed_findings": len(facts["confirmed_findings"]),
        "confirmed_weaknesses": len(facts.get("confirmed_weaknesses", [])),
        "ai_hypotheses_unverified": len(outcome.analysis.hypotheses) if outcome.analysis else 0})
    return AssessmentFiles(md_path, js_path, audit.path, md_sha)


def open_audit(assessments_root: Path, session_id: str) -> AuditLog:
    uuid.UUID(session_id)
    audit = AuditLog(Path(assessments_root) / session_id / AUDIT_NAME)
    check = audit.verify_detailed()
    if not check.ok:
        raise ValueError(f"assessment audit chain is broken - refusing to append ({check.describe()})")
    return audit
