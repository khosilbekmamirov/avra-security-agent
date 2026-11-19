"""Read-only, structured retrieval for the conversational agent (M11.3, ADR 0019).

Every function here reads AVRA's own local records - session audit logs, hash-checked
evidence, verification and research reports - and returns a SMALL, bounded dict:

* nothing here writes a file, sends a request or calls a model;
* verdicts are recomputed in memory by the deterministic Verification Engine from
  trusted evidence (the model never decides them);
* server-controlled text (titles, header values, paths) is bounded and labelled;
* raw audit logs are never returned - only counts, ids, hashes and verdicts.

The chat agent exposes these as read-only tools. They run automatically: they only look
at evidence AVRA already holds.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

MAX_SESSIONS = 20
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class KnowledgeError(Exception):
    """A request for something that does not exist or is not allowed."""


def data_dir() -> Path:
    return Path(os.environ.get("AVRA_DATA_DIR", "data"))


def _sid(session_id: str) -> str:
    s = str(session_id).strip().lower()
    if not _UUID.fullmatch(s):
        raise KnowledgeError("session_id must be a full session UUID (see list_investigations)")
    if not (data_dir() / "sessions" / f"{s}.jsonl").is_file():
        raise KnowledgeError(f"no recorded session {s}")
    return s


def resolve_session(ref: str | None) -> str:
    """A full UUID, a unique prefix of at least 6 characters, or 'latest'."""
    sessions = _session_files()
    if not sessions:
        raise KnowledgeError("no recorded sessions")
    if not ref or ref == "latest":
        return sessions[0].stem
    ref = str(ref).strip().lower()
    if len(ref) < 6:
        raise KnowledgeError("use at least 6 characters of the session id")
    hits = [p.stem for p in sessions if p.stem.startswith(ref)]
    if len(hits) != 1:
        raise KnowledgeError(f"{'no' if not hits else 'more than one'} session matches {ref!r}")
    return hits[0]


def _session_files() -> list[Path]:
    d = data_dir() / "sessions"
    if not d.is_dir():
        return []
    files = [p for p in d.glob("*.jsonl") if _UUID.fullmatch(p.stem)]
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)


def _records(sid: str):
    from avra.storage.audit import AuditLog

    log = AuditLog(data_dir() / "sessions" / f"{sid}.jsonl")
    return log.read_all(), log.verify()


def _reports(sid: str) -> dict:
    out: dict = {}
    a = data_dir() / "assessments" / sid
    if a.is_dir():
        research = sorted(a.glob("research-*.md"))
        assess = sorted(a.glob("assessment-*.md"))
        if research:
            out["latest_research_report"] = str(research[-1])
        if assess:
            out["latest_assessment_report"] = str(assess[-1])
    v = data_dir() / "verification" / sid
    if v.is_dir():
        reps = sorted(v.glob("report-*.json"), key=lambda p: p.stat().st_mtime)
        if reps:
            out["latest_verification_report"] = str(reps[-1])
    return out


def list_investigations() -> dict:
    """Recorded sessions, newest first: targets, tool runs, research runs, report paths."""
    rows = []
    for p in _session_files()[:MAX_SESSIONS]:
        sid = p.stem
        try:
            recs, valid = _records(sid)
        except Exception:  # noqa: BLE001 - one unreadable log must not hide the others
            rows.append({"session_id": sid, "audit_valid": False, "error": "unreadable"})
            continue
        tools: dict[str, int] = {}
        targets: set[str] = set()
        runs, label = 0, ""
        for r in recs:
            d = r.data if isinstance(r.data, dict) else {}
            if r.event == "session_created":
                label = str(d.get("scope_session_name", ""))[:80]
            elif r.event == "tool_result_received":
                tools[str(d.get("tool"))] = tools.get(str(d.get("tool")), 0) + 1
                ports = d.get("ports") or [d.get("port")]
                targets.update(f"{d.get('host')}:{x}" for x in ports if x)
            elif r.event == "research_started":
                runs += 1
        rows.append({"session_id": sid, "scope_label": label, "audit_valid": valid,
                     "created": recs[0].ts if recs else None,
                     "last_activity": recs[-1].ts if recs else None,
                     "targets": sorted(targets)[:10], "tool_runs": tools,
                     "research_runs": runs, **_reports(sid)})
    return {"investigations": rows, "count": len(rows),
            "note": "Sessions recorded by AVRA on this machine; newest first."}


def _cycle(sid: str):
    from avra.verification.cycle import Budget, ResearchCycle, RuleBasedProposer
    from avra.verification.engine import VerificationEngine
    from avra.verification.evidence import load_session_evidence
    from avra.verification.rules import validation_registry

    ev = load_session_evidence(data_dir() / "sessions", data_dir() / "evidence", sid)
    state = ResearchCycle(VerificationEngine(validation_registry()), [RuleBasedProposer()],
                          Budget()).run(ev)
    return ev, state


def investigation(session_id: str) -> dict:
    """Engine verdicts (recomputed in memory), services, the latest research run and reports."""
    from avra.assessment import CONFIG_WEAKNESS_RULES, research_trace
    from avra.verification.evidence import HttpObservation, TcpPortObservation
    from avra.verification.models import RuleKind, Verdict

    sid = _sid(session_id)
    ev, state = _cycle(sid)
    services, http = [], []
    for o in ev.observations:
        if isinstance(o, TcpPortObservation):
            services.append({"target": o.target.label(), "tcp_state": o.state,
                             "evidence": o.ref.request_id})
        elif isinstance(o, HttpObservation):
            f = o.facts
            http.append({"target": o.target.label(), "path": getattr(o, "path", "/"),
                         "tool": o.ref.tool, "outcome": o.outcome,
                         "status_code": f.status_code if f else None,
                         "content_type": (f.content_type[:60] if f else ""),
                         "body_bytes": f.body_bytes if f else 0,
                         **({"truncated_at_256KiB_limit": True} if o.truncated else {}),
                         "title_server_claim": (f.title[:80] if f else ""),
                         "evidence": o.ref.request_id,
                         "evidence_sha256": o.ref.sha256[:16]})
    groups: dict[str, list] = {"verified_observations": [], "configuration_weaknesses": [],
                               "confirmed_vulnerabilities": [], "rejected": [],
                               "inconclusive": []}
    for e in sorted(state.entries.values(), key=lambda e: e.hypothesis.rule_id):
        r = e.result
        row = {"rule": r.rule_id, "target": r.target.label(), "verdict": r.verdict.value,
               "reason": r.reason[:200], "evidence": [x.request_id for x in r.evidence_used][:3]}
        if r.verdict is Verdict.CONFIRMED:
            key = ("verified_observations" if r.rule_kind is RuleKind.OBSERVATION
                   else "configuration_weaknesses" if r.rule_id in CONFIG_WEAKNESS_RULES
                   else "confirmed_vulnerabilities")
        elif r.verdict is Verdict.REJECTED:
            key = "rejected"
        else:
            key = "inconclusive"
            row["missing_evidence"] = list(r.missing_evidence)[:3]
        groups[key].append(row)
    recs, valid = _records(sid)
    trace = research_trace(recs)
    last_run = {}
    if trace:
        last_run = {"objective": trace.get("objective", "")[:300], "model": trace.get("model"),
                    "prompt_version": trace.get("prompt_version"), "stop": trace.get("stop"),
                    "model_calls": trace.get("calls"),
                    "steps": [s[:200] for s in trace.get("steps", [])][-15:],
                    "model_closing_summary_UNVERIFIED": (trace.get("finish") or "")[:800],
                    "board_hypotheses": [
                        {"id": k, "class": v.get("vuln_class"), "target": v.get("target"),
                         "endpoint": v.get("endpoint"), "state": v.get("state"),
                         "endpoint_observed": v.get("endpoint_observed"),
                         "statement_UNVERIFIED": str(v.get("statement", ""))[:200]}
                        for k, v in list(trace.get("board", {}).items())[:8]]}
    return {"session_id": sid, "audit_chain_valid": valid,
            "evidence_trusted": ev.trusted,
            "excluded_evidence": [{"id": i.label, "code": i.code} for i in ev.issues][:5],
            "services": services[:10], "http_responses": http[:10], **groups,
            "latest_research_run": last_run, "reports": _reports(sid),
            "legend": ("Verdicts come only from AVRA's deterministic Verification Engine on "
                       "hash-checked evidence. A configuration weakness is a hardening gap, "
                       "not a proven exploitable vulnerability. Anything marked UNVERIFIED is "
                       "model text.")}


def summary(session_id: str) -> dict:
    """M13: a SMALL, deterministic, evidence-grounded digest of one investigation.

    Built purely from :func:`investigation` (engine verdicts recomputed in memory) plus the
    session audit order; no model call, nothing invented. The engine's verdict is carried
    through verbatim - an INCONCLUSIVE stays INCONCLUSIVE. ``next_step`` is a neutral
    suggestion derived only from the verdict, never a finding. This digest is what ``/summary``
    renders and what the compact ``summarize_investigation`` tool returns, so the common
    "explain the latest result" need costs few or zero tokens."""
    sid = _sid(session_id)
    inv = investigation(sid)

    def _verdict_for(rule_id: str) -> dict | None:
        for grp in ("verified_observations", "configuration_weaknesses",
                    "confirmed_vulnerabilities", "rejected", "inconclusive"):
            for row in inv[grp]:
                if row["rule"] == rule_id:
                    return row
        return None

    # Chronological order of nmap results from the hash-chained audit log (not model text).
    recs, _valid = _records(sid)
    nmap_order = [str(r.data.get("request_id")) for r in recs
                  if r.event == "tool_result_received"
                  and str((r.data or {}).get("tool")) == "nmap_connect_scan"]
    state_by_rid = {s["evidence"]: s["tcp_state"] for s in inv["services"]}
    ordered = [state_by_rid[rid] for rid in nmap_order if rid in state_by_rid]
    if not ordered:  # fall back to whatever evidence we have, unordered
        ordered = [s["tcp_state"] for s in inv["services"]]

    port_status = None
    if ordered:
        counts: dict[str, int] = {}
        for st in ordered:
            counts[st] = counts.get(st, 0) + 1
        v = _verdict_for("net.tcp_port_open")
        targets = sorted({s["target"] for s in inv["services"]})
        port_status = {
            "targets": targets[:5],
            "latest_state": ordered[-1] if nmap_order else None,  # None if order unknown
            "state_counts": counts,
            "scan_count": sum(counts.values()),
            "conflicting": len(counts) > 1,
            "verdict": v["verdict"] if v else "not_evaluated",
            "reason": v["reason"] if v else "",
        }

    http = [{"target": h["target"], "path": h.get("path", "/"), "outcome": h["outcome"],
             "status_code": h["status_code"]} for h in inv["http_responses"][:5]]

    verdict_counts = {k: len(inv[k]) for k in
                      ("verified_observations", "configuration_weaknesses",
                       "confirmed_vulnerabilities", "rejected", "inconclusive")}

    return {
        "session_id": sid,
        "audit_chain_valid": inv["audit_chain_valid"],
        "evidence_trusted": inv["evidence_trusted"],
        "port_status": port_status,
        "http": http,
        "verdict_counts": verdict_counts,
        "configuration_weaknesses": [{"rule": r["rule"], "target": r["target"]}
                                     for r in inv["configuration_weaknesses"][:5]],
        "confirmed_vulnerabilities": [{"rule": r["rule"], "target": r["target"]}
                                      for r in inv["confirmed_vulnerabilities"][:5]],
        "next_step": _next_step(port_status, verdict_counts),
        "note": ("Deterministic digest from AVRA's engine on hash-checked evidence. A "
                 "configuration weakness is a hardening gap, not a proven exploit. "
                 "INCONCLUSIVE means unresolved, not a finding."),
    }


def _next_step(port_status: dict | None, verdict_counts: dict) -> str:
    """A neutral next-step suggestion derived ONLY from the engine verdict; never a finding."""
    if port_status is None:
        return "No trusted scan evidence yet: run an in-scope nmap_connect_scan to establish it."
    v = port_status["verdict"]
    if v == "INCONCLUSIVE" or port_status["conflicting"]:
        return ("The port state conflicts between scans. Check the target service is actually "
                "running, then re-scan to resolve it.")
    if v == "CONFIRMED" and any("open" in s for s in port_status["state_counts"]):
        return "Port confirmed open. If useful, propose an in-scope http_probe of '/'."
    if v == "REJECTED":
        return "The port was not observed open. Confirm the service is meant to be running."
    return "Review the recorded evidence; propose an in-scope re-check if the state is unclear."


def explain(session_id: str, rule_id: str) -> dict:
    """Why one rule reached its verdict: criteria, evidence, limitations, fix."""
    from avra.assessment import CONFIG_WEAKNESS_RULES, RULE_REMEDIATION
    from avra.verification.rules import validation_registry

    sid = _sid(session_id)
    rule = validation_registry().get(str(rule_id))
    if rule is None:
        raise KnowledgeError(f"unknown rule {str(rule_id)[:80]!r}; see the rule ids in "
                             "get_investigation")
    _ev, state = _cycle(sid)
    hits = [e for e in state.entries.values() if e.hypothesis.rule_id == rule.id]
    if not hits:
        return {"rule": rule.id, "title": rule.title, "examined": False,
                "why": "This rule was not applicable to the session's evidence (the rule chain "
                       "did not reach it).", "confirmed_requires": rule.confirmed_requires}
    out = []
    for e in hits[:3]:
        r = e.result
        out.append({"target": r.target.label(), "verdict": r.verdict.value,
                    "reason_code": r.reason_code, "reason": r.reason,
                    "criteria": [c.model_dump() for c in r.checks],
                    "evidence": [{"request_id": x.request_id, "tool": x.tool,
                                  "sha256": x.sha256} for x in r.evidence_used][:3],
                    "missing_evidence": list(r.missing_evidence),
                    "limitations": list(r.limitations)[:6]})
    return {"rule": rule.id, "title": rule.title, "kind": rule.kind.value,
            "severity": rule.severity, "description": rule.description,
            "references": list(rule.references),
            "classification": ("configuration weakness (not proven exploitable)"
                               if rule.id in CONFIG_WEAKNESS_RULES else rule.kind.value),
            "remediation": RULE_REMEDIATION.get(rule.id, ""), "results": out}


def web_surface(session_id: str) -> dict:
    from avra.recon.web_surface import surface_digest, surfaces_from_evidence
    from avra.verification.evidence import load_session_evidence

    sid = _sid(session_id)
    ev = load_session_evidence(data_dir() / "sessions", data_dir() / "evidence", sid)
    surfaces, issues = surfaces_from_evidence(ev, data_dir() / "evidence")
    return {"session_id": sid, "surfaces": [surface_digest(s, 20) for s in surfaces],
            "excluded": [i.code for i in issues][:5],
            "note": ("'referenced_not_fetched' = a recorded response mentions it; 'fetched' = "
                     "AVRA requested exactly that path. Paths are server-controlled data.")}


def research_history(session_id: str) -> dict:
    """What happened in the latest research run (bounded trace from the audit log)."""
    from avra.assessment import research_trace

    sid = _sid(session_id)
    recs, valid = _records(sid)
    runs = sum(1 for r in recs if r.event == "research_started")
    t = research_trace(recs)
    if not t:
        return {"session_id": sid, "research_runs": 0,
                "note": "No research run recorded in this session."}
    return {"session_id": sid, "audit_chain_valid": valid, "research_runs": runs,
            "latest": {"objective": t["objective"][:300], "model": t["model"],
                       "provider": t["provider"], "prompt_version": t["prompt_version"],
                       "model_calls": t["calls"], "tokens_in": t["tokens_in"],
                       "tokens_out": t["tokens_out"], "context_compactions": t["compactions"],
                       "stop": t["stop"], "steps": [s[:220] for s in t["steps"]][-25:],
                       "model_closing_summary_UNVERIFIED": t["finish"][:1000]}}


def analysis(session_id: str, checker: Any = None) -> tuple[Any, Any, dict]:
    """One read-only pass over a session: hash-checked evidence, the engine's in-memory
    verdicts and the deterministic plan. Shared by ``plan`` and the M14.2 controller."""
    from avra.recon.web_surface import surfaces_from_evidence
    from avra.research import next_steps

    sid = _sid(session_id)
    ev, state = _cycle(sid)
    surfaces, _ = surfaces_from_evidence(ev, data_dir() / "evidence")
    recs, _valid = _records(sid)
    out = next_steps.plan(evidence=ev, state=state, surfaces=surfaces, records=recs,
                          checker=checker, scope_allows=scope_allows)
    return ev, state, {"session_id": sid, **out}


def plan(session_id: str, checker: Any = None) -> dict:
    """Evidence-driven next steps (M12.1, ``avra.research.next_steps``): inventory, steps with
    value + readiness (in the bound scope or not), and a conclusion - including when to stop."""
    return analysis(session_id, checker)[2]


def _step(tool: str, host: str, port: int, path: str | None, why: str, checker) -> dict:
    step = {"kind": tool, "target": f"{host}:{port}", **({"path": path} if path else {}),
            "why": why, "needs": "owner approval (/approve) + scope + operational Runner"}
    if checker is not None:
        step["scope_allows"] = scope_allows(checker, tool, host, port, path)
    else:
        step["scope_allows"] = None
        step["scope_note"] = "no scope bound to this chat (start avra chat --scope <file>)"
    return step


def scope_allows(checker, tool: str, host: str, port: int, path: str | None = None) -> bool:
    from avra.policy.tools import authorize_tool_request
    from avra.runner.schemas import (
        HttpGetPathRequest,
        HttpProbeRequest,
        NmapConnectScanRequest,
    )

    nil = uuid.UUID(int=0)
    try:
        if tool == "http_probe":
            req = HttpProbeRequest(request_id=nil, session_id=nil, host=host, port=port)
        elif tool == "http_get_path":
            req = HttpGetPathRequest(request_id=nil, session_id=nil, host=host, port=port,
                                     path=path or "")
        elif tool == "nmap_connect_scan":
            req = NmapConnectScanRequest(request_id=nil, session_id=nil, host=host,
                                         ports=[port])
        else:
            return False
    except ValueError:
        return False
    return authorize_tool_request(checker, req).allowed


def scope_summary(checker: Any) -> list[str]:
    """Owner-facing lines describing exactly what a bound scope authorizes (M12.3).

    Reused by the chat banner, ``/status`` and the CLI so the owner always sees the
    authorized target and permitted operations, never just a scope name. Reads only the
    already-loaded Scope object; contacts nothing."""
    if checker is None:
        return ["No scope bound: chat is read-only. No live action can be proposed or "
                "approved (start with --scope to enable proposals)."]
    s = checker.scope
    head = (f"Scope '{s.session_name}', expires {s.expires_at.isoformat()}"
            + ("  [EXPIRED - live actions refused]" if s.is_expired else ""))
    lines = [head]
    for t in s.targets:
        ports = ",".join(str(p) for p in t.ports)
        tools = ", ".join(t.allowed_tools) or "(none)"
        line = f"  target {t.host} port(s) {ports}: tools [{tools}]"
        if t.http_paths:
            line += f"; paths [{', '.join(t.http_paths)}]"
        lines.append(line)
    return lines


def capabilities() -> dict:
    """A fixed, honest description of what AVRA can and cannot do in chat."""
    return {
        "can_do_now": [
            "list and summarize recorded investigations (sessions) on this machine",
            ("explain engine verdicts: verified observations, configuration weaknesses, "
            "rejected and open hypotheses, with evidence ids and hashes"),
            "show the web surface found in recorded responses",
            "replay what happened in a research run",
            "build an evidence-grounded plan of next steps",
            "evaluate controlled validation fixtures (offline)",
        ],
        "needs_your_explicit_approval": [
            ("a live passive HTTP probe (GET /), a read-only GET of one discovered path, or an "
            "nmap connect scan - one action per /approve, only inside the bound scope, through "
            "the audited Runner pipeline, and only while the kill switch is disengaged"),
        ],
        "never": ["run shell commands", "send arbitrary requests or payloads",
                  "submit forms or log in", "act outside the scope file",
                  "treat a model's claim as a verified finding"],
    }


def to_json(data: Any, limit: int = 6000) -> str:
    text = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
    return text if len(text) <= limit else text[:limit] + '..."[truncated]"'
