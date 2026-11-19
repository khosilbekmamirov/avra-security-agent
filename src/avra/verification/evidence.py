"""Load a session's evidence as trusted, typed observations (M8.4, ADR 0009).

Evidence is trusted only if ALL of these hold, otherwise it is excluded with
an ``EvidenceIssue`` and can support nothing (fail closed):

1. The session audit chain verifies (``AuditLog.verify``). The chain is
   unsigned: it shows the log is internally consistent, not who wrote it.
2. The ``tool_result_received`` record pairs with exactly one earlier
   ``tool_request_sent`` (same request_id, tool, host and port(s)); a
   request_id with two results is contradictory and excluded.
3. The run completed (status ``completed``, exit 0), the Runner's output
   hash was verified, and the recorded evidence hash equals the Runner's
   ``output_sha256``.
4. The evidence file — located ONLY from validated UUIDs, never from the
   recorded path — is a regular file (no symlink/junction) whose SHA-256
   equals the audit record.
5. Its content parses with the tool's own strict parser and matches the
   request: nmap hosts/ports must be the requested ones; an HTTP envelope
   must carry exactly the fixed request for that host:port.

Original audit logs and evidence files are only read, never written.

The model's free-text ``record_hypothesis`` notes are collected as
``ModelNote``s: shown as unverified text, never turned into hypotheses.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from avra.core.snapshot import SnapshotError, scope_from_snapshot
from avra.recon.http_probe import (
    HttpProbeError,
    HttpResponseFacts,
    parse_envelope,
    parse_http_response,
)
from avra.recon.nmap_xml import NmapXmlError, parse_nmap_xml
from avra.reporting.store import _inspect  # symlink/junction-safe regular-file check
from avra.storage.audit import AuditLog
from avra.verification.models import (
    EvidenceIssue,
    EvidenceKind,
    EvidenceRef,
    Target,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LOOP_EVENTS = ("verification_hypothesis", "verification_verdict", "verification_repeat",
                "verification_no_progress", "verification_request_refused")
_LOOP_FIELDS = ("step", "trigger", "hypothesis_id", "rule_id", "rule_version", "target",
                "origin", "proposed_by", "rationale", "verdict", "reason_code", "revised_from",
                "evidence", "result_sha256", "idle_steps", "prompt_version", "stop_reason",
                "verification_loop", "verification", "detail", "status", "host", "port",
                "reason")
_TOOLS = {"nmap_connect_scan": (EvidenceKind.NMAP_XML, ".xml"),
          "http_probe": (EvidenceKind.HTTP_ENVELOPE, ".json"),
          "http_get_path": (EvidenceKind.HTTP_ENVELOPE, ".json")}  # M10.5


@dataclass(frozen=True)
class TcpPortObservation:
    ref: EvidenceRef
    target: Target
    state: str   # nmap: open | closed | filtered | open|filtered | ...
    reason: str  # nmap: syn-ack | conn-refused | no-response | ...
    host_status: str


@dataclass(frozen=True)
class HttpObservation:
    ref: EvidenceRef
    target: Target
    outcome: str  # envelope outcome (response_received, connection_refused, ...)
    complete: bool
    truncated: bool
    response_sha256: str
    facts: HttpResponseFacts | None  # None when no response bytes were received
    path: str = "/"  # M10.5: the requested path (http_probe is always GET /)


Observation = TcpPortObservation | HttpObservation


@dataclass(frozen=True)
class ModelNote:
    audit_seq: int
    statement: str
    basis: str


@dataclass
class SessionEvidence:
    session_id: str
    audit_present: bool = False
    audit_valid: bool = False
    audit_sha256: str = ""
    audit_records: int = 0
    scope_session_name: str = ""
    scope_snapshot_recorded: bool = False
    observations: list[Observation] = field(default_factory=list)
    issues: list[EvidenceIssue] = field(default_factory=list)
    model_notes: list[ModelNote] = field(default_factory=list)
    # M8.5: the research loop's own record (verification_* events, prompt
    # versions, stop reasons), read back for the verification report.
    loop_events: list[dict] = field(default_factory=list)
    # The owner's environment description (scope ``description``) from the
    # latest research run, taken only if that run's scope snapshot verifies
    # against its recorded hash; otherwise empty (fail closed). It is context
    # for an LLM proposer only: the engine and the rules never read it, so it
    # cannot change a verdict.
    owner_environment: str = ""
    # M8.6 (G4): the scope each research run actually used, from its own
    # research_started record (label only trusted when its snapshot verifies).
    # ``scope_session_name`` above is the label recorded when the SESSION was
    # created (e.g. by `avra probe http`), which can differ.
    run_scopes: list[dict] = field(default_factory=list)

    @property
    def trusted(self) -> bool:
        return self.audit_present and self.audit_valid

    def for_target(self, target: Target) -> list[Observation]:
        return [o for o in self.observations if o.target == target]

    def targets(self) -> list[Target]:
        return sorted({o.target for o in self.observations}, key=lambda t: (t.host, t.port))

    def refs(self) -> dict[str, EvidenceRef]:
        return {o.ref.request_id: o.ref for o in self.observations}

    def provenance_limitations(self) -> list[str]:
        out = [("The audit chain is unsigned: it proves internal consistency, "
                "not who wrote it (ADR 0006/0009).")]
        if not self.scope_snapshot_recorded:
            out.append("This session recorded no scope snapshot; the scope in force "
                       "at collection time is not attested.")
        return out


def _uuid(value: object) -> uuid.UUID | None:
    if not isinstance(value, str):
        return None
    try:
        u = uuid.UUID(value)
    except ValueError:
        return None
    return u if str(u) == value else None


def evidence_file(evidence_root: Path, session_id: uuid.UUID, request_id: uuid.UUID,
                  tool: str) -> Path:
    return Path(evidence_root) / str(session_id) / f"{request_id}{_TOOLS[tool][1]}"


def load_session_evidence(sessions_dir: Path, evidence_root: Path,
                          session_id: str) -> SessionEvidence:
    """Read-only. Never raises for bad evidence: problems become issues."""
    out = SessionEvidence(session_id=session_id)
    sid = _uuid(session_id)
    if sid is None:
        out.issues.append(EvidenceIssue(label=str(session_id)[:64], code="invalid_session_id"))
        return out
    log_path = Path(sessions_dir) / f"{sid}.jsonl"
    entry = _inspect(log_path)
    if entry.kind != "regular":
        out.issues.append(EvidenceIssue(label=log_path.name,
                                        code="audit_missing" if entry.kind == "absent"
                                        else "audit_unsafe", detail=entry.why or ""))
        return out
    out.audit_present, out.audit_sha256 = True, entry.sha256 or ""
    audit = AuditLog(log_path)
    try:
        records = audit.read_all()
        out.audit_valid = audit.verify()
    except (OSError, ValueError, KeyError, TypeError) as exc:  # malformed JSONL etc.
        out.issues.append(EvidenceIssue(label=log_path.name, code="audit_unreadable",
                                        detail=type(exc).__name__))
        return out
    out.audit_records = len(records)
    if not out.audit_valid:
        out.issues.append(EvidenceIssue(label=log_path.name, code="audit_chain_broken",
                                        detail="hash chain does not verify; no evidence "
                                               "from this session is trusted"))
        return out

    sent: dict[str, dict] = {}
    sent_seq: dict[str, int] = {}
    results: dict[str, list[tuple[int, dict]]] = {}
    for rec in records:
        d = rec.data if isinstance(rec.data, dict) else {}
        if rec.event == "session_created":
            out.scope_session_name = str(d.get("scope_session_name", ""))[:100]
        elif rec.event in _LOOP_EVENTS or rec.event in ("research_started", "research_stopped"):
            if rec.event == "research_started":
                out.scope_snapshot_recorded = bool(d.get("scope_snapshot")) and \
                    bool(d.get("scope_snapshot_sha256"))
                out.owner_environment = ""
                run_scope = {"seq": rec.seq, "scope_session_name": None,
                             "scope_snapshot_sha256": None, "snapshot_verified": False,
                             "prompt_version": str(d.get("prompt_version", ""))[:40] or None}
                if out.scope_snapshot_recorded:
                    try:
                        scope = scope_from_snapshot(d["scope_snapshot"],
                                                    d["scope_snapshot_sha256"])
                        out.owner_environment = scope.description.strip()
                        run_scope.update(scope_session_name=scope.session_name[:100],
                                         scope_snapshot_sha256=d["scope_snapshot_sha256"],
                                         snapshot_verified=True)
                    except SnapshotError:
                        pass  # fail closed: no context rather than unverified context
                out.run_scopes.append(run_scope)
            # research runs are part of the loop trace only in verification mode
            if rec.event in _LOOP_EVENTS or "verification_loop" in d or "verification" in d:
                keep = {k: d[k] for k in _LOOP_FIELDS if k in d}
                if rec.event == "research_started":
                    keep.update(run_scope=out.run_scopes[-1])
                out.loop_events.append({"seq": rec.seq, "event": rec.event, **keep})
        elif rec.event == "llm_hypothesis":
            out.model_notes.append(ModelNote(audit_seq=rec.seq,
                                             statement=str(d.get("statement", ""))[:1000],
                                             basis=str(d.get("basis", ""))[:1000]))
        elif rec.event == "tool_request_sent":
            rid = str(d.get("request_id"))
            if rid in sent:
                out.issues.append(EvidenceIssue(label=rid[:64], code="duplicate_request"))
                sent[rid] = {}  # poisoned: any result for it is excluded
            else:
                sent[rid] = d
                sent_seq[rid] = rec.seq
        elif rec.event == "tool_result_received":
            results.setdefault(str(d.get("request_id")), []).append((rec.seq, d))

    for rid, items in sorted(results.items()):
        if len(items) != 1:
            out.issues.append(EvidenceIssue(label=rid[:64], code="contradictory_results",
                                            detail=f"{len(items)} results for one request"))
            continue
        seq, res = items[0]
        if rid in sent_seq and sent_seq[rid] >= seq:  # a result cannot precede its request
            out.issues.append(EvidenceIssue(label=rid[:64], code="result_before_request"))
            continue
        try:
            _load_one(out, sid, Path(evidence_root), rid, seq, sent.get(rid), res)
        except (ValueError, TypeError, KeyError) as exc:  # never raise for bad evidence
            out.issues.append(EvidenceIssue(label=rid[:64], code="malformed_record",
                                            detail=type(exc).__name__))
    for rid in sorted(set(sent) - set(results)):
        if sent[rid]:
            out.issues.append(EvidenceIssue(label=rid[:64], code="no_result",
                                            detail="request sent but no result recorded"))
    out.observations.sort(key=lambda o: (o.target.host, o.target.port, o.ref.audit_seq))
    return out


def _load_one(out: SessionEvidence, sid: uuid.UUID, evidence_root: Path, rid: str,
              seq: int, req: dict | None, res: dict) -> None:
    def issue(code: str, detail: str = "") -> None:
        out.issues.append(EvidenceIssue(label=rid[:64], code=code, detail=detail[:300]))

    request_id = _uuid(rid)
    if request_id is None:
        return issue("invalid_request_id")
    if not req:
        return issue("unpaired_result", "no matching tool_request_sent")
    tool = res.get("tool")
    if tool not in _TOOLS:
        return issue("unsupported_evidence", f"tool {str(tool)[:40]!r}")
    if req.get("tool") != tool or req.get("host") != res.get("host"):
        return issue("request_result_mismatch", "tool or host differs")
    if tool in ("http_probe", "http_get_path") and req.get("port") != res.get("port"):
        return issue("request_result_mismatch", "port differs")
    if tool == "http_get_path" and (not isinstance(req.get("path"), str)
                                    or req.get("path") != res.get("path")):
        return issue("request_result_mismatch", "path differs")
    if tool == "nmap_connect_scan" and req.get("ports") != res.get("ports"):
        return issue("request_result_mismatch", "ports differ")
    if res.get("status") != "completed" or res.get("exit_code") != 0:
        return issue("run_not_completed", f"status={res.get('status')} "
                                          f"exit={res.get('exit_code')}")
    if res.get("hash_verified") is not True:
        return issue("output_hash_unverified")
    recorded = res.get("evidence_sha256")
    if not isinstance(recorded, str) or not _HEX64.fullmatch(recorded):
        return issue("no_evidence_hash")
    if recorded != res.get("output_sha256"):
        return issue("hash_mismatch", "evidence hash differs from the Runner's output hash")
    path = evidence_file(evidence_root, sid, request_id, tool)
    entry = _inspect(path)
    if entry.kind != "regular":
        return issue("missing_file" if entry.kind == "absent" else "unsafe_file", entry.why or "")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != recorded:
        return issue("hash_mismatch", "file SHA-256 differs from the audit record")

    kind = _TOOLS[tool][0]
    ref = EvidenceRef(session_id=str(sid), request_id=rid, tool=tool, kind=kind,
                      sha256=recorded, audit_seq=seq)
    host = req.get("host")
    if tool == "nmap_connect_scan":
        ports = req.get("ports")
        if not isinstance(ports, list):
            return issue("malformed_request", "ports")
        try:
            report = parse_nmap_xml(raw.decode("utf-8"))
        except (NmapXmlError, UnicodeDecodeError) as exc:
            return issue("malformed_evidence", str(exc))
        if report.exit_status == "error":
            return issue("incomplete_scan", "nmap runstats exit=error")
        found = []
        for h in report.hosts:
            if h.address != host:
                return issue("target_mismatch", "nmap host differs from the request")
            for p in h.ports:
                if p.protocol != "tcp" or p.port not in ports:
                    return issue("target_mismatch", f"unrequested port {p.port}/{p.protocol}")
                found.append(TcpPortObservation(ref=ref, target=Target(host=host, port=p.port),
                                                state=p.state, reason=p.reason,
                                                host_status=h.status))
        out.observations.extend(found)
        return None
    port = req.get("port")
    try:
        req_path = req.get("path") if tool == "http_get_path" else None
        env, _req, resp = parse_envelope(raw.decode("ascii"), host=host, port=port,
                                         path=req_path)
    except (HttpProbeError, UnicodeDecodeError) as exc:
        return issue("malformed_evidence", str(exc))
    if env.response_sha256 != res.get("response_sha256", env.response_sha256):
        return issue("hash_mismatch", "response hash differs from the audit record")
    facts = (parse_http_response(resp, complete=env.complete, truncated=env.truncated)
             if resp else None)
    out.observations.append(HttpObservation(
        ref=ref, target=Target(host=host, port=port), outcome=env.outcome,
        complete=env.complete, truncated=env.truncated,
        response_sha256=env.response_sha256, facts=facts, path=req_path or "/"))
    return None
