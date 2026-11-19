"""M8.8 Phase 1B (finding F-1): Ctrl+C or a failure AFTER the Runner answered.

Phase 1A showed that an interrupt during post-result processing (leaving the
kill-switch context, storing evidence, parsing, writing ``tool_result_received``)
left the request without any terminal audit record, and evidence stored just
before the audit write was not traceable. These tests drive the real scan and
HTTP-probe pipelines (fake tunnel/client in-process, no network) and require:

* exactly ONE terminal record per submitted request, with its exact request_id;
* the KeyboardInterrupt is re-raised, never swallowed;
* no cancel is ever sent for a job the Runner already answered;
* any evidence file on disk is traceable from the audit (evidence or output hash);
* a failed audit write is never reported as a completed request.
"""

from __future__ import annotations

import hashlib
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pytest
from test_http_probe import _envelope  # real probe child output for host .103:3000

from avra.policy.scope import ScopeChecker
from avra.runner.schemas import (
    RejectionStage,
    RunnerRejection,
    ToolRunResult,
    ToolRunStatus,
)
from avra.runner_client import http_probe as probe_mod
from avra.runner_client import scan as scan_mod
from avra.runner_client.client import RunnerToken, RunOutcome
from avra.runner_client.tunnel import TunnelConfig
from avra.schemas.scope import ActionTier, Scope, Target
from avra.storage.audit import AuditLog, AuditWriteError

HOST, PORT = "10.66.7.103", 3000
TOKEN = RunnerToken("m88-test-token-" + "x" * 30)
XML = (Path(__file__).resolve().parents[1] / "fixtures/nmap/m5-juice-shop-3000-open.xml").read_text("utf-8")
TERMINAL = {"tool_result_received", "tool_request_interrupted", "tool_request_failed",
            "tool_request_rejected", "tool_request_denied_locally"}

SCOPE = Scope(session_name="m88", expires_at=datetime.now(UTC) + timedelta(days=1),
              targets=[Target(host=HOST, ports=[PORT],
                              allowed_tiers=[ActionTier.ACTIVE_SAFE, ActionTier.PASSIVE],
                              allowed_tools=["nmap_connect_scan", "http_probe"])])


class Tunnel:
    def __init__(self, cfg):
        pass

    def __enter__(self):
        return "http://127.0.0.1:1"

    def __exit__(self, *exc):
        return False


class Client:
    """Answers health/run like a Runner; records every call (incl. cancels)."""

    calls: ClassVar[list] = []
    answer: ClassVar[str] = "completed"

    def __init__(self, base_url, token):
        pass

    def health(self):
        Client.calls.append("health")
        return {"status": "ok"}

    def run(self, request):
        Client.calls.append(("run", str(request.request_id), str(request.session_id)))
        if Client.answer == "rejected":
            return RunOutcome(403, rejection=RunnerRejection(
                stage=RejectionStage.SCOPE, reason="not in scope", request_id=request.request_id))
        raw = XML if request.tool.value == "nmap_connect_scan" else _envelope()
        raw = raw if isinstance(raw, str) else raw.decode("ascii")
        now = datetime.now(UTC)
        return RunOutcome(200, result=ToolRunResult(
            request_id=request.request_id, tool=request.tool, status=ToolRunStatus.COMPLETED,
            started_at=now, finished_at=now, exit_code=0, raw_output=raw,
            output_sha256=hashlib.sha256(raw.encode()).hexdigest()), hash_verified=True)

    def cancel(self, *a, **k):
        Client.calls.append(("cancel", *[str(x) for x in a]))
        raise AssertionError("a cancel must never be sent for an answered request")


class InterruptingAudit(AuditLog):
    """Real AuditLog; raises at a chosen event, before or after the real write."""

    def __init__(self, path, event, when, exc=KeyboardInterrupt):
        super().__init__(path)
        self.event, self.when, self.exc, self.fired = event, when, exc, False

    def record(self, event, data=None):
        if event == self.event and not self.fired and self.when == "before":
            self.fired = True
            raise self.exc() if isinstance(self.exc, type) else self.exc
        rec = super().record(event, data)
        if event == self.event and not self.fired and self.when == "after":
            self.fired = True
            raise self.exc() if isinstance(self.exc, type) else self.exc
        return rec


def _run(kind, audit, tmp_path):
    common = {"checker": ScopeChecker(SCOPE), "audit": audit, "session_id": SID, "host": HOST,
              "token": TOKEN, "evidence_root": tmp_path / "evidence",
              "tunnel_cfg": TunnelConfig(), "tunnel_factory": Tunnel, "client_factory": Client}
    if kind == "scan":
        return scan_mod.run_nmap_connect_scan(ports=[PORT], timeout_seconds=30, **common)
    return probe_mod.run_http_probe(port=PORT, timeout_seconds=10,
                                    approval=probe_mod.APPROVAL_INTERACTIVE_TTY, **common)


SID = uuid.uuid4()


@pytest.fixture(autouse=True)
def _reset():
    Client.calls, Client.answer = [], "completed"


def _terminal(path: Path) -> tuple[str, list]:
    recs = AuditLog(path).read_all()
    sent = [r for r in recs if r.event == "tool_request_sent"]
    assert len(sent) == 1
    rid = sent[0].data["request_id"]
    term = [r for r in recs if r.event in TERMINAL and r.data.get("request_id") == rid]
    assert AuditLog(path).verify()
    return rid, term


def _evidence_traceable(tmp_path: Path, terminal) -> None:
    hashes = {terminal[0].data.get("evidence_sha256"), terminal[0].data.get("output_sha256")} - {None}
    for f in (tmp_path / "evidence").rglob("*"):
        if f.is_file():
            assert hashlib.sha256(f.read_bytes()).hexdigest() in hashes, f"untraceable evidence {f.name}"


def _raise_before(real):
    def f(*a, **k):
        raise KeyboardInterrupt
    return f


def _raise_after(real):
    def f(*a, **k):
        real(*a, **k)
        raise KeyboardInterrupt
    return f


PARSER = {"scan": "parse_nmap_xml", "probe": "parse_envelope"}


@pytest.mark.parametrize("kind", ["scan", "probe"])
@pytest.mark.parametrize("window", ["parse", "evidence_before", "evidence_after", "audit_before"])
def test_interrupt_after_result_leaves_exactly_one_terminal_record(kind, window, tmp_path, monkeypatch):
    audit = AuditLog(tmp_path / "a.jsonl")
    if window == "parse":
        monkeypatch.setattr(scan_mod if kind == "scan" else probe_mod, PARSER[kind], _raise_before(None))
    elif window == "evidence_before":
        monkeypatch.setattr(scan_mod if kind == "scan" else probe_mod, "store_evidence", _raise_before(None))
    elif window == "evidence_after":
        mod = scan_mod if kind == "scan" else probe_mod
        monkeypatch.setattr(mod, "store_evidence", _raise_after(mod.store_evidence))
    else:
        audit = InterruptingAudit(tmp_path / "a.jsonl", "tool_result_received", "before")

    with pytest.raises(KeyboardInterrupt):
        _run(kind, audit, tmp_path)

    rid, term = _terminal(tmp_path / "a.jsonl")
    assert [t.event for t in term] == ["tool_request_interrupted"]
    d = term[0].data
    assert d["request_id"] == rid and d["phase"] == "after_result" and d["submitted"] is True
    assert d["result_status"] == "completed" and d["output_sha256"]
    assert ("run", rid, str(SID)) in Client.calls
    assert not [c for c in Client.calls if c[0] == "cancel"]  # never cancel an answered job
    _evidence_traceable(tmp_path, term)


@pytest.mark.parametrize("kind", ["scan", "probe"])
def test_interrupt_right_after_the_result_record_adds_no_second_terminal(kind, tmp_path):
    audit = InterruptingAudit(tmp_path / "a.jsonl", "tool_result_received", "after")
    with pytest.raises(KeyboardInterrupt):
        _run(kind, audit, tmp_path)
    _rid, term = _terminal(tmp_path / "a.jsonl")
    assert [t.event for t in term] == ["tool_result_received"]  # no contradictory pair
    _evidence_traceable(tmp_path, term)


@pytest.mark.parametrize("kind", ["scan", "probe"])
def test_interrupt_while_recording_a_rejection(kind, tmp_path):
    Client.answer = "rejected"
    audit = InterruptingAudit(tmp_path / "a.jsonl", "tool_request_rejected", "before")
    with pytest.raises(KeyboardInterrupt):
        _run(kind, audit, tmp_path)
    _rid, term = _terminal(tmp_path / "a.jsonl")
    assert [t.event for t in term] == ["tool_request_interrupted"]
    assert term[0].data["runner_rejection_stage"] == "scope"
    assert not [c for c in Client.calls if c[0] == "cancel"]


@pytest.mark.parametrize("kind", ["scan", "probe"])
def test_failed_result_write_is_never_reported_as_completed(kind, tmp_path):
    audit = InterruptingAudit(tmp_path / "a.jsonl", "tool_result_received", "before",
                              exc=AuditWriteError("disk full (simulated)"))
    with pytest.raises(AuditWriteError):
        _run(kind, audit, tmp_path)
    _rid, term = _terminal(tmp_path / "a.jsonl")
    assert [t.event for t in term] == ["tool_request_failed"]
    d = term[0].data
    assert d["phase"] == "after_result" and d["error"] == "AuditWriteError"
    assert any("AuditWriteError" in e for e in d["errors"])
    _evidence_traceable(tmp_path, term)


@pytest.mark.parametrize("kind", ["scan", "probe"])
def test_interrupt_while_leaving_the_kill_switch_context(kind, tmp_path, monkeypatch):
    """Phase 1A window 'post_response': raised as the pipeline leaves `with stack:`."""
    from avra.control import killswitch as ks_mod

    real_active = ks_mod.KillSwitch.active

    @contextmanager
    def active(self, *a, **k):
        with real_active(self, *a, **k) as ticket:
            yield ticket
        raise KeyboardInterrupt  # after the ticket was released, as the pipeline leaves

    monkeypatch.setattr(ks_mod.KillSwitch, "active", active)
    with pytest.raises(KeyboardInterrupt):
        _run(kind, AuditLog(tmp_path / "a.jsonl"), tmp_path)
    _rid, term = _terminal(tmp_path / "a.jsonl")
    assert [t.event for t in term] == ["tool_request_interrupted"]
    assert term[0].data["phase"] == "after_result"
    assert not [c for c in Client.calls if c[0] == "cancel"]


@pytest.mark.parametrize("kind", ["scan", "probe"])
def test_unexpected_error_before_any_result_gets_a_terminal_record(kind, tmp_path):
    class Boom(Client):
        def run(self, request):
            raise RuntimeError("unexpected client bug (simulated)")

    common = {"checker": ScopeChecker(SCOPE), "audit": AuditLog(tmp_path / "a.jsonl"),
              "session_id": SID, "host": HOST, "token": TOKEN,
              "evidence_root": tmp_path / "evidence", "tunnel_cfg": TunnelConfig(),
              "tunnel_factory": Tunnel, "client_factory": Boom}
    with pytest.raises(RuntimeError):
        if kind == "scan":
            scan_mod.run_nmap_connect_scan(ports=[PORT], timeout_seconds=30, **common)
        else:
            probe_mod.run_http_probe(port=PORT, timeout_seconds=10,
                                     approval=probe_mod.APPROVAL_INTERACTIVE_TTY, **common)
    _rid, term = _terminal(tmp_path / "a.jsonl")
    assert [t.event for t in term] == ["tool_request_failed"]
    assert term[0].data["phase"] == "before_result" and term[0].data["error"] == "RuntimeError"


@pytest.mark.parametrize("kind", ["scan", "probe"])
def test_normal_run_still_has_exactly_one_result_record(kind, tmp_path):
    out = _run(kind, AuditLog(tmp_path / "a.jsonl"), tmp_path)
    assert out.ok
    _rid, term = _terminal(tmp_path / "a.jsonl")
    assert [t.event for t in term] == ["tool_result_received"]
