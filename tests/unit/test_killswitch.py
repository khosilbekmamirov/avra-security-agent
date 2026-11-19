"""M8.7 Stage 3 (ADR 0012): the local, persistent, fail-closed kill switch.

Offline only. Every test uses its own state directory (tests/conftest.py and
the fixtures below); the operational latch in %LOCALAPPDATA%\\AVRA is never
touched. Providers, tunnels and Runner clients are fakes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avra.control import killswitch as ks_mod
from avra.control.killswitch import (
    EV_DENIED,
    EV_ENGAGED,
    EV_FAILED,
    EV_RESET,
    MAX_STATE_BYTES,
    REMOTE_NOTICE,
    KillSwitch,
    KillSwitchEngaged,
    KillSwitchError,
    Latch,
)
from avra.llm.tools import PROPOSE_SCAN
from avra.storage.audit import AuditLog, inspect_audit_file
from tests.unit.test_llm_research import (
    PROPOSAL,
    FakeProvider,
    _resp,
    _session,
    _use,
)

SRC = str(Path(__file__).resolve().parents[2] / "src")
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic-sessions"
WINDOWS = os.name == "nt"


@pytest.fixture
def state(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "state"
    monkeypatch.setenv("AVRA_STATE_DIR", str(path))  # default KillSwitch() uses it too
    return path


@pytest.fixture
def ks(state) -> KillSwitch:
    return KillSwitch(state, lock_timeout=5)


def _tree(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file()}


def _control_events(ks: KillSwitch) -> list[str]:
    return [r.event for r in inspect_audit_file(ks.audit_path).records]


# --- persistence and state semantics ------------------------------------------------------


def test_fresh_machine_is_disengaged_and_status_creates_nothing(ks, state):
    st = ks.status()
    assert st.latch is Latch.DISENGAGED and not st.blocking
    assert not state.exists()


def test_engage_persists_and_survives_a_new_instance(ks, state):
    res = ks.engage("test stop")
    assert res.changed and res.audit_recorded and res.status.latch is Latch.ENGAGED
    again = KillSwitch(state)
    st = again.status()
    assert st.latch is Latch.ENGAGED and st.blocking and "test stop" in st.detail
    assert _control_events(ks) == [EV_ENGAGED]
    assert inspect_audit_file(ks.audit_path).verification.ok


_READ = "from avra.control.killswitch import KillSwitch; print(KillSwitch().status().latch.value)"
_ENGAGE = "from avra.control.killswitch import KillSwitch; KillSwitch().engage('from a child')"


def _child(code: str, state: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1",
           "AVRA_STATE_DIR": str(state)}
    return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True,
                          timeout=120, check=False)


def test_engaged_state_survives_process_restart(state):
    assert _child(_ENGAGE, state).returncode == 0
    assert _child(_READ, state).stdout.strip() == "ENGAGED"
    assert KillSwitch(state).status().latch is Latch.ENGAGED


def test_repeated_engage_is_idempotent(ks):
    first = ks.engage("one")
    second = ks.engage("two")
    assert not second.changed and second.audit_recorded
    assert second.status.epoch == first.status.epoch
    recs = inspect_audit_file(ks.audit_path).records
    assert [r.event for r in recs] == [EV_ENGAGED, EV_ENGAGED]
    assert recs[1].data["already"] == "ENGAGED"


@pytest.mark.parametrize("content", [
    b"{not json",
    b"[]",
    b'{"v": 2, "state": "engaged", "transition_id": "' + b"a" * 32 + b'", "changed_at": "t",'
    b' "reason": "r", "by": "cli"}',
    b'{"v": 1, "state": "maybe", "transition_id": "' + b"a" * 32 + b'", "changed_at": "t",'
    b' "reason": "r", "by": "cli"}',
    (b'{"v": 1, "state": "disengaged", "transition_id": "short", "changed_at": "t",'
    b' "reason": "r", "by": "cli"}'),
    b'{"v": 1, "v": 1, "state": "disengaged", "transition_id": "' + b"a" * 32 + b'",'
    b' "changed_at": "t", "reason": "r", "by": "cli"}',
    b"\xff\xfe",
])
def test_invalid_latch_file_fails_closed(ks, content):
    ks.engage("x")
    ks.state_path.write_bytes(content)
    st = ks.status()
    assert st.latch is Latch.CORRUPT and st.blocking


def test_oversized_latch_file_fails_closed(ks):
    ks.engage("x")
    ks.state_path.write_bytes(b" " * (MAX_STATE_BYTES + 1))
    assert ks.status().latch is Latch.CORRUPT


def test_latch_path_that_is_a_directory_fails_closed(ks):
    ks.control.mkdir(parents=True)
    ks.state_path.mkdir()
    assert ks.status().latch is Latch.CORRUPT


def test_unreadable_latch_fails_closed(ks, monkeypatch):
    ks.engage("x")

    def denied(self):
        raise PermissionError("access denied")

    monkeypatch.setattr(KillSwitch, "_read_state_file", denied)
    st = ks.status()
    assert st.latch is Latch.UNREADABLE and st.blocking


def test_deleted_latch_file_after_engage_still_blocks(ks):
    ks.engage("x")
    ks.state_path.unlink()
    st = ks.status()
    assert st.latch is Latch.CORRUPT and "audit says engaged" in st.detail
    res = ks.engage("re-engage")  # engage restores a clean ENGAGED latch
    assert res.status.latch is Latch.ENGAGED


def test_forged_disengaged_file_is_corrupt(ks):
    ks.engage("x")
    doc = json.loads(ks.state_path.read_bytes())
    doc["state"] = "disengaged"  # no matching kill_switch_reset record exists
    ks.state_path.write_text(json.dumps(doc), encoding="utf-8")
    assert ks.status().latch is Latch.CORRUPT


def test_damaged_control_audit_fails_closed_and_blocks_reset(ks):
    ks.engage("x")
    with ks.audit_path.open("ab") as fh:
        fh.write(b'{"torn')
    st = ks.status()
    assert st.latch is Latch.CORRUPT and "control audit damaged" in st.detail
    before = ks.audit_path.read_bytes()
    with pytest.raises(KillSwitchError, match="refused"):
        ks.reset("try")
    assert ks.audit_path.read_bytes() == before  # damage preserved as evidence


def test_corrupt_latch_file_is_never_overwritten(ks):
    ks.engage("x")
    ks.state_path.write_bytes(b"garbage evidence")
    with pytest.raises(KillSwitchError, match="kept as evidence"):
        ks.engage("again")
    assert ks.state_path.read_bytes() == b"garbage evidence"
    assert ks.status().blocking


def test_stray_temp_file_from_a_crash_is_ignored(ks):
    ks.engage("x")
    (ks.control / ".killswitch.json.deadbeefdeadbeef.tmp").write_bytes(b"partial")
    assert ks.status().latch is Latch.ENGAGED


# --- write failures and crash consistency ---------------------------------------------------


@pytest.mark.parametrize("target", ["_replace", "_fsync"])
def test_engage_write_failure_is_not_reported_as_engaged(ks, monkeypatch, target):
    def boom(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ks_mod, target, boom)
    with pytest.raises(KillSwitchError, match="NOT engaged"):
        ks.engage("x")
    monkeypatch.undo()
    assert ks.status().latch is Latch.DISENGAGED  # honest: it did not engage
    assert not list(ks.control.glob(".killswitch.json.*.tmp"))  # own temp cleaned up
    assert _control_events(ks) == [EV_FAILED]


def test_crash_after_latch_write_before_audit_still_blocks(ks, monkeypatch):
    real = AuditLog.record

    def no_record(self, event, data=None):
        if event == EV_ENGAGED:
            raise OSError("crash")
        return real(self, event, data)

    monkeypatch.setattr(AuditLog, "record", no_record)
    res = ks.engage("x")
    assert res.status.latch is Latch.ENGAGED and not res.audit_recorded
    monkeypatch.undo()
    st = KillSwitch(ks.state).status()
    assert st.latch is Latch.ENGAGED and any("not (yet) recorded" in n for n in st.notes)


def test_crash_after_reset_record_before_latch_write_stays_engaged(ks, monkeypatch):
    ks.engage("x")
    real = KillSwitch._write_state

    def crash(self, state, *a, **k):
        if state == "disengaged":
            raise OSError("power loss")
        return real(self, state, *a, **k)

    monkeypatch.setattr(KillSwitch, "_write_state", crash)
    with pytest.raises(KillSwitchError, match="still ENGAGED"):
        ks.reset("done")
    monkeypatch.undo()
    st = ks.status()
    assert st.latch is Latch.ENGAGED  # never silently disengaged
    assert _control_events(ks)[-2:] == [EV_RESET, EV_FAILED]
    assert ks.reset("retry").status.latch is Latch.DISENGAGED


def test_reset_audit_failure_changes_nothing(ks, monkeypatch):
    ks.engage("x")
    latch = ks.state_path.read_bytes()

    def no_record(self, event, data=None):
        raise OSError("disk full")

    monkeypatch.setattr(AuditLog, "record", no_record)
    with pytest.raises(KillSwitchError, match="control audit record failed"):
        ks.reset("done")
    monkeypatch.undo()
    assert ks.state_path.read_bytes() == latch and ks.status().latch is Latch.ENGAGED


def test_reset_then_status_and_epoch(ks):
    e = ks.engage("x").status.epoch
    st = ks.reset("maintenance finished").status
    assert st.latch is Latch.DISENGAGED and st.epoch != e
    assert _control_events(ks) == [EV_ENGAGED, EV_RESET]
    assert json.loads(ks.state_path.read_bytes())["state"] == "disengaged"  # kept, not deleted


@pytest.mark.parametrize("reason", ["", "   ", "bad\x07bell", "x" * 501])
def test_reset_and_engage_need_a_clean_reason(ks, reason):
    ks.engage("x")
    with pytest.raises(ValueError):
        ks.reset(reason)
    assert ks.status().latch is Latch.ENGAGED


def test_reset_refused_unless_engaged(ks):
    with pytest.raises(KillSwitchError, match="DISENGAGED"):
        ks.reset("nothing to reset")


# --- path safety --------------------------------------------------------------------------------


def _junction(link: Path, target: Path) -> bool:
    target.mkdir(parents=True, exist_ok=True)
    try:
        if WINDOWS:
            r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                               capture_output=True, text=True, check=False)
            return r.returncode == 0
        os.symlink(target, link, target_is_directory=True)
        return True
    except OSError:
        return False


def test_junction_or_symlink_control_dir_fails_closed(ks, tmp_path):
    ks.state.mkdir(parents=True)
    if not _junction(ks.control, tmp_path / "elsewhere"):
        pytest.skip("cannot create a junction/symlink here")
    assert ks.status().latch is Latch.CORRUPT
    with pytest.raises(KillSwitchError, match="unsafe"):
        ks.engage("x")
    with pytest.raises(KillSwitchEngaged), ks.active("nmap_connect_scan"):
        pass
    assert not any((tmp_path / "elsewhere").iterdir())  # nothing written through the link


def test_symlinked_latch_file_fails_closed(ks, tmp_path):
    ks.engage("x")
    target = tmp_path / "other.json"
    target.write_bytes(ks.state_path.read_bytes())
    ks.state_path.unlink()
    try:
        os.symlink(target, ks.state_path)
    except OSError:
        pytest.skip("symlink creation needs a privilege on this host")
    assert ks.status().latch is Latch.CORRUPT


# --- concurrency -----------------------------------------------------------------------------------


def test_concurrent_engage_from_many_processes(state):
    procs = [subprocess.Popen([sys.executable, "-c", _ENGAGE],
                              env={**os.environ, "PYTHONPATH": SRC, "AVRA_STATE_DIR": str(state),
                                   "PYTHONDONTWRITEBYTECODE": "1"},
                              stderr=subprocess.PIPE, text=True) for _ in range(5)]
    for p in procs:
        _o, err = p.communicate(timeout=120)
        assert p.returncode == 0, err
    ks = KillSwitch(state)
    st = ks.status()
    assert st.latch is Latch.ENGAGED and not st.notes
    snap = inspect_audit_file(ks.audit_path)
    assert snap.verification.ok and [r.event for r in snap.records] == [EV_ENGAGED] * 5
    assert sum(1 for r in snap.records if "already" not in r.data) == 1  # one real transition


def test_concurrent_engage_and_reset_stay_consistent(ks):
    ks.engage("start")
    errors: list[Exception] = []

    def engager():
        for _ in range(15):
            try:
                ks.engage("again")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    def resetter():
        for _ in range(15):
            try:
                KillSwitch(ks.state).reset("cycle")
            except KillSwitchError:
                pass  # refused when not engaged at that moment: expected
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=engager), threading.Thread(target=resetter)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    st = ks.status()
    assert st.latch in (Latch.ENGAGED, Latch.DISENGAGED) and not st.notes
    snap = inspect_audit_file(ks.audit_path)
    assert snap.verification.ok
    last = next(r for r in reversed(snap.records) if r.event in (EV_ENGAGED, EV_RESET))
    assert (last.event == EV_ENGAGED) == (st.latch is Latch.ENGAGED)  # no lost transition


# --- the gate and active work --------------------------------------------------------------------


def test_gate_denies_when_engaged_and_records_it(ks):
    ks.engage("x")
    with pytest.raises(KillSwitchEngaged, match="'nmap_connect_scan' refused"),             ks.active("nmap_connect_scan", session_id="s1"):
        pytest.fail("must not run")
    rec = inspect_audit_file(ks.audit_path).records[-1]
    assert rec.event == EV_DENIED and rec.data["operation"] == "nmap_connect_scan"


def test_reset_refused_while_work_is_registered(ks):
    ks.engage("x")
    ks.reset("go")
    with ks.active("research"):
        ks.engage("stop")
        assert ks.active_work() and "research" in ks.active_work()[0]
        with pytest.raises(KillSwitchError, match="still registered as running"):
            ks.reset("too early")
    assert ks.active_work() == []
    assert ks.reset("now").status.latch is Latch.DISENGAGED


def test_stale_marker_from_a_dead_process_is_not_active(ks, state):
    code = ("import os\nfrom avra.control.killswitch import KillSwitch\n"
            "g = KillSwitch().active('research'); g.__enter__(); os._exit(0)")
    assert _child(code, state).returncode == 0
    assert list(ks.active_dir.glob("*.active"))  # marker left behind by the crash
    assert ks.active_work() == []  # but nobody holds it


def test_ticket_detects_engage_and_reset_during_a_run(ks):
    with ks.active("research") as ticket:
        ticket.check("start")
        ks.engage("stop")
        with pytest.raises(KillSwitchEngaged):
            ticket.check("next")
    ks.reset("ok")
    with ks.active("research") as ticket:
        other = KillSwitch(ks.state)
        other.engage("stop")
        # A reset is refused while the run is registered...
        with pytest.raises(KillSwitchError):
            other.reset("sneaky")
    # ...and even a completed engage+reset cycle changes the epoch:
    other.reset("ok")
    with ks.active("research") as ticket:
        epoch = ticket.epoch
    other.engage("a")
    other.reset("b")
    assert other.status().epoch != epoch


def test_gate_fails_closed_when_the_lock_cannot_be_taken(ks):
    ks.engage("x")
    ks.reset("y")
    quick = KillSwitch(ks.state, lock_timeout=0.2)
    from avra.storage.audit import audit_file_lock

    with audit_file_lock(ks.lock_path, 1),             pytest.raises(KillSwitchEngaged, match="gate unavailable"),             quick.active("nmap_connect_scan"):
        pass


# --- enforcement: scan and probe pipelines ---------------------------------------------------------


class _Tunnels:
    def __init__(self):
        self.opened = 0

    def __call__(self, cfg):
        outer = self

        class T:
            def __enter__(self):
                outer.opened += 1
                return "http://127.0.0.1:1"

            def __exit__(self, *a):
                return False

        return T()


class _Client:
    calls = 0

    def __init__(self, base_url, token):
        pass

    def health(self):
        _Client.calls += 1

    def run(self, request):
        from avra.runner.schemas import RejectionStage, RunnerRejection
        from avra.runner_client.client import RunOutcome

        _Client.calls += 1
        return RunOutcome(403, rejection=RunnerRejection(stage=RejectionStage.SCOPE, reason="t",
                                                         request_id=request.request_id))


def _scope(tool="nmap_connect_scan", tier="active-safe"):
    from avra.policy.scope import ScopeChecker
    from avra.schemas.scope import ActionTier, Scope, Target

    return ScopeChecker(Scope(session_name="t", expires_at=datetime.now(UTC) + timedelta(days=1),
                              targets=[Target(host="10.66.7.103", ports=[3000],
                                              allowed_tiers=[ActionTier(tier)],
                                              allowed_tools=[tool])]))


def _scan(tmp_path, audit, **kw):
    from avra.runner_client.client import RunnerToken
    from avra.runner_client.scan import run_nmap_connect_scan
    from avra.runner_client.tunnel import TunnelConfig

    return run_nmap_connect_scan(checker=_scope(), audit=audit, session_id=uuid.uuid4(),
                                 host="10.66.7.103", ports=[3000], timeout_seconds=30,
                                 token=RunnerToken("t" * 43), evidence_root=tmp_path / "ev",
                                 tunnel_cfg=TunnelConfig(), client_factory=_Client, **kw)


def _probe(tmp_path, audit, **kw):
    from avra.runner_client import http_probe as pipeline
    from avra.runner_client.client import RunnerToken
    from avra.runner_client.tunnel import TunnelConfig

    return pipeline.run_http_probe(checker=_scope("http_probe", "passive"), audit=audit,
                                   session_id=uuid.uuid4(), host="10.66.7.103", port=3000,
                                   timeout_seconds=5, token=RunnerToken("t" * 43),
                                   evidence_root=tmp_path / "ev", tunnel_cfg=TunnelConfig(),
                                   approval=pipeline.APPROVAL_INTERACTIVE_TTY,
                                   client_factory=_Client, **kw)


@pytest.mark.parametrize("pipeline", [_scan, _probe])
def test_pipeline_blocked_opens_no_tunnel_and_sends_nothing(tmp_path, ks, pipeline):
    ks.engage("x")
    tunnels, _Client.calls = _Tunnels(), 0
    audit = AuditLog(tmp_path / "s.jsonl")
    out = pipeline(tmp_path, audit, tunnel_factory=tunnels)  # default KillSwitch(): no bypass
    assert tunnels.opened == 0 and _Client.calls == 0
    assert not out.allowed_locally and out.local_reason == "kill switch engaged"
    events = [r.event for r in audit.read_all()]
    assert events == ["tool_request_denied_locally"] and "tool_request_sent" not in events
    assert audit.read_all()[0].data["kill_switch"] == "ENGAGED"
    assert _control_events(ks)[-1] == EV_DENIED


@pytest.mark.parametrize("pipeline", [_scan, _probe])
def test_pipeline_runs_normally_when_disengaged(tmp_path, ks, pipeline):
    tunnels = _Tunnels()
    audit = AuditLog(tmp_path / "s.jsonl")
    out = pipeline(tmp_path, audit, tunnel_factory=tunnels)
    assert tunnels.opened == 1 and out.rejection is not None
    assert ks.active_work() == []  # the registration ended with the request


def test_engage_after_the_gate_stops_before_the_tunnel(tmp_path, ks):
    class EngageWhenSent(AuditLog):
        def record(self, event, data=None):
            rec = super().record(event, data)
            if event == "tool_request_sent":  # `avra kill` from another window, right now
                KillSwitch(ks.state).engage("race")
            return rec

    tunnels = _Tunnels()
    audit = EngageWhenSent(tmp_path / "s.jsonl")
    out = _scan(tmp_path, audit, tunnel_factory=tunnels)
    assert tunnels.opened == 0
    assert [r.event for r in audit.read_all()] == ["tool_request_sent", "tool_request_failed"]
    assert audit.read_all()[-1].data["error"] == "KillSwitchEngaged"
    assert not out.ok


def test_explicit_killswitch_argument_cannot_be_a_bypass(tmp_path, ks, state):
    ks.engage("x")
    other_state = KillSwitch(tmp_path / "unused")  # a caller passing some other switch...
    tunnels = _Tunnels()
    out = _scan(tmp_path, AuditLog(tmp_path / "s.jsonl"), tunnel_factory=tunnels,
                killswitch=other_state)
    # ...only selects WHICH latch is consulted; the default is always the
    # machine's own. Documented: library callers choose their state dir.
    assert tunnels.opened == 1 and out.allowed_locally
    out = _scan(tmp_path, AuditLog(tmp_path / "s2.jsonl"), tunnel_factory=tunnels)
    assert tunnels.opened == 1 and not out.allowed_locally


# --- enforcement: research loop -------------------------------------------------------------------


def test_research_refused_before_anything_when_engaged(tmp_path, ks):
    ks.engage("x")
    s, prov, audit, calls = _session(tmp_path, [_resp("end_turn", text="done")])
    with pytest.raises(KillSwitchEngaged):
        s.run("check the lab")
    assert prov.calls == 0 and calls == {"approve": [], "execute": []}
    assert audit.read_all() == []  # session evidence untouched


class _EngagingProvider(FakeProvider):
    """Simulates `avra kill` from a second PowerShell while a call is in flight."""

    def __init__(self, script, ks, then_reset=False):
        super().__init__(script)
        self.ks, self.then_reset = ks, then_reset

    def complete(self, *, system, messages, tools):
        resp = super().complete(system=system, messages=messages, tools=tools)
        other = KillSwitch(self.ks.state)
        other.engage("operator pressed kill")
        if self.then_reset:
            with pytest.raises(KillSwitchError, match="still registered"):
                other.reset("too early")  # refused: the run is registered as active
        return resp


def _run_with(tmp_path, ks, provider, **kw):
    s, _prov, audit, calls = _session(tmp_path, [], **kw)
    s.provider = provider
    return s.run("check the lab"), audit, calls


def test_running_loop_stops_at_next_checkpoint_without_approval(tmp_path, ks):
    prov = _EngagingProvider([_resp("tool_use", [_use(PROPOSE_SCAN, 1, **PROPOSAL)])], ks)
    result, audit, calls = _run_with(tmp_path, ks, prov)
    assert result.stop_reason.value == "kill_switch" and prov.calls == 1
    assert calls == {"approve": [], "execute": []}  # no approval prompt, no tool run
    events = [r.event for r in audit.read_all()]
    assert "llm_proposal" not in events and events[-1] == "research_stopped"
    rej = next(r for r in audit.read_all() if r.event == "llm_proposal_rejected")
    assert rej.data["reason"] == "kill_switch"
    assert audit.read_all()[-1].data["stop_reason"] == "kill_switch"
    assert audit.verify()


def test_engaged_during_approval_never_executes(tmp_path, ks):
    def approve(view):
        KillSwitch(ks.state).engage("pressed while the prompt was open")
        return True

    prov = FakeProvider([_resp("tool_use", [_use(PROPOSE_SCAN, 1, **PROPOSAL)])])
    result, audit, calls = _run_with(tmp_path, ks, prov, approve=approve)
    assert result.stop_reason.value == "kill_switch" and calls["execute"] == []
    events = [r.event for r in audit.read_all()]
    assert events.index("owner_decision") < events.index("llm_proposal_rejected")
    assert next(r for r in audit.read_all() if r.event == "llm_proposal_rejected").data[
        "reason"] == "kill_switch_after_approval"


def test_no_further_paid_call_after_engagement(tmp_path, ks):
    prov = _EngagingProvider([_resp("tool_use", [_use("record_observation", 1, note="n",
                                                      evidence_request_id=None)]),
                              _resp("end_turn", text="never sent")], ks)
    result, _audit, _calls = _run_with(tmp_path, ks, prov)
    assert result.stop_reason.value == "kill_switch" and prov.calls == 1


def test_reset_is_refused_mid_run_and_work_never_resumes(tmp_path, ks):
    prov = _EngagingProvider([_resp("tool_use", [_use(PROPOSE_SCAN, 1, **PROPOSAL)])], ks,
                             then_reset=True)
    result, _audit, calls = _run_with(tmp_path, ks, prov)
    assert result.stop_reason.value == "kill_switch" and calls["execute"] == []
    assert ks.active_work() == []  # run ended -> registration gone, reset now allowed
    assert ks.reset("after the run").status.latch is Latch.DISENGAGED


def test_kill_switch_report_status_is_interrupted():
    from avra.core.research import StopReason
    from avra.reporting import _STOP_TO_EXECUTION, ExecutionStatus

    assert _STOP_TO_EXECUTION[StopReason.KILL_SWITCH] is ExecutionStatus.INTERRUPTED


# --- enforcement: model calls ------------------------------------------------------------------------


def test_claude_provider_makes_no_api_request_when_engaged(ks):
    from avra.llm.config import LLMConfig
    from avra.llm.provider import ApiKey, ClaudeProvider, LLMProviderError
    from tests.unit.test_llm_research import FakeClient, _sdk_message

    ks.engage("x")
    client = FakeClient(_sdk_message())
    prov = ClaudeProvider(LLMConfig(), ApiKey("sk-ant-" + "x" * 40), client=client)
    with pytest.raises(LLMProviderError, match="no API request was made"):
        prov.count_input_tokens(system=[], messages=[], tools=[])
    with pytest.raises(LLMProviderError, match="no API request was made"):
        prov.complete(system=[], messages=[], tools=[])
    assert client.messages.calls == [] and client.messages.counts == []


def test_model_proposer_blocked(ks):
    from avra.verification.model_proposer import ModelProposer

    ks.engage("x")
    prov, records = FakeProvider([_resp("end_turn")]), []
    mp = ModelProposer(prov, on_call=records.append)
    assert mp.propose(ctx=None) == []
    assert mp.finished and "kill switch" in mp.stop_detail and prov.calls == 0
    assert records == [{"phase": "kill_switch", "latch": "ENGAGED"}]


# --- CLI ------------------------------------------------------------------------------------------


@pytest.fixture
def cli(state, monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from avra.cli import main

    monkeypatch.setattr(main, "_killswitch", lambda: KillSwitch(state, lock_timeout=5))
    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path / "data"))
    return CliRunner(), main


def test_cli_kill_engages_and_states_the_remote_limit(cli, state):
    runner, main = cli
    # Stage 3 behaviour, now explicit: --local-only never contacts the Runner
    # (remote outcomes: tests/unit/test_stage5_remote_stop.py).
    r = runner.invoke(main.app, ["kill", "--local-only", "--reason", "smoke test"])
    assert r.exit_code == 0, r.output
    assert "LOCAL STOP ENGAGED" in r.output and REMOTE_NOTICE in r.output.replace("\n", " ")
    low = r.output.lower()
    assert "kali job stopped" not in low and "remote job cancelled" not in low
    assert "confirmed" not in low
    assert KillSwitch(state).status().latch is Latch.ENGAGED
    r2 = runner.invoke(main.app, ["kill", "--local-only"])
    assert r2.exit_code == 0 and "already engaged" in r2.output


def test_cli_kill_write_failure_is_nonzero(cli, state, monkeypatch):
    runner, main = cli

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(ks_mod, "_replace", boom)
    r = runner.invoke(main.app, ["kill"])
    assert r.exit_code == 1 and "NOT engaged" in r.output


def test_cli_kill_audit_failure_is_nonzero_but_latch_holds(cli, state, monkeypatch):
    runner, main = cli
    real = AuditLog.record

    def no_engage_record(self, event, data=None):
        if event == EV_ENGAGED:
            raise OSError("disk full")
        return real(self, event, data)

    monkeypatch.setattr(AuditLog, "record", no_engage_record)
    r = runner.invoke(main.app, ["kill"])
    assert r.exit_code == 1 and "audit record FAILED" in r.output
    assert KillSwitch(state).status().latch is Latch.ENGAGED


def test_cli_status_is_read_only(cli, state):
    runner, main = cli
    r = runner.invoke(main.app, ["kill", "--status"])
    assert r.exit_code == 0 and "DISENGAGED" in r.output and not state.exists()
    KillSwitch(state).engage("x")
    before = _tree(state)
    r = runner.invoke(main.app, ["kill", "--status"])
    assert r.exit_code == 3 and "ENGAGED" in r.output and "REMOTE CANCELLATION" in r.output
    assert "hash chain valid" in r.output
    assert _tree(state) == before


def test_cli_status_reports_corruption(cli, state):
    runner, main = cli
    KillSwitch(state).engage("x")
    KillSwitch(state).state_path.write_bytes(b"junk")
    r = runner.invoke(main.app, ["kill", "--status"])
    assert r.exit_code == 1 and "CORRUPT" in r.output


def _engaged(state):
    KillSwitch(state).engage("x")


def test_cli_reset_noninteractive_refused(cli, state):
    runner, main = cli
    _engaged(state)
    r = runner.invoke(main.app, ["kill", "--reset"], input="reason\nRESET\n")
    assert r.exit_code == 2 and KillSwitch(state).status().latch is Latch.ENGAGED


@pytest.mark.parametrize("answers,ok", [
    ("maintenance finished\nRESET\n", True),
    ("\nRESET\n", False),            # empty reason
    ("reason\nreset\n", False),      # wrong confirmation word
    ("reason\n\n", False),           # no confirmation
])
def test_cli_reset_interactive(cli, state, monkeypatch, answers, ok):
    runner, main = cli
    monkeypatch.setattr(main, "_interactive", lambda: True)
    _engaged(state)
    r = runner.invoke(main.app, ["kill", "--reset"], input=answers)
    assert (r.exit_code == 0) is ok, r.output
    assert "cannot establish whether a job is still running" in r.output
    latch = KillSwitch(state).status().latch
    assert latch is (Latch.DISENGAGED if ok else Latch.ENGAGED)
    if ok:
        assert "Nothing was restarted" in r.output


def test_cli_reset_refuses_corrupt_state(cli, state, monkeypatch):
    runner, main = cli
    monkeypatch.setattr(main, "_interactive", lambda: True)
    _engaged(state)
    KillSwitch(state).state_path.write_bytes(b"junk")
    r = runner.invoke(main.app, ["kill", "--reset"], input="r\nRESET\n")
    assert r.exit_code == 1 and KillSwitch(state).state_path.read_bytes() == b"junk"


def test_cli_reset_refused_while_work_runs(cli, state, monkeypatch):
    runner, main = cli
    monkeypatch.setattr(main, "_interactive", lambda: True)
    ks = KillSwitch(state)
    with ks.active("research"):
        ks.engage("x")
        r = runner.invoke(main.app, ["kill", "--reset"], input="r\nRESET\n")
    assert r.exit_code == 1 and "still registered" in r.output
    assert ks.status().latch is Latch.ENGAGED


def test_cli_reset_audit_failure_keeps_engaged(cli, state, monkeypatch):
    runner, main = cli
    monkeypatch.setattr(main, "_interactive", lambda: True)
    _engaged(state)

    def no_record(self, event, data=None):
        raise OSError("disk full")

    monkeypatch.setattr(AuditLog, "record", no_record)
    r = runner.invoke(main.app, ["kill", "--reset"], input="r\nRESET\n")
    assert r.exit_code == 1 and KillSwitch(state).status().latch is Latch.ENGAGED


SCOPE = str(Path(__file__).resolve().parents[2] / "scope" / "example.scope.yaml")


@pytest.mark.parametrize("args,prompt", [
    (["research", "--scope", SCOPE, "--objective", "x"], "Start this session"),
    (["scan", "nmap-connect", "--scope", SCOPE, "--host", "10.66.7.103", "--port", "3000"],
     "Send this request"),
    (["probe", "http", "--scope", SCOPE, "--host", "10.66.7.103", "--port", "3000"],
     "Send this request"),
])
def test_cli_executable_commands_refused_without_prompting(cli, state, monkeypatch, args,
                                                           prompt):
    runner, main = cli
    monkeypatch.setattr(main, "_interactive", lambda: True)
    _engaged(state)
    r = runner.invoke(main.app, args, input="y\ny\n")
    assert r.exit_code == 3, r.output
    assert prompt not in r.output and "kill switch is ENGAGED" in r.output


def test_cli_model_verification_refused(cli, state):
    import typer

    _runner, main = cli
    _engaged(state)
    with pytest.raises(typer.Exit) as info:
        main._model_proposer(0.25)
    assert info.value.exit_code == 3


def test_read_only_commands_still_work_when_engaged(cli, state, tmp_path):
    runner, main = cli
    _engaged(state)
    root = tmp_path / "data"
    shutil.copytree(FIXTURES, root)
    before = _tree(root)
    for args in (["session", "show", "4460bea8-d974-406c-bb65-75c3be0a899f"],
                 ["report", "verify", "4460bea8-d974-406c-bb65-75c3be0a899f"],
                 ["audit", "verify", "4460bea8-d974-406c-bb65-75c3be0a899f"],
                 ["verify", "rules"], ["kill", "--status"]):
        r = runner.invoke(main.app, args)
        assert "kill switch is ENGAGED" not in r.output, args
        assert r.exit_code != 3 or args[0] == "kill", (args, r.output)
    assert _tree(root) == before  # evidence untouched


def test_historical_fixtures_are_untouched_by_the_suite_state():
    import hashlib

    digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()[:16]
               for p in sorted(FIXTURES.rglob("*.jsonl"))}
    assert digests == {"4460bea8-d974-406c-bb65-75c3be0a899f.jsonl": "18d3161d9dc95ecf",
                       "7e868faf-768d-49af-aea6-81dc9d435e20.jsonl": "d5aa12233db3684e"}


def test_real_state_dir_is_never_used_by_tests(state, real_state_baseline):
    from avra.storage.anchors import state_dir

    at_start, snapshot_now = real_state_baseline
    assert state_dir() == state
    # The real dir may exist from real CLI use (Stage 7); the suite must not
    # have created or changed anything in it (also asserted at session end).
    assert snapshot_now() == at_start
    time.sleep(0)  # (keeps the import used on all platforms)
