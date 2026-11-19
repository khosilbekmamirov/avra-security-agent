"""M14.2 `avra investigate` CLI - offline. Data is a COPY of the recorded lab sessions;
the Runner path (`_chat_execute`) is replaced, so nothing is sent anywhere."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from avra.cli import main
from avra.cli.main import app
from avra.control.killswitch import KillSwitch
from avra.research.investigation import ActionStatus, Investigation, InvState

REPO = Path(__file__).resolve().parents[2]
SID = "7e868faf-768d-49af-aea6-81dc9d435e20"
SCOPE = """session_name: "inv-test"
expires_at: "2099-12-31T23:59:59Z"
targets:
  - host: "10.66.7.103"
    ports: [3000]
    allowed_tiers: ["passive"]
    allowed_tools: ["http_get_path"]
    http_paths: ["/main.js"]
"""


@pytest.fixture
def data(tmp_path, monkeypatch):
    root = tmp_path / "data"
    shutil.copytree(REPO / "tests" / "fixtures" / "synthetic-sessions", root)
    monkeypatch.setenv("AVRA_DATA_DIR", str(root))
    monkeypatch.setattr(main, "_killswitch", lambda: KillSwitch())
    calls = []

    def no_runner(act, **kw):
        calls.append((act.kind, act.host, act.port, act.path, kw.get("request_id")))
        return {"ok": False, "request_id": kw.get("request_id"),
                "errors": ["RunnerClientError: cannot reach the Runner (test)"]}
    monkeypatch.setattr(main, "_chat_execute", no_runner)
    scope = tmp_path / "s.scope.yaml"
    scope.write_text(SCOPE, encoding="utf-8")
    return root, scope, calls


def _id(out: str) -> str:
    return re.search(r"Investigation ([0-9a-f-]{36})", out).group(1)


def _inv(root, inv_id):
    return Investigation.load(root / "investigations", inv_id, reconcile=False)


def test_start_non_interactive_pauses_with_one_pending_proposal(data):
    root, scope, calls = data
    r = CliRunner().invoke(app, ["investigate", "start", SID[:8], "--scope", str(scope),
                                 "--objective", "which API routes does the bundle list?"])
    assert r.exit_code == 2, r.output
    assert "Proposed by the deterministic planner" in r.output and "/main.js" in r.output
    inv = _inv(root, _id(r.output))
    assert inv.state is InvState.WAITING_APPROVAL and calls == []
    (act,) = inv.actions.values()
    assert (act.tool, act.path, act.status) == ("http_get_path", "/main.js",
                                                ActionStatus.PROPOSED)
    bound = next(n for n in inv.notes if n["kind"] == "scope_bound")["data"]
    assert len(bound["scope_sha256"]) == 64

    # list / show are read-only
    before = inv._log.read_all()
    assert _id(r.output) in CliRunner().invoke(app, ["investigate", "list"]).output
    s = CliRunner().invoke(app, ["investigate", "show", _id(r.output)[:8]])
    assert s.exit_code == 0 and "WAITING_APPROVAL" in s.output
    assert len(_inv(root, _id(r.output))._log.read_all()) == len(before)


def test_resume_refuses_a_different_scope_file(data, tmp_path):
    _root, scope, _ = data
    r = CliRunner().invoke(app, ["investigate", "start", SID, "--scope", str(scope),
                                 "--objective", "x"])
    other = tmp_path / "other.scope.yaml"
    other.write_text(SCOPE.replace("inv-test", "inv-test-2"), encoding="utf-8")
    r2 = CliRunner().invoke(app, ["investigate", "resume", _id(r.output)[:8], "--scope",
                                  str(other)])
    assert r2.exit_code == 1 and "not the one the investigation was started with" in r2.output


def test_interactive_deny_then_cancel(data, monkeypatch):
    root, scope, calls = data
    monkeypatch.setattr(main, "_interactive", lambda: True)
    r = CliRunner().invoke(app, ["investigate", "start", SID, "--scope", str(scope),
                                 "--objective", "x"], input="nope\n")
    inv = _inv(root, _id(r.output))
    assert calls == [] and next(iter(inv.actions.values())).status is ActionStatus.DENIED
    assert inv.terminal  # nothing else is in scope
    r2 = CliRunner().invoke(app, ["investigate", "cancel", _id(r.output)])
    assert r2.exit_code == 1 and "already ended" in r2.output


def test_interactive_approval_needs_fingerprint_and_confirmation(data, monkeypatch):
    root, scope, calls = data
    monkeypatch.setattr(main, "_interactive", lambda: True)

    def typed_fingerprint(text, **kw):
        return re.search(r"fingerprint ([0-9a-f]{12})", text).group(1)
    monkeypatch.setattr(typer, "prompt", typed_fingerprint)
    # the second confirmation is answered "n": nothing runs
    r = CliRunner().invoke(app, ["investigate", "start", SID, "--scope", str(scope),
                                 "--objective", "x"], input="n\n")
    assert calls == [] and "Send this ONE passive request" in r.output
    # answered "y": exactly one call, with the request id recorded before sending
    r = CliRunner().invoke(app, ["investigate", "start", SID, "--scope", str(scope),
                                 "--objective", "x"], input="y\n")
    inv = _inv(root, _id(r.output))
    (act,) = inv.actions.values()
    assert calls == [("http_get_path", "10.66.7.103", 3000, "/main.js", act.request_id)]
    assert act.status is ActionStatus.FAILED and inv.terminal  # the stand-in Runner failed
    rep = CliRunner().invoke(app, ["investigate", "report", _id(r.output), "--scope",
                                   str(scope)])
    assert rep.exit_code == 0, rep.output
    md = next((root / "investigations" / "reports" / inv.investigation_id).glob("*.md"))
    text = md.read_text(encoding="utf-8")
    assert "## FAILED" in text and "/main.js" in text and "NOT TESTED" in text
    js = json.loads(next(md.parent.glob("*.json")).read_text(encoding="utf-8"))
    assert js["failed"][0]["request_id"] == act.request_id


def test_cancel_denies_pending_and_kill_switch_refuses_start(data):
    root, scope, calls = data
    r = CliRunner().invoke(app, ["investigate", "start", SID, "--scope", str(scope),
                                 "--objective", "x"])
    c = CliRunner().invoke(app, ["investigate", "cancel", _id(r.output)])
    assert c.exit_code == 0
    inv = _inv(root, _id(r.output))
    assert inv.state is InvState.CANCELLED
    assert all(a.status is ActionStatus.DENIED for a in inv.actions.values())
    KillSwitch().engage("test")
    k = CliRunner().invoke(app, ["investigate", "start", SID, "--scope", str(scope),
                                 "--objective", "x"])
    assert k.exit_code == main.EXIT_KILL_SWITCH and calls == []


def test_ctrl_c_during_execution_is_reconciled_immediately(data, monkeypatch):
    root, scope, _ = data
    monkeypatch.setattr(main, "_interactive", lambda: True)
    monkeypatch.setattr(typer, "prompt", lambda text, **kw: re.search(
        r"fingerprint ([0-9a-f]{12})", text).group(1))

    def interrupted(act, **kw):
        raise KeyboardInterrupt
    monkeypatch.setattr(main, "_chat_execute", interrupted)
    r = CliRunner().invoke(app, ["investigate", "start", SID, "--scope", str(scope),
                                 "--objective", "x"], input="y\n")
    assert r.exit_code == 130 and "never be re-run" in r.output
    inv = _inv(root, _id(r.output))
    assert inv.state is InvState.FAILED
    assert next(iter(inv.actions.values())).status is ActionStatus.INTERRUPTED


def test_cli_module_is_ascii():
    src = (REPO / "src" / "avra" / "cli" / "investigate.py").read_bytes()
    assert all(b < 128 for b in src)


def test_approval_screen_strips_terminal_spoofing(data, monkeypatch):
    from avra.cli import investigate

    out = []
    monkeypatch.setattr(main, "_say", lambda t, **k: out.append(t))
    act = type("A", (), {"describe": lambda self: "x", "reason": "r\u202eevil\x9b[2J",
                         "expected_evidence": "e", "fingerprint": "f" * 64})()
    investigate._decide_factory(False)(act, "model \x1b[31msays\u2066")
    joined = "".join(out)
    assert "\u202e" not in joined and "\x9b" not in joined and "\x1b" not in joined
    assert "\u2066" not in joined and "UNVERIFIED" in joined
