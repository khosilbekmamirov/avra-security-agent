"""M8.3: ``avra probe http`` — owner-only CLI entry point for ``http_probe``.

Real CLI + real Windows pipeline (scope, approval gate, audit, evidence,
envelope parsing); only the SSH tunnel and the Runner client are fakes, and
the child's envelope comes from ``probe()`` with a scripted fake socket.
No network, no lab, no API.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest
import yaml
from typer.testing import CliRunner

import avra.cli.main as cli
from avra.runner.schemas import ToolRunResult, ToolRunStatus
from avra.runner.tools import http_probe as child
from avra.runner_client import http_probe as pipeline
from avra.runner_client.client import RunOutcome
from avra.storage.audit import AuditLog

HOST, PORT = "10.66.7.103", 3000
HTML = (b"HTTP/1.1 200 OK\r\nServer: ExampleServer/9\r\nContent-Type: text/html\r\n"
        b"Content-Length: 39\r\n\r\n<html><title>Lab App</title></html>\r\n\r\n")


class _Sock:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def settimeout(self, t):
        pass

    def connect(self, addr):
        pass

    def sendall(self, data):
        pass

    def recv(self, n):
        return self.chunks.pop(0) if self.chunks else b""

    def close(self):
        pass


def _envelope_text():
    env = child.probe(HOST, PORT, 5, socket_factory=lambda: _Sock([HTML]))
    return child.encode_envelope(env)


class _Calls:
    def __init__(self):
        self.tunnels = 0
        self.runs = []


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Data dir, token, scope files and a fake tunnel/Runner behind the real pipeline."""
    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AVRA_RUNNER_TOKEN", "t" * 43)
    calls = _Calls()
    text = _envelope_text()

    class Tunnel:
        def __init__(self, cfg):
            pass

        def __enter__(self):
            calls.tunnels += 1
            return "http://127.0.0.1:50000"

        def __exit__(self, *a):
            pass

    class Client:
        def __init__(self, base, token):
            pass

        def health(self):
            return {"status": "ok"}

        def run(self, request):
            calls.runs.append(request)
            return RunOutcome(200, result=ToolRunResult(
                request_id=request.request_id, tool="http_probe",
                status=ToolRunStatus.COMPLETED, started_at=datetime.now(UTC),
                finished_at=datetime.now(UTC), exit_code=0, raw_output=text,
                output_sha256=hashlib.sha256(text.encode()).hexdigest()), hash_verified=True)

    real = pipeline.run_http_probe

    def wrapped(**kw):
        return real(**kw, tunnel_factory=Tunnel, client_factory=Client)

    monkeypatch.setattr(pipeline, "run_http_probe", wrapped)
    return tmp_path, calls


def _scope(tmp_path, tools=("http_probe",), tiers=("passive",), name="probe.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump({
        "session_name": "m83-test", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"host": HOST, "ports": [PORT], "allowed_tiers": list(tiers),
                     "allowed_tools": list(tools)}]}), encoding="utf-8")
    return path


def _invoke(monkeypatch, scope, *, interactive=True, answers=None, extra=()):
    monkeypatch.setattr(cli, "_interactive", lambda: interactive)
    args = ["probe", "http", "--scope", str(scope), "--host", HOST, "--port", str(PORT),
            *extra]
    return CliRunner().invoke(cli.app, args, input=answers)


def _audits(tmp_path):
    sessions = tmp_path / "data" / "sessions"
    return sorted(sessions.glob("*.jsonl")) if sessions.exists() else []


def _events(path):
    return [r.event for r in AuditLog(path).read_all()]


# --- refusals: nothing sent, nothing recorded ---------------------------------------------

def test_refused_without_an_interactive_terminal_even_with_a_piped_yes(world, monkeypatch):
    tmp_path, calls = world
    r = _invoke(monkeypatch, _scope(tmp_path), interactive=False, answers="y\n")
    assert r.exit_code == 2 and "interactive terminal" in r.output
    assert calls.tunnels == 0 and calls.runs == [] and _audits(tmp_path) == []


def test_there_is_no_yes_option(world, monkeypatch):
    tmp_path, calls = world
    r = _invoke(monkeypatch, _scope(tmp_path), answers="y\n", extra=("--yes",))
    assert r.exit_code != 0 and calls.runs == [] and _audits(tmp_path) == []


@pytest.mark.parametrize("answers", ["\n", "n\n", "no\n", ""])
def test_default_answer_cancels_and_sends_nothing(world, monkeypatch, answers):
    tmp_path, calls = world
    r = _invoke(monkeypatch, _scope(tmp_path), answers=answers)
    assert r.exit_code == 1 and "nothing sent" in r.output.lower()
    assert calls.tunnels == 0 and calls.runs == [] and _audits(tmp_path) == []


@pytest.mark.parametrize("extra", [("--port", "0"), ("--timeout", "31"), ("--host", "localhost")])
def test_invalid_request_is_refused_before_any_prompt(world, monkeypatch, extra):
    tmp_path, calls = world
    r = _invoke(monkeypatch, _scope(tmp_path), answers="y\n", extra=extra)
    assert r.exit_code == 1 and "Send this request?" not in r.output
    assert calls.runs == [] and _audits(tmp_path) == []


# --- preview shown before approval ----------------------------------------------------------

def test_preview_shows_target_exact_request_and_scope_decision(world, monkeypatch):
    tmp_path, _calls = world
    r = _invoke(monkeypatch, _scope(tmp_path), answers="n\n")
    out = r.output
    assert out.index("Send this request?") > out.index("Windows policy: ALLOWED")
    assert f"Target:  {HOST}:{PORT}" in out
    for line in child.request_bytes(HOST, PORT).decode().split("\r\n")[:-2]:
        assert f"    {line}" in out
    assert "<blank line>" in out


# --- scope denial: no prompt, denial audited, nothing sent -----------------------------------

def test_scope_denial_never_prompts_and_sends_nothing(world, monkeypatch):
    tmp_path, calls = world
    # shaped like the production research scope: nmap only, active-safe
    scope = _scope(tmp_path, tools=("nmap_connect_scan",), tiers=("active-safe",))
    r = _invoke(monkeypatch, scope, answers="y\n")
    assert r.exit_code == 1 and "Windows policy: DENIED" in r.output
    assert "Send this request?" not in r.output and "Nothing sent" in r.output
    assert calls.tunnels == 0 and calls.runs == []
    (log,) = _audits(tmp_path)
    assert _events(log) == ["session_created", "tool_request_denied_locally"]
    assert "approval" not in json.dumps([r.data for r in AuditLog(log).read_all()])


# --- approved: real pipeline, fake Runner ----------------------------------------------------

def test_explicit_yes_runs_once_and_records_the_approval(world, monkeypatch):
    tmp_path, calls = world
    r = _invoke(monkeypatch, _scope(tmp_path), answers="y\n")
    assert r.exit_code == 0, r.output
    assert calls.tunnels == 1 and len(calls.runs) == 1
    sent = calls.runs[0]
    assert (sent.tool.value, sent.host, sent.port, sent.timeout_seconds) == (
        "http_probe", HOST, PORT, 10)
    (log,) = _audits(tmp_path)
    audit = AuditLog(log)
    assert audit.verify()
    assert _events(log) == ["session_created", "tool_request_sent", "tool_result_received"]
    recs = audit.read_all()
    assert recs[1].data["approval"] == "interactive_tty_confirm"
    assert recs[2].data["protocol_observed"] is True and recs[2].data["http_status_code"] == 200
    assert "TENTATIVE header:server" in r.output and "TENTATIVE html:title" in r.output
    assert "protocol_observed=True status=200" in r.output
    evidence = list((tmp_path / "data" / "evidence").rglob("*.json"))
    assert len(evidence) == 1


def test_nmap_connect_cli_still_has_its_yes_option():
    """M8.3 must not change the existing nmap command (--yes stays there)."""
    import inspect

    assert "yes" in inspect.signature(cli.scan_nmap_connect).parameters
    assert "yes" not in inspect.signature(cli.probe_http).parameters
