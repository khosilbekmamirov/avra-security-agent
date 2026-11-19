"""M8.1 (ADR 0007): typed HTTP probe — request contract, default deny on both
sides, the bounded child program, envelope pairing, response parsing and
the Windows pipeline. Mocks only: a scripted fake socket and fake
tunnel/client. No network, no local server, no lab, no API.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import socket
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from avra.llm.prompts import PROMPT_VERSION
from avra.llm.tools import TOOL_DEFINITIONS
from avra.policy.scope import ScopeChecker
from avra.policy.tools import authorize_tool_request
from avra.recon.http_probe import (
    MAX_HEADERS,
    HttpProbeError,
    HttpResponseFacts,
    parse_envelope,
    parse_http_response,
)
from avra.runner.core import PROCESS_TIMEOUT_GRACE_SECONDS, Runner
from avra.runner.execution import ProcessOutcome, ProcessResult
from avra.runner.policy import Authorized, Denied, RunnerPolicy
from avra.runner.registry import get_tool
from avra.runner.schemas import (
    HttpProbeRequest,
    NmapConnectScanRequest,
    RejectionStage,
    RunnerRejection,
    ToolRunResult,
    ToolRunStatus,
)
from avra.runner.tools import http_probe as child
from avra.runner_client.client import RunnerClientError, RunnerToken, RunOutcome
from avra.runner_client.http_probe import (
    APPROVAL_INTERACTIVE_TTY,
    HttpProbeOutcome,
    run_http_probe,
)
from avra.runner_client.tunnel import TunnelConfig, TunnelError
from avra.schemas.scope import ActionTier, Scope, Target
from avra.storage.audit import AuditLog

HOST, PORT = "10.66.7.103", 3000
SID = uuid.uuid4()
HTML = (b"HTTP/1.1 200 OK\r\nServer: ExampleServer/9\r\nX-Powered-By: Express\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\nContent-Length: 46\r\n\r\n"
        b"<html><title>OWASP Juice Shop</title></html>\n")


def _scope(tools=("nmap_connect_scan",), tiers=(ActionTier.ACTIVE_SAFE,), ports=(PORT,)):
    """Default: shaped exactly like the production lab scope (nmap only)."""
    return Scope(session_name="t", expires_at=datetime.now(UTC) + timedelta(days=1),
                 targets=[Target(host=HOST, ports=list(ports), allowed_tiers=list(tiers),
                                 allowed_tools=list(tools))])


HTTP_SCOPE = {"tools": ("nmap_connect_scan", "http_probe"),
              "tiers": (ActionTier.ACTIVE_SAFE, ActionTier.PASSIVE)}


def _req(**kw):
    base = {"request_id": uuid.uuid4(), "session_id": SID, "host": HOST, "port": PORT}
    return HttpProbeRequest(**{**base, **kw})


# --- request contract ------------------------------------------------------------------

def test_valid_request_and_fixed_shape():
    r = _req()
    assert r.timeout_seconds == 10 and r.tool.value == "http_probe"
    assert set(HttpProbeRequest.model_fields) == {
        "tool", "request_id", "session_id", "host", "port", "timeout_seconds"}


@pytest.mark.parametrize("host", [
    "juice.shop", "localhost", "http://10.66.7.103:3000/", "10.66.7.103/32",
    "192.168.056.103", "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1",
    "255.255.255.255", "::1", "10.66.7.103 ", "",
])
def test_hostnames_urls_and_bad_addresses_rejected(host):
    with pytest.raises(ValidationError):
        _req(host=host)


@pytest.mark.parametrize("field,value", [
    ("port", 0), ("port", 65536), ("port", "3000"), ("port", True), ("port", 3000.0),
    ("timeout_seconds", 0), ("timeout_seconds", 31), ("timeout_seconds", "10"),
])
def test_bad_ports_and_timeouts_rejected(field, value):
    with pytest.raises(ValidationError):
        _req(**{field: value})


@pytest.mark.parametrize("extra", [
    {"method": "POST"}, {"path": "/admin"}, {"url": "http://x/"}, {"headers": {"A": "b"}},
    {"body": "x"}, {"proxy": "http://p:8080"}, {"scheme": "https"}, {"ports": [3000]},
    {"follow_redirects": True}, {"retries": 3}, {"tier": "passive"},
])
def test_no_caller_controlled_method_path_url_headers_body_proxy(extra):
    with pytest.raises(ValidationError):
        HttpProbeRequest.model_validate({"tool": "http_probe", "request_id": str(uuid.uuid4()),
                                         "session_id": str(SID), "host": HOST, "port": PORT,
                                         **extra})


def test_registry_fixes_tier_executable_argv_and_targets():
    spec = get_tool("http_probe")
    assert spec.tier is ActionTier.PASSIVE and spec.executable == "http_probe"
    r = _req(timeout_seconds=7)
    cmd = spec.build_command(r)
    assert cmd.argv == ("http_probe", "--host", HOST, "--port", "3000", "--timeout", "7")
    assert cmd.timeout_seconds == 7
    assert spec.scope_targets(r) == ((HOST, PORT),)
    with pytest.raises(TypeError):
        spec.build_command(NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=SID,
                                                  host=HOST, ports=[PORT]))


# --- default deny on BOTH sides --------------------------------------------------------------

def test_windows_policy_default_denies_http_probe_with_the_production_scope_shape():
    d = authorize_tool_request(ScopeChecker(_scope()), _req())
    assert not d.allowed and "not in scope" in d.reason


@pytest.mark.parametrize("scope_kw,req_kw,allowed", [
    ({"tools": ("http_probe",), "tiers": (ActionTier.ACTIVE_SAFE,)}, {}, False),  # no tier
    ({"tools": ("nmap_connect_scan",), "tiers": (ActionTier.PASSIVE,)}, {}, False),  # no tool
    (HTTP_SCOPE, {}, True),
    (HTTP_SCOPE, {"port": 22}, False),
    (HTTP_SCOPE, {"host": "192.168.56.104"}, False),
])
def test_windows_policy_needs_tool_tier_host_and_port(scope_kw, req_kw, allowed):
    assert authorize_tool_request(ScopeChecker(_scope(**scope_kw)), _req(**req_kw)).allowed is \
        allowed


def _payload(**kw):
    return {"tool": "http_probe", "request_id": str(uuid.uuid4()), "session_id": str(SID),
            "host": HOST, "port": PORT, "timeout_seconds": 5, **kw}


def test_runner_policy_default_denies_and_rejects_smuggled_fields():
    policy = RunnerPolicy(_scope())
    d = policy.authorize_request(_payload())
    assert isinstance(d, Denied) and d.stage == "scope"
    d = RunnerPolicy(_scope(**HTTP_SCOPE)).authorize_request(_payload(url="http://x/"))
    assert isinstance(d, Denied) and d.stage == "invalid_request"
    a = RunnerPolicy(_scope(**HTTP_SCOPE)).authorize_request(_payload())
    assert isinstance(a, Authorized) and a.command.argv[0] == "http_probe"


def test_nmap_authorization_is_unchanged():
    nmap = NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=SID, host=HOST,
                                  ports=[PORT])
    assert authorize_tool_request(ScopeChecker(_scope()), nmap).allowed
    # allowing http_probe on a port grants nmap nothing extra
    only_http = _scope(tools=("http_probe",), tiers=(ActionTier.PASSIVE,))
    assert not authorize_tool_request(ScopeChecker(only_http), nmap).allowed
    assert get_tool("nmap_connect_scan").tier is ActionTier.ACTIVE_SAFE


class _Exec:
    def __init__(self, stdout=b"{}"):
        self.executables = {"nmap": "/usr/bin/nmap", "http_probe": "/opt/x/avra-http-probe"}
        self.calls, self.stdout = [], stdout

    def run(self, argv, limits, cancel=None):
        self.calls.append((tuple(argv), limits.timeout_seconds))
        return ProcessResult(outcome=ProcessOutcome.EXITED, exit_code=0, stdout=self.stdout,
                             stderr=b"", stdout_truncated=False, stderr_truncated=False,
                             duration_seconds=0.1)


def test_runner_core_never_runs_a_denied_probe_and_runs_an_allowed_one(tmp_path):
    ex = _Exec()
    res = Runner(RunnerPolicy(_scope()), ex, AuditLog(tmp_path / "a.jsonl")).handle(_payload())
    assert isinstance(res, RunnerRejection) and res.stage is RejectionStage.SCOPE
    assert ex.calls == []
    res = Runner(RunnerPolicy(_scope(**HTTP_SCOPE)), ex,
                 AuditLog(tmp_path / "b.jsonl")).handle(_payload())
    assert isinstance(res, ToolRunResult) and res.status is ToolRunStatus.COMPLETED
    assert ex.calls == [(("http_probe", "--host", HOST, "--port", "3000", "--timeout", "5"),
                         5 + PROCESS_TIMEOUT_GRACE_SECONDS)]


# --- the child program (fake socket, fake clock) ---------------------------------------------

class FakeSocket:
    def __init__(self, chunks=(), connect_exc=None):
        self.chunks, self.connect_exc = list(chunks), connect_exc
        self.connected, self.sent, self.timeouts, self.closed = [], [], [], False

    def settimeout(self, t):
        self.timeouts.append(t)

    def connect(self, addr):
        self.connected.append(addr)
        if self.connect_exc:
            raise self.connect_exc

    def sendall(self, data):
        self.sent.append(bytes(data))

    def recv(self, n):
        if not self.chunks:
            return b""
        item = self.chunks.pop(0)
        if isinstance(item, BaseException):
            raise item
        if len(item) > n:
            self.chunks.insert(0, item[n:])
            item = item[:n]
        return item

    def close(self):
        self.closed = True


class Clock:
    def __init__(self, step=0.0):
        self.t, self.step = 1000.0, step

    def __call__(self):
        self.t += self.step
        return self.t


def _probe(sock, timeout=5, clock=None):
    made = []

    def factory():
        made.append(sock)
        return sock
    env = child.probe(HOST, PORT, timeout, socket_factory=factory, clock=clock or Clock())
    return env, made


def test_child_sends_exactly_the_fixed_request_once_no_dns_no_retries():
    sock = FakeSocket([HTML])
    env, made = _probe(sock)
    assert len(made) == 1 and sock.connected == [(HOST, PORT)] and sock.closed
    assert sock.sent == [child.request_bytes(HOST, PORT)]
    assert child.request_bytes(HOST, PORT) == (
        b"GET / HTTP/1.0\r\nHost: 10.66.7.103:3000\r\n"
        b"User-Agent: AVRA-http-probe/1 (owner-authorized lab)\r\n"
        b"Accept: */*\r\nConnection: close\r\n\r\n")
    assert env["outcome"] == "response_received" and env["complete"] and not env["truncated"]
    assert base64.b64decode(env["response_b64"]) == HTML
    assert env["response_sha256"] == hashlib.sha256(HTML).hexdigest()
    assert env["request_sha256"] == hashlib.sha256(child.request_bytes(HOST, PORT)).hexdigest()


def test_default_socket_is_plain_ipv4_tcp():
    s = child._default_socket()
    try:
        assert (s.family, s.type) == (socket.AF_INET, socket.SOCK_STREAM)
    finally:
        s.close()


@pytest.mark.parametrize("connect_exc,outcome", [
    (ConnectionRefusedError(), "connection_refused"),
    (TimeoutError(), "connect_timeout"),
    (OSError("unreachable"), "network_error"),
])
def test_connect_failures_are_outcomes_not_crashes(connect_exc, outcome):
    sock = FakeSocket(connect_exc=connect_exc)
    env, _ = _probe(sock)
    assert env["outcome"] == outcome and env["response_bytes"] == 0 and sock.sent == []


def test_read_timeout_keeps_partial_bytes():
    env, _ = _probe(FakeSocket([b"HTTP/1.1 200 OK\r\n", TimeoutError()]))
    assert env["outcome"] == "read_timeout" and not env["complete"]
    assert base64.b64decode(env["response_b64"]) == b"HTTP/1.1 200 OK\r\n"


def test_reset_and_empty_response():
    assert _probe(FakeSocket([ConnectionResetError()]))[0]["outcome"] == "connection_reset"
    assert _probe(FakeSocket([]))[0]["outcome"] == "connection_reset"  # closed, zero bytes


def test_response_is_capped_exactly():
    big = b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * (child.MAX_RESPONSE_BYTES * 2)
    env, _ = _probe(FakeSocket([big]))
    assert env["truncated"] and not env["complete"]
    assert env["response_bytes"] == child.MAX_RESPONSE_BYTES


def test_total_time_budget_is_enforced():
    # every clock read advances 2 s; budget 5 s -> must stop reading
    env, _ = _probe(FakeSocket([b"HTTP/1.1 200 OK\r\n"] * 50), timeout=5, clock=Clock(step=2.0))
    assert env["outcome"] == "read_timeout"


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "10.66.7.103.evil"])
def test_child_revalidates_the_target(host):
    with pytest.raises(ValueError):
        child.probe(host, PORT, 5, socket_factory=lambda: FakeSocket([HTML]))


@pytest.mark.parametrize("argv", [
    [], ["--host", HOST], ["--port", "3000", "--host", HOST, "--timeout", "5"],
    ["--host", "localhost", "--port", "3000", "--timeout", "5"],
    ["--host", HOST, "--port", "3e3", "--timeout", "5"],
    ["--host", HOST, "--port", "3000", "--timeout", "99"],
    ["--host", HOST, "--port", "３000", "--timeout", "5"],
])
def test_child_argv_is_strict(argv):
    out = io.StringIO()
    assert child.main(argv, out=out) == child.EXIT_USAGE and out.getvalue() == ""


def test_child_output_is_one_ascii_json_envelope(monkeypatch):
    monkeypatch.setattr(child, "_default_socket", lambda: FakeSocket([HTML + b"\xff\xfe"]))
    out = io.StringIO()
    assert child.main(["--host", HOST, "--port", "3000", "--timeout", "5"], out=out) == 0
    text = out.getvalue()
    assert text.isascii() and text.endswith("\n") and text.count("\n") == 1
    assert json.loads(text)["format"] == "avra-http-probe/1"


# --- envelope pairing ----------------------------------------------------------------------

def _envelope(resp=HTML, **over):
    sock = FakeSocket([resp] if resp else [])
    env, _ = _probe(sock)
    env.update(over)
    return child.encode_envelope(env)


def test_envelope_round_trip():
    _env, req, resp = parse_envelope(_envelope(), host=HOST, port=PORT)
    assert resp == HTML and req == child.request_bytes(HOST, PORT)


@pytest.mark.parametrize("over,why", [
    ({"response_b64": base64.b64encode(b"HTTP/1.1 500 X\r\n\r\n").decode()}, "response bytes"),
    ({"request_b64": base64.b64encode(b"GET /admin HTTP/1.0\r\n\r\n").decode()},
     "request bytes"),
    ({"port": 8080}, "host/port"),
    ({"format": "other/1"}, "valid"),
    ({"extra": 1}, "valid"),
    ({"response_b64": "!!!"}, "base64"),
    ({"outcome": "connection_refused"}, "must not carry"),
    ({"outcome": "connect_timeout"}, "must not carry"),
    ({"error": "TimeoutError"}, "inconsistent"),
    ({"truncated": True}, "truncated flag"),
    ({"outcome": "read_timeout", "error": "TimeoutError"}, "complete flag"),
])
def test_envelope_tampering_or_mispairing_rejected(over, why):
    with pytest.raises(HttpProbeError, match=why):
        parse_envelope(_envelope(**over), host=HOST, port=PORT)


def test_envelope_duplicate_keys_and_huge_ints_rejected_not_crashing():
    text = _envelope()
    dup = text.rstrip("\n")[:-1] + ',"port":3000}\n'  # later key would silently win
    with pytest.raises(HttpProbeError, match="duplicate keys"):
        parse_envelope(dup, host=HOST, port=PORT)
    huge = text.replace('"elapsed_ms":', '"elapsed_ms":' + "9" * 5000 + ',"x":', 1)
    with pytest.raises(HttpProbeError, match="valid"):
        parse_envelope(huge, host=HOST, port=PORT)


def test_reset_mid_response_keeps_partial_bytes_as_valid_evidence():
    env, _ = _probe(FakeSocket([b"HTTP/1.1 200 OK\r\n", ConnectionResetError()]))
    assert env["outcome"] == "connection_reset" and not env["complete"]
    _e, _req, resp = parse_envelope(child.encode_envelope(env), host=HOST, port=PORT)
    assert resp == b"HTTP/1.1 200 OK\r\n"


def test_envelope_for_a_different_target_rejected():
    with pytest.raises(HttpProbeError):
        parse_envelope(_envelope(), host="192.168.56.104", port=PORT)


def test_forged_fixed_request_for_another_path_rejected():
    forged = (b"GET /ftp HTTP/1.0\r\nHost: 10.66.7.103:3000\r\n\r\n")
    over = {"request_b64": base64.b64encode(forged).decode(),
            "request_sha256": hashlib.sha256(forged).hexdigest(), "request_bytes": len(forged)}
    with pytest.raises(HttpProbeError, match="not the fixed probe request"):
        parse_envelope(_envelope(**over), host=HOST, port=PORT)


def test_non_ascii_envelope_rejected():
    with pytest.raises(HttpProbeError, match="ASCII"):
        parse_envelope(_envelope().replace("avra", "ävra"), host=HOST, port=PORT)


# --- response parsing: read, never repair, never conclude --------------------------------------

def test_html_response_gives_protocol_and_only_tentative_indications():
    f = parse_http_response(HTML)
    assert f.protocol_observed and f.identity_level == "protocol_observed"
    assert (f.status_code, f.http_version, f.title) == (200, "1.1", "OWASP Juice Shop")
    assert [(i.source, i.value, i.tentative) for i in f.indications] == [
        ("header:server", "ExampleServer/9", True), ("header:x-powered-by", "Express", True),
        ("html:title", "OWASP Juice Shop", True)]
    assert "not a confirmed product" in f.indication_note


def test_no_vulnerability_or_confirmed_identity_fields_exist():
    names = set(HttpResponseFacts.model_fields) | set(HttpProbeOutcome.__dataclass_fields__)
    assert not {n for n in names if any(w in n for w in (
        "vuln", "finding", "exploit", "confirmed", "identified", "product", "version_"))}
    # an alarming status/banner changes nothing beyond recording it
    f = parse_http_response(b"HTTP/1.1 500 Internal Server Error\r\nServer: Vulnerable 0day\r\n"
                            b"\r\n")
    assert f.identity_level == "protocol_observed" and f.status_code == 500


def test_redirect_is_recorded_not_followed():
    f = parse_http_response(b"HTTP/1.1 302 Found\r\nLocation: http://evil.example/\r\n"
                            b"Content-Length: 0\r\n\r\n")
    assert f.is_redirect and f.location == "http://evil.example/"


@pytest.mark.parametrize("data,why", [
    (b"SSH-2.0-OpenSSH_9\r\n", "invalid HTTP status line"),
    (b"HTTP/1.1 200 OK\r\nServer: x\r\n", "not terminated"),
    (b"HTTP/1.1 200 OK\r\n" + b"X-A: " + b"a" * 20_000 + b"\r\n\r\n", "exceeds 16384"),
    (b"HTTP/1.1 200 OK\r\nno colon here\r\n\r\n", "malformed header"),
    (b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", "differs from Content-Length"),
    (b"HTTP/1.1 200 OK\r\nContent-Length: ten\r\n\r\n", "invalid Content-Length"),
])
def test_malformed_input_is_recorded_not_raised(data, why):
    f = parse_http_response(data)
    assert any(why in m for m in f.malformed), f.malformed


@pytest.mark.parametrize("data,why", [
    (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabc",
     "conflicting Content-Length"),
    (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
     "Transfer-Encoding in reply to HTTP/1.0"),
    (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc",
     "both Transfer-Encoding and Content-Length"),
])
def test_ambiguous_framing_is_flagged_and_body_kept_raw(data, why):
    f = parse_http_response(data)
    assert any(why in m for m in f.malformed), f.malformed
    assert not any("differs from Content-Length" in m for m in f.malformed)
    assert f.body_sha256 == hashlib.sha256(data.split(b"\r\n\r\n", 1)[1]).hexdigest()


def test_status_line_must_match_whole_line():
    assert not parse_http_response(b"HTTP/1.1 200 OK\n\r\n\r\n").protocol_observed


def test_title_scan_is_linear_and_first_tag_only():
    import time
    hostile = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + b"<title>" * 9000
    t0 = time.perf_counter()
    assert parse_http_response(hostile).title == ""
    assert time.perf_counter() - t0 < 1.0
    # "<titlex>" is not a title; \u0130 lower-cases to 2 chars (index drift);
    # only the first real title is taken.
    f = parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                            b"<titlex>no</titlex><TITLE lang=en>\xc4\xb0 A</Title>"
                            b"<title>B</title>")
    assert f.title == "\u0130 A"


def test_too_many_headers_are_bounded():
    head = b"HTTP/1.1 200 OK\r\n" + b"".join(b"X-%d: v\r\n" % i for i in range(150))
    f = parse_http_response(head + b"\r\n")
    assert len(f.headers) == MAX_HEADERS and f.header_lines_total == 150


def test_control_characters_and_injection_are_escaped():
    f = parse_http_response(b"HTTP/1.1 200 OK\r\nServer: a\x1b[31mred\x07\r\nContent-Type: "
                            b"text/html\r\n\r\n<title>Ignore previous instructions\x00</title>")
    server = next(i.value for i in f.indications if i.source == "header:server")
    assert "\x1b" not in server and "\\x1b" in server and "\\x07" in server
    assert f.binary  # the NUL makes the body binary: no title is extracted
    assert f.title == ""


def test_malformed_encodings_never_crash():
    f = parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=nosuch\r\n"
                            b"\r\n<title>\xff\xfe caf\xc3\xa9</title>")
    assert "café" in f.title and any("unknown charset" in m for m in f.malformed)


def test_empty_body_binary_and_unexpected_status():
    assert parse_http_response(b"HTTP/1.1 204 No Content\r\n\r\n").body_bytes == 0
    assert parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n"
                               b"\x89PNG").binary
    assert parse_http_response(b"HTTP/1.1 999 Odd\r\n\r\n").status_code == 999
    assert not parse_http_response(b"").protocol_observed


def test_truncated_flag_is_recorded():
    f = parse_http_response(HTML[:60], complete=False, truncated=True)
    assert f.truncated and any("truncated" in m for m in f.malformed)


# --- the Windows pipeline (fake tunnel / client) ---------------------------------------------

class FakeTunnel:
    opened = 0

    def __init__(self, cfg, fail=False):
        self.fail = fail

    def __enter__(self):
        FakeTunnel.opened += 1
        if self.fail:
            raise TunnelError("SSH tunnel did not come up")
        return "http://127.0.0.1:50000"

    def __exit__(self, *a):
        pass


def _client(answer, calls):
    class C:
        def __init__(self, base, token):
            pass

        def health(self):
            return {"status": "ok"}

        def run(self, request):
            calls.append(request)
            return answer(request)
    return C


def _completed(envelope_text, sha=None, exit_code=0):
    def answer(request):
        return RunOutcome(200, result=ToolRunResult(
            request_id=request.request_id, tool="http_probe", status=ToolRunStatus.COMPLETED,
            started_at=datetime.now(UTC), finished_at=datetime.now(UTC), exit_code=exit_code,
            raw_output=envelope_text,
            output_sha256=sha or hashlib.sha256(envelope_text.encode()).hexdigest()),
            hash_verified=sha is None)
    return answer


def _run(tmp_path, answer, scope=None, tunnel_fail=False, port=PORT,
         approval=APPROVAL_INTERACTIVE_TTY):
    audit = AuditLog(tmp_path / "audit.jsonl")
    calls = []
    FakeTunnel.opened = 0
    out = run_http_probe(
        checker=ScopeChecker(scope or _scope(**HTTP_SCOPE)), audit=audit, session_id=SID,
        host=HOST, port=port, timeout_seconds=5, token=RunnerToken("s" * 43),
        evidence_root=tmp_path / "evidence", tunnel_cfg=TunnelConfig(), approval=approval,
        tunnel_factory=lambda cfg: FakeTunnel(cfg, fail=tunnel_fail),
        client_factory=_client(answer, calls))
    return out, audit, calls


def _events(audit):
    return [r.event for r in audit.read_all()]


@pytest.mark.parametrize("approval", [None, "", "yes", "interactive_tty_confirm "])
def test_pipeline_in_scope_but_without_owner_approval_sends_nothing(tmp_path, approval):
    out, audit, calls = _run(tmp_path, _completed(_envelope()), approval=approval)
    assert not out.allowed_locally and out.local_reason == "no interactive owner approval"
    assert calls == [] and FakeTunnel.opened == 0 and not out.ok
    assert _events(audit) == ["tool_request_denied_locally"]


def test_pipeline_records_the_approval_only_on_the_sent_request(tmp_path):
    _out, audit, _calls = _run(tmp_path, _completed(_envelope()))
    sent = [r for r in audit.read_all() if r.event == "tool_request_sent"]
    assert len(sent) == 1 and sent[0].data["approval"] == "interactive_tty_confirm"


def test_pipeline_default_deny_sends_nothing(tmp_path):
    out, audit, calls = _run(tmp_path, _completed(_envelope()), scope=_scope())
    assert not out.allowed_locally and calls == [] and FakeTunnel.opened == 0
    assert _events(audit) == ["tool_request_denied_locally"]


def test_pipeline_success_stores_evidence_and_audits_no_server_text(tmp_path):
    out, audit, calls = _run(tmp_path, _completed(_envelope()))
    assert len(calls) == 1 and out.ok  # exactly one request, no retries
    assert out.facts.protocol_observed and out.facts.status_code == 200
    assert out.evidence.path.suffix == ".json"
    assert hashlib.sha256(out.evidence.path.read_bytes()).hexdigest() == \
        out.result.output_sha256
    assert _events(audit) == ["tool_request_sent", "tool_result_received"]
    rec = audit.read_all()[-1].data
    assert rec["protocol_observed"] and rec["http_status_code"] == 200
    assert rec["indication_sources"] == ["header:server", "header:x-powered-by", "html:title"]
    log = audit.path.read_text(encoding="utf-8")
    for server_text in ("ExampleServer", "Express", "OWASP Juice Shop"):
        assert server_text not in log  # server-controlled text stays in evidence only
    assert audit.verify()


def test_pipeline_refused_port_is_ok_but_no_protocol(tmp_path):
    env, _ = _probe(FakeSocket(connect_exc=ConnectionRefusedError()))
    out, audit, _ = _run(tmp_path, _completed(child.encode_envelope(env)))
    assert out.ok and out.envelope.outcome == "connection_refused" and out.facts is None
    assert audit.read_all()[-1].data["protocol_observed"] is False


def test_pipeline_reset_mid_response_still_parses_partial_bytes(tmp_path):
    env, _ = _probe(FakeSocket([HTML[:40], ConnectionResetError()]))
    out, audit, _ = _run(tmp_path, _completed(child.encode_envelope(env)))
    assert out.ok and out.envelope.outcome == "connection_reset"
    assert out.facts is not None and out.facts.protocol_observed and not out.facts.complete
    assert audit.read_all()[-1].data["http_status_code"] == 200


@pytest.mark.parametrize("answer,why", [
    (_completed(_envelope(), sha="0" * 64), "hash could not be verified"),
    (_completed(_envelope(), exit_code=2), "exited with code 2"),
    (_completed(_envelope(port=8080)), "envelope:"),
    (_completed("not json"), "envelope:"),
])
def test_pipeline_untrustworthy_results_are_not_ok(tmp_path, answer, why):
    out, audit, _ = _run(tmp_path, answer)
    assert not out.ok and any(why in e for e in out.errors), out.errors
    assert out.facts is None or why == "hash could not be verified"
    assert audit.verify()


def test_pipeline_runner_rejection_and_tunnel_failure(tmp_path):
    def reject(request):
        return RunOutcome(403, rejection=RunnerRejection(stage=RejectionStage.SCOPE,
                                                         reason="out of scope",
                                                         request_id=request.request_id))
    out, audit, _ = _run(tmp_path, reject)
    assert out.rejection is not None and not out.ok
    assert _events(audit)[-1] == "tool_request_rejected"
    out, audit, calls = _run(tmp_path / "b", _completed(_envelope()), tunnel_fail=True)
    assert calls == [] and not out.ok and _events(audit)[-1] == "tool_request_failed"


def test_pipeline_client_error_is_recorded_once_without_retry(tmp_path):
    def boom(request):
        raise RunnerClientError("cannot reach the Runner: TimeoutError")
    out, audit, calls = _run(tmp_path, boom)
    assert len(calls) == 1 and not out.ok
    assert _events(audit) == ["tool_request_sent", "tool_request_failed"]


# --- nothing reaches the model ---------------------------------------------------------------

def test_http_probe_is_not_exposed_to_the_model():
    assert "http_probe" not in {t["name"] for t in TOOL_DEFINITIONS}
    assert PROMPT_VERSION == "m7-v2"


def test_no_tracked_scope_lists_http_probe_or_intrusive():
    """M8.1 owner decision: ``example.scope.yaml`` no longer pre-lists
    ``http_probe`` nor the unneeded ``intrusive`` tier. Default deny: no
    tracked scope file may list either. Local, gitignored scope files (e.g.
    the owner's M8.3 probe scope) are deliberately out of this check."""
    import subprocess

    import yaml
    repo = Path(__file__).resolve().parents[2]
    listed = subprocess.run(["git", "ls-files", "scope"], cwd=repo, capture_output=True,
                            text=True, check=False)
    if listed.returncode != 0:
        pytest.skip("needs a Git checkout to know which scope files are tracked")
    tracked = [repo / p for p in listed.stdout.split() if p.endswith(".yaml")]
    assert tracked, "expected at least scope/example.scope.yaml to be tracked"
    for path in tracked:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for target in data.get("targets", []):
            assert "http_probe" not in target.get("allowed_tools", []), path.name
            assert "intrusive" not in target.get("allowed_tiers", []), path.name
