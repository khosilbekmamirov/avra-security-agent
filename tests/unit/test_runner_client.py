"""M6.1/M6.2: tunnel argv + lifecycle (fake ssh) and the urllib Runner client
(against a loopback stub server). No real SSH, no Kali, no scans."""

from __future__ import annotations

import hashlib
import io
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from avra.runner.schemas import NmapConnectScanRequest, RejectionStage, ToolRunStatus
from avra.runner_client import client as rc
from avra.runner_client import tunnel as tn

ROOT = Path(__file__).resolve().parents[2]
OPEN_XML = (ROOT / "tests/fixtures/nmap/m5-juice-shop-3000-open.xml").read_text(encoding="utf-8")
TOKEN = "t" * 43


# --- tunnel ---------------------------------------------------------------


def test_argv_is_fixed_and_restricted():
    cfg = tn.TunnelConfig(key_path=Path("k"))
    argv = tn.build_ssh_argv(cfg, "ssh", 50000)
    joined = " ".join(argv)
    for opt in ("-N", "-F none", "BatchMode=yes", "IdentitiesOnly=yes", "IdentityAgent=none",
                "StrictHostKeyChecking=yes", "ForwardAgent=no", "ExitOnForwardFailure=yes"):
        assert opt in joined
    assert argv[-1] == "avra-tunnel@192.168.56.104"
    assert ["-L", "127.0.0.1:50000:127.0.0.1:8765"] == argv[argv.index("-L"):argv.index("-L") + 2]
    assert "-A" not in argv and "-R" not in argv and "-D" not in argv
    assert argv.count("-L") == 1


@pytest.mark.parametrize("bad", ["kali.local", "192.168.56.104 -oProxyCommand=x", "::1", ""])
def test_tunnel_host_must_be_ipv4_literal(bad):
    with pytest.raises(tn.TunnelError):
        tn.TunnelConfig(kali_host=bad)


class FakeProc:
    def __init__(self, stderr_text: str, exits: bool = False):
        self.stderr = io.StringIO(stderr_text)
        self._rc = 255 if exits else None
        self.terminated = False

    def poll(self):
        return self._rc

    def terminate(self):
        self.terminated = True
        self._rc = 0

    def kill(self):
        self._rc = -9

    def wait(self, timeout=None):
        return self._rc


def _tunnel(tmp_path, stderr_for_port):
    key = tmp_path / "key"
    key.write_text("x")
    procs = []

    def popen(argv):
        port = int(argv[argv.index("-L") + 1].split(":")[1])
        procs.append(FakeProc(stderr_for_port(port), exits="denied" in stderr_for_port(port)))
        return procs[-1]

    cfg = tn.TunnelConfig(key_path=key, ssh_path="ssh", ready_timeout=2)
    return tn.SshTunnel(cfg, popen=popen), procs


def test_tunnel_ready_then_closed(tmp_path):
    t, procs = _tunnel(tmp_path, lambda p: (
        'debug1: Authenticated to 192.168.56.104 ([192.168.56.104]:22) using "publickey".\n'
        f"debug1: Local forwarding listening on 127.0.0.1 port {p}.\n"))
    with t as base:
        assert base.startswith("http://127.0.0.1:")
    assert procs[0].terminated


def test_tunnel_auth_failure_raises_with_diagnostics(tmp_path):
    t, _ = _tunnel(tmp_path, lambda p: "avra-tunnel@192.168.56.104: Permission denied (publickey).\n")
    with pytest.raises(tn.TunnelError, match="Permission denied"):
        t.open()


def test_tunnel_listener_on_other_port_is_not_ready(tmp_path):
    t, _ = _tunnel(tmp_path, lambda p: "debug1: Local forwarding listening on 127.0.0.1 port 1.\n")
    with pytest.raises(tn.TunnelError, match="did not come up"):
        t.open()


def test_tunnel_missing_key(tmp_path):
    cfg = tn.TunnelConfig(key_path=tmp_path / "nope", ssh_path="ssh")
    with pytest.raises(tn.TunnelError, match="runtime key not found"):
        tn.SshTunnel(cfg, popen=lambda a: pytest.fail("must not start ssh")).open()


# --- token ------------------------------------------------------------------


def test_token_never_shown():
    tok = rc.RunnerToken(TOKEN)
    assert TOKEN not in repr(tok) and TOKEN not in str(tok) and TOKEN not in f"{tok}"
    assert tok.header() == f"Bearer {TOKEN}"


@pytest.mark.parametrize("bad", ["short", "x" * 600, "a b" + "c" * 40])
def test_token_validation_does_not_echo_value(bad):
    with pytest.raises(rc.RunnerClientError) as exc:
        rc.RunnerToken(bad)
    assert bad not in str(exc.value)


def test_load_token_env_then_dotenv(tmp_path):
    envf = tmp_path / ".env"
    envf.write_text(f"OTHER=1\nAVRA_RUNNER_TOKEN={TOKEN}\n", encoding="utf-8")
    assert rc.load_token(env={}, env_file=envf).header().endswith(TOKEN)
    assert rc.load_token(env={"AVRA_RUNNER_TOKEN": "u" * 40}, env_file=envf).header().endswith("u" * 40)
    with pytest.raises(rc.RunnerClientError):
        rc.load_token(env={}, env_file=tmp_path / "missing")


@pytest.mark.parametrize("url", ["http://192.168.56.104:8765", "https://127.0.0.1:1",
                                 "http://localhost:8765", "http://127.0.0.1:8765/v1",
                                 "http://u:p@127.0.0.1:8765", "http://127.0.0.1"])
def test_client_requires_loopback_tunnel_url(url):
    with pytest.raises(rc.RunnerClientError):
        rc.RunnerClient(url, rc.RunnerToken(TOKEN))


# --- client against a loopback stub ------------------------------------------


class Stub:
    """Loopback HTTP server returning one scripted answer per path."""

    def __init__(self):
        self.answers: dict[str, tuple[int, bytes]] = {}
        self.seen: list[tuple[str, str, dict, bytes]] = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def _do(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                stub.seen.append((self.command, self.path, dict(self.headers), body))
                status, payload = stub.answers.get(self.path, (404, b'{"error":"not_found"}'))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = _do

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub():
    s = Stub()
    yield s
    s.close()


def _request():
    return NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=uuid.uuid4(),
                                  host="10.66.7.103", ports=[3000], timeout_seconds=60)


def _result(req, raw=OPEN_XML, sha=None):
    return json.dumps({
        "request_id": str(req.request_id), "tool": "nmap_connect_scan", "status": "completed",
        "reason": "", "started_at": "2026-11-06T11:40:07Z", "finished_at": "2026-11-06T11:40:08Z",
        "exit_code": 0, "raw_output": raw, "output_truncated": False,
        "output_sha256": sha or hashlib.sha256(raw.encode()).hexdigest(),
    }).encode()


def test_health_and_auth_header(stub, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.1:9")  # must be ignored
    stub.answers["/v1/health"] = (200, b'{"status":"ok","tools":["nmap_connect_scan"]}')
    c = rc.RunnerClient(stub.url, rc.RunnerToken(TOKEN))
    assert c.health()["status"] == "ok"
    assert stub.seen[0][2]["Authorization"] == f"Bearer {TOKEN}"


def test_401_is_auth_error_without_token_in_message(stub):
    stub.answers["/v1/health"] = (401, b'{"error":"unauthorized"}')
    with pytest.raises(rc.RunnerAuthError) as exc:
        rc.RunnerClient(stub.url, rc.RunnerToken(TOKEN)).health()
    assert TOKEN not in str(exc.value)


def test_completed_result_validated_and_hash_verified(stub):
    req = _request()
    stub.answers["/v1/tools/run"] = (200, _result(req))
    out = rc.RunnerClient(stub.url, rc.RunnerToken(TOKEN)).run(req)
    assert out.result.status is ToolRunStatus.COMPLETED
    assert out.hash_verified is True
    sent = json.loads(stub.seen[0][3])
    assert sent["host"] == "10.66.7.103" and sent["ports"] == [3000]


def test_hash_mismatch_is_reported(stub):
    req = _request()
    stub.answers["/v1/tools/run"] = (200, _result(req, sha="0" * 64))
    assert rc.RunnerClient(stub.url, rc.RunnerToken(TOKEN)).run(req).hash_verified is False


def test_other_request_id_is_an_error(stub):
    req = _request()
    stub.answers["/v1/tools/run"] = (200, _result(_request()))
    with pytest.raises(rc.RunnerClientError, match="different request_id"):
        rc.RunnerClient(stub.url, rc.RunnerToken(TOKEN)).run(req)


def test_scope_rejection_parsed(stub):
    req = _request()
    stub.answers["/v1/tools/run"] = (403, json.dumps(
        {"stage": "scope", "reason": "not in scope", "request_id": str(req.request_id)}).encode())
    out = rc.RunnerClient(stub.url, rc.RunnerToken(TOKEN)).run(req)
    assert out.rejection.stage is RejectionStage.SCOPE and out.result is None


@pytest.mark.parametrize("status,payload", [
    (200, b"not json"),
    (200, b'{"status":"completed"}'),  # fails strict schema
    (200, b"[]"),
    (502, b'{"error":"x"}'),
])
def test_bad_answers_are_errors(stub, status, payload):
    stub.answers["/v1/tools/run"] = (status, payload)
    with pytest.raises(rc.RunnerClientError):
        rc.RunnerClient(stub.url, rc.RunnerToken(TOKEN)).run(_request())


def test_unreachable_runner_is_client_error():
    port = tn.free_loopback_port()
    with pytest.raises(rc.RunnerClientError, match="cannot reach"):
        rc.RunnerClient(f"http://127.0.0.1:{port}", rc.RunnerToken(TOKEN)).health()
