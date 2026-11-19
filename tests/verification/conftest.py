"""Fixture sessions for the Verification Engine tests (M8.4).

Sessions are produced by the REAL Windows pipelines (``run_http_probe``,
``run_nmap_connect_scan``): real scope check, real audit chain, real
write-once evidence. Only the SSH tunnel and the Runner are fakes, and the
HTTP envelope is produced by the real child ``probe()`` over a scripted
socket. Every fixture session is labelled ``SIMULATED-FIXTURE`` and targets
192.168.56.250 (not a lab VM), so nothing here can be mistaken for a real
lab finding.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avra.policy.scope import ScopeChecker
from avra.runner.schemas import ToolRunResult, ToolRunStatus
from avra.runner.tools import http_probe as child
from avra.runner_client.client import RunnerToken, RunOutcome
from avra.runner_client.http_probe import APPROVAL_INTERACTIVE_TTY, run_http_probe
from avra.runner_client.scan import run_nmap_connect_scan
from avra.runner_client.tunnel import TunnelConfig
from avra.schemas.scope import ActionTier, Scope, Target
from avra.storage.audit import AuditLog
from avra.verification.evidence import load_session_evidence

HOST, PORT = "192.168.56.250", 8080
FIXTURE_LABEL = "SIMULATED-FIXTURE"
REPO = Path(__file__).resolve().parents[2]


def http_response(*, status="200 OK", headers=(("Content-Type", "text/html"),),
                  body=b"<html><title>Fixture</title></html>", content_length=True) -> bytes:
    lines = [f"HTTP/1.1 {status}".encode()]
    for name, value in headers:
        lines.append(f"{name}: {value}".encode())
    if content_length:
        lines.append(f"Content-Length: {len(body)}".encode())
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def nmap_xml(state: str, port: int = PORT, host: str = HOST, reason: str | None = None) -> str:
    reason = reason or {"open": "syn-ack", "closed": "conn-refused"}.get(state, "no-response")
    return (f'<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sT" version="7.95">'
            f'<host><status state="up" reason="user-set"/><address addr="{host}" '
            f'addrtype="ipv4"/><ports><port protocol="tcp" portid="{port}"><state '
            f'state="{state}" reason="{reason}"/><service name="http-proxy" method="table" '
            f'conf="3"/></port></ports></host><runstats><finished exit="success"/>'
            f'</runstats></nmaprun>')


class _Sock:
    def __init__(self, chunks, connect_exc=None):
        self.chunks, self.connect_exc = list(chunks), connect_exc

    def settimeout(self, t):
        pass

    def connect(self, addr):
        if self.connect_exc:
            raise self.connect_exc

    def sendall(self, data):
        pass

    def recv(self, n):
        if not self.chunks:
            return b""
        c = self.chunks.pop(0)
        if isinstance(c, Exception):
            raise c
        return c

    def close(self):
        pass


class _Tunnel:
    def __init__(self, cfg):
        pass

    def __enter__(self):
        return "http://127.0.0.1:50000"

    def __exit__(self, *a):
        pass


def _client(raw: str, tool: str):
    class C:
        def __init__(self, base, token):
            pass

        def health(self):
            return {"status": "ok"}

        def run(self, request):
            return RunOutcome(200, result=ToolRunResult(
                request_id=request.request_id, tool=tool, status=ToolRunStatus.COMPLETED,
                started_at=datetime.now(UTC), finished_at=datetime.now(UTC), exit_code=0,
                raw_output=raw, output_sha256=hashlib.sha256(raw.encode()).hexdigest()),
                hash_verified=True)
    return C


class Lab:
    def __init__(self, root: Path):
        self.root = root
        self.sessions = root / "data" / "sessions"
        self.evidence_root = root / "data" / "evidence"
        self.checker = ScopeChecker(Scope(
            session_name=FIXTURE_LABEL, expires_at=datetime.now(UTC) + timedelta(days=1),
            targets=[Target(host=HOST, ports=[PORT, 22, 8443],
                            allowed_tiers=[ActionTier.PASSIVE, ActionTier.ACTIVE_SAFE],
                            allowed_tools=["http_probe", "nmap_connect_scan"])]))

    def new_session(self) -> tuple[str, AuditLog]:
        sid = uuid.uuid4()
        audit = AuditLog(self.sessions / f"{sid}.jsonl")
        audit.record("session_created", {"session_id": str(sid), "label": "fixture",
                                         "scope_session_name": FIXTURE_LABEL})
        return str(sid), audit

    def http(self, sid: str, audit: AuditLog, chunks=(), connect_exc=None, port=PORT) -> str:
        env = child.probe(HOST, port, 5, socket_factory=lambda: _Sock(chunks, connect_exc))
        out = run_http_probe(
            checker=self.checker, audit=audit, session_id=uuid.UUID(sid), host=HOST, port=port,
            timeout_seconds=5, token=RunnerToken("t" * 43), evidence_root=self.evidence_root,
            tunnel_cfg=TunnelConfig(), approval=APPROVAL_INTERACTIVE_TTY,
            tunnel_factory=_Tunnel, client_factory=_client(child.encode_envelope(env),
                                                           "http_probe"))
        assert out.ok, out.errors
        return str(out.request.request_id)

    def nmap(self, sid: str, audit: AuditLog, xml: str, port=PORT) -> str:
        out = run_nmap_connect_scan(
            checker=self.checker, audit=audit, session_id=uuid.UUID(sid), host=HOST,
            ports=[port], timeout_seconds=30, token=RunnerToken("t" * 43),
            evidence_root=self.evidence_root, tunnel_cfg=TunnelConfig(),
            tunnel_factory=_Tunnel, client_factory=_client(xml, "nmap_connect_scan"))
        assert out.ok, out.errors
        return str(out.request.request_id)

    def http_session(self, *responses: bytes) -> str:
        sid, audit = self.new_session()
        for r in responses:
            self.http(sid, audit, chunks=[r])
        return sid

    def evidence(self, sid: str):
        return load_session_evidence(self.sessions, self.evidence_root, sid)

    def evidence_file(self, sid: str, rid: str, ext: str) -> Path:
        return self.evidence_root / sid / f"{rid}{ext}"


@pytest.fixture
def lab(tmp_path) -> Lab:
    return Lab(tmp_path)
