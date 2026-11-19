"""M6.3–M6.5: Windows-side policy, nmap XML parsing (defusedxml), evidence
storage, the end-to-end orchestration with fake tunnel/client, and the CLI's
local-deny path. No network, no SSH, no scans."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from avra.core.research import classify_result, scan_summary
from avra.policy.scope import ScopeChecker
from avra.policy.tools import authorize_tool_request
from avra.recon.nmap_xml import NmapXmlError, parse_nmap_xml
from avra.runner.schemas import (
    NmapConnectScanRequest,
    RejectionStage,
    RunnerRejection,
    ToolRunResult,
    ToolRunStatus,
)
from avra.runner_client.client import RunnerClientError, RunnerToken, RunOutcome
from avra.runner_client.scan import ScanOutcome, run_nmap_connect_scan
from avra.runner_client.tunnel import TunnelConfig, TunnelError
from avra.schemas.scope import ActionTier, Scope, Target
from avra.storage.audit import AuditLog
from avra.storage.evidence import EvidenceError, EvidenceRef, store_evidence

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests" / "fixtures" / "nmap"
OPEN_XML = (FIX / "m5-juice-shop-3000-open.xml").read_text(encoding="utf-8")
CLOSED_XML = (FIX / "m5-juice-shop-3000-closed.xml").read_text(encoding="utf-8")
TOKEN = "s" * 43


def _scope(expires=timedelta(days=30), tiers=("active-safe",), tools=("nmap_connect_scan",),
           ports=(3000,)):
    return Scope(
        session_name="t", expires_at=datetime.now(UTC) + expires,
        targets=[Target(host="10.66.7.103", ports=list(ports),
                        allowed_tiers=[ActionTier(t) for t in tiers], allowed_tools=list(tools))],
    )


def _req(host="10.66.7.103", ports=(3000,)):
    return NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=uuid.uuid4(),
                                  host=host, ports=list(ports), timeout_seconds=60)


# --- M6.3 policy -------------------------------------------------------------


def test_in_scope_allowed():
    assert authorize_tool_request(ScopeChecker(_scope()), _req()).allowed


@pytest.mark.parametrize("scope_kw,req_kw", [
    ({}, {"ports": (22,)}),
    ({}, {"ports": (3000, 22)}),  # one bad port denies the whole request
    ({}, {"host": "192.168.56.104"}),
    ({"tiers": ("passive",)}, {}),  # tool's registry tier is active-safe
    ({"tools": ("http_probe",)}, {}),
])
def test_default_deny(scope_kw, req_kw):
    assert not authorize_tool_request(ScopeChecker(_scope(**scope_kw)), _req(**req_kw)).allowed


def test_expired_scope_denies():
    scope = _scope().model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    assert not authorize_tool_request(ScopeChecker(scope), _req()).allowed


# --- M6.4 parser ------------------------------------------------------------------


def test_parse_real_open_and_closed():
    o, c = parse_nmap_xml(OPEN_XML), parse_nmap_xml(CLOSED_XML)
    assert o.port_states() == {("10.66.7.103", 3000): "open"}
    assert c.port_states() == {("10.66.7.103", 3000): "closed"}
    assert c.hosts[0].ports[0].reason == "conn-refused"
    assert o.exit_status == "success" and "--unprivileged -sT" in o.args.replace("-&#45;", "--")


BOMB = """<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaaaaaaaa">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>"""
XXE = """<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<nmaprun>&x;</nmaprun>"""


@pytest.mark.parametrize("xml", [BOMB, XXE, "<html/>", "", "<nmaprun>", "<nmaprun/>",
                                 "x" * 1_000_001])
def test_parser_rejects_unsafe_or_incomplete(xml):
    with pytest.raises(NmapXmlError):
        parse_nmap_xml(xml)


# --- M6.5 evidence ----------------------------------------------------------------


def test_evidence_written_once(tmp_path):
    s, r = uuid.uuid4(), uuid.uuid4()
    ref = store_evidence(tmp_path, s, r, ".xml", b"<x/>")
    assert ref.path.read_bytes() == b"<x/>" and ref.sha256 == hashlib.sha256(b"<x/>").hexdigest()
    with pytest.raises(EvidenceError):
        store_evidence(tmp_path, s, r, ".xml", b"other")
    assert ref.path.read_bytes() == b"<x/>"


@pytest.mark.parametrize("sid,suffix", [("../x", ".xml"), (None, ".exe")])
def test_evidence_names_only_from_uuids(tmp_path, sid, suffix):
    with pytest.raises(EvidenceError):
        store_evidence(tmp_path, sid if sid else uuid.uuid4(), uuid.uuid4(), suffix, b"")


# --- M6.5 orchestration (fake tunnel + client) ------------------------------------


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


def _client(answer):
    class C:
        def __init__(self, base, token):
            self.token = token

        def health(self):
            return {"status": "ok"}

        def run(self, request):
            return answer(request)
    return C


def _completed(request, raw=OPEN_XML, sha=None):
    return RunOutcome(200, result=ToolRunResult(
        request_id=request.request_id, tool="nmap_connect_scan", status=ToolRunStatus.COMPLETED,
        started_at=datetime.now(UTC), finished_at=datetime.now(UTC), exit_code=0,
        raw_output=raw, output_sha256=sha or hashlib.sha256(raw.encode()).hexdigest(),
    ), hash_verified=sha is None)


def _run(tmp_path, answer, host="10.66.7.103", ports=(3000,), tunnel_fail=False, scope=None):
    audit = AuditLog(tmp_path / "audit.jsonl")
    FakeTunnel.opened = 0
    out = run_nmap_connect_scan(
        checker=ScopeChecker(scope or _scope()), audit=audit, session_id=uuid.uuid4(),
        host=host, ports=list(ports), timeout_seconds=60, token=RunnerToken(TOKEN),
        evidence_root=tmp_path / "evidence", tunnel_cfg=TunnelConfig(),
        tunnel_factory=lambda cfg: FakeTunnel(cfg, fail=tunnel_fail),
        client_factory=_client(answer),
    )
    return out, audit


def _events(audit):
    return [r.event for r in audit.read_all()]


def test_success_path(tmp_path):
    out, audit = _run(tmp_path, _completed)
    assert out.ok
    assert out.report.port_states() == {("10.66.7.103", 3000): "open"}
    assert out.evidence.sha256 == out.result.output_sha256
    assert out.evidence.path.read_text(encoding="utf-8") == OPEN_XML
    assert _events(audit) == ["tool_request_sent", "tool_result_received"]
    rec = audit.read_all()[-1].data
    assert rec["port_states"] == [{"host": "10.66.7.103", "port": 3000, "state": "open",
                                   "reason": "syn-ack", "service": "ppp",
                                   "service_method": "table", "service_confidence": 3}]
    assert rec["nmap_exit_status"] == "success"
    assert rec["host_statuses"] == [{"host": "10.66.7.103", "status": "up"}]
    assert audit.verify()
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert TOKEN not in text and "<nmaprun" not in text  # no secret, no raw output


def test_local_deny_sends_nothing(tmp_path):
    def never(request):
        pytest.fail("must not reach the Runner")
    out, audit = _run(tmp_path, never, ports=(22,))
    assert not out.allowed_locally and FakeTunnel.opened == 0
    assert _events(audit) == ["tool_request_denied_locally"]


def test_audit_failure_before_send_sends_nothing(tmp_path):
    class BrokenAudit:
        def record(self, *a, **k):
            raise OSError("disk full")

    with pytest.raises(OSError):
        run_nmap_connect_scan(
            checker=ScopeChecker(_scope()), audit=BrokenAudit(), session_id=uuid.uuid4(),
            host="10.66.7.103", ports=[3000], timeout_seconds=60, token=RunnerToken(TOKEN),
            evidence_root=tmp_path, tunnel_cfg=TunnelConfig(),
            tunnel_factory=lambda cfg: pytest.fail("must not open the tunnel"),
            client_factory=_client(lambda r: pytest.fail("must not send")),
        )


def test_runner_rejection_recorded(tmp_path):
    rej = lambda r: RunOutcome(403, rejection=RunnerRejection(
        stage=RejectionStage.SCOPE, reason="not in scope", request_id=r.request_id))
    out, audit = _run(tmp_path, rej)
    assert not out.ok and out.rejection.stage is RejectionStage.SCOPE
    assert _events(audit) == ["tool_request_sent", "tool_request_rejected"]


def test_tunnel_failure_recorded(tmp_path):
    out, audit = _run(tmp_path, _completed, tunnel_fail=True)
    assert not out.ok and _events(audit)[-1] == "tool_request_failed"


def test_client_error_recorded(tmp_path):
    def boom(request):
        raise RunnerClientError("Runner response failed validation (HTTP 200): 1 error(s)")
    out, audit = _run(tmp_path, boom)
    assert not out.ok and _events(audit)[-1] == "tool_request_failed"


def test_hash_mismatch_is_not_ok(tmp_path):
    out, audit = _run(tmp_path, lambda r: _completed(r, sha="0" * 64))
    assert not out.ok and "output hash could not be verified" in out.errors
    assert audit.read_all()[-1].data["hash_verified"] is False


def test_unparseable_output_is_not_ok(tmp_path):
    out, _ = _run(tmp_path, lambda r: _completed(r, raw="<html/>"))
    assert not out.ok and any(e.startswith("parse:") for e in out.errors)


# --- CLI: local deny path end to end (no network) ----------------------------------


SCOPE_YAML = """session_name: cli-test
expires_at: "{exp}"
targets:
  - host: "10.66.7.103"
    ports: [3000]
    allowed_tiers: ["active-safe"]
    allowed_tools: ["nmap_connect_scan"]
"""


def test_cli_out_of_scope_is_denied_locally(tmp_path, monkeypatch):
    from avra.cli.main import app

    scope = tmp_path / "s.yaml"
    scope.write_text(SCOPE_YAML.format(exp=(datetime.now(UTC) + timedelta(days=1)).isoformat()),
                     encoding="utf-8")
    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AVRA_RUNNER_TOKEN", TOKEN)
    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(app, ["scan", "nmap-connect", "--scope", str(scope),
                                 "--host", "10.66.7.103", "--port", "22", "--yes"])
    assert r.exit_code == 1, r.output
    assert "Denied by local policy" in r.output
    assert TOKEN not in r.output
    logs = list((tmp_path / "data" / "sessions").glob("*.jsonl"))
    assert len(logs) == 1
    assert [rec.event for rec in AuditLog(logs[0]).read_all()] == [
        "session_created", "tool_request_denied_locally"]


def test_cli_confirmation_no_sends_nothing(tmp_path, monkeypatch):
    from avra.cli.main import app

    scope = tmp_path / "s.yaml"
    scope.write_text(SCOPE_YAML.format(exp=(datetime.now(UTC) + timedelta(days=1)).isoformat()),
                     encoding="utf-8")
    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AVRA_RUNNER_TOKEN", TOKEN)
    r = CliRunner().invoke(app, ["scan", "nmap-connect", "--scope", str(scope),
                                 "--host", "10.66.7.103", "--port", "3000"], input="n\n")
    assert r.exit_code == 1 and "nothing sent" in r.output
    assert not (tmp_path / "data").exists()


def test_cli_source_is_ascii_for_windows_consoles():
    # A non-ASCII "→" crashed `avra scan nmap-connect --help` on a cp1251/cp437
    # Windows console (UnicodeEncodeError) during M6 development.
    src = (ROOT / "src" / "avra" / "cli" / "main.py").read_text(encoding="utf-8")
    assert all(ord(c) < 128 for c in src)


# --- M7.8 Stage 2: result parsing & interpretation --------------------------------

FILTERED_XML = (FIX / "m7-3000-filtered.xml").read_text(encoding="utf-8")
MIXED_XML = (FIX / "m7-mixed-states.xml").read_text(encoding="utf-8")
DOWN_XML = (FIX / "m7-host-down.xml").read_text(encoding="utf-8")
PROBED_XML = (FIX / "m7-3000-probed.xml").read_text(encoding="utf-8")


def _completed_outcome(xml, errors=None, exit_code=0):
    """A COMPLETED ScanOutcome with matching evidence hash (ok unless errors)."""
    req = _req()
    sha = hashlib.sha256(xml.encode()).hexdigest()
    res = ToolRunResult(request_id=req.request_id, tool="nmap_connect_scan",
                        status=ToolRunStatus.COMPLETED, started_at=datetime.now(UTC),
                        finished_at=datetime.now(UTC), exit_code=exit_code, raw_output=xml,
                        output_sha256=sha)
    ev = EvidenceRef(path=Path("x.xml"), sha256=sha, size=len(xml))
    return ScanOutcome(req, True, "in scope", result=res, hash_verified=True, evidence=ev,
                       report=parse_nmap_xml(xml), errors=list(errors or []))


# parser metadata

def test_parser_extracts_service_method_and_confidence():
    table = parse_nmap_xml(OPEN_XML).hosts[0].ports[0]
    assert (table.service, table.service_method, table.service_confidence) == ("ppp", "table", 3)
    assert table.service_identified is False          # a port-table guess, not detection
    probed = parse_nmap_xml(PROBED_XML).hosts[0].ports[0]
    assert (probed.service_method, probed.service_confidence) == ("probed", 10)
    assert probed.service_identified is True


def test_parser_handles_filtered_mixed_and_host_down():
    assert parse_nmap_xml(FILTERED_XML).hosts[0].ports[0].state == "filtered"
    mixed = parse_nmap_xml(MIXED_XML)
    assert {p.port: p.state for p in mixed.hosts[0].ports} == {80: "closed", 3000: "open",
                                                               9000: "filtered"}
    down = parse_nmap_xml(DOWN_XML)
    assert down.hosts[0].status == "down" and down.hosts[0].ports == ()


def test_parser_rejects_nonnumeric_service_conf():
    bad = OPEN_XML.replace('conf="3"', 'conf="high"')
    with pytest.raises(NmapXmlError):
        parse_nmap_xml(bad)


# classification / model-facing summary

def test_classify_states():
    assert classify_result(_completed_outcome(OPEN_XML))[0] == "completed"
    assert classify_result(_completed_outcome(MIXED_XML))[0] == "completed"
    assert classify_result(_completed_outcome(CLOSED_XML))[0] == "no_open_ports"
    assert classify_result(_completed_outcome(FILTERED_XML))[0] == "no_open_ports"
    assert classify_result(_completed_outcome(DOWN_XML))[0] == "host_down"
    assert classify_result(_completed_outcome(OPEN_XML, errors=["bad hash"]))[0] == "failed"
    assert classify_result(ScanOutcome(_req(), False, "out of scope"))[0] == "denied_local"


def test_summary_grounds_service_as_guess_not_identity():
    s = scan_summary(_completed_outcome(OPEN_XML))
    assert s["result_state"] == "completed" and s["ok"] is True and s["open_port_count"] == 1
    assert s["nmap_exit_status"] == "success"
    assert s["hosts"] == [{"host": "10.66.7.103", "status": "up"}]
    p = s["ports"][0]
    assert p["service_guess"] == "ppp" and p["service_method"] == "table"
    assert p["service_confidence"] == 3 and p["service_identified"] is False


def test_summary_reports_probed_identity_when_present():
    p = scan_summary(_completed_outcome(PROBED_XML))["ports"][0]
    assert p["service_identified"] is True and p["service_method"] == "probed"


def test_summary_explains_zero_open_ports_and_host_down():
    closed = scan_summary(_completed_outcome(CLOSED_XML))
    assert closed["result_state"] == "no_open_ports" and closed["open_port_count"] == 0
    assert "closed or filtered" in closed["note"]
    down = scan_summary(_completed_outcome(DOWN_XML))
    assert down["result_state"] == "host_down" and "not up" in down["note"]


# §5: a bad outcome must never read as clean evidence

def test_nonzero_exit_code_is_not_ok(tmp_path):
    def answer(request):
        return RunOutcome(200, result=ToolRunResult(
            request_id=request.request_id, tool="nmap_connect_scan",
            status=ToolRunStatus.COMPLETED, started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC), exit_code=1, raw_output=OPEN_XML,
            output_sha256=hashlib.sha256(OPEN_XML.encode()).hexdigest()), hash_verified=True)
    out, _ = _run(tmp_path, answer)
    assert not out.ok and any("exited with code 1" in e for e in out.errors)
    assert classify_result(out)[0] == "failed"


def test_nmap_runstats_error_is_not_ok(tmp_path):
    err_xml = OPEN_XML.replace('exit="success"', 'exit="error"')
    out, _ = _run(tmp_path, lambda r: _completed(r, raw=err_xml))
    assert not out.ok and any("exit=error" in e for e in out.errors)
    assert scan_summary(out)["ok"] is False
