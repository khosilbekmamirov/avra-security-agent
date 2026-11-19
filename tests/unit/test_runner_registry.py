"""Tool Registry — expected behavior (ADR 0003 decision 6, M2.1)."""

from __future__ import annotations

import uuid

from avra.runner.registry import get_tool, parse_request, registered_tools
from avra.runner.schemas import NmapConnectScanRequest, ToolName
from avra.schemas.scope import ActionTier


def _payload(**overrides):
    data = {
        "tool": "nmap_connect_scan",
        "request_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "host": "10.66.7.103",
        "ports": [3000],
    }
    data.update(overrides)
    return data


def test_only_nmap_connect_scan_registered():
    assert registered_tools() == ("nmap_connect_scan", "http_probe", "http_get_path")


def test_nmap_spec_fields():
    spec = get_tool("nmap_connect_scan")
    assert spec.name is ToolName.NMAP_CONNECT_SCAN
    assert spec.request_model is NmapConnectScanRequest
    assert spec.tier is ActionTier.ACTIVE_SAFE
    assert spec.executable == "nmap"


def test_parse_request_returns_spec_and_typed_request():
    spec, req = parse_request(_payload())
    assert spec.name is ToolName.NMAP_CONNECT_SCAN
    assert isinstance(req, NmapConnectScanRequest)


def test_nmap_command_is_exact_argv():
    spec, req = parse_request(_payload(ports=[22, 3000], timeout_seconds=30))
    cmd = spec.build_command(req)
    assert cmd.argv == (
        "nmap", "--unprivileged", "-sT", "-Pn", "-n",
        "--max-retries", "1",
        "--host-timeout", "30s",
        "-p", "22,3000",
        "-oX", "-",
        "10.66.7.103",
    )
    assert cmd.timeout_seconds == 30
