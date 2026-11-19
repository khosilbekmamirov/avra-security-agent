"""Tool Runner input validation — hostile/malformed requests must be
rejected at the schema layer, before any policy check or subprocess
(ADR 0003, M1)."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from avra.runner.schemas import (
    MAX_OUTPUT_CHARS,
    MAX_PORTS_PER_REQUEST,
    MAX_TIMEOUT_SECONDS,
    NmapConnectScanRequest,
    ToolName,
    ToolRunResult,
    ToolRunStatus,
)


def _base(**overrides):
    data = {
        "request_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "host": "10.66.7.103",
        "ports": [3000],
    }
    data.update(overrides)
    return data


def _reject(**overrides):
    with pytest.raises(ValidationError):
        NmapConnectScanRequest.model_validate(_base(**overrides))


@pytest.mark.parametrize(
    "host",
    [
        "juice-shop.local",  # hostname -> DNS could resolve anywhere
        "localhost",
        "192.168.56.0/24",  # CIDR range
        "10.66.7.103/32",
        "10.66.7.103 -oN /tmp/x",  # flag injection
        "-iL /etc/passwd",
        "--script=vuln",
        "10.66.7.103;id",  # shell metacharacters
        "$(id)",
        "`id`",
        "10.66.7.103\n192.168.56.1",
        " 10.66.7.103",
        "10.66.7.103 ",
        "192.168.056.103",  # leading zero / octal ambiguity
        "192.168.56",
        "",
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
        "224.0.0.1",
        "169.254.1.1",
        "240.0.0.1",
        "::1",  # IPv6 not supported in MVP
        "fe80::1",
    ],
)
def test_bad_host_rejected(host):
    _reject(host=host)


@pytest.mark.parametrize("host", [3232250983, None, ["10.66.7.103"]])
def test_non_string_host_rejected(host):
    _reject(host=host)


@pytest.mark.parametrize(
    "ports",
    [
        [],
        [0],
        [65536],
        [-1],
        ["3000"],  # strings not coerced
        ["1-65535"],  # ranges not allowed
        [True],  # bool is not a port
        [3000.0],
        [3000, 3000],  # duplicates
        list(range(1, MAX_PORTS_PER_REQUEST + 2)),  # too many
        "3000",
        None,
    ],
)
def test_bad_ports_rejected(ports):
    _reject(ports=ports)


@pytest.mark.parametrize(
    "timeout", [0, -5, MAX_TIMEOUT_SECONDS + 1, "60", 1.5, True]
)
def test_bad_timeout_rejected(timeout):
    _reject(timeout_seconds=timeout)


@pytest.mark.parametrize(
    "field,value",
    [
        # The caller must never be able to supply its own authorization.
        ("scope", {"targets": [{"host": "10.0.0.1"}]}),
        ("tier", "passive"),
        ("allowed_tools", ["nmap_connect_scan"]),
        # Nor any free-form command material.
        ("args", ["-sS", "-O"]),
        ("extra_args", "--script vuln"),
        ("flags", "-A"),
        ("command", "nmap -A 10.66.7.103"),
        ("shell", True),
    ],
)
def test_unknown_fields_rejected(field, value):
    _reject(**{field: value})


@pytest.mark.parametrize("tool", ["bash", "nmap", "sh", "nmap_syn_scan", ""])
def test_other_tools_rejected(tool):
    _reject(tool=tool)


@pytest.mark.parametrize("field", ["request_id", "session_id"])
def test_ids_must_be_uuids(field):
    _reject(**{field: "not-a-uuid"})


def test_missing_required_fields_rejected():
    with pytest.raises(ValidationError):
        NmapConnectScanRequest.model_validate({"host": "10.66.7.103"})


def test_result_output_size_capped():
    with pytest.raises(ValidationError):
        ToolRunResult(
            request_id=uuid.uuid4(),
            tool=ToolName.NMAP_CONNECT_SCAN,
            status=ToolRunStatus.FAILED,
            raw_output="x" * (MAX_OUTPUT_CHARS + 1),
        )


def test_result_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        ToolRunResult.model_validate(
            {
                "request_id": str(uuid.uuid4()),
                "tool": "nmap_connect_scan",
                "status": "denied",
                "reason": "not in scope",
                "confirmed_vulnerability": True,
            }
        )
