"""Tool Registry — only registered tools, no dynamic registration, no
shell (ADR 0003 decision 6, M2.1)."""

from __future__ import annotations

import uuid

import pytest
from pydantic import BaseModel, ValidationError

import avra.runner.registry as registry
from avra.runner.registry import UnknownToolError, get_tool, parse_request


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


@pytest.mark.parametrize(
    "name",
    [
        "bash", "sh", "nmap", "python", "http_request", "",
        "NMAP_CONNECT_SCAN", "nmap_connect_scan ", " nmap_connect_scan",
        "nmap_connect_scan;id", None, 123, ["nmap_connect_scan"],
    ],
)
def test_unknown_tool_names_rejected(name):
    with pytest.raises(UnknownToolError):
        get_tool(name)
    with pytest.raises(UnknownToolError):
        parse_request(_payload(tool=name))


def test_missing_tool_field_rejected():
    payload = _payload()
    del payload["tool"]
    with pytest.raises(UnknownToolError):
        parse_request(payload)


@pytest.mark.parametrize("payload", [None, "nmap_connect_scan", [], 42])
def test_non_object_request_rejected(payload):
    with pytest.raises(UnknownToolError):
        parse_request(payload)


def test_registry_is_read_only():
    with pytest.raises(TypeError):
        registry._REGISTRY["bash"] = registry._REGISTRY["nmap_connect_scan"]


def test_no_dynamic_registration_api():
    public = {n for n in dir(registry) if not n.startswith("_")}
    assert not {n for n in public if "register" in n and n != "registered_tools"}


def test_spec_is_immutable():
    spec = get_tool("nmap_connect_scan")
    with pytest.raises(AttributeError):
        spec.executable = "/bin/sh"


def test_request_schema_still_rejects_caller_scope_and_args():
    for field, value in [("scope", {}), ("tier", "passive"), ("args", ["-A"])]:
        with pytest.raises(ValidationError):
            parse_request(_payload(**{field: value}))


def test_executable_fixed_and_argv_has_no_shell():
    spec, req = parse_request(_payload())
    argv = spec.build_command(req).argv
    assert argv[0] == "nmap"
    assert isinstance(argv, tuple)
    assert not any(a in ("sh", "bash", "-c", "/bin/sh") for a in argv)
    assert all(not any(ch in a for ch in ";|&$`\n") for a in argv)


def test_nmap_never_privileged():
    spec, req = parse_request(_payload())
    argv = spec.build_command(req).argv
    assert "--unprivileged" in argv
    assert "--privileged" not in argv
    assert "-sT" in argv and not {"-sS", "-sU", "-O", "-A", "--script"} & set(argv)


def test_build_command_rejects_wrong_request_type():
    class Other(BaseModel):
        timeout_seconds: int = 1

    with pytest.raises(TypeError):
        get_tool("nmap_connect_scan").build_command(Other())
