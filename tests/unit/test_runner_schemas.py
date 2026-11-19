"""Tool Runner schemas — expected-valid shapes (ADR 0003, M1)."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from avra.runner.schemas import (
    DEFAULT_TIMEOUT_SECONDS,
    NmapConnectScanRequest,
    ToolName,
    ToolRunResult,
    ToolRunStatus,
)


def _request(**overrides):
    data = {
        "request_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "host": "10.66.7.103",
        "ports": [3000],
    }
    data.update(overrides)
    return NmapConnectScanRequest.model_validate(data)


def test_valid_request_and_defaults():
    req = _request()
    assert req.tool is ToolName.NMAP_CONNECT_SCAN
    assert req.host == "10.66.7.103"
    assert req.ports == [3000]
    assert req.timeout_seconds == DEFAULT_TIMEOUT_SECONDS


def test_request_json_round_trip():
    req = _request(ports=[22, 3000], timeout_seconds=30)
    again = NmapConnectScanRequest.model_validate_json(req.model_dump_json())
    assert again == req


def test_request_is_immutable():
    req = _request()
    with pytest.raises(ValidationError):
        req.host = "192.168.56.104"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_completed_result_valid():
    start = datetime.now(UTC)
    res = ToolRunResult(
        request_id=uuid.uuid4(),
        tool=ToolName.NMAP_CONNECT_SCAN,
        status=ToolRunStatus.COMPLETED,
        started_at=start,
        finished_at=start + timedelta(seconds=2),
        exit_code=0,
        raw_output="<nmaprun/>",
        output_sha256=_sha("<nmaprun/>"),
    )
    assert res.status is ToolRunStatus.COMPLETED


def test_denied_result_valid():
    res = ToolRunResult(
        request_id=uuid.uuid4(),
        tool=ToolName.NMAP_CONNECT_SCAN,
        status=ToolRunStatus.DENIED,
        reason="192.168.56.1:22 is not in scope",
    )
    assert res.raw_output is None


def test_completed_result_requires_hash_and_exit_code():
    with pytest.raises(ValidationError):
        ToolRunResult(
            request_id=uuid.uuid4(),
            tool=ToolName.NMAP_CONNECT_SCAN,
            status=ToolRunStatus.COMPLETED,
        )


def test_denied_result_must_not_report_execution():
    with pytest.raises(ValidationError):
        ToolRunResult(
            request_id=uuid.uuid4(),
            tool=ToolName.NMAP_CONNECT_SCAN,
            status=ToolRunStatus.DENIED,
            reason="not in scope",
            exit_code=0,
        )


def test_denied_result_requires_reason():
    with pytest.raises(ValidationError):
        ToolRunResult(
            request_id=uuid.uuid4(),
            tool=ToolName.NMAP_CONNECT_SCAN,
            status=ToolRunStatus.DENIED,
        )


def test_result_rejects_bad_hash_and_time_order():
    start = datetime.now(UTC)
    with pytest.raises(ValidationError):
        ToolRunResult(
            request_id=uuid.uuid4(),
            tool=ToolName.NMAP_CONNECT_SCAN,
            status=ToolRunStatus.FAILED,
            output_sha256="not-a-hash",
        )
    with pytest.raises(ValidationError):
        ToolRunResult(
            request_id=uuid.uuid4(),
            tool=ToolName.NMAP_CONNECT_SCAN,
            status=ToolRunStatus.FAILED,
            started_at=start,
            finished_at=start - timedelta(seconds=1),
        )
