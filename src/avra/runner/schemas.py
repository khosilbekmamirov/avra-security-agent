"""Strict request/response schemas for the Tool Runner (ADR 0003, M1).

These models are the Runner's first line of defense: anything that isn't
exactly the expected shape is rejected before it reaches policy checks or
a subprocess. Notably:

- Unknown fields are forbidden, so a caller can't smuggle in a ``scope``,
  ``tier``, ``args`` or ``flags`` field. The Runner loads its own trusted
  scope and decides the tier itself (``avra.runner.registry``).
- ``host`` must be a canonical IPv4 literal — no hostnames (no DNS
  tricks), no CIDR ranges, no extra characters that could become nmap
  flags.
- ``ports`` are strict integers only — no strings, ranges, or booleans.

Passing schema validation does NOT mean a request is authorized; the
Runner's own default-deny scope check (M2) decides that.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

# Hard limits. The Runner may enforce tighter ones at runtime, never looser.
MAX_PORTS_PER_REQUEST = 32
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 120
MAX_OUTPUT_CHARS = 1_000_000
MAX_REASON_CHARS = 1_000
# http_probe (ADR 0007): one fixed GET, a short total budget.
HTTP_PROBE_DEFAULT_TIMEOUT_SECONDS = 10
HTTP_PROBE_MAX_TIMEOUT_SECONDS = 30


class ToolName(str, Enum):
    NMAP_CONNECT_SCAN = "nmap_connect_scan"
    HTTP_PROBE = "http_probe"
    HTTP_GET_PATH = "http_get_path"  # M10.5 (ADR 0018)


# M10.5: one same-origin path. Path only (no query, no fragment), a URL-safe character set,
# no dot segments, no doubled or back slashes and no percent-encoded '.', '/' or '\', so the
# server and the scope check cannot disagree about which path is meant.
HTTP_PATH_MAX = 200
_HTTP_PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                             "-._~!$&'()*+,;=:@%/")


def validate_http_path(value: object) -> str:
    """Return ``value`` if it is an unambiguous absolute path; raise ValueError otherwise.
    Shared by the request schema, the scope schema and the child program."""
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError("path must be a string starting with '/'")
    if len(value) > HTTP_PATH_MAX:
        raise ValueError(f"path longer than {HTTP_PATH_MAX} characters")
    if any(c not in _HTTP_PATH_CHARS for c in value):
        raise ValueError("path may only contain URL-safe characters (no query, fragment, "
                         "space or control characters)")
    if "//" in value:
        raise ValueError("path must not contain '//'")
    segments = value.split("/")
    if any(s in (".", "..") for s in segments):
        raise ValueError("path must not contain '.' or '..' segments")
    low = value.lower()
    if any(enc in low for enc in ("%2e", "%2f", "%5c", "%00", "%25")):
        raise ValueError("path must not percent-encode '.', '/', '\\', '%' or NUL")
    i = 0
    while (i := low.find("%", i)) != -1:
        if len(low) < i + 3 or any(c not in "0123456789abcdef" for c in low[i + 1:i + 3]):
            raise ValueError("path has an invalid percent-escape")
        i += 3
    return value


def validate_ipv4_target(value: str) -> str:
    """Return ``value`` if it's a canonical, scannable IPv4 literal.

    Shared by request schemas and the Runner's scope loader so both apply
    exactly the same rule. Raises ValueError otherwise.
    """
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError(
            "host must be a literal IPv4 address "
            "(no hostnames, CIDR ranges, or extra characters)"
        ) from None
    if str(addr) != value:
        raise ValueError("host must be in canonical dotted-decimal form")
    if (
        addr.is_unspecified
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
        or addr == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise ValueError(f"host {value} is not a valid scan target address")
    return value


class NmapConnectScanRequest(BaseModel):
    """A request to run one nmap TCP connect scan against one host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: Literal[ToolName.NMAP_CONNECT_SCAN] = ToolName.NMAP_CONNECT_SCAN
    request_id: UUID
    session_id: UUID
    host: StrictStr
    ports: list[StrictInt] = Field(min_length=1, max_length=MAX_PORTS_PER_REQUEST)
    timeout_seconds: StrictInt = Field(
        default=DEFAULT_TIMEOUT_SECONDS,
        ge=MIN_TIMEOUT_SECONDS,
        le=MAX_TIMEOUT_SECONDS,
    )

    @field_validator("host")
    @classmethod
    def host_is_ipv4_literal(cls, value: str) -> str:
        return validate_ipv4_target(value)

    @field_validator("ports")
    @classmethod
    def ports_valid_and_unique(cls, ports: list[int]) -> list[int]:
        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid port: {port}")
        if len(set(ports)) != len(ports):
            raise ValueError("ports must not contain duplicates")
        return ports


class HttpProbeRequest(BaseModel):
    """One fixed ``GET / HTTP/1.0`` to one IPv4 literal and port (ADR 0007).

    Deliberately has NO method, path, URL, header, body, scheme or proxy
    field: none of those can be chosen by a caller or the model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: Literal[ToolName.HTTP_PROBE] = ToolName.HTTP_PROBE
    request_id: UUID
    session_id: UUID
    host: StrictStr
    port: StrictInt = Field(ge=1, le=65535)
    timeout_seconds: StrictInt = Field(
        default=HTTP_PROBE_DEFAULT_TIMEOUT_SECONDS,
        ge=MIN_TIMEOUT_SECONDS,
        le=HTTP_PROBE_MAX_TIMEOUT_SECONDS,
    )

    @field_validator("host")
    @classmethod
    def host_is_ipv4_literal(cls, value: str) -> str:
        return validate_ipv4_target(value)


class HttpGetPathRequest(BaseModel):
    """M10.5 (ADR 0018): one fixed ``GET <path> HTTP/1.0`` to one IPv4 literal and port.

    Like ``HttpProbeRequest`` there is NO method, URL, header, body, query, scheme or proxy
    field; the only addition is a validated same-origin ``path``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: Literal[ToolName.HTTP_GET_PATH] = ToolName.HTTP_GET_PATH
    request_id: UUID
    session_id: UUID
    host: StrictStr
    port: StrictInt = Field(ge=1, le=65535)
    path: StrictStr
    timeout_seconds: StrictInt = Field(
        default=HTTP_PROBE_DEFAULT_TIMEOUT_SECONDS,
        ge=MIN_TIMEOUT_SECONDS,
        le=HTTP_PROBE_MAX_TIMEOUT_SECONDS,
    )

    @field_validator("host")
    @classmethod
    def host_is_ipv4_literal(cls, value: str) -> str:
        return validate_ipv4_target(value)

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return validate_http_path(value)


class RejectionStage(str, Enum):
    UNKNOWN_TOOL = "unknown_tool"
    INVALID_REQUEST = "invalid_request"
    SCOPE = "scope"
    AUDIT_UNAVAILABLE = "audit_unavailable"  # fail closed: can't record it
    INTERNAL_ERROR = "internal_error"
    # M8.7 Stage 4 (ADR 0012). Unknown to pre-Stage-4 clients, whose strict
    # schema then rejects the answer (fail closed, never read as success).
    EMERGENCY_STOP = "emergency_stop"  # Runner latch not READY: nothing runs
    CANCELLED = "cancelled"  # cancelled before it started (tombstone): nothing ran


class RunnerRejection(BaseModel):
    """The Runner refused a request before anything ran.

    Used whenever a request can't be (or mustn't be) executed: unknown
    tool, invalid payload, out of scope, or the audit log can't record
    the attempt. ``request_id`` is set only when the payload carried a
    valid one.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: RejectionStage
    reason: str = Field(min_length=1, max_length=MAX_REASON_CHARS)
    request_id: UUID | None = None


class ToolRunStatus(str, Enum):
    COMPLETED = "completed"  # tool ran and exited
    DENIED = "denied"  # Runner's policy check refused it; nothing ran
    TIMED_OUT = "timed_out"  # tool was killed after its timeout
    FAILED = "failed"  # tool could not be started or errored
    CANCELLED = "cancelled"  # M8.7: stopped on request; output withheld, never evidence


class ToolRunResult(BaseModel):
    """The Runner's answer to one tool request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    tool: ToolName
    status: ToolRunStatus
    reason: str = Field(default="", max_length=MAX_REASON_CHARS)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    raw_output: str | None = Field(default=None, max_length=MAX_OUTPUT_CHARS)
    output_truncated: bool = False
    output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def consistent_with_status(self) -> ToolRunResult:
        if self.status is ToolRunStatus.DENIED:
            if (
                self.started_at is not None
                or self.exit_code is not None
                or self.raw_output is not None
            ):
                raise ValueError("a denied request must not report any execution")
            if not self.reason:
                raise ValueError("a denied request must state a reason")
        if self.status is ToolRunStatus.CANCELLED and (
            self.raw_output is not None or self.output_sha256 is not None or not self.reason
        ):
            raise ValueError("a cancelled run must state a reason and carry no output")
        if self.status is ToolRunStatus.COMPLETED:
            if self.exit_code is None or self.output_sha256 is None:
                raise ValueError(
                    "a completed run must report exit_code and output_sha256"
                )
        if (
            self.started_at is not None
            and self.finished_at is not None
            and self.finished_at < self.started_at
        ):
            raise ValueError("finished_at must not be before started_at")
        return self


# --- M8.7 Stage 4: cancellation and emergency stop (ADR 0012) -------------------------


class CancelReason(str, Enum):
    OPERATOR_REQUEST = "operator_request"
    CLIENT_INTERRUPT = "client_interrupt"  # e.g. Ctrl+C on Windows
    LOCAL_KILL_SWITCH = "local_kill_switch"  # the Windows latch was engaged


class CancelRequest(BaseModel):
    """Identifies ONE job by both of its ids. Nothing else is accepted: no
    PID, process group, path, command, signal or tool argument."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    request_id: UUID
    session_id: UUID
    reason: CancelReason

    @field_validator("request_id", "session_id", mode="before")
    @classmethod
    def uuid_text(cls, value: object) -> UUID:
        if not isinstance(value, str) or len(value) != 36:
            raise ValueError("must be a canonical UUID string")
        parsed = UUID(value)
        if str(parsed) != value:
            raise ValueError("must be a canonical lower-case UUID string")
        return parsed

    @field_validator("reason", mode="before")
    @classmethod
    def reason_text(cls, value: object) -> CancelReason:
        return CancelReason(value) if isinstance(value, str) else value  # strict enum


class CancelOutcome(str, Enum):
    REQUESTED = "cancellation_requested"  # signalled; the job had not ended yet
    APPLIED = "cancellation_applied"  # the job ended as cancelled
    ALREADY_CANCELLED = "already_cancelled"
    ALREADY_FINISHED = "already_finished"  # it ended before the cancel took effect
    NOT_ACTIVE = "not_active"  # unknown now; a later run with these ids is refused (TTL)
    MISMATCH = "identifier_mismatch"  # one id matches a known job, the other does not
    UNAVAILABLE = "cancellation_unavailable"


class CancelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: CancelOutcome
    request_id: UUID
    session_id: UUID
    audit_recorded: bool


class EmergencyReason(str, Enum):
    OPERATOR_EMERGENCY_STOP = "operator_emergency_stop"
    LOCAL_KILL_SWITCH = "local_kill_switch"


class EmergencyStopRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: EmergencyReason


class EmergencyStopResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: Literal["engaged", "already_engaged", "not_durable"]
    latch: str  # READY / STOPPED / CORRUPT / UNREADABLE as read back from disk
    durable: bool  # the persistent latch reads back as STOPPED
    audit_recorded: bool
    active_job: Literal["none", "cancelled", "cancel_requested", "already_finished"]
