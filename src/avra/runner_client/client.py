"""Typed HTTP client for the Runner API (ADR 0003, M6.2) — stdlib urllib.

- Talks only to a loopback base URL (the local end of the SSH tunnel).
- The token is held in ``RunnerToken``: never printed, never in repr,
  never in exceptions or audit records.
- Responses are validated with the Runner's own strict schemas
  (``ToolRunResult`` / ``RunnerRejection``) — extra or inconsistent fields
  are an error, not something to guess around.
- Response bodies are size-capped before parsing.
- M8.7 Stage 5 (ADR 0012): ``cancel`` / ``emergency_stop`` speak only to the
  two Stage 4 stop endpoints (allowlist below), validate the answer
  strictly, never retry, and return a typed result that never claims the
  remote job stopped unless the Runner explicitly said so. ``run`` refuses
  while the local kill switch blocks (defence in depth: the pipelines check
  first).
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import ValidationError

from avra.runner.schemas import (
    MAX_OUTPUT_CHARS,
    CancelOutcome,
    CancelReason,
    CancelResponse,
    EmergencyReason,
    EmergencyStopResponse,
    HttpProbeRequest,
    NmapConnectScanRequest,
    RunnerRejection,
    ToolRunResult,
)

TOKEN_ENV = "AVRA_RUNNER_TOKEN"
MIN_TOKEN_CHARS = 32
MAX_TOKEN_CHARS = 512
# Worst case JSON-escaped raw output (\uXXXX = 6 chars per char) + envelope.
MAX_RESPONSE_BYTES = 6 * MAX_OUTPUT_CHARS + 64_000
HEALTH_TIMEOUT = 15.0
RUN_TIMEOUT_MARGIN = 30.0  # on top of the tool's own timeout
# Stop-only calls (Stage 5). The Runner waits up to 6 s for a cancel to take
# effect; an emergency stop also writes and reads back its latch.
CANCEL_TIMEOUT = 15.0
EMERGENCY_STOP_TIMEOUT = 20.0
MAX_STOP_RESPONSE_BYTES = 16 * 1024
CANCEL_PATH = "/v1/tools/cancel"
EMERGENCY_STOP_PATH = "/v1/emergency-stop"
STOP_ONLY_PATHS = frozenset({CANCEL_PATH, EMERGENCY_STOP_PATH})


class RunnerClientError(Exception):
    """Transport/protocol problem talking to the Runner. Never holds secrets."""


class RunnerProtocolError(RunnerClientError):
    """The Runner answered, but not with a well-formed, bounded JSON object."""


class RunnerAuthError(RunnerClientError):
    """The Runner answered 401 — wrong or missing token."""


class RunnerToken:
    """The bearer token. Its value is only reachable via ``header()``."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not MIN_TOKEN_CHARS <= len(value) <= MAX_TOKEN_CHARS:
            raise RunnerClientError(f"{TOKEN_ENV}: token must be {MIN_TOKEN_CHARS}-"
                                    f"{MAX_TOKEN_CHARS} characters")
        if not all(33 <= ord(c) <= 126 for c in value):
            raise RunnerClientError(f"{TOKEN_ENV}: token must be printable ASCII without spaces")
        self._value = value

    def header(self) -> str:
        return f"Bearer {self._value}"

    def __repr__(self) -> str:
        return "RunnerToken(<redacted>)"

    __str__ = __repr__


def load_token(env: dict[str, str] | None = None, env_file: Path | None = None) -> RunnerToken:
    """``AVRA_RUNNER_TOKEN`` from the environment, else from the project's
    ``.env`` (gitignored). Errors never include the value."""
    env = os.environ if env is None else env
    value = env.get(TOKEN_ENV, "").strip()
    if not value and env_file is not None and env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, sep, rest = line.partition("=")
            if sep and key.strip() == TOKEN_ENV:
                value = rest.strip().strip('"').strip("'")
                break
    if not value:
        raise RunnerClientError(f"{TOKEN_ENV} is not set (environment or .env)")
    return RunnerToken(value)


def _require_loopback(base_url: str) -> str:
    parts = urlsplit(base_url)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or not parts.port:
        raise RunnerClientError("Runner base URL must be http://127.0.0.1:<port> (tunnel end)")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise RunnerClientError("Runner base URL must not carry a path, query or credentials")
    return f"http://127.0.0.1:{parts.port}"


@dataclass(frozen=True)
class RunOutcome:
    """What came back for one run request."""

    http_status: int
    result: ToolRunResult | None = None
    rejection: RunnerRejection | None = None
    hash_verified: bool | None = None  # raw_output vs output_sha256 (None: nothing to check)


# Outcomes after which the Runner itself states the job is NOT running.
CANCEL_CONFIRMED = frozenset({CancelOutcome.APPLIED, CancelOutcome.ALREADY_CANCELLED,
                              CancelOutcome.ALREADY_FINISHED, CancelOutcome.NOT_ACTIVE})


@dataclass(frozen=True)
class StopCallResult:
    """What a stop-only call established. ``category`` is ``ok`` only for a
    valid Runner answer; everything else means NOTHING was confirmed:
    ``unsupported`` (404/405: Runner older than Stage 4), ``auth_failed``,
    ``rejected`` (400), ``rate_limited`` (429), ``unavailable`` (503 without a
    usable body), ``invalid_response``, ``transport`` (unreachable, timeout,
    reset, tunnel), ``config``, ``interrupted``."""

    category: str
    http_status: int | None = None
    cancel: CancelResponse | None = None
    emergency: EmergencyStopResponse | None = None
    detail: str = ""

    @property
    def cancel_confirmed(self) -> bool:
        """The Runner says this job is not running (cancelled, finished or
        unknown and now tombstoned). ``cancellation_requested`` is NOT."""
        return self.cancel is not None and self.cancel.outcome in CANCEL_CONFIRMED

    @property
    def emergency_confirmed(self) -> bool:
        """The Runner's persistent latch reads back STOPPED (durable)."""
        return (self.emergency is not None and self.emergency.durable
                and self.emergency.latch == "STOPPED")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow redirects
        return None


class RunnerClient:
    def __init__(self, base_url: str, token: RunnerToken, *, killswitch: Any = None) -> None:
        self._base = _require_loopback(base_url)
        self._token = token
        self._killswitch = killswitch
        # No proxies (env HTTP_PROXY must never see the token), no redirects.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    def _call(self, method: str, path: str, body: dict | None, timeout: float,
              max_bytes: int = MAX_RESPONSE_BYTES) -> tuple[int, dict]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Authorization": self._token.header(), "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self._base + path, data=data, method=method, headers=headers)
        try:
            resp = self._opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            resp = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RunnerClientError(f"cannot reach the Runner: {type(exc).__name__}") from None
        with resp:
            status = resp.status if hasattr(resp, "status") else resp.code
            raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise RunnerProtocolError("Runner response too large")
        if status == 401:
            raise RunnerAuthError("Runner rejected the token (401)")
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RunnerProtocolError(f"Runner sent a non-JSON response (HTTP {status})") from None
        if not isinstance(payload, dict):
            raise RunnerProtocolError(f"Runner sent an unexpected JSON shape (HTTP {status})")
        return status, payload

    def health(self) -> dict:
        status, payload = self._call("GET", "/v1/health", None, HEALTH_TIMEOUT)
        if status != 200 or payload.get("status") != "ok":
            raise RunnerClientError(f"Runner not healthy (HTTP {status}): {payload}")
        return payload

    def run(self, request: NmapConnectScanRequest | HttpProbeRequest) -> RunOutcome:
        # Defence in depth (Stage 5): no execution request leaves this
        # machine while the local kill switch blocks - whatever the caller.
        from avra.control.killswitch import KillSwitch

        (self._killswitch if self._killswitch is not None else KillSwitch()).check(
            "runner_client.run", request_id=str(request.request_id))
        body = request.model_dump(mode="json")
        timeout = request.timeout_seconds + RUN_TIMEOUT_MARGIN
        status, payload = self._call("POST", "/v1/tools/run", body, timeout)
        try:
            if status == 200:
                result = ToolRunResult.model_validate(payload)
            elif status in (400, 403, 409, 429, 500, 503) and "stage" in payload:
                return RunOutcome(status, rejection=RunnerRejection.model_validate(payload))
            else:
                raise RunnerClientError(f"unexpected Runner answer (HTTP {status}): {payload}")
        except ValidationError as exc:
            raise RunnerClientError(
                f"Runner response failed validation (HTTP {status}): {exc.error_count()} error(s)"
            ) from None
        if result.request_id != request.request_id:
            raise RunnerClientError("Runner answered a different request_id")
        verified = None
        if result.raw_output is not None and result.output_sha256 and not result.output_truncated:
            digest = hashlib.sha256(result.raw_output.encode("utf-8")).hexdigest()
            verified = digest == result.output_sha256
        return RunOutcome(status, result=result, hash_verified=verified)

    # -- stop-only calls (M8.7 Stage 5) -------------------------------------------------

    def _stop_call(self, path: str, body: dict, timeout: float) -> tuple[int | None, dict, str]:
        if path not in STOP_ONLY_PATHS:  # never anything but the two stop endpoints
            raise ValueError("not a stop-only endpoint")
        try:
            status, payload = self._call("POST", path, body, timeout,
                                         max_bytes=MAX_STOP_RESPONSE_BYTES)
        except RunnerAuthError:
            return 401, {}, "auth_failed"
        except RunnerProtocolError:
            return None, {}, "invalid_response"
        except RunnerClientError:
            return None, {}, "transport"
        return status, payload, ""

    def cancel(self, request_id: UUID, session_id: UUID, reason: CancelReason,
               *, timeout: float = CANCEL_TIMEOUT) -> StopCallResult:
        """Ask the Runner to cancel ONE job. Never raises for Runner/transport
        problems; never retries. Read ``cancel_confirmed`` - delivery alone
        proves nothing."""
        body = {"request_id": str(request_id), "session_id": str(session_id),
                "reason": CancelReason(reason).value}
        status, payload, err = self._stop_call(CANCEL_PATH, body, timeout)
        if err:
            return StopCallResult(err, status)
        if status in (404, 405):
            return StopCallResult("unsupported", status, detail="Runner has no cancel endpoint")
        if status in (200, 503) and "outcome" in payload:
            try:
                res = CancelResponse.model_validate(payload)
            except ValidationError:
                return StopCallResult("invalid_response", status)
            if res.request_id != request_id or res.session_id != session_id:
                return StopCallResult("invalid_response", status,
                                      detail="Runner answered for different ids")
            if (status == 503) != (res.outcome is CancelOutcome.UNAVAILABLE):
                return StopCallResult("invalid_response", status)
            return StopCallResult("ok", status, cancel=res)
        return StopCallResult(_category(status, payload), status)

    def emergency_stop(self, reason: EmergencyReason,
                       *, timeout: float = EMERGENCY_STOP_TIMEOUT) -> StopCallResult:
        """Ask the Runner to engage its persistent emergency latch. Never
        raises for Runner/transport problems; never retries. Read
        ``emergency_confirmed``."""
        body = {"reason": EmergencyReason(reason).value}
        status, payload, err = self._stop_call(EMERGENCY_STOP_PATH, body, timeout)
        if err:
            return StopCallResult(err, status)
        if status in (404, 405):
            return StopCallResult("unsupported", status,
                                  detail="Runner has no emergency-stop endpoint")
        if status in (200, 503) and "outcome" in payload:
            try:
                res = EmergencyStopResponse.model_validate(payload)
            except ValidationError:
                return StopCallResult("invalid_response", status)
            complete = res.durable and res.audit_recorded
            if (status == 200) != complete:  # the Runner's own contract (Stage 4)
                return StopCallResult("invalid_response", status)
            return StopCallResult("ok", status, emergency=res)
        return StopCallResult(_category(status, payload), status)


def _category(status: int | None, payload: dict) -> str:
    if status == 400:
        return "rejected"
    if status == 429:
        return "rate_limited"
    if status in (500, 503):
        return "unavailable"
    return "invalid_response"
