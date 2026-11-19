"""Runner HTTP layer (ADR 0003 decisions 2, 3 and 7; M3.2).

A thin Starlette app in front of ``Runner.try_handle()``. It authorizes
nothing itself — scope, tools and tiers are decided only by the Runner
core. Its job is to keep untrusted HTTP input bounded and authenticated:

1. ``_BearerAuth`` (outermost, pure ASGI) authenticates *every* request,
   before routing and before any body is read. No token → 401 for every
   path, including unknown ones. Exactly one ``Authorization`` header,
   ``Bearer <token>``, length-capped before hashing.
2. ``POST /v1/tools/run``: JSON content type only; ``Content-Length``
   validated; body streamed with a byte cap and a read deadline; parsed
   JSON goes to ``Runner.try_handle`` in a worker thread; busy → 429.
3. ``GET /v1/health``: authenticated readiness — booleans only, no paths
   (incl. ``emergency_stop_clear`` since M8.7).
4. M8.7 Stage 4 (ADR 0012): ``POST /v1/tools/cancel`` (one job, by
   request_id AND session_id) and ``POST /v1/emergency-stop`` (persistent
   latch, then cancel the active job). Same auth, content-type, size and
   read-deadline rules as a run; at most ``STOP_RATE_MAX`` such requests
   per ``STOP_RATE_WINDOW_SECONDS`` per endpoint (429 beyond; separate
   buckets, so cancel traffic cannot block an emergency stop). There is deliberately NO
   reset endpoint: the latch is reset only locally on Kali.
5. While a run executes, its own connection is watched: if the client
   disconnects (uvicorn delivers ``http.disconnect`` only on connection
   loss or after the response was sent), the job THAT request registered
   (opaque per-connection owner, never payload ids) is cancelled. The watcher
   stops as soon as the result exists, so a completed response is never
   treated as a disconnect.

Every error response is a small generic JSON body: no tracebacks, paths
or secrets. HTTP-level rejections the Runner never sees (auth failure,
oversize, bad content type, malformed JSON, busy, read timeout) are
written to the same audit log as ``http_rejected``; auth failures are
throttled so they can't flood it.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from pathlib import Path

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from avra.runner.config import MAX_TOKEN_CHARS, BearerToken
from avra.runner.core import AuditSink, Runner
from avra.runner.policy import RunnerPolicy
from avra.runner.registry import registered_tools
from avra.runner.schemas import CancelOutcome, RejectionStage, RunnerRejection

MAX_BODY_BYTES = 16 * 1024
# h11's incomplete-event cap only bites when headers arrive in pieces;
# headers sent in one burst (up to ~64 KiB) pass the parser, so the app
# enforces its own total-header cap before anything else.
MAX_HEADER_BYTES = 16 * 1024
BODY_READ_TIMEOUT_SECONDS = 5.0
AUTH_AUDIT_INTERVAL_SECONDS = 10.0
_MAX_AUTH_HEADER = len("Bearer ") + MAX_TOKEN_CHARS

_NO_STORE = {"Cache-Control": "no-store"}
_CLOSE = {"Cache-Control": "no-store", "Connection": "close"}

_REJECTION_STATUS = {
    RejectionStage.UNKNOWN_TOOL: 400,
    RejectionStage.INVALID_REQUEST: 400,
    RejectionStage.SCOPE: 403,
    RejectionStage.AUDIT_UNAVAILABLE: 503,
    RejectionStage.INTERNAL_ERROR: 500,
    RejectionStage.EMERGENCY_STOP: 503,
    RejectionStage.CANCELLED: 409,
}
STOP_RATE_MAX = 30
STOP_RATE_WINDOW_SECONDS = 60.0

HealthChecks = Callable[[], Mapping[str, bool]]


def _error(status: int, code: str, *, close: bool = False, extra=None) -> JSONResponse:
    headers = dict(_CLOSE if close else _NO_STORE)
    if extra:
        headers.update(extra)
    return JSONResponse({"error": code}, status_code=status, headers=headers)


def _client_host(scope: Scope) -> str | None:
    client = scope.get("client")
    return client[0] if client else None


class _HttpAudit:
    """Writes ``http_rejected`` events; auth failures are throttled."""

    def __init__(self, audit: AuditSink, clock: Callable[[], float] = time.monotonic):
        self._audit = audit
        self._clock = clock
        self._lock = threading.Lock()
        self._last_auth_record: float | None = None
        self._suppressed = 0

    def rejected(self, reason: str, scope: Scope) -> None:
        try:
            self._audit.record(
                "http_rejected", {"reason": reason, "client": _client_host(scope)}
            )
        except Exception:
            pass  # the request is being rejected anyway

    def auth_failed(self, scope: Scope) -> None:
        with self._lock:
            now = self._clock()
            if (
                self._last_auth_record is not None
                and now - self._last_auth_record < AUTH_AUDIT_INTERVAL_SECONDS
            ):
                self._suppressed += 1
                return
            suppressed, self._suppressed = self._suppressed, 0
            self._last_auth_record = now
        try:
            self._audit.record(
                "http_rejected",
                {
                    "reason": "auth_failed",
                    "client": _client_host(scope),
                    "suppressed_since_last": suppressed,
                },
            )
        except Exception:
            pass


def _credential_from(scope: Scope) -> str | None:
    """Return the bearer credential, or None if the header is unacceptable."""
    values = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
    if len(values) != 1:
        return None
    raw = values[0]
    if len(raw) > _MAX_AUTH_HEADER:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    scheme, sep, credential = text.partition(" ")
    if not sep or scheme.lower() != "bearer" or not credential:
        return None
    if not all(33 <= ord(c) <= 126 for c in credential):
        return None  # includes extra spaces
    return credential


class _BearerAuth:
    def __init__(self, app: ASGIApp, token: BearerToken, http_audit: _HttpAudit):
        self._app = app
        self._token = token
        self._audit = http_audit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "lifespan":
                await self._app(scope, receive, send)
            return  # websockets etc. are never served
        header_bytes = sum(len(k) + len(v) for k, v in scope.get("headers", []))
        if header_bytes > MAX_HEADER_BYTES:
            self._audit.rejected("headers_too_large", scope)
            await _error(431, "headers_too_large", close=True)(scope, receive, send)
            return
        credential = _credential_from(scope)
        if credential is None or not self._token.matches(credential):
            self._audit.auth_failed(scope)
            response = _error(
                401, "unauthorized", close=True, extra={"WWW-Authenticate": "Bearer"}
            )
            await response(scope, receive, send)
            return
        await self._app(scope, receive, send)


class _BodyError(Exception):
    def __init__(self, status: int, code: str, close: bool = False):
        self.status, self.code, self.close = status, code, close


async def _read_bounded_body(request: Request) -> bytes:
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1:
        raise _BodyError(400, "bad_content_length")
    if lengths:
        value = lengths[0]
        if not value.isascii() or not value.isdigit():
            raise _BodyError(400, "bad_content_length")
        # Compare digit counts first: int() refuses > 4300 digits (ValueError,
        # which surfaced as a generic 500). Leading zeros don't change the value.
        digits = value.lstrip("0") or "0"
        if len(digits) > len(str(MAX_BODY_BYTES)) or int(digits) > MAX_BODY_BYTES:
            raise _BodyError(413, "too_large", close=True)

    async def collect() -> bytes:
        chunks, total = [], 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                raise _BodyError(413, "too_large", close=True)
            chunks.append(chunk)
        return b"".join(chunks)

    try:
        return await asyncio.wait_for(collect(), timeout=BODY_READ_TIMEOUT_SECONDS)
    except TimeoutError:
        raise _BodyError(408, "body_timeout", close=True) from None


def _is_json(request: Request) -> bool:
    values = request.headers.getlist("content-type")
    if len(values) != 1:
        return False
    return values[0].split(";", 1)[0].strip().lower() == "application/json"


class _StopRateLimit:
    """Sliding window for cancel/emergency-stop requests (bounded memory)."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._times: deque[float] = deque(maxlen=STOP_RATE_MAX)

    def allow(self) -> bool:
        with self._lock:
            now = self._clock()
            if len(self._times) == STOP_RATE_MAX and \
                    now - self._times[0] < STOP_RATE_WINDOW_SECONDS:
                return False
            self._times.append(now)
            return True


async def _wait_for_disconnect(request: Request) -> None:
    """Returns only when the server reports this connection as gone. Any
    other message (e.g. a pipelined request's bytes) is ignored."""
    while True:
        message = await request.receive()
        if message.get("type") == "http.disconnect":
            return


def default_health_checks(
    policy: RunnerPolicy, audit_path: Path, executables: Mapping[str, str],
    runner: Runner | None = None,
) -> HealthChecks:
    """Readiness checks used by ``/v1/health``. Booleans only."""

    def checks() -> dict[str, bool]:
        audit_ok = os.access(audit_path.parent, os.W_OK) and (
            not audit_path.exists() or os.access(audit_path, os.W_OK)
        )
        exec_ok = all(
            os.path.isfile(p) and os.access(p, os.X_OK) for p in executables.values()
        )
        out = {"scope": not policy.is_expired, "audit": audit_ok, "executables": exec_ok}
        if runner is not None:
            out["emergency_stop_clear"] = runner.emergency_blocked() is None
        return out

    return checks


def create_app(
    *,
    runner: Runner,
    token: BearerToken,
    audit: AuditSink,
    health_checks: HealthChecks,
    clock: Callable[[], float] = time.monotonic,
) -> ASGIApp:
    http_audit = _HttpAudit(audit, clock)

    async def health(request: Request) -> JSONResponse:
        try:
            results = {k: bool(v) for k, v in health_checks().items()}
        except Exception:
            results = {"checks": False}
        if all(results.values()):
            return JSONResponse(
                {"status": "ok", "tools": list(registered_tools())}, headers=_NO_STORE
            )
        return JSONResponse(
            {"status": "unavailable", "checks": results},
            status_code=503,
            headers=_NO_STORE,
        )

    # Separate buckets (review R2): cancel traffic can never use up the
    # emergency stop's allowance.
    cancel_limit = _StopRateLimit(clock)
    stop_limit = _StopRateLimit(clock)

    async def _json_body(request: Request):
        """(payload, None) or (None, error response). Same rules for every POST."""
        if not _is_json(request):
            http_audit.rejected("bad_content_type", request.scope)
            return None, _error(415, "unsupported_media_type")
        try:
            body = await _read_bounded_body(request)
        except _BodyError as exc:
            http_audit.rejected(exc.code, request.scope)
            return None, _error(exc.status, exc.code, close=exc.close)
        try:
            return json.loads(body), None
        except (ValueError, RecursionError):
            http_audit.rejected("malformed_json", request.scope)
            return None, _error(400, "malformed_json")

    async def run_tool(request: Request) -> JSONResponse:
        payload, err = await _json_body(request)
        if err is not None:
            return err
        # Opaque per-connection identity (review R1): a disconnect cancels only
        # the job THIS request registered, never one named by payload ids.
        owner = object()
        job = asyncio.ensure_future(run_in_threadpool(runner.try_handle, payload, owner=owner))
        watcher = asyncio.ensure_future(_wait_for_disconnect(request))
        try:
            done, _pending = await asyncio.wait({job, watcher},
                                                return_when=asyncio.FIRST_COMPLETED)
            if watcher in done and not job.done():
                # This client is gone while its own job runs: stop that job only.
                await run_in_threadpool(runner.cancel_owned, owner)
            result = await job
        finally:
            watcher.cancel()
        if result is None:
            http_audit.rejected("busy", request.scope)
            return _error(429, "busy", extra={"Retry-After": "5"})
        status = (
            _REJECTION_STATUS[result.stage] if isinstance(result, RunnerRejection) else 200
        )
        return JSONResponse(
            result.model_dump(mode="json"), status_code=status, headers=_NO_STORE
        )

    async def cancel_tool(request: Request) -> JSONResponse:
        if not cancel_limit.allow():
            http_audit.rejected("stop_rate_limited", request.scope)
            return _error(429, "rate_limited", extra={"Retry-After": "10"})
        payload, err = await _json_body(request)
        if err is not None:
            return err
        result = await run_in_threadpool(runner.cancel, payload)
        if isinstance(result, RunnerRejection):
            return JSONResponse(result.model_dump(mode="json"),
                                status_code=_REJECTION_STATUS[result.stage], headers=_NO_STORE)
        status = 503 if result.outcome is CancelOutcome.UNAVAILABLE else 200
        return JSONResponse(result.model_dump(mode="json"), status_code=status,
                            headers=_NO_STORE)

    async def emergency_stop(request: Request) -> JSONResponse:
        if not stop_limit.allow():
            http_audit.rejected("stop_rate_limited", request.scope)
            return _error(429, "rate_limited", extra={"Retry-After": "10"})
        payload, err = await _json_body(request)
        if err is not None:
            return err
        result = await run_in_threadpool(runner.emergency_stop, payload)
        if isinstance(result, RunnerRejection):
            return JSONResponse(result.model_dump(mode="json"),
                                status_code=_REJECTION_STATUS[result.stage], headers=_NO_STORE)
        complete = result.durable and result.audit_recorded
        return JSONResponse(result.model_dump(mode="json"), status_code=200 if complete else 503,
                            headers=_NO_STORE)

    async def not_found(request: Request, exc: Exception) -> JSONResponse:
        if isinstance(exc, HTTPException) and exc.status_code == 405:
            return _error(405, "method_not_allowed")
        return _error(404, "not_found")

    async def internal(request: Request, exc: Exception) -> JSONResponse:
        return _error(500, "internal_error")

    app = Starlette(
        debug=False,
        routes=[
            Route("/v1/health", health, methods=["GET"]),
            Route("/v1/tools/run", run_tool, methods=["POST"]),
            Route("/v1/tools/cancel", cancel_tool, methods=["POST"]),
            Route("/v1/emergency-stop", emergency_stop, methods=["POST"]),
        ],
        exception_handlers={404: not_found, 405: not_found, Exception: internal},
    )
    return _BearerAuth(app, token, http_audit)
