"""Executor + child program for ``http_probe`` (ADR 0007, M8.1).

Two halves:

* ``build_args`` / ``scope_targets`` — used by the Runner registry: only
  ``host``, ``port`` and ``timeout_seconds`` from the validated request
  reach the argv; everything else is fixed here.
* ``main`` — the child program the Runner starts (console script
  ``avra-http-probe``) inside its sandbox. It sends exactly one fixed
  ``GET / HTTP/1.0`` over a raw IPv4 socket (no DNS, no proxy, no
  redirects, no retries), reads at most ``MAX_RESPONSE_BYTES`` within the
  time budget, and prints one pure-ASCII JSON envelope with the exact
  request and response bytes in base64. It never interprets the response.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import sys
import time
from collections.abc import Callable, Sequence

from avra.runner.schemas import (
    HTTP_PROBE_MAX_TIMEOUT_SECONDS,
    HttpGetPathRequest,
    HttpProbeRequest,
    validate_http_path,
    validate_ipv4_target,
)

ENVELOPE_FORMAT = "avra-http-probe/1"
GET_PATH_FORMAT = "avra-http-get-path/1"  # M10.5: same envelope + the requested path"
MAX_RESPONSE_BYTES = 262_144
USER_AGENT = "AVRA-http-probe/1 (owner-authorized lab)"
_RECV_CHUNK = 8_192
EXIT_OK = 0
EXIT_USAGE = 2


def scope_targets(request: HttpProbeRequest | HttpGetPathRequest
                  ) -> tuple[tuple[str, int], ...]:
    """The one (host, port) this request touches — it must be in scope."""
    return ((request.host, request.port),)


def build_args(request: HttpProbeRequest) -> tuple[str, ...]:
    """The child's arguments (without the executable). Nothing else is
    configurable: method, path, headers and limits are fixed in code."""
    return ("--host", request.host, "--port", str(request.port),
            "--timeout", str(request.timeout_seconds))


def scope_path(request: HttpGetPathRequest) -> str:
    return request.path


def build_get_path_args(request: HttpGetPathRequest) -> tuple[str, ...]:
    """M10.5: the same fixed child, plus a validated path. Nothing else is configurable."""
    return (*build_args(request), "--path", validate_http_path(request.path))


def request_bytes(host: str, port: int, path: str = "/") -> bytes:
    """The ONLY request shape this tool ever sends. HTTP/1.0 so the server does
    not use chunked encoding; Host is the IP literal, never a name. The path is
    ``/`` for http_probe, or a validated same-origin path for http_get_path."""
    validate_http_path(path)
    return (f"GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii")


SocketFactory = Callable[[], socket.socket]


def _default_socket() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def probe(host: str, port: int, timeout_seconds: float, *,
          socket_factory: SocketFactory = _default_socket,
          clock: Callable[[], float] = time.monotonic, path: str | None = None) -> dict:
    """One connection, one fixed request, bounded read. Returns the
    envelope dict (never raises for network conditions)."""
    validate_ipv4_target(host)  # defense in depth: the child re-checks
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    req = request_bytes(host, port, path or "/")
    deadline = clock() + timeout_seconds
    received = bytearray()
    outcome, error, truncated, complete = "response_received", "", False, False
    started = clock()
    sock = socket_factory()
    try:
        sock.settimeout(max(0.001, deadline - clock()))
        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            outcome, error = "connection_refused", "ConnectionRefusedError"
        except TimeoutError:  # socket.timeout is TimeoutError (3.10+)
            outcome, error = "connect_timeout", "TimeoutError"
        except OSError as exc:
            outcome, error = "network_error", type(exc).__name__
        if not error:
            try:
                sock.settimeout(max(0.001, deadline - clock()))
                sock.sendall(req)
                while True:
                    remaining = deadline - clock()
                    if remaining <= 0:
                        raise TimeoutError
                    sock.settimeout(remaining)
                    chunk = sock.recv(min(_RECV_CHUNK, MAX_RESPONSE_BYTES + 1 - len(received)))
                    if not chunk:
                        complete = True
                        break
                    received.extend(chunk)
                    if len(received) > MAX_RESPONSE_BYTES:
                        del received[MAX_RESPONSE_BYTES:]
                        truncated = True
                        break
            except TimeoutError:
                outcome, error = "read_timeout", "TimeoutError"
            except (ConnectionResetError, BrokenPipeError):
                outcome, error = "connection_reset", "ConnectionResetError"
            except OSError as exc:
                outcome, error = "network_error", type(exc).__name__
            if outcome == "response_received" and not received:
                outcome = "connection_reset"  # closed without a single byte
                error = error or "EmptyResponse"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    resp = bytes(received)
    return {
        **({"format": ENVELOPE_FORMAT} if path is None
           else {"format": GET_PATH_FORMAT, "path": path}),
        "host": host, "port": port,
        "outcome": outcome, "error": error,
        "request_b64": base64.b64encode(req).decode("ascii"),
        "request_sha256": hashlib.sha256(req).hexdigest(),
        "request_bytes": len(req),
        "response_b64": base64.b64encode(resp).decode("ascii"),
        "response_sha256": hashlib.sha256(resp).hexdigest(),
        "response_bytes": len(resp),
        "truncated": truncated,
        "complete": complete and not truncated,
        "elapsed_ms": round((clock() - started) * 1000),
    }


def encode_envelope(envelope: dict) -> str:
    """Canonical, pure-ASCII JSON (sorted keys, no spaces) + trailing LF."""
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True) + "\n"


def _parse_argv(argv: Sequence[str]) -> tuple[str, int, int, str | None]:
    path = None
    if len(argv) == 8 and argv[6] == "--path":  # M10.5: http_get_path
        path = validate_http_path(argv[7])
        argv = argv[:6]
    if len(argv) != 6 or argv[0::2] != ["--host", "--port", "--timeout"]:
        raise ValueError("usage: avra-http-probe --host <ipv4> --port <n> --timeout <s> "
                         "[--path </path>]")
    host = validate_ipv4_target(argv[1])
    if not (argv[3].isascii() and argv[3].isdigit() and argv[5].isascii()
            and argv[5].isdigit()):
        raise ValueError("port and timeout must be plain decimal integers")
    port, timeout = int(argv[3]), int(argv[5])
    if not 1 <= port <= 65535 or not 1 <= timeout <= HTTP_PROBE_MAX_TIMEOUT_SECONDS:
        raise ValueError("port or timeout out of range")
    return host, port, timeout, path


def main(argv: Sequence[str] | None = None, *, out=None) -> int:
    out = sys.stdout if out is None else out
    try:
        host, port, timeout, path = _parse_argv(list(sys.argv[1:] if argv is None else argv))
    except ValueError as exc:
        print(str(exc)[:200], file=sys.stderr)
        return EXIT_USAGE
    out.write(encode_envelope(probe(host, port, timeout, path=path)))
    out.flush()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    raise SystemExit(main())
