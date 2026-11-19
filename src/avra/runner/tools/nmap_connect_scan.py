"""Executor for ``nmap_connect_scan``: TCP connect scan, fixed flags.

Only ``host``, ``ports`` and ``timeout_seconds`` from the validated
request reach the argument list; every flag is chosen here.
"""

from __future__ import annotations

from avra.runner.schemas import NmapConnectScanRequest


def scope_targets(request: NmapConnectScanRequest) -> tuple[tuple[str, int], ...]:
    """Every (host, port) this request would touch — all must be in scope."""
    return tuple((request.host, port) for port in request.ports)


def build_args(request: NmapConnectScanRequest) -> tuple[str, ...]:
    """Return nmap's arguments (without the executable itself)."""
    return (
        # Never use raw sockets, even if the binary has file capabilities
        # (Kali's /usr/lib/nmap/nmap ships with cap_net_raw/cap_net_admin,
        # and its /usr/bin/nmap wrapper adds --privileged for non-root).
        "--unprivileged",
        "-sT",  # TCP connect scan: no raw sockets, no root needed
        "-Pn",  # don't ping first; target is already known from scope
        "-n",  # never do DNS resolution
        "--max-retries",
        "1",
        "--host-timeout",
        f"{request.timeout_seconds}s",
        "-p",
        ",".join(str(port) for port in request.ports),
        "-oX",
        "-",  # XML to stdout, parsed later by a safe parser
        request.host,
    )
