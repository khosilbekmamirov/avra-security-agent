"""Runner server entrypoint (ADR 0003, M3.3).

``python -m avra.runner`` → ``main()``:

1. Load and validate ``RunnerConfig`` (fail closed → exit 2).
2. Take ``AuditOwnerLock`` for the audit log (another Runner owns it →
   exit 3) and re-verify the hash chain *under* the lock.
3. Build executor, Runner core and HTTP app; record ``runner_started``.
4. Serve with hardened uvicorn settings on the configured address only.
5. On shutdown (signal or ``stop()``): record ``runner_stopped``, release
   the lock — always, even if startup or binding failed (exit 4).

M8.7 Stage 4 (ADR 0012): the persistent emergency latch
(``<audit dir>/emergency-stop.json``) is read at start and on every run. A
Runner whose latch is not READY still starts (health says
``emergency_stop_clear: false``) but executes nothing. The latch is reset
ONLY locally, with the Runner stopped:
``python -m avra.runner --reset-emergency-stop`` (interactive; exit 5 if
refused). There is no HTTP reset.

Uvicorn settings and why:

- ``proxy_headers=False`` — never trust ``X-Forwarded-*``; the audited
  client address is the real peer.
- ``server_header=False`` — no version banner.
- ``access_log=False`` — uvicorn's access log prints the full request
  line incl. query string; a misused ``?token=...`` would end up in logs.
  Rejections are audited by the app instead.
- ``limit_concurrency=4``, ``backlog=16`` — small, bounded.
- ``timeout_keep_alive=5`` — idle connections closed quickly.
- ``h11_max_incomplete_event_size=16384`` — header size cap.
- ``http="h11"``, ``ws="none"``, ``lifespan="off"`` — pure-Python HTTP/1.1
  parser, no websockets, nothing else listening.
- ``timeout_graceful_shutdown=10``.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import signal
import sys
import threading
from collections.abc import Mapping

import uvicorn

from avra.runner.audit_owner import AuditOwnerLock, AuditOwnershipError
from avra.runner.config import RunnerConfig, RunnerConfigError, load_runner_config
from avra.runner.core import Runner
from avra.runner.emergency import LatchError, LatchState, RunnerLatch
from avra.runner.execution import SubprocessRunner
from avra.runner.http_app import create_app, default_health_checks
from avra.runner.registry import registered_tools
from avra.storage.audit import AuditLog

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_AUDIT_OWNED = 3
EXIT_START_FAILED = 4
EXIT_RESET_REFUSED = 5
_STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM)

UVICORN_SETTINGS = {
    "proxy_headers": False,
    "server_header": False,
    "date_header": True,
    "access_log": False,
    "limit_concurrency": 4,
    "backlog": 16,
    "timeout_keep_alive": 5,
    "timeout_graceful_shutdown": 10,
    "h11_max_incomplete_event_size": 16 * 1024,
    "http": "h11",
    "ws": "none",
    "lifespan": "off",
    "loop": "asyncio",
}


def build_uvicorn_config(app, cfg: RunnerConfig, *, log_level: str = "info") -> uvicorn.Config:
    # Defense in depth: config validation already forbids wildcards.
    if ipaddress.IPv4Address(cfg.bind_host).is_unspecified:
        raise RunnerConfigError("refusing to bind a wildcard address")
    return uvicorn.Config(
        app, host=cfg.bind_host, port=cfg.port, log_level=log_level, **UVICORN_SETTINGS
    )


class RunnerServer:
    """One Runner process's lifetime: lock → serve → release."""

    def __init__(self, cfg: RunnerConfig, *, log_level: str = "info") -> None:
        self._cfg = cfg
        self._log_level = log_level
        self._server: uvicorn.Server | None = None
        self._runner: Runner | None = None

    @property
    def started(self) -> bool:
        return bool(self._server and self._server.started)

    def stop(self) -> None:
        """Ask uvicorn to exit and cancel the running job right away (review
        R3), in a helper thread so a signal handler never blocks."""
        if self._server is not None:
            self._server.should_exit = True
        if self._runner is not None:
            threading.Thread(target=self._runner.cancel_active, args=("runner_shutdown",),
                             kwargs={"wait": False}, daemon=True).start()

    @contextlib.contextmanager
    def _stop_signals(self):
        """Make SIGTERM/SIGINT a graceful stop that returns to ``run()``.

        uvicorn installs its own handlers while serving, restores the
        previous ones afterwards and then RE-RAISES the captured signal
        (``signal.raise_signal``). With the default handlers restored that
        killed the process before ``run()``'s ``finally`` could write
        ``runner_stopped`` — seen live on Kali (M4.5): ``systemctl stop``
        left no stop record. With these handlers in place the re-raised
        signal only asks for a stop, so shutdown is recorded and the audit
        lock is released normally.
        """
        if threading.current_thread() is not threading.main_thread():
            yield
            return

        def request_stop(signum, frame):
            self.stop()

        previous = {sig: signal.signal(sig, request_stop) for sig in _STOP_SIGNALS}
        try:
            yield
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)

    def run(self) -> int:
        cfg = self._cfg
        owner = AuditOwnerLock(cfg.audit_path)
        try:
            owner.acquire()
        except AuditOwnershipError as exc:
            _err(f"refusing to start: {exc}")
            return EXIT_AUDIT_OWNED

        audit = AuditLog(cfg.audit_path)
        started_recorded = False
        try:
            if not audit.verify():  # re-check now that nobody else can write
                _err("refusing to start: audit log fails hash-chain verification")
                return EXIT_START_FAILED

            latch = RunnerLatch.beside(audit)
            runner = Runner(cfg.policy, SubprocessRunner(cfg.executables), audit, latch=latch)
            self._runner = runner
            app = create_app(
                runner=runner,
                token=cfg.token,
                audit=audit,
                health_checks=default_health_checks(
                    cfg.policy, cfg.audit_path, cfg.executables, runner
                ),
            )
            self._server = uvicorn.Server(
                build_uvicorn_config(app, cfg, log_level=self._log_level)
            )
            audit.record(
                "runner_started",
                {
                    "bind_host": cfg.bind_host,
                    "port": cfg.port,
                    "pid": os.getpid(),
                    "tools": list(registered_tools()),
                    "emergency_latch": latch.load().state.value,
                },
            )
            started_recorded = True
            try:
                with self._stop_signals():
                    self._server.run()
            except SystemExit:
                pass  # uvicorn may exit on bind failure; handled below
            return EXIT_OK if self._server.started else EXIT_START_FAILED
        except Exception as exc:
            _err(f"Runner failed: {type(exc).__name__}")
            return EXIT_START_FAILED
        finally:
            if self._runner is not None:
                # Never record runner_stopped while a job still runs: cancel it
                # and wait (bounded) for its execution_finished (review R3).
                try:
                    self._runner.cancel_active("runner_shutdown", wait=True)
                except Exception:  # noqa: BLE001 - shutdown continues; systemd is the backstop
                    _err("could not cancel the active job during shutdown")
            if started_recorded:
                try:
                    audit.record(
                        "runner_stopped",
                        {"pid": os.getpid(), "served": bool(self.started)},
                    )
                except Exception:
                    pass
            owner.release()


def _err(message: str) -> None:
    print(f"avra-runner: {message}", file=sys.stderr)


def check(cfg: RunnerConfig) -> int:
    """Validate everything a real start would, without binding a port or
    writing to the audit log. Also reports if another Runner owns the log."""
    owner = AuditOwnerLock(cfg.audit_path)
    try:
        owner.acquire()
    except AuditOwnershipError:
        _err("check: audit log is owned by a running Runner")
        return EXIT_AUDIT_OWNED
    try:
        audit = AuditLog(cfg.audit_path)
        if not audit.verify():
            _err("check: audit log fails hash-chain verification")
            return EXIT_START_FAILED
        latch = RunnerLatch.beside(audit).load()
    finally:
        owner.release()
    print(
        "avra-runner: configuration OK — "
        f"bind {cfg.bind_host}:{cfg.port}, tools {', '.join(registered_tools())}, "
        f"executables {', '.join(sorted(cfg.executables))}; "
        f"emergency latch {latch.state.value} ({latch.detail})"
    )
    return EXIT_OK


def reset_emergency_stop(cfg: RunnerConfig, *, interactive: bool | None = None,
                         ask=input) -> int:
    """LOCAL operator recovery only (never reachable over HTTP). Needs the
    Runner stopped (it takes the audit owner lock), a valid STOPPED latch, a
    real terminal, a reason and the word RESET. Restarts nothing."""
    if interactive is None:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
    owner = AuditOwnerLock(cfg.audit_path)
    try:
        owner.acquire()
    except AuditOwnershipError:
        _err("reset refused: a Runner is running - stop it first (systemctl stop avra-runner)")
        return EXIT_AUDIT_OWNED
    try:
        audit = AuditLog(cfg.audit_path)
        if not audit.verify():
            _err("reset refused: audit log fails hash-chain verification")
            return EXIT_RESET_REFUSED
        latch = RunnerLatch.beside(audit)
        st = latch.load()
        print(f"avra-runner: emergency latch {st.state.value} - {st.detail}")
        if st.state is not LatchState.STOPPED:
            _err("reset refused: only a valid STOPPED latch can be reset; a CORRUPT or "
                 "UNREADABLE latch must be investigated by hand (it is kept as evidence)")
            return EXIT_RESET_REFUSED
        if not interactive:
            _err("reset refused: needs an interactive terminal")
            return EXIT_RESET_REFUSED
        print("Resetting does NOT restart any job and does not touch the Windows-side kill "
              "switch. New work must be started explicitly from Windows.")
        reason = ask("Reason for the reset: ").strip()
        typed = ask("Type RESET to clear the emergency stop: ").strip()
        if not reason or typed != "RESET":
            _err("reset cancelled - latch still STOPPED")
            return EXIT_RESET_REFUSED
        try:
            after = latch.reset(reason, by="local_operator")
        except (LatchError, ValueError) as exc:
            _err(str(exc))
            return EXIT_RESET_REFUSED
        print(f"avra-runner: emergency latch {after.state.value}. Nothing was restarted.")
        return EXIT_OK
    finally:
        owner.release()


def main(env: Mapping[str, str] | None = None, argv: list[str] | None = None) -> int:
    """``python -m avra.runner [--check | --reset-emergency-stop]``. Every
    setting comes from the Runner's own environment (config.py)."""
    args = [] if argv is None else list(argv)
    if args not in ([], ["--check"], ["--reset-emergency-stop"]):
        _err("usage: python -m avra.runner [--check | --reset-emergency-stop]")
        return EXIT_CONFIG
    try:
        cfg = load_runner_config(env)
    except RunnerConfigError as exc:
        _err(f"configuration rejected: {exc}")
        return EXIT_CONFIG
    if args == ["--check"]:
        return check(cfg)
    if args == ["--reset-emergency-stop"]:
        return reset_emergency_stop(cfg)
    return RunnerServer(cfg).run()
