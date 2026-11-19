"""Controlled subprocess execution for the Tool Runner (ADR 0003, M2.2b
Part 1).

``SubprocessRunner`` is the only place in AVRA that starts a tool process.
It is deliberately low-level and is NOT an authorization point: it must
only ever be called by the Runner core *after* ``RunnerPolicy`` has
authorized a request. It is never exposed to requests directly.

Guarantees:

- ``shell=False`` always; argv is a list, never a command string.
- argv[0] is a *logical* name (e.g. ``"nmap"``) mapped to a fixed,
  trusted absolute path given at construction — never a path from a
  request, never a PATH lookup.
- Minimal environment (nothing inherited from the Runner's own
  environment, so tokens/secrets don't leak), stdin closed, a fresh
  temporary working directory per run, removed afterwards.
- Wall-clock timeout. On timeout or output-limit violation the process is
  terminated (SIGTERM, then SIGKILL after a grace period) and reaped.
- On Linux/POSIX the child runs in its own process group/session and the
  whole group — including descendants — is signalled.
- stdout and stderr are read concurrently by two threads (no pipe
  deadlock), each capped; exceeding a cap is a failure.
- Cancellation (M8.7 Stage 4, ADR 0012): an optional ``threading.Event``
  given by the Runner core. Set before start -> the process is never
  started; set while running -> the SAME termination as a timeout (SIGTERM
  to the job's own process group, SIGKILL after the grace period, reap,
  group sweep). Outcome ``CANCELLED``. Within one poll iteration the order
  is fixed: cancel, then output limit, then timeout. Only the process (and
  group) this call created is ever signalled - never a PID from a request.

Windows (development host only — the Runner itself runs on the Kali VM):
there are no POSIX process groups, so only the direct child is killed;
descendants it started may survive. Tests that depend on group killing
are skipped on Windows. Do not run the Runner on Windows.
"""

from __future__ import annotations

import os
import select
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import IO

IS_POSIX = os.name == "posix"

MAX_PROCESS_TIMEOUT_SECONDS = 600.0
DEFAULT_MAX_STDOUT_BYTES = 1_000_000
DEFAULT_MAX_STDERR_BYTES = 64_000
_READ_CHUNK = 65_536
_POLL_INTERVAL = 0.05


def default_child_env() -> dict[str, str]:
    """The only environment a tool process gets. Nothing is inherited
    except, on Windows, SYSTEMROOT (needed for processes to start at all
    — dev/test host only)."""
    if IS_POSIX:
        return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    env = {"PATH": ""}
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


@dataclass(frozen=True)
class ExecutionLimits:
    timeout_seconds: float
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES
    kill_grace_seconds: float = 2.0

    def __post_init__(self) -> None:
        if not 0 < self.timeout_seconds <= MAX_PROCESS_TIMEOUT_SECONDS:
            raise ValueError(
                f"timeout_seconds must be in (0, {MAX_PROCESS_TIMEOUT_SECONDS}]"
            )
        if self.max_stdout_bytes <= 0 or self.max_stderr_bytes <= 0:
            raise ValueError("output limits must be positive")
        if not 0 < self.kill_grace_seconds <= 10:
            raise ValueError("kill_grace_seconds must be in (0, 10]")


class ProcessOutcome(str, Enum):
    EXITED = "exited"  # process ended on its own (any exit code)
    TIMED_OUT = "timed_out"  # killed after the wall-clock timeout
    OUTPUT_LIMIT = "output_limit"  # killed after exceeding an output cap
    START_FAILED = "start_failed"  # could not be started at all
    CANCELLED = "cancelled"  # stopped on request (M8.7); never started if cancelled first


@dataclass(frozen=True)
class ProcessResult:
    outcome: ProcessOutcome
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float
    error: str = ""  # start failure detail
    cleanup_error: str = ""  # non-fatal cleanup problem, for the audit log

    @property
    def ok(self) -> bool:
        """True only if the process ran to completion within all limits.
        A non-zero exit code is still ``ok`` here — interpreting it is the
        caller's job."""
        return self.outcome is ProcessOutcome.EXITED


class _CappedReader(threading.Thread):
    """Drains one pipe to EOF, keeping at most ``limit`` bytes.

    It keeps draining (and discarding) past the limit so the child never
    blocks on a full pipe, and sets ``limit_hit`` so the caller can kill
    the process.
    """

    def __init__(self, stream: IO[bytes], limit: int, limit_hit: threading.Event):
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self._limit_hit = limit_hit
        self._chunks: list[bytes] = []
        self._kept = 0
        self.truncated = False
        # M8.7 Stage 6: lets the runner stop waiting for EOF. On POSIX a
        # descendant that left the job's process group (setsid) can keep the
        # pipe open forever; a blocking read would then hang run() past its
        # timeout/cancel (found on Linux). Windows keeps the blocking read.
        self.stop = threading.Event()

    def _consume(self, chunk: bytes) -> None:
        room = self._limit - self._kept
        if len(chunk) > room:
            if room > 0:
                self._chunks.append(chunk[:room])
                self._kept += room
            self.truncated = True
            self._limit_hit.set()
        else:
            self._chunks.append(chunk)
            self._kept += len(chunk)

    def run(self) -> None:
        try:
            if IS_POSIX:
                self._run_polling()
            else:
                while True:
                    chunk = self._stream.read1(_READ_CHUNK)  # type: ignore[attr-defined]
                    if not chunk:
                        break
                    self._consume(chunk)
        except (OSError, ValueError):
            pass  # pipe closed underneath us during cleanup

    def _run_polling(self) -> None:
        """POSIX: raw reads only when poll() says data/EOF is ready, so the
        thread notices ``stop`` and never holds the stream's lock while idle."""
        fd = self._stream.fileno()
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while not self.stop.is_set():
            if not poller.poll(int(_POLL_INTERVAL * 1000)):
                continue
            chunk = os.read(fd, _READ_CHUNK)
            if not chunk:
                break
            self._consume(chunk)

    @property
    def data(self) -> bytes:
        return b"".join(self._chunks)


class SubprocessRunner:
    """Runs argv lists for a fixed set of trusted executables."""

    def __init__(
        self,
        executables: Mapping[str, str],
        *,
        env: Mapping[str, str] | None = None,
    ) -> None:
        resolved: dict[str, str] = {}
        for name, path in executables.items():
            if not isinstance(name, str) or not name or os.sep in name or "/" in name:
                raise ValueError(f"invalid logical executable name: {name!r}")
            if not isinstance(path, str) or not os.path.isabs(path):
                raise ValueError(f"executable for {name!r} must be an absolute path")
            if not os.path.isfile(path) or not os.access(path, os.X_OK):
                raise ValueError(f"executable for {name!r} not found or not executable")
            resolved[name] = path
        if not resolved:
            raise ValueError("at least one executable must be configured")
        self._executables = MappingProxyType(resolved)
        self._env = dict(default_child_env() if env is None else env)

    @property
    def executables(self) -> Mapping[str, str]:
        return self._executables

    def _resolve_argv(self, argv: Sequence[str]) -> list[str]:
        if isinstance(argv, str) or not isinstance(argv, Sequence) or not argv:
            raise ValueError("argv must be a non-empty sequence of strings")
        if not all(isinstance(a, str) for a in argv):
            raise ValueError("argv must contain only strings")
        if any("\x00" in a for a in argv):
            raise ValueError("argv must not contain NUL characters")
        name = argv[0]
        if name not in self._executables:
            raise ValueError(f"executable {name!r} is not configured")
        return [self._executables[name], *argv[1:]]

    def run(self, argv: Sequence[str], limits: ExecutionLimits,
            cancel: threading.Event | None = None) -> ProcessResult:
        """Run one process under ``limits``. Invalid argv raises ValueError
        before anything starts; everything else returns a ProcessResult."""
        command = self._resolve_argv(argv)
        start = time.monotonic()
        if cancel is not None and cancel.is_set():
            return ProcessResult(outcome=ProcessOutcome.CANCELLED, exit_code=None, stdout=b"",
                                 stderr=b"", stdout_truncated=False, stderr_truncated=False,
                                 duration_seconds=0.0, error="cancelled before start")
        workdir = tempfile.mkdtemp(prefix="avra-run-")
        try:
            return self._run_in(command, limits, workdir, start, cancel)
        except BaseException:
            _remove_dir(workdir)  # unexpected error: don't leak the workdir
            raise

    def _run_in(
        self, command: list[str], limits: ExecutionLimits, workdir: str, start: float,
        cancel: threading.Event | None = None,
    ) -> ProcessResult:
        popen_kwargs: dict = {
            "shell": False,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": workdir,
            "env": self._env,
            "close_fds": True,
        }
        if IS_POSIX:
            popen_kwargs["start_new_session"] = True  # own session + group
        else:
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(command, **popen_kwargs)
        except (OSError, ValueError) as exc:
            cleanup_error = _remove_dir(workdir)
            return ProcessResult(
                outcome=ProcessOutcome.START_FAILED,
                exit_code=None,
                stdout=b"",
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                duration_seconds=time.monotonic() - start,
                error=f"{type(exc).__name__}: {exc}"[:500],
                cleanup_error=cleanup_error,
            )

        limit_hit = threading.Event()
        out_reader = _CappedReader(proc.stdout, limits.max_stdout_bytes, limit_hit)
        err_reader = _CappedReader(proc.stderr, limits.max_stderr_bytes, limit_hit)
        deadline = start + limits.timeout_seconds
        outcome = ProcessOutcome.EXITED
        try:
            out_reader.start()
            err_reader.start()
            while proc.poll() is None:
                if cancel is not None and cancel.is_set():
                    outcome = ProcessOutcome.CANCELLED
                    break
                if limit_hit.is_set():
                    outcome = ProcessOutcome.OUTPUT_LIMIT
                    break
                if time.monotonic() >= deadline:
                    outcome = ProcessOutcome.TIMED_OUT
                    break
                limit_hit.wait(_POLL_INTERVAL)
        except BaseException:
            # Never leave a running process behind (e.g. Ctrl+C here).
            _terminate(proc, limits.kill_grace_seconds)
            _kill_group(proc.pid)
            raise

        cleanup_notes = []
        if outcome is not ProcessOutcome.EXITED:
            note = _terminate(proc, limits.kill_grace_seconds)
            if note:
                cleanup_notes.append(note)
        elif limit_hit.is_set():
            outcome = ProcessOutcome.OUTPUT_LIMIT  # exited, but overflowed
        # Exited or not, sweep any descendants left in the group (POSIX).
        # While any member is alive the group id can't be reused, so this
        # can't hit an unrelated group except in the (tiny) window where
        # the group is already empty and its id was reissued — and the
        # Runner user can only signal its own processes anyway.
        _kill_group(proc.pid)

        for reader in (out_reader, err_reader):
            reader.join(timeout=limits.kill_grace_seconds + 1)
            if reader.is_alive() and IS_POSIX:
                # The job's group is gone but someone still holds the pipe: a
                # descendant that escaped the group (setsid). Stop waiting so
                # run() stays bounded; the escapee itself is a documented limit.
                reader.stop.set()
                reader.join(timeout=1)
                cleanup_notes.append("output pipe held open by a process outside the job's "
                                     "process group; stopped reading")
            if reader.is_alive():
                cleanup_notes.append("output reader did not finish")
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

        dir_note = _remove_dir(workdir)
        if dir_note:
            cleanup_notes.append(dir_note)

        return ProcessResult(
            outcome=outcome,
            exit_code=proc.returncode,
            stdout=out_reader.data,
            stderr=err_reader.data,
            stdout_truncated=out_reader.truncated,
            stderr_truncated=err_reader.truncated,
            duration_seconds=time.monotonic() - start,
            cleanup_error="; ".join(cleanup_notes)[:500],
        )


def _kill_group(pgid: int, sig: int | None = None) -> None:
    """Signal a whole process group (POSIX only). Missing group is fine."""
    if not IS_POSIX:
        return
    try:
        os.killpg(pgid, signal.SIGKILL if sig is None else sig)
    except (ProcessLookupError, PermissionError):
        pass


def _terminate(proc: subprocess.Popen, grace: float) -> str:
    """SIGTERM the group, wait ``grace``, then SIGKILL; always reap.
    Returns a cleanup note if the process couldn't be reaped."""
    try:
        if IS_POSIX:
            _kill_group(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=grace)
            return ""
        except subprocess.TimeoutExpired:
            pass
        if IS_POSIX:
            _kill_group(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
        proc.wait(timeout=grace)
        return ""
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"could not reap process {proc.pid}: {exc}"[:200]


def _remove_dir(path: str) -> str:
    try:
        shutil.rmtree(path)
        return ""
    except OSError as exc:
        return f"workdir cleanup failed: {exc}"[:200]
