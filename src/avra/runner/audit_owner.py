"""Single-owner guard for the Runner's audit log (ADR 0003, M3.1).

``AuditLog``'s lock only serializes threads inside one process. Two
Runner processes appending to the same file could still interleave and
break the hash chain, so the Runner must hold ``AuditOwnerLock`` for its
whole lifetime (acquired at startup, M3.3). A second Runner pointed at
the same audit log then fails to start instead of corrupting it.

The lock is advisory and OS-level (``fcntl.flock`` on Linux,
``msvcrt.locking`` on Windows) on a sibling ``<audit>.lock`` file: it
stops other cooperating AVRA processes, not an unrelated program that
writes the file directly — file permissions are the defense there (M4).
The OS releases it automatically if the process dies.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import IO

if os.name == "posix":
    import fcntl
else:  # pragma: no cover - exercised on the Windows dev host only
    import msvcrt


class AuditOwnershipError(Exception):
    """Another process already owns this audit log."""


class AuditOwnerLock:
    def __init__(self, audit_path: str | Path) -> None:
        self.lock_path = Path(str(audit_path) + ".lock")
        self._fh: IO[str] | None = None

    @property
    def held(self) -> bool:
        return self._fh is not None

    def acquire(self) -> None:
        if self._fh is not None:
            return
        fh = open(self.lock_path, "a+", encoding="utf-8")  # noqa: SIM115
        try:
            if os.name == "posix":
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            fh.close()
            raise AuditOwnershipError(
                "the audit log is already owned by another Runner process"
            ) from None
        self._fh = fh

    def release(self) -> None:
        fh, self._fh = self._fh, None
        if fh is None:
            return
        try:
            if os.name == "posix":
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            else:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass  # closing the file releases it anyway
        finally:
            fh.close()

    def __enter__(self) -> AuditOwnerLock:
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()
