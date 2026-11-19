"""AuditLog thread safety and single-owner process lock (ADR 0003, M3.1)."""

from __future__ import annotations

import subprocess
import sys
import threading

import pytest

from avra.runner.audit_owner import AuditOwnerLock, AuditOwnershipError
from avra.storage.audit import AuditLog

PYTHON = getattr(sys, "_base_executable", sys.executable) or sys.executable
SRC = str(__import__("pathlib").Path(__file__).resolve().parents[2] / "src")


@pytest.mark.parametrize("shared_instance", [True, False])
def test_concurrent_records_keep_chain_intact(tmp_path, shared_instance):
    path = tmp_path / "audit.jsonl"
    shared = AuditLog(path)
    threads, per_thread, n_threads = [], 40, 8
    start = threading.Barrier(n_threads)

    def worker(i):
        log = shared if shared_instance else AuditLog(path)
        start.wait()
        for j in range(per_thread):
            log.record("evt", {"thread": i, "n": j})

    for i in range(n_threads):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    records = shared.read_all()
    assert len(records) == n_threads * per_thread
    assert [r.seq for r in records] == list(range(1, n_threads * per_thread + 1))
    assert shared.verify()


def test_owner_lock_is_exclusive_in_process(tmp_path):
    path = tmp_path / "audit.jsonl"
    with AuditOwnerLock(path) as first:
        assert first.held
        with pytest.raises(AuditOwnershipError):
            AuditOwnerLock(path).acquire()
    # released on exit -> can be taken again
    with AuditOwnerLock(path) as again:
        assert again.held


def test_owner_lock_blocks_second_process(tmp_path):
    path = tmp_path / "audit.jsonl"
    child = (
        "import sys\n"
        f"sys.path.insert(0, {SRC!r})\n"
        "from avra.runner.audit_owner import AuditOwnerLock, AuditOwnershipError\n"
        "try:\n"
        "    AuditOwnerLock(sys.argv[1]).acquire()\n"
        "except AuditOwnershipError:\n"
        "    print('blocked')\n"
        "else:\n"
        "    print('acquired')\n"
    )
    with AuditOwnerLock(path):
        out = subprocess.run(
            [PYTHON, "-c", child, str(path)],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout.strip()
    assert out == "blocked"

    out = subprocess.run(
        [PYTHON, "-c", child, str(path)],
        capture_output=True, text=True, timeout=30, check=True,
    ).stdout.strip()
    assert out == "acquired"
