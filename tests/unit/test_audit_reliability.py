"""M8.7 Stage 1 (ADR 0012): durable appends, cross-process writer lock,
structured verification diagnostics, controlled errors, fail closed.

Offline only. Child processes are plain Python interpreters running
``avra.storage.audit`` against files under ``tmp_path``."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from avra.storage import audit as audit_mod
from avra.storage.audit import (
    GENESIS_HASH,
    AuditCorruptError,
    AuditLockTimeout,
    AuditLog,
    AuditStatus,
    AuditUnreadableError,
    AuditWriteError,
    _FileLock,
    _lock_for,
    _record_hash,
)

SRC = str(Path(__file__).resolve().parents[2] / "src")
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic-sessions"


def _child_env() -> dict[str, str]:
    return {**os.environ, "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}


def _log(tmp_path: Path, n: int = 4, **kw) -> AuditLog:
    log = AuditLog(tmp_path / "audit.jsonl", **kw)
    for i in range(n):
        log.record("step", {"i": i})
    return log


def _lines(log: AuditLog) -> list[str]:
    return log.path.read_bytes().decode("utf-8").splitlines()


def _write_lines(log: AuditLog, lines: list[str], *, final_newline: bool = True) -> None:
    text = "\n".join(lines) + ("\n" if final_newline else "")
    log.path.write_bytes(text.encode("utf-8"))


def _tear(log: AuditLog) -> None:
    with log.path.open("ab") as fh:
        fh.write(b'{"torn')


def _assert_refuses_append(log: AuditLog, status: AuditStatus) -> None:
    before = log.path.read_bytes()
    with pytest.raises(AuditCorruptError) as info:
        log.record("after_damage", {"x": 1})
    assert info.value.verification.status is status
    assert log.path.read_bytes() == before  # never truncated, repaired or extended


# --- valid logs and the unchanged record format ---------------------------------------


def test_valid_log_reports_count_and_head(tmp_path):
    log = _log(tmp_path, 5)
    v = log.verify_detailed()
    assert v.ok and v.exists and v.status is AuditStatus.VALID
    assert v.record_count == 5 and v.last_seq == 5
    assert v.head_hash == log.read_all()[-1].hash
    assert log.verify() is True


def test_missing_log_is_valid_and_empty(tmp_path):
    log = AuditLog(tmp_path / "none.jsonl")
    v = log.verify_detailed()
    assert v.ok and not v.exists and v.record_count == 0
    assert log.read_all() == [] and log.verify()
    assert not log.path.exists()  # checking never creates the file


def test_record_bytes_keep_the_historical_format(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    rec = log.record("e", {"k": "v"})
    expected = json.dumps(asdict(rec), sort_keys=True) + os.linesep
    assert log.path.read_bytes() == expected.encode("utf-8")
    assert rec.hash == _record_hash(1, rec.ts, "e", {"k": "v"}, GENESIS_HASH)


def test_record_is_fsynced(tmp_path, monkeypatch):
    calls = []
    real = audit_mod._fsync
    monkeypatch.setattr(audit_mod, "_fsync", lambda fd: (calls.append(fd), real(fd)))
    _log(tmp_path, 3)
    assert len(calls) == 3


# --- torn and malformed data ------------------------------------------------------------


def test_torn_partial_last_line(tmp_path):
    log = _log(tmp_path, 3)
    with log.path.open("ab") as fh:
        fh.write(b'{"data": {"i": 3}, "event": "st')  # crash mid-write
    v = log.verify_detailed()
    assert v.status is AuditStatus.TORN_TAIL and v.line == 4
    assert v.record_count == 3 and v.last_seq == 3
    assert log.verify() is False
    with pytest.raises(AuditCorruptError, match="torn_tail at line 4"):
        log.read_all()
    _assert_refuses_append(log, AuditStatus.TORN_TAIL)


def test_complete_record_without_newline_is_torn(tmp_path):
    log = _log(tmp_path, 2)
    lines = _lines(log)
    _write_lines(log, lines, final_newline=False)
    v = log.verify_detailed()
    assert v.status is AuditStatus.TORN_TAIL and v.record_count == 1
    _assert_refuses_append(log, AuditStatus.TORN_TAIL)


def test_unparseable_last_line_is_torn(tmp_path):
    log = _log(tmp_path, 2)
    _write_lines(log, [*_lines(log), "{not json"])
    assert log.verify_detailed().status is AuditStatus.TORN_TAIL


@pytest.mark.parametrize("bad", [
    "{not json",
    "[1, 2, 3]",
    '{"seq": 2, "ts": "t", "event": "e", "data": {}, "prev_hash": "x", "hash": "y", "x": 1}',
    '{"seq": 2, "ts": "t", "event": "e", "data": {}, "prev_hash": "x"}',
    '{"seq": "2", "ts": "t", "event": "e", "data": {}, "prev_hash": "x", "hash": "y"}',
    '{"seq": true, "ts": "t", "event": "e", "data": {}, "prev_hash": "x", "hash": "y"}',
    '{"seq": 2, "ts": 5, "event": "e", "data": {}, "prev_hash": "x", "hash": "y"}',
    '{"seq": 2, "seq": 2, "ts": "t", "event": "e", "data": {}, "prev_hash": "x", "hash": "y"}',
])
def test_malformed_middle_record(tmp_path, bad):
    log = _log(tmp_path, 3)
    lines = _lines(log)
    _write_lines(log, [lines[0], bad, *lines[1:]])
    v = log.verify_detailed()
    assert v.status is AuditStatus.MALFORMED_RECORD and v.line == 2
    with pytest.raises(AuditCorruptError, match="malformed_record at line 2"):
        log.read_all()
    _assert_refuses_append(log, AuditStatus.MALFORMED_RECORD)


def test_invalid_utf8_is_malformed(tmp_path):
    log = _log(tmp_path, 2)
    raw = log.path.read_bytes()
    log.path.write_bytes(b"\xff\xfe\n" + raw)
    v = log.verify_detailed()
    assert v.status is AuditStatus.MALFORMED_RECORD and v.line == 1


def test_blank_lines_are_tolerated_as_before(tmp_path):
    log = _log(tmp_path, 2)
    _write_lines(log, [_lines(log)[0], "", "   ", _lines(log)[1]])
    assert log.verify_detailed().ok
    log.record("next")
    assert log.verify()


# --- chain damage -----------------------------------------------------------------------


def test_modified_record_is_a_hash_mismatch(tmp_path):
    log = _log(tmp_path, 4)
    lines = _lines(log)
    rec = json.loads(lines[1])
    rec["data"]["i"] = 99  # edited content, stale hash
    lines[1] = json.dumps(rec, sort_keys=True)
    _write_lines(log, lines)
    v = log.verify_detailed()
    assert v.status is AuditStatus.HASH_MISMATCH and v.line == 2
    assert "content does not match its hash" in v.detail
    assert v.last_seq == 1  # valid prefix stops before the edit
    assert len(log.read_all()) == 4  # still readable for inspection
    _assert_refuses_append(log, AuditStatus.HASH_MISMATCH)


def test_invalid_record_hash_field(tmp_path):
    log = _log(tmp_path, 3)
    lines = _lines(log)
    rec = json.loads(lines[-1])
    rec["hash"] = "f" * 64
    lines[-1] = json.dumps(rec, sort_keys=True)
    _write_lines(log, lines)
    v = log.verify_detailed()
    assert v.status is AuditStatus.HASH_MISMATCH and v.line == 3
    _assert_refuses_append(log, AuditStatus.HASH_MISMATCH)


def test_broken_prev_hash_link_with_self_consistent_hash(tmp_path):
    log = _log(tmp_path, 3)
    lines = _lines(log)
    rec = json.loads(lines[2])
    rec["prev_hash"] = "a" * 64
    rec["hash"] = _record_hash(rec["seq"], rec["ts"], rec["event"], rec["data"], rec["prev_hash"])
    lines[2] = json.dumps(rec, sort_keys=True)
    _write_lines(log, lines)
    v = log.verify_detailed()
    assert v.status is AuditStatus.HASH_MISMATCH and "prev_hash" in v.detail


def test_missing_sequence_number(tmp_path):
    log = _log(tmp_path, 5)
    lines = _lines(log)
    del lines[2]  # record 3 removed
    _write_lines(log, lines)
    v = log.verify_detailed()
    assert v.status is AuditStatus.SEQ_GAP and v.line == 3
    assert v.detail == "expected seq 3, found 4"
    _assert_refuses_append(log, AuditStatus.SEQ_GAP)


def test_reordered_records_are_a_sequence_error(tmp_path):
    log = _log(tmp_path, 3)
    lines = _lines(log)
    lines[1], lines[2] = lines[2], lines[1]
    _write_lines(log, lines)
    assert log.verify_detailed().status is AuditStatus.SEQ_GAP


def test_first_problem_in_file_order_is_reported(tmp_path):
    log = _log(tmp_path, 4)
    lines = _lines(log)
    rec = json.loads(lines[0])
    rec["data"]["i"] = 7
    lines[0] = json.dumps(rec, sort_keys=True)
    _write_lines(log, [*lines, "{torn"])
    v = log.verify_detailed()
    assert v.status is AuditStatus.HASH_MISMATCH and v.line == 1
    # read_all reports the FORMAT problem (the reason it cannot parse).
    with pytest.raises(AuditCorruptError) as info:
        log.read_all()
    assert info.value.verification.status is AuditStatus.TORN_TAIL


def test_verification_is_deterministic(tmp_path):
    log = _log(tmp_path, 3)
    _write_lines(log, [*_lines(log)[:2], "garbage", _lines(log)[2]])
    assert len({log.verify_detailed() for _ in range(5)}) == 1


def test_verify_never_raises_on_garbage(tmp_path):
    path = tmp_path / "junk.jsonl"
    path.write_bytes(os.urandom(4096))
    assert AuditLog(path).verify() is False


def test_error_messages_carry_no_record_content(tmp_path):
    log = _log(tmp_path, 2)
    secret = "TOP-SECRET-VALUE"
    _write_lines(log, [_lines(log)[0], '{"oops": "' + secret + '"', _lines(log)[1]])
    with pytest.raises(AuditCorruptError) as info:
        log.read_all()
    assert secret not in str(info.value) and secret not in log.verify_detailed().describe()


# --- unreadable data and write failures --------------------------------------------------


def test_unreadable_audit_path(tmp_path):
    path = tmp_path / "is-a-directory.jsonl"
    path.mkdir()
    log = AuditLog(path)
    v = log.verify_detailed()
    assert v.status is AuditStatus.UNREADABLE and log.verify() is False
    with pytest.raises(AuditUnreadableError):
        log.read_all()
    with pytest.raises(AuditWriteError):
        log.record("x")


def test_fsync_failure_fails_closed(tmp_path, monkeypatch):
    log = _log(tmp_path, 2)

    def boom(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(audit_mod, "_fsync", boom)
    with pytest.raises(AuditWriteError, match="NOT recorded") as info:
        log.record("x", {"payload": "never in the message"})
    assert isinstance(info.value, OSError)  # existing `except OSError` callers still catch it
    assert "never in the message" not in str(info.value)
    monkeypatch.undo()
    # The bytes may have reached the file (over-report, never under-report);
    # either way the chain is still well formed and appendable.
    assert log.verify()
    log.record("after")
    assert log.verify()


@pytest.mark.skipif(os.name == "posix" and os.geteuid() == 0, reason="root ignores modes")
def test_write_failure_fails_closed(tmp_path):
    log = _log(tmp_path, 2)
    before = log.path.read_bytes()
    os.chmod(log.path, stat.S_IREAD)
    try:
        with pytest.raises(AuditWriteError):
            log.record("x")
    finally:
        os.chmod(log.path, stat.S_IREAD | stat.S_IWRITE)
    assert log.path.read_bytes() == before


def test_lock_timeout_must_be_bounded(tmp_path):
    for bad in (0, -1, 301):
        with pytest.raises(ValueError):
            AuditLog(tmp_path / "a.jsonl", lock_timeout=bad)


# --- locking ------------------------------------------------------------------------------


def test_lock_timeout_against_another_handle(tmp_path):
    log = _log(tmp_path, 1, lock_timeout=0.3)
    before = log.path.read_bytes()
    with _FileLock(log.path, 1.0):
        start = time.monotonic()
        with pytest.raises(AuditLockTimeout, match="nothing was recorded"):
            log.record("blocked")
        assert time.monotonic() - start < 5
    assert log.path.read_bytes() == before
    log.record("after")
    assert [r.event for r in log.read_all()] == ["step", "after"] and log.verify()


def test_in_process_lock_timeout(tmp_path):
    log = _log(tmp_path, 1, lock_timeout=0.2)
    lock = _lock_for(log.path)
    lock.acquire()
    try:
        with pytest.raises(AuditLockTimeout):
            log.record("blocked")
    finally:
        lock.release()
    log.record("after")
    assert log.verify()


_HOLDER = """
import sys
from pathlib import Path
from avra.storage.audit import _FileLock
with _FileLock(Path(sys.argv[1]), 10):
    print("LOCKED", flush=True)
    sys.stdin.readline()
"""


def test_lock_timeout_against_another_process(tmp_path):
    log = _log(tmp_path, 1, lock_timeout=0.5)
    before = log.path.read_bytes()
    child = subprocess.Popen([sys.executable, "-c", _HOLDER, str(log.path)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                             env=_child_env())
    try:
        assert child.stdout.readline().strip() == "LOCKED"
        with pytest.raises(AuditLockTimeout):
            log.record("blocked")
        assert log.path.read_bytes() == before
    finally:
        child.communicate("\n", timeout=30)
    log.record("after")
    assert log.verify()


_WRITER = """
import sys, time
from pathlib import Path
from avra.storage.audit import AuditLog
path, name, n, go = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), Path(sys.argv[4])
log = AuditLog(path, lock_timeout=120)
while not go.exists():
    time.sleep(0.005)
for i in range(n):
    log.record("w", {"writer": name, "i": i})
"""


def test_concurrent_writers_from_independent_processes(tmp_path):
    path, go = tmp_path / "shared.jsonl", tmp_path / "go"
    writers, per = 4, 25
    procs = [subprocess.Popen([sys.executable, "-c", _WRITER, str(path), f"w{k}", str(per),
                               str(go)], env=_child_env(), stderr=subprocess.PIPE, text=True)
             for k in range(writers)]
    time.sleep(0.5)
    go.write_text("go")
    for p in procs:
        _out, err = p.communicate(timeout=180)
        assert p.returncode == 0, err
    log = AuditLog(path)
    v = log.verify_detailed()
    assert v.ok and v.record_count == writers * per
    records = log.read_all()
    assert [r.seq for r in records] == list(range(1, writers * per + 1))
    seen = {(r.data["writer"], r.data["i"]) for r in records}
    assert seen == {(f"w{k}", i) for k in range(writers) for i in range(per)}


def test_concurrent_threads_still_serialize(tmp_path):
    log = AuditLog(tmp_path / "t.jsonl")

    def work(k):
        for i in range(20):
            AuditLog(log.path).record("t", {"k": k, "i": i})

    threads = [threading.Thread(target=work, args=(k,)) for k in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    v = log.verify_detailed()
    assert v.ok and v.record_count == 80


# --- fail closed at the execution boundaries ------------------------------------------------


def test_runner_refuses_to_execute_on_damaged_audit(tmp_path):
    from avra.runner.core import Runner
    from avra.runner.policy import RunnerPolicy
    from avra.runner.schemas import RejectionStage, RunnerRejection
    from tests.unit.test_runner_core import SCOPE_YAML, FakeExecutor, payload

    scope = tmp_path / "runner.scope.yaml"
    scope.write_text(SCOPE_YAML, encoding="utf-8")
    log = _log(tmp_path, 2)
    with log.path.open("ab") as fh:
        fh.write(b'{"torn')
    before = log.path.read_bytes()
    ex = FakeExecutor()
    res = Runner(RunnerPolicy.from_scope_file(scope), ex, log).handle(payload())
    assert isinstance(res, RunnerRejection) and res.stage is RejectionStage.AUDIT_UNAVAILABLE
    assert ex.calls == [] and log.path.read_bytes() == before


def test_runner_refuses_to_execute_when_audit_is_locked(tmp_path):
    from avra.runner.core import Runner
    from avra.runner.policy import RunnerPolicy
    from avra.runner.schemas import RejectionStage, RunnerRejection
    from tests.unit.test_runner_core import SCOPE_YAML, FakeExecutor, payload

    scope = tmp_path / "runner.scope.yaml"
    scope.write_text(SCOPE_YAML, encoding="utf-8")
    log = _log(tmp_path, 1, lock_timeout=0.2)
    ex = FakeExecutor()
    with _FileLock(log.path, 1.0):
        res = Runner(RunnerPolicy.from_scope_file(scope), ex, log).handle(payload())
    assert isinstance(res, RunnerRejection) and res.stage is RejectionStage.AUDIT_UNAVAILABLE
    assert ex.calls == []


# --- CLI: controlled diagnostics, no tracebacks ---------------------------------------------


def _cli_session(tmp_path, monkeypatch, damage):
    import uuid

    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path / "data"))
    sid = str(uuid.uuid4())
    log = AuditLog(tmp_path / "data" / "sessions" / f"{sid}.jsonl")
    log.record("session_created", {"session_id": sid})
    log.record("x", {})
    damage(log)
    return sid, log


@pytest.mark.parametrize("damage,status", [
    (_tear, "torn_tail"),
    (lambda log: _write_lines(log, [_lines(log)[1]]), "seq_gap"),
])
def test_cli_session_show_reports_damage_without_traceback(tmp_path, monkeypatch, damage, status):
    from typer.testing import CliRunner

    from avra.cli.main import app

    sid, _ = _cli_session(tmp_path, monkeypatch, damage)
    result = CliRunner().invoke(app, ["session", "show", sid])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)  # controlled exit, not a crash
    assert "Chain integrity: BROKEN" in result.output and status in result.output


def test_cli_refuses_to_continue_a_damaged_session(tmp_path, monkeypatch):
    import typer

    from avra.cli.main import _open_session

    sid, log = _cli_session(tmp_path, monkeypatch, _tear)
    before = log.path.read_bytes()
    with pytest.raises(typer.Exit):
        _open_session(Path("scope.yaml"), None, sid)
    assert log.path.read_bytes() == before


# --- historical compatibility ------------------------------------------------------------------


def _historical_logs() -> list[Path]:
    logs = sorted(FIXTURES.rglob("*.jsonl"))
    assert logs, "historical fixtures missing"
    return logs


@pytest.mark.parametrize("path", _historical_logs(), ids=lambda p: p.name[:8])
def test_historical_logs_verify_unchanged(path):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    log = AuditLog(path)
    v = log.verify_detailed()
    assert v.ok and v.record_count == len(log.read_all()) > 0
    assert log.verify() is True
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest  # read-only


def test_appending_to_a_copy_of_a_historical_log(tmp_path):
    src = _historical_logs()[0]
    original = src.read_bytes()
    copy = tmp_path / src.name
    copy.write_bytes(original)
    log = AuditLog(copy)
    n = log.verify_detailed().record_count
    log.record("stage1_append", {"ok": True})
    assert copy.read_bytes().startswith(original)  # old bytes untouched
    v = log.verify_detailed()
    assert v.ok and v.record_count == n + 1
