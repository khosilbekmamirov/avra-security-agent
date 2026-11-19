from __future__ import annotations

import json
from pathlib import Path

from avra.storage.audit import AuditLog


def test_record_and_read_back(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("session_created", {"session_id": "abc"})
    log.record("scope_checked", {"host": "192.168.56.10", "allowed": True})

    records = log.read_all()
    assert [r.event for r in records] == ["session_created", "scope_checked"]
    assert records[0].seq == 1
    assert records[1].seq == 2
    assert records[1].prev_hash == records[0].hash


def test_chain_is_valid_for_fresh_log(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.record("step", {"i": i})
    assert log.verify()


def test_empty_log_verifies_true(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.read_all() == []
    assert log.verify()


def test_tampering_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("session_created", {"session_id": "abc"})
    log.record("finding_recorded", {"severity": "low"})
    assert log.verify()

    # Tamper with the first record's data without recomputing its hash.
    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["data"]["severity_was"] = "low"  # mutate payload, hash now stale
    lines[0] = json.dumps(first, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tampered = AuditLog(path)
    assert not tampered.verify()


def test_appending_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record("a", {})
    AuditLog(path).record("b", {})  # new instance, same file
    records = AuditLog(path).read_all()
    assert [r.event for r in records] == ["a", "b"]
    assert AuditLog(path).verify()
