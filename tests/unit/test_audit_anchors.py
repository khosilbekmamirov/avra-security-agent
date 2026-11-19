"""M8.7 Stage 2 (ADR 0012): HMAC audit anchors, DPAPI key ring, CLI.

Offline only. Every test uses its own temporary state directory
(AVRA_STATE_DIR is forced to tmp_path); no operational key is created, and
the real %LOCALAPPDATA% is never touched. Keys are injected (StaticKeys) or
protected with a fake protector; real DPAPI is used only for throw-away
test keys inside tmp_path."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from avra.storage import anchors as anchors_mod
from avra.storage import keys as keys_mod
from avra.storage.anchors import (
    _MAC_DOMAIN,
    ANCHOR_VERSION,
    AnchorError,
    AnchorStatus,
    AnchorStore,
    AnchorWriteError,
    Severity,
    _canonical,
    _mac,
    create_key,
    log_identity,
)
from avra.storage.audit import AuditLog
from avra.storage.keys import (
    KeyInvalidError,
    Keyring,
    KeyUnavailableError,
    StaticKeys,
    key_id_for,
)

SRC = str(Path(__file__).resolve().parents[2] / "src")
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic-sessions"
KEY_A = bytes(range(32))
KEY_B = bytes(range(100, 132))
WINDOWS = os.name == "nt"


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """Never touch the real %LOCALAPPDATA%\\AVRA."""
    monkeypatch.setenv("AVRA_STATE_DIR", str(tmp_path / "state"))


class FakeProtector:
    """Stands in for DPAPI: reversible, tagged, never equal to the raw key."""

    TAG = b"FAKEDPAPI"

    def __init__(self, tag: bytes = TAG) -> None:
        self.tag = tag

    def protect(self, data: bytes) -> bytes:
        return self.tag + bytes(b ^ 0xA5 for b in data)

    def unprotect(self, blob: bytes) -> bytes:
        if not blob.startswith(self.tag):
            raise KeyUnavailableError("fake DPAPI refused to decrypt the key")
        return bytes(b ^ 0xA5 for b in blob[len(self.tag):])


def _no_acl(_d: Path) -> None:
    pass


class World:
    def __init__(self, tmp_path: Path, *, protector=None) -> None:
        self.state = tmp_path / "state"
        self.logs = tmp_path / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.protector = protector or FakeProtector()
        self.keyring = Keyring(self.state, protector=self.protector)
        self.store = AnchorStore(self.state, self.keyring)

    def keygen(self, *, rotate: bool = False, key: bytes | None = None) -> str:
        rnd = (lambda n: key) if key is not None else os.urandom
        return create_key(self.state, self.keyring, self.store, rotate=rotate, acl=_no_acl,
                          random=rnd)

    def fresh(self) -> AnchorStore:
        """A new process's view (no key cache)."""
        return AnchorStore(self.state, Keyring(self.state, protector=self.protector))

    def log(self, name: str = "s.jsonl", n: int = 3) -> AuditLog:
        log = AuditLog(self.logs / name)
        for i in range(n):
            log.record("step", {"i": i})
        return log

    @property
    def anchors_file(self) -> Path:
        return self.store.anchors_path

    def anchor_lines(self) -> list[bytes]:
        return self.anchors_file.read_bytes().split(b"\n")[:-1]

    def write_anchor_lines(self, lines: list[bytes]) -> None:
        self.anchors_file.write_bytes(b"".join(line + b"\n" for line in lines))


@pytest.fixture
def w(tmp_path) -> World:
    world = World(tmp_path)
    world.keygen(key=KEY_A)
    return world


def _status(w: World, log: AuditLog | Path) -> AnchorStatus:
    return w.fresh().verify_log(getattr(log, "path", log)).status


def _resign(obj: dict, key: bytes = KEY_A) -> bytes:
    obj = {k: v for k, v in obj.items() if k != "mac"}
    obj["mac"] = _mac(key, _MAC_DOMAIN, obj)
    return _canonical(obj)


# --- HMAC correctness and the happy path ------------------------------------------------


def test_seal_produces_a_correct_hmac_and_verifies(w):
    log = w.log()
    res = w.store.seal(log.path)
    assert res.anchor is not None and res.audit_seq == 3
    [line] = w.anchor_lines()
    obj = json.loads(line)
    body = {k: v for k, v in obj.items() if k != "mac"}
    expected = hmac.new(KEY_A, b"AVRA-audit-anchor-v1\x00" + _canonical(body),
                        hashlib.sha256).hexdigest()
    assert obj["mac"] == expected and obj["v"] == ANCHOR_VERSION
    assert obj["audit_head_hash"] == log.read_all()[-1].hash
    assert obj["log_genesis_hash"] == log.read_all()[0].hash
    assert obj["key_id"] == key_id_for(KEY_A) and obj["prev_anchor_hash"] == "0" * 64
    assert line == _canonical(obj)  # deterministic canonical form
    v = w.fresh().verify_log(log.path)
    assert v.status is AnchorStatus.VERIFIED and v.exit_code == 0 and v.chain.ok
    assert v.anchored_seq == 3


def test_sealing_twice_at_the_same_head_writes_nothing(w):
    log = w.log()
    w.store.seal(log.path)
    before = w.anchors_file.read_bytes()
    assert w.store.seal(log.path).anchor is None
    assert w.anchors_file.read_bytes() == before


def test_path_aliases_resolve_to_one_identity(w, monkeypatch):
    log = w.log()
    w.store.seal(log.path)
    monkeypatch.chdir(log.path.parent)
    assert _status(w, Path(log.path.name)) is AnchorStatus.VERIFIED
    if WINDOWS:
        assert _status(w, Path(str(log.path).upper())) is AnchorStatus.VERIFIED
        assert log_identity(str(log.path).upper()) == log_identity(log.path)


def test_a_copy_at_another_path_is_not_covered(w, tmp_path):
    log = w.log()
    w.store.seal(log.path)
    copy = tmp_path / "copy.jsonl"
    shutil.copyfile(log.path, copy)
    v = w.fresh().verify_log(copy)
    assert v.status is AnchorStatus.LEGACY_UNANCHORED
    assert any("another path" in n for n in v.notes)


# --- audit log tampering -------------------------------------------------------------------


def test_modified_audit_record(w):
    log = w.log(n=4)
    w.store.seal(log.path)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["data"]["i"] = 42
    lines[1] = json.dumps(rec, sort_keys=True)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = w.fresh().verify_log(log.path)
    assert v.status is AnchorStatus.HASH_MISMATCH and v.exit_code == 1


def test_entire_audit_file_rewrite_is_detected(w):
    log = w.log(n=3)
    w.store.seal(log.path)
    log.path.unlink()
    forged = AuditLog(log.path)  # a brand-new, perfectly valid chain
    for i in range(3):
        forged.record("step", {"i": i})
    v = w.fresh().verify_log(log.path)
    assert v.chain.ok  # the unkeyed chain alone cannot see this...
    assert v.status is AnchorStatus.HASH_MISMATCH  # ...the anchor does


def test_rewrite_that_keeps_the_first_record_is_detected(w):
    """Keep record 1 (same genesis), rebuild records 2..n with a recomputed,
    perfectly valid unkeyed chain: only the anchored head hash can see it."""
    from avra.storage.audit import _record_hash

    log = w.log(n=3)
    w.store.seal(log.path)
    recs = log.read_all()
    lines = [log.path.read_bytes().splitlines()[0]]
    prev = recs[0].hash
    for r in recs[1:]:
        data = {"i": 1000 + r.seq}
        h = _record_hash(r.seq, r.ts, r.event, data, prev)
        lines.append(json.dumps({"seq": r.seq, "ts": r.ts, "event": r.event, "data": data,
                                 "prev_hash": prev, "hash": h}, sort_keys=True).encode())
        prev = h
    log.path.write_bytes(b"\n".join(lines) + b"\n")
    v = w.fresh().verify_log(log.path)
    assert v.chain.ok and v.status is AnchorStatus.HASH_MISMATCH


def test_tail_truncation_below_an_anchor(w):
    log = w.log(n=5)
    w.store.seal(log.path)
    lines = log.path.read_bytes().splitlines(keepends=True)
    log.path.write_bytes(b"".join(lines[:3]))
    v = w.fresh().verify_log(log.path)
    assert v.chain.ok and v.status is AnchorStatus.TRUNCATED and v.exit_code == 1


def test_deleted_audit_log_is_truncated(w):
    log = w.log()
    w.store.seal(log.path)
    log.path.unlink()
    assert _status(w, log) is AnchorStatus.TRUNCATED


def test_truncation_between_two_anchors_is_caught(w):
    log = w.log(n=2)
    w.store.seal(log.path)
    log.record("more", {})
    log.record("more", {})
    w.store.seal(log.path)
    lines = log.path.read_bytes().splitlines(keepends=True)
    log.path.write_bytes(b"".join(lines[:3]))  # above anchor 1, below anchor 2
    assert _status(w, log) is AnchorStatus.TRUNCATED


def test_additional_records_after_an_anchor_are_unanchored_tail(w):
    log = w.log(n=2)
    w.store.seal(log.path)
    log.record("after_seal", {})  # e.g. crash before the next seal
    v = w.fresh().verify_log(log.path)
    assert v.status is AnchorStatus.UNANCHORED_TAIL and v.severity is Severity.WARNING
    assert v.exit_code == 2 and "NOT protected" in v.detail
    w.store.seal(log.path)
    assert _status(w, log) is AnchorStatus.VERIFIED
    assert len(w.anchor_lines()) == 2


def test_damaged_tail_after_anchor_is_a_failure_overall(w):
    log = w.log(n=2)
    w.store.seal(log.path)
    with log.path.open("ab") as fh:
        fh.write(b'{"torn')
    v = w.fresh().verify_log(log.path)
    assert v.status is AnchorStatus.UNANCHORED_TAIL and not v.chain.ok
    assert v.exit_code == 1  # a broken chain is never just a warning


def test_seal_refuses_damaged_or_tampered_logs(w):
    log = w.log(n=3)
    w.store.seal(log.path)
    lines = log.path.read_bytes().splitlines(keepends=True)
    log.path.write_bytes(b"".join(lines[:2]))
    before = w.anchors_file.read_bytes()
    with pytest.raises(AnchorError) as info:
        w.store.seal(log.path)  # never "re-anchor" a truncated log
    assert info.value.status is AnchorStatus.TRUNCATED
    assert w.anchors_file.read_bytes() == before


# --- anchor store tampering ------------------------------------------------------------------


def _two_anchor_world(w: World):
    a, b = w.log("a.jsonl"), w.log("b.jsonl")
    w.store.seal(a.path)
    w.store.seal(b.path)
    return a, b


def test_anchor_field_edit_without_key_is_corrupt(w):
    a, _b = _two_anchor_world(w)
    lines = w.anchor_lines()
    obj = json.loads(lines[0])
    obj["audit_seq"] = 2  # stale mac
    lines[0] = _canonical(obj)
    w.write_anchor_lines(lines)
    st = w.fresh().load()
    assert st.status is AnchorStatus.ANCHOR_CORRUPT
    assert _status(w, a) is AnchorStatus.ANCHOR_CORRUPT  # every log fails closed


def test_anchor_forged_with_another_key_is_corrupt(w):
    _two_anchor_world(w)
    lines = w.anchor_lines()
    obj = json.loads(lines[1])
    obj["audit_seq"] = 1
    lines[1] = _resign(obj, KEY_B)  # attacker's own key, same claimed key_id
    w.write_anchor_lines(lines)
    assert w.fresh().load().status is AnchorStatus.ANCHOR_CORRUPT


def test_forged_anchor_appended_after_the_witness_is_corrupt(w, tmp_path):
    """Anchors beyond the witness are tolerated (interrupted seal) ONLY if
    their MAC verifies: a forged one must not make a tampered log VERIFIED."""
    a = w.log("a.jsonl")
    w.store.seal(a.path)
    victim = w.log("victim.jsonl")  # never sealed by the owner
    recs = victim.read_all()
    prev = hashlib.sha256(w.anchor_lines()[-1]).hexdigest()
    forged = {"v": 1, "anchor_seq": 2, "prev_anchor_hash": prev,
              "log_id": log_identity(victim.path), "log_genesis_hash": recs[0].hash,
              "audit_seq": len(recs), "audit_head_hash": recs[-1].hash,
              "sealed_at": "2026-11-11T00:00:00+00:00", "key_id": key_id_for(KEY_A)}
    w.write_anchor_lines([*w.anchor_lines(), _resign(forged, KEY_B)])
    st = w.fresh().load()
    assert st.status is AnchorStatus.ANCHOR_CORRUPT and "authentication" in st.detail
    assert _status(w, victim) is AnchorStatus.ANCHOR_CORRUPT
    # Control: the same anchor with the real key would be accepted.
    w.write_anchor_lines([*w.anchor_lines()[:-1], _resign(forged, KEY_A)])
    assert _status(w, victim) is AnchorStatus.VERIFIED


def test_non_canonical_anchor_line_is_corrupt(w):
    _two_anchor_world(w)
    lines = w.anchor_lines()
    lines[0] = json.dumps(json.loads(lines[0]), sort_keys=True).encode()  # spaces added
    w.write_anchor_lines(lines)
    assert "canonical" in w.fresh().load().detail


def test_broken_anchor_chain(w):
    _two_anchor_world(w)
    lines = w.anchor_lines()
    obj = json.loads(lines[1])
    obj["prev_anchor_hash"] = "a" * 64
    lines[1] = _resign(obj)  # even with a valid MAC the link is checked
    w.write_anchor_lines(lines)
    st = w.fresh().load()
    assert st.status is AnchorStatus.ANCHOR_CORRUPT and "does not link" in st.detail


def test_removed_middle_anchor_is_a_gap(w):
    w.log("c.jsonl")
    _two_anchor_world(w)
    w.store.seal(w.logs / "c.jsonl")
    lines = w.anchor_lines()
    w.write_anchor_lines([lines[0], lines[2]])
    assert w.fresh().load().status is AnchorStatus.ANCHOR_CORRUPT


def test_duplicate_anchor_sequence(w):
    _two_anchor_world(w)
    lines = w.anchor_lines()
    w.write_anchor_lines([lines[0], lines[0], lines[1]])
    st = w.fresh().load()
    assert st.status is AnchorStatus.ANCHOR_CORRUPT and "anchor_seq" in st.detail


@pytest.mark.parametrize("change,why", [
    (lambda o: o.update(audit_seq=1), "does not increase"),
    (lambda o: o.update(log_genesis_hash="b" * 64), "genesis"),
])
def test_inconsistent_historical_anchor_state(w, change, why):
    log = w.log(n=2)
    w.store.seal(log.path)
    log.record("x", {})
    w.store.seal(log.path)
    lines = w.anchor_lines()
    obj = json.loads(lines[1])
    change(obj)
    seq1_hash = hashlib.sha256(lines[0]).hexdigest()
    assert obj["prev_anchor_hash"] == seq1_hash
    lines[1] = _resign(obj)  # validly keyed, but inconsistent with history
    w.write_anchor_lines(lines)
    st = w.fresh().load()
    assert st.status is AnchorStatus.ANCHOR_CORRUPT and why in st.detail


# --- deletion and rollback of the anchor store ------------------------------------------------


def test_deleting_the_anchor_directory_is_detected(w):
    log = w.log()
    w.store.seal(log.path)
    shutil.rmtree(w.anchors_file.parent)
    v = w.fresh().verify_log(log.path)
    assert v.status is AnchorStatus.ANCHOR_CORRUPT and "rolled back" in v.detail


def test_rolling_back_the_anchor_store_is_detected(w):
    a, b = w.log("a.jsonl"), w.log("b.jsonl")
    w.store.seal(a.path)
    old = w.anchors_file.read_bytes()
    w.store.seal(b.path)
    w.anchors_file.write_bytes(old)  # rollback to before b was sealed
    assert w.fresh().load().status is AnchorStatus.ANCHOR_CORRUPT


def test_deleting_the_witness_is_detected(w):
    w.store.seal(w.log().path)
    w.store.witness_path.unlink()
    assert w.fresh().load().status is AnchorStatus.ANCHOR_CORRUPT


def test_deleting_anchors_and_witness_but_not_the_key_is_detected(w):
    w.store.seal(w.log().path)
    shutil.rmtree(w.anchors_file.parent)
    w.store.witness_path.unlink()
    assert w.fresh().load().status is AnchorStatus.ANCHOR_CORRUPT


def test_replacing_the_witness_with_an_old_copy_is_detected(w):
    a, b = w.log("a.jsonl"), w.log("b.jsonl")
    w.store.seal(a.path)
    old_witness, old_store = w.store.witness_path.read_bytes(), w.anchors_file.read_bytes()
    w.store.seal(b.path)
    w.store.witness_path.write_bytes(old_witness)  # roll back the witness only
    st = w.fresh().load()
    assert st.status is AnchorStatus.VERIFIED and st.notes  # store ahead: authenticated, noted
    w.anchors_file.write_bytes(old_store)  # ...and BOTH rolled back consistently
    st = w.fresh().load()
    assert st.status is AnchorStatus.VERIFIED  # documented limit: consistent rollback
    assert _status(w, b) is AnchorStatus.LEGACY_UNANCHORED  # but b is NOT "verified"


def test_deleting_the_entire_state_is_a_documented_limit(w):
    log = w.log()
    w.store.seal(log.path)
    shutil.rmtree(w.state)
    v = w.fresh().verify_log(log.path)
    # Undetectable locally (ADR 0012) - but never reported as VERIFIED.
    assert v.status is AnchorStatus.LEGACY_UNANCHORED and v.exit_code == 2
    assert "not initialized" in v.detail


# --- keys ----------------------------------------------------------------------------------------


def test_wrong_key_is_unavailable(w):
    log = w.log()
    w.store.seal(log.path)
    other = AnchorStore(w.state, StaticKeys([KEY_B]))
    st = other.load()
    assert st.status is AnchorStatus.KEY_UNAVAILABLE
    assert other.verify_log(log.path).exit_code == 1


def test_missing_key_ring(w):
    log = w.log()
    w.store.seal(log.path)
    w.keyring.path.unlink()
    v = w.fresh().verify_log(log.path)
    assert v.status is AnchorStatus.KEY_UNAVAILABLE and v.exit_code == 1


def test_missing_key_is_never_regenerated_silently(w):
    log = w.log()
    w.store.seal(log.path)
    w.keyring.path.unlink()
    with pytest.raises(AnchorError):
        w.fresh().seal(log.path)
    assert not w.keyring.path.exists()
    with pytest.raises(AnchorError, match="anchors already exist"):
        World(w.state.parent, protector=w.protector).keygen()  # key-loss case
    assert not w.keyring.path.exists()


def test_undecryptable_key_blob(w):
    w.store.seal(w.log().path)
    other = AnchorStore(w.state, Keyring(w.state, protector=FakeProtector(b"OTHERUSER")))
    assert other.load().status is AnchorStatus.KEY_UNAVAILABLE


def test_key_blob_not_matching_its_id_is_invalid(w):
    w.store.seal(w.log().path)
    doc = json.loads(w.keyring.path.read_bytes())
    doc["keys"][0]["blob"] = base64.b64encode(FakeProtector().protect(KEY_B)).decode()
    w.keyring.path.write_text(json.dumps(doc), encoding="utf-8")
    assert w.fresh().load().status is AnchorStatus.KEY_INVALID


@pytest.mark.parametrize("ring", [
    b"not json",
    b'{"v": 1, "keys": []}',
    b'{"v": 2, "keys": [{"x": 1}]}',
])
def test_malformed_key_ring_is_invalid(w, ring):
    w.store.seal(w.log().path)
    w.keyring.path.write_bytes(ring)
    assert w.fresh().load().status is AnchorStatus.KEY_INVALID


def test_short_key_is_invalid(w):
    doc = json.loads(w.keyring.path.read_bytes())
    doc["keys"][0]["blob"] = base64.b64encode(FakeProtector().protect(b"short")).decode()
    w.keyring.path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(KeyInvalidError, match="wrong length"):
        Keyring(w.state, protector=w.protector).key(doc["keys"][0]["key_id"])


def test_key_rotation_keeps_old_anchors_verifiable(w):
    a = w.log("a.jsonl")
    w.store.seal(a.path)
    new_id = w.keygen(rotate=True, key=KEY_B)
    assert new_id == key_id_for(KEY_B)
    b = w.log("b.jsonl")
    w.store.seal(b.path)
    fresh = w.fresh()
    assert fresh.verify_log(a.path).status is AnchorStatus.VERIFIED  # old key, retired
    assert fresh.verify_log(b.path).status is AnchorStatus.VERIFIED
    ring = json.loads(w.keyring.path.read_bytes())["keys"]
    assert [(k["key_id"], k["status"]) for k in ring] == [
        (key_id_for(KEY_A), "retired"), (new_id, "active")]
    assert json.loads(w.store.witness_path.read_bytes())["key_id"] == new_id
    assert [json.loads(x)["key_id"] for x in w.anchor_lines()] == [key_id_for(KEY_A), new_id]


def test_rotation_refused_when_the_store_is_unsound(w):
    w.store.seal(w.log().path)
    shutil.rmtree(w.anchors_file.parent)
    before = w.keyring.path.read_bytes()
    with pytest.raises(AnchorError):
        w.keygen(rotate=True)
    assert w.keyring.path.read_bytes() == before


def test_keygen_refuses_when_a_key_exists(w):
    before = w.keyring.path.read_bytes()
    with pytest.raises(AnchorError, match="--rotate"):
        w.keygen()
    assert w.keyring.path.read_bytes() == before


def test_keygen_acl_runs_first_and_its_failure_writes_nothing(tmp_path):
    world = World(tmp_path)
    calls = []

    def failing_acl(directory: Path) -> None:
        calls.append(sorted(p.name for p in directory.iterdir()))
        raise KeyUnavailableError("acl failed")

    with pytest.raises(KeyUnavailableError):
        create_key(world.state, world.keyring, world.store, rotate=False, acl=failing_acl)
    assert calls == [[]]  # ran before anything was written into the keys folder
    assert not world.keyring.path.exists() and not world.store.witness_path.exists()


def test_first_keygen_writes_witness_before_the_key_ring(tmp_path, monkeypatch):
    world = World(tmp_path)
    real = keys_mod._atomic_write

    def crash(path, data):
        raise OSError("crash while writing the key ring")

    monkeypatch.setattr(keys_mod, "_atomic_write", crash)
    with pytest.raises(OSError):
        world.keygen()
    assert world.store.witness_path.exists() and not world.keyring.path.exists()
    # Not bricked: no anchors exist, so keygen may start over.
    monkeypatch.setattr(keys_mod, "_atomic_write", real)
    world.keygen()
    assert world.fresh().load().status is AnchorStatus.VERIFIED


def test_keygen_never_touches_the_real_state_dir(tmp_path):
    assert anchors_mod.state_dir() == tmp_path / "state"


# --- real DPAPI (throw-away test keys inside tmp_path) ---------------------------------------


@pytest.mark.skipif(not WINDOWS, reason="DPAPI is Windows-only")
class TestDpapi:
    def test_round_trip_is_user_scoped(self):
        p = keys_mod.DpapiProtector()
        blob = p.protect(KEY_A)
        assert KEY_A not in blob
        keys_mod.check_dpapi_blob(blob)  # current-user scope, sane header
        assert p.unprotect(blob) == KEY_A

    def test_corrupted_payload_is_refused(self):
        p = keys_mod.DpapiProtector()
        blob = bytearray(p.protect(KEY_A))
        blob[-5] ^= 0xFF
        with pytest.raises(KeyUnavailableError):
            p.unprotect(bytes(blob))

    def test_corrupted_header_is_invalid(self):
        p = keys_mod.DpapiProtector()
        blob = bytearray(p.protect(KEY_A))
        blob[6] ^= 0xFF  # provider GUID
        with pytest.raises(KeyInvalidError):
            p.unprotect(bytes(blob))

    def test_machine_scoped_blob_is_refused(self):
        p = keys_mod.DpapiProtector()
        blob = p.protect(KEY_A, flags=0x1 | 0x4)  # CRYPTPROTECT_LOCAL_MACHINE
        with pytest.raises(KeyInvalidError, match="machine-scoped"):
            p.unprotect(blob)

    def test_other_context_cannot_decrypt(self):
        """Stand-in for another user/app: different entropy. (A real second
        Windows account cannot be created offline; DPAPI CurrentUser scope is
        the documented boundary - ADR 0012.)"""
        blob = keys_mod.DpapiProtector().protect(KEY_A)
        with pytest.raises(KeyUnavailableError):
            keys_mod.DpapiProtector(entropy=b"another-context").unprotect(blob)

    def test_keyring_with_real_dpapi_and_store(self, tmp_path):
        world = World(tmp_path, protector=keys_mod.DpapiProtector())
        world.keygen()
        log = world.log()
        world.store.seal(log.path)
        assert world.fresh().verify_log(log.path).status is AnchorStatus.VERIFIED

    def test_real_acl_restricts_inheritance_and_keeps_owner_access(self, tmp_path):
        d = tmp_path / "keys"
        d.mkdir()
        keys_mod.restrict_windows_acl(d)
        (d / "probe").write_bytes(b"x")
        icacls = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "icacls.exe"
        out = subprocess.run([str(icacls), str(d)], capture_output=True, text=True,
                             check=True).stdout
        aces = [ln for ln in out.splitlines() if ":(" in ln]
        # Exactly two entries (this user + SYSTEM; account names are localized,
        # so compare structure, not names), full control, none inherited.
        assert len(aces) == 2, out
        assert all("(OI)(CI)(F)" in ln and "(I)" not in ln for ln in aces), out
        assert any("NT AUTHORITY\\" in ln for ln in aces), out
        user = os.environ.get("USERNAME", "")
        assert any(ln.rstrip().endswith(f"\\{user}:(OI)(CI)(F)") for ln in aces), out
        (d / "probe").unlink()  # the owner keeps full access


def test_non_windows_without_dpapi(tmp_path, monkeypatch):
    world = World(tmp_path)
    world.keygen(key=KEY_A)
    world.store.seal(world.log().path)
    monkeypatch.setattr(keys_mod, "dpapi_available", lambda: False)
    no_dpapi = AnchorStore(world.state, Keyring(world.state))  # real (unavailable) DPAPI
    assert no_dpapi.load().status is AnchorStatus.KEY_UNAVAILABLE
    with pytest.raises(KeyUnavailableError, match="DPAPI is not available"):
        keys_mod.DpapiProtector()
    fresh = World(tmp_path / "other")
    fresh.keyring = Keyring(fresh.state)
    fresh.store = AnchorStore(fresh.state, fresh.keyring)
    with pytest.raises(KeyUnavailableError):
        fresh.keygen()
    assert not fresh.keyring.path.exists()


# --- crash consistency, write failures, concurrency --------------------------------------------


def test_interrupted_anchor_write_fails_closed(w):
    log = w.log()
    w.store.seal(log.path)
    with w.anchors_file.open("ab") as fh:
        fh.write(b'{"anchor_seq":2,"v"')
    st = w.fresh().load()
    assert st.status is AnchorStatus.ANCHOR_CORRUPT and "incomplete" in st.detail
    assert _status(w, log) is AnchorStatus.ANCHOR_CORRUPT
    other = w.log("other.jsonl")
    with pytest.raises(AnchorError):
        w.store.seal(other.path)


def test_crash_after_anchor_before_witness_is_authenticated_and_repaired(w, monkeypatch):
    log = w.log()

    def crash(*a, **k):
        raise AnchorWriteError("simulated crash before the witness update")

    monkeypatch.setattr(AnchorStore, "_write_witness", crash)
    with pytest.raises(AnchorWriteError):
        w.store.seal(log.path)  # failure is reported, not ignored
    monkeypatch.undo()
    st = w.fresh().load()
    assert st.status is AnchorStatus.VERIFIED and st.notes and st.witness_seq == 0
    assert _status(w, log) is AnchorStatus.VERIFIED
    assert w.store.seal(log.path).anchor is None  # same head: only repairs the witness
    assert w.fresh().load().witness_seq == 1


def test_anchor_write_failure_is_reported_and_store_stays_consistent(w, monkeypatch):
    log = w.log()
    before = w.anchors_file.read_bytes()

    def boom(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(anchors_mod.os, "fsync", boom)
    with pytest.raises(AnchorWriteError, match="NOT sealed"):
        w.store.seal(log.path)
    monkeypatch.undo()
    # The partial anchor (bytes written, fsync failed) is complete and keyed,
    # or absent; either way the store stays consistent and fail-closed checks hold.
    st = w.fresh().load()
    assert st.status is AnchorStatus.VERIFIED
    assert w.anchors_file.read_bytes().startswith(before)


def test_crash_between_audit_append_and_seal(w):
    log = w.log(n=2)
    w.store.seal(log.path)
    log.record("tool_request_sent", {})  # process dies here, no seal
    assert _status(w, log) is AnchorStatus.UNANCHORED_TAIL


_SEALER = """
import sys, time
from pathlib import Path
from avra.storage.anchors import AnchorStore
from avra.storage.keys import StaticKeys
state, log, go = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
store = AnchorStore(state, StaticKeys([bytes.fromhex(sys.argv[4])]), lock_timeout=120)
while not go.exists():
    time.sleep(0.005)
store.seal(log)
"""


def test_concurrent_sealing_from_independent_processes(tmp_path):
    state, go = tmp_path / "state", tmp_path / "go"
    store = AnchorStore(state, StaticKeys([KEY_A]))
    store.initialize_witness(key_id_for(KEY_A), KEY_A)
    logs = []
    for k in range(5):
        log = AuditLog(tmp_path / f"log{k}.jsonl")
        for i in range(k + 1):
            log.record("e", {"i": i})
        logs.append(log.path)
    env = {**os.environ, "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}
    procs = [subprocess.Popen([sys.executable, "-c", _SEALER, str(state), str(p), str(go),
                               KEY_A.hex()], env=env, stderr=subprocess.PIPE, text=True)
             for p in [*logs, logs[0]]]  # log0 twice: one seals, one is a no-op
    time.sleep(0.5)
    go.write_text("go")
    for p in procs:
        _o, err = p.communicate(timeout=180)
        assert p.returncode == 0, err
    st = AnchorStore(state, StaticKeys([KEY_A])).load()
    assert st.status is AnchorStatus.VERIFIED and len(st.anchors) == 5
    assert [a.anchor_seq for a in st.anchors] == [1, 2, 3, 4, 5] and st.witness_seq == 5
    fresh = AnchorStore(state, StaticKeys([KEY_A]))
    assert all(fresh.verify_log(p).status is AnchorStatus.VERIFIED for p in logs)


# --- empty, legacy and historical logs -----------------------------------------------------------


def test_uninitialized_machine_reports_legacy(tmp_path):
    world = World(tmp_path)
    log = world.log()
    v = world.store.verify_log(log.path)
    assert v.status is AnchorStatus.LEGACY_UNANCHORED and v.exit_code == 2
    assert v.chain.ok and "not initialized" in v.detail
    assert not world.state.exists()  # verification created nothing


def test_initialized_but_unsealed_log_is_legacy(w):
    v = w.fresh().verify_log(w.log().path)
    assert v.status is AnchorStatus.LEGACY_UNANCHORED and "never sealed" in v.detail


def test_empty_and_missing_logs(w, tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    with pytest.raises(AnchorError, match="empty"):
        w.store.seal(empty)
    assert w.fresh().verify_log(tmp_path / "nope.jsonl").status is AnchorStatus.UNREADABLE
    with pytest.raises(AnchorError):
        w.store.seal(tmp_path / "nope.jsonl")


def test_unreadable_log(w, tmp_path):
    d = tmp_path / "dir.jsonl"
    d.mkdir()
    assert w.fresh().verify_log(d).status is AnchorStatus.UNREADABLE


def test_historical_logs_verify_as_legacy_without_being_touched(w):
    for p in sorted(FIXTURES.rglob("*.jsonl")):
        before = p.read_bytes()
        v = w.fresh().verify_log(p)
        assert v.chain.ok and v.status is AnchorStatus.LEGACY_UNANCHORED
        assert p.read_bytes() == before


def test_historical_report_compatibility_after_sealing(w, tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from avra.cli.main import app

    root = tmp_path / "data"
    shutil.copytree(FIXTURES, root)
    monkeypatch.setenv("AVRA_DATA_DIR", str(root))
    runner = CliRunner()
    sessions = sorted((root / "sessions").glob("*.jsonl"))
    before = {p.name: (p.read_bytes(), runner.invoke(app, ["report", "verify", p.stem]))
              for p in sessions}
    for p in sessions:
        w.store.seal(p)
    for p in sessions:
        old_bytes, old = before[p.name]
        new = runner.invoke(app, ["report", "verify", p.stem])
        assert p.read_bytes() == old_bytes  # sealing never writes the audit log
        assert (new.exit_code, new.output) == (old.exit_code, old.output)
        assert w.fresh().verify_log(p).status is AnchorStatus.VERIFIED


# --- no secrets anywhere --------------------------------------------------------------------------


def test_no_key_material_in_files_errors_or_reprs(w, tmp_path):
    log = w.log()
    w.store.seal(log.path)
    texts = [repr(w.keyring), repr(StaticKeys([KEY_A])), repr(w.store.load())]
    for f in [w.anchors_file, w.store.witness_path, w.keyring.path, log.path]:
        texts.append(f.read_bytes().decode("latin-1"))
    for broken in (lambda: AnchorStore(w.state, StaticKeys([KEY_B])).seal(log.path),
                   lambda: Keyring(w.state, protector=FakeProtector(b"X")).key(key_id_for(KEY_A)),
                   lambda: StaticKeys([b"short"])):
        try:
            broken()
        except Exception as exc:  # noqa: BLE001 - collecting messages
            texts.append(str(exc))
    blob = "\n".join(texts)
    for secret in (KEY_A.hex(), base64.b64encode(KEY_A).decode(), KEY_A.decode("latin-1")):
        assert secret not in blob


# --- CLI ---------------------------------------------------------------------------------------


@pytest.fixture
def cli(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from avra.cli import main

    world = World(tmp_path)
    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(main, "_audit_keyring", lambda state: Keyring(
        state, protector=world.protector, acl=_no_acl))
    world.sessions = tmp_path / "data" / "sessions"
    world.sessions.mkdir(parents=True)
    return world, CliRunner(), main.app


def _session(world, sid="11111111-1111-4111-8111-111111111111", n=2) -> Path:
    log = AuditLog(world.sessions / f"{sid}.jsonl")
    for i in range(n):
        log.record("e", {"i": i})
    return log.path


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file()}


def test_cli_keygen_refuses_without_a_terminal(cli, tmp_path):
    world, runner, app = cli
    result = runner.invoke(app, ["audit", "keygen"], input="y\n")
    assert result.exit_code == 2 and "Nothing created" in result.output
    assert not world.state.exists()


def test_cli_keygen_interactive(cli, monkeypatch):
    from avra.cli import main

    world, runner, app = cli
    monkeypatch.setattr(main, "_interactive", lambda: True)
    assert runner.invoke(app, ["audit", "keygen"], input="n\n").exit_code == 1
    assert not world.keyring.path.exists()
    result = runner.invoke(app, ["audit", "keygen"], input="y\n")
    assert result.exit_code == 0, result.output
    kid = Keyring(world.state, protector=world.protector).active_key_id()
    assert kid in result.output
    again = runner.invoke(app, ["audit", "keygen"], input="y\n")
    assert again.exit_code == 1 and "--rotate" in again.output


def test_cli_seal_verify_status_and_exit_codes(cli):
    world, runner, app = cli
    world.keygen(key=KEY_A)
    path = _session(world)
    sid = path.stem

    r = runner.invoke(app, ["audit", "verify", sid])
    assert r.exit_code == 2 and "LEGACY_UNANCHORED" in r.output
    assert "Hash chain:     valid" in r.output and "Anchor (HMAC):" in r.output

    r = runner.invoke(app, ["audit", "seal", sid])
    assert r.exit_code == 0 and "anchored as anchor 1" in r.output

    snapshot = {**_tree(world.state), **_tree(world.sessions)}
    r = runner.invoke(app, ["audit", "verify", sid])
    assert r.exit_code == 0 and "VERIFIED" in r.output
    r = runner.invoke(app, ["audit", "verify", "--all"])
    assert r.exit_code == 0
    r = runner.invoke(app, ["audit", "status"])
    assert r.exit_code == 0 and key_id_for(KEY_A) in r.output and "Anchors: 1" in r.output
    assert {**_tree(world.state), **_tree(world.sessions)} == snapshot  # read-only

    AuditLog(path).record("later", {})
    r = runner.invoke(app, ["audit", "verify", sid])
    assert r.exit_code == 2 and "UNANCHORED_TAIL" in r.output
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(lines[0])
    r = runner.invoke(app, ["audit", "verify", sid])
    assert r.exit_code == 1 and "TRUNCATED" in r.output
    r = runner.invoke(app, ["audit", "verify", "--all"])
    assert r.exit_code == 1
    for out in (r.output,):
        assert KEY_A.hex() not in out


def test_cli_verify_all_detects_a_deleted_anchored_log(cli):
    world, runner, app = cli
    world.keygen(key=KEY_A)
    path = _session(world)
    runner.invoke(app, ["audit", "seal", path.stem])
    path.unlink()
    r = runner.invoke(app, ["audit", "verify", "--all"])
    assert r.exit_code == 1 and "TRUNCATED" in r.output


def test_cli_status_and_verify_without_any_key(cli):
    world, runner, app = cli
    path = _session(world)
    r = runner.invoke(app, ["audit", "status"])
    assert r.exit_code == 2 and "not initialized" in r.output
    r = runner.invoke(app, ["audit", "verify", path.stem])
    assert r.exit_code == 2 and "LEGACY_UNANCHORED" in r.output
    r = runner.invoke(app, ["audit", "seal", path.stem])
    assert r.exit_code == 1 and "NOT sealed" in r.output
    assert not world.state.exists()  # nothing created implicitly


def test_cli_target_validation(cli):
    _world, runner, app = cli
    assert runner.invoke(app, ["audit", "verify"]).exit_code == 1
    assert runner.invoke(app, ["audit", "verify", "not-a-uuid"]).exit_code == 1
    assert runner.invoke(app, ["audit", "verify", "--all", "--log", "x"]).exit_code == 1
