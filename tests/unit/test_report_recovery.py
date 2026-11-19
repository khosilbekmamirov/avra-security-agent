"""M7.9.2R: controlled recovery of attested-but-unpublished reports.

Every case builds its own synthetic session in tmp_path: real AuditLog, real
store_report with publication forced to fail (so the report is attested and
RECOVERABLE), then exercises complete_publication() and `avra report recover`.
No network, no API, no scans, no project data.
"""

from __future__ import annotations

import hashlib
import os
import sys
import uuid
from pathlib import Path

import pytest
from typer.testing import CliRunner

from avra.cli import main as cli
from avra.reporting import (
    EvidenceConfidence,
    ExecutionStatus,
    ReportScope,
    ResearchCoverage,
    ResearchReport,
    ValidationResult,
    Verdict,
    store,
)
from avra.reporting.replay import verify_session
from avra.reporting.store import (
    EVENT_GENERATED,
    EVENT_PUBLICATION_COMPLETED,
    EVENT_RECOVERY_AUTHORIZED,
    EVENT_RECOVERY_FAILED,
    PublicationState,
    RecoveryStatus,
    ReportStoreError,
    complete_publication,
    recovery_candidates,
    report_states,
    store_report,
    unfinished_recoveries,
)
from avra.storage.audit import AuditLog

PASS = ValidationResult(verdict=Verdict.PASS)
OK = "owner approved (test)"


class Crash(BaseException):
    """The process dies (not an OSError the code could handle)."""


def _report(sid, summary):
    return ResearchReport(
        session_id=str(sid), objective="o",
        scope=ReportScope(session_name="lab", expires_at="2026-12-31T23:59:59+00:00",
                          targets=()),
        tool_runs=(), verified_facts=(), model_observations=(), hypotheses=(),
        errors_and_limitations=(), execution_status=ExecutionStatus.COMPLETED,
        coverage=ResearchCoverage.NOT_EVALUATED,
        evidence_confidence=EvidenceConfidence.INCONCLUSIVE, model_summary=summary)


def _no_link(*a, **k):
    raise OSError("publication unavailable")


class Session:
    def __init__(self, tmp_path: Path, n: int = 1):
        self.root = tmp_path / "data"
        self.dir = self.root / "sessions"
        self.sid = uuid.uuid4()
        self.audit = AuditLog(self.dir / f"{self.sid}.jsonl")
        self.audit.record("session_created", {})
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(store, "_link", _no_link)
            for i in range(n):
                self.audit.record("research_started", {})
                self.audit.record("research_stopped", {})
                with pytest.raises(ReportStoreError, match="NOT published"):
                    store_report(_report(self.sid, f"run {i}"), PASS, audit=self.audit,
                                 session_id=self.sid, directory=self.dir)
        self.pending = recovery_candidates(self.audit, self.dir)
        assert len(self.pending) == n

    def pair(self, i=0):
        return (self.pending[i].event_seq, self.pending[i].sha256)

    def temp(self, i=0):
        return self.dir / self.pending[i].temp_file

    def final(self, i=0):
        return self.dir / self.pending[i].report_file

    def events(self, name):
        return [r for r in self.audit.read_all() if r.event == name]

    def tree(self):
        out = {}
        for dirpath, dirnames, filenames in os.walk(self.root.parent):
            for name in dirnames + filenames:
                p = Path(dirpath) / name
                st = os.lstat(p)
                out[str(p.relative_to(self.root.parent))] = (
                    hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file()
                    and not p.is_symlink() else f"other:{st.st_mode}")
        return out

    def recover(self, *pairs, confirmation=OK):
        return complete_publication(self.audit, self.dir, authorized=frozenset(pairs),
                                    confirmation=confirmation)


@pytest.fixture
def s(tmp_path):
    return Session(tmp_path)


# --- exact authorization ----------------------------------------------------------------

def test_authorization_is_mandatory(s):
    with pytest.raises(TypeError):
        complete_publication(s.audit, s.dir)  # no default authorization exists


@pytest.mark.parametrize("bad", [
    {(2, "a" * 64)},                     # mutable set
    [(2, "a" * 64)],                     # list
    frozenset({(True, "a" * 64)}),       # bool is not a seq
    frozenset({(2, "a" * 63)}),          # short hash
    frozenset({(2, "A" * 64)}),          # upper-case hex
    frozenset({("2", "a" * 64)}),        # seq as text
    frozenset({(0, "a" * 64)}),          # seq < 1
    frozenset({(2, "a" * 64, "x")}),     # wrong arity
])
def test_malformed_authorization_is_rejected_before_anything(s, bad):
    before = s.tree()
    with pytest.raises(ReportStoreError, match="authorization"):
        complete_publication(s.audit, s.dir, authorized=bad, confirmation=OK)
    assert s.tree() == before


def test_conflicting_unknown_or_mismatched_authorization_rejected(s):
    seq, sha = s.pair()
    before = s.tree()
    for pairs, why in (({(seq, sha), (seq, "b" * 64)}, "conflicting"),
                       ({(999, sha)}, "unknown"),
                       ({(seq, "b" * 64)}, "does not match")):
        with pytest.raises(ReportStoreError, match=why):
            complete_publication(s.audit, s.dir, authorized=frozenset(pairs), confirmation=OK)
    assert s.tree() == before


def test_missing_confirmation_rejected(s):
    with pytest.raises(ReportStoreError, match="confirmation"):
        s.recover(s.pair(), confirmation="  ")
    assert not s.final().exists()


def test_empty_authorization_does_nothing(s):
    before = s.tree()
    assert s.recover() == []
    assert s.tree() == before


def test_exact_authorized_entry_is_published_and_audited(s):
    seq, sha = s.pair()
    [o] = s.recover((seq, sha))
    assert o.status is RecoveryStatus.PUBLISHED and o.report_file == s.pending[0].report_file
    assert hashlib.sha256(s.final().read_bytes()).hexdigest() == sha
    assert not s.temp().exists() and os.lstat(s.final()).st_nlink == 1
    [auth] = s.events(EVENT_RECOVERY_AUTHORIZED)
    [done] = s.events(EVENT_PUBLICATION_COMPLETED)
    assert auth.data == {"report_generated_seq": seq, "report_file": o.report_file,
                         "sha256": sha, "owner_confirmed": True, "confirmation": OK}
    assert done.data["recovery_authorized_seq"] == auth.seq == o.authorization_seq
    assert o.completion_seq == done.seq and s.audit.verify()
    assert report_states(s.audit, s.dir)[0].state is PublicationState.PUBLISHED
    assert unfinished_recoveries(s.audit) == []


def test_only_authorized_entries_are_processed(tmp_path):
    s = Session(tmp_path, n=3)
    outcomes = s.recover(s.pair(1))
    assert [o.event_seq for o in outcomes] == [s.pending[1].event_seq]
    states = {st.event_seq: st.state for st in report_states(s.audit, s.dir)}
    assert states[s.pending[1].event_seq] is PublicationState.PUBLISHED
    assert states[s.pending[0].event_seq] is PublicationState.RECOVERABLE  # not approved
    assert states[s.pending[2].event_seq] is PublicationState.RECOVERABLE


def test_forged_traversal_event_cannot_be_authorized(s):
    outside = s.root.parent / "outside.txt"
    outside.write_bytes(b"outside")
    forged = s.audit.record(EVENT_GENERATED, {
        "report_file": "../moved.json", "temp_file": "../outside.txt",
        "sha256": hashlib.sha256(b"outside").hexdigest(), "size": 7,
        "research_started_seq": 2, "research_stopped_seq": 3,
        "research_stopped_hash": s.audit.read_all()[2].hash})
    before = s.tree()
    with pytest.raises(ReportStoreError, match="does not match"):
        s.recover((forged.seq, hashlib.sha256(b"outside").hexdigest()))
    assert s.tree() == before and outside.exists()


# --- changes after approval: refused, nothing overwritten ---------------------------------

def test_source_changed_after_approval_is_refused(s):
    pair = s.pair()
    s.temp().write_bytes(b"swapped content")
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.REFUSED and "changed since approval" in o.detail
    assert not s.final().exists() and not s.events(EVENT_RECOVERY_AUTHORIZED)


def test_final_name_appearing_is_never_overwritten(s):
    pair = s.pair()
    s.final().write_bytes(b"someone else's report")
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.REFUSED
    assert s.final().read_bytes() == b"someone else's report"


def test_final_name_appearing_during_publication(s, monkeypatch):
    pair, final = s.pair(), s.final()
    real = store._link

    def racing(src, dst, **kw):
        final.write_bytes(b"raced in")
        return real(src, dst, **kw)

    monkeypatch.setattr(store, "_link", racing)
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.FAILED and "nothing overwritten" in o.detail
    assert final.read_bytes() == b"raced in" and s.temp().exists()
    [failed] = s.events(EVENT_RECOVERY_FAILED)
    assert failed.data["stage"] == "link" and not s.events(EVENT_PUBLICATION_COMPLETED)


@pytest.mark.skipif(os.name != "nt", reason="Windows share-mode semantics")
def test_held_source_cannot_be_renamed_or_deleted_on_windows(s, monkeypatch):
    """While recovery holds the verified source open (no delete sharing), the
    temp NAME cannot be swapped or removed — the path-based link sees the file
    that was verified."""
    pair, temp = s.pair(), s.temp()
    real = store._link

    def attempt_swap_then_link(src, dst, **kw):
        with pytest.raises(PermissionError):
            os.replace(temp, temp.with_name("orig.bin"))
        with pytest.raises(PermissionError):
            temp.unlink()
        return real(src, dst, **kw)

    monkeypatch.setattr(store, "_link", attempt_swap_then_link)
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.PUBLISHED
    assert hashlib.sha256(s.final().read_bytes()).hexdigest() == pair[1]


@pytest.mark.skipif(os.name != "posix", reason="POSIX rename semantics")
def test_name_swap_is_irrelevant_with_handle_link_on_posix(s, monkeypatch):
    pair, temp = s.pair(), s.temp()
    attested = temp.read_bytes()
    real = store._link

    def swap_then_link(src, dst, **kw):
        os.replace(temp, temp.with_name("orig.bin"))
        temp.write_bytes(b"attacker bytes")
        return real(src, dst, **kw)

    monkeypatch.setattr(store, "_link", swap_then_link)
    [o] = s.recover(pair)
    if not store._PROC_FD.is_dir():
        assert o.status is RecoveryStatus.FAILED  # no /proc: path link, swap detected
    else:
        assert o.status is RecoveryStatus.PUBLISHED  # linked the OPEN, verified file
        assert s.final().read_bytes() == attested


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc semantics")
def test_linux_proc_fd_link_publishes_the_open_file(tmp_path):
    """Integration (Linux only): linkat(/proc/self/fd/N, AT_SYMLINK_FOLLOW)
    creates a hard link to the OPEN file, even after its name was swapped, and
    never replaces an existing destination."""
    src, dst = tmp_path / "src.tmp", tmp_path / "dst.json"
    src.write_bytes(b"verified bytes")
    fd = os.open(src, os.O_RDONLY)
    try:
        held = os.fstat(fd)
        os.replace(src, tmp_path / "moved.tmp")
        src.write_bytes(b"attacker bytes")
        store._link_from_handle(fd, src, dst)
        with pytest.raises(FileExistsError):
            store._link_from_handle(fd, src, dst)
    finally:
        os.close(fd)
    assert (os.lstat(dst).st_dev, os.lstat(dst).st_ino) == (held.st_dev, held.st_ino)
    assert dst.read_bytes() == b"verified bytes"


def test_non_linux_uses_path_link(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(store.sys, "platform", "win32")
    monkeypatch.setattr(store, "_link", lambda *a, **k: calls.append((a, k)))
    store._link_from_handle(99, tmp_path / "t", tmp_path / "f")
    assert calls == [((tmp_path / "t", tmp_path / "f"), {})]


def test_in_place_modification_before_link_is_detected(s, monkeypatch):
    """The one window left on every platform: the held file is rewritten in
    place. The post-link proof (same file AND same bytes) catches it; nothing
    is deleted and nothing is claimed as recovered."""
    pair, temp = s.pair(), s.temp()
    real = store._link

    def rewrite_then_link(src, dst, **kw):
        with open(temp, "r+b") as fh:
            fh.write(b"X")
        return real(src, dst, **kw)

    monkeypatch.setattr(store, "_link", rewrite_then_link)
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.FAILED and "not deleted" in o.detail
    assert s.final().exists() and temp.exists()  # nothing removed
    [failed] = s.events(EVENT_RECOVERY_FAILED)
    assert failed.data["stage"] == "verify" and not s.events(EVENT_PUBLICATION_COMPLETED)
    assert report_states(s.audit, s.dir)[0].state is PublicationState.CONFLICT


def test_hardlinked_source_is_refused(s):
    pair, temp = s.pair(), s.temp()
    os.link(temp, s.root.parent / "extra-link.bin")
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.REFUSED and not s.final().exists()


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions")
def test_junction_source_is_refused(s):
    import _winapi

    pair, temp = s.pair(), s.temp()
    target = s.root.parent / "outside-dir"
    target.mkdir()
    os.replace(temp, temp.with_name("orig.bin"))
    _winapi.CreateJunction(str(target), str(temp))
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.REFUSED and not s.final().exists()
    assert list(target.iterdir()) == []


def test_symlink_source_is_refused(s):
    pair, temp = s.pair(), s.temp()
    outside = s.root.parent / "outside.bin"
    outside.write_bytes(temp.read_bytes())
    os.replace(temp, temp.with_name("orig.bin"))
    try:
        os.symlink(outside, temp)
    except OSError:
        pytest.skip("creating symlinks needs a privilege on this system")
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.REFUSED and not s.final().exists()


def test_open_verified_detects_replacement_between_lstat_and_open(s, monkeypatch):
    temp, sha = s.temp(), s.pair()[1]
    real_open = os.open

    def swapping_open(path, flags, *a):
        if Path(path) == temp:
            os.replace(temp, temp.with_name("orig.bin"))
            temp.write_bytes(temp.with_name("orig.bin").read_bytes())  # new file, same bytes
        return real_open(path, flags, *a)

    monkeypatch.setattr(store.os, "open", swapping_open)
    with pytest.raises(store._Changed, match="replaced between check and open"):
        store._open_verified(temp, sha, single_link=True)


# --- crash and audit-failure handling -----------------------------------------------------

def _fail_record_on(audit, event, exc):
    real = audit.record

    def record(name, data=None):
        if name == event:
            raise exc
        return real(name, data)

    audit.record = record


def test_authorization_audit_failure_publishes_nothing(s):
    pair = s.pair()
    _fail_record_on(s.audit, EVENT_RECOVERY_AUTHORIZED, OSError("disk"))
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.FAILED and "nothing published" in o.detail
    assert not s.final().exists() and s.temp().exists()


def test_completion_audit_failure_is_never_reported_as_audited(s):
    pair = s.pair()
    _fail_record_on(s.audit, EVENT_PUBLICATION_COMPLETED, OSError("disk"))
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.PUBLISHED_UNAUDITED and o.completion_seq is None
    assert hashlib.sha256(s.final().read_bytes()).hexdigest() == pair[1]
    assert unfinished_recoveries(s.audit) == [o.authorization_seq]
    assert recovery_candidates(s.audit, s.dir) == []  # published; nothing more to do
    # never represented as a fully audited publication
    assert report_states(s.audit, s.dir)[0].state is \
        PublicationState.PUBLISHED_RECOVERY_UNAUDITED
    # and a repeated recovery cannot "fix" it by re-publishing or overwriting
    before = s.tree()
    [again] = s.recover(pair)
    assert again.status is RecoveryStatus.REFUSED and s.tree() == before


def _authorized_but_open(s):
    """An approved recovery whose completion record failed to be written."""
    pair = s.pair()
    real = s.audit.record

    def fail_completion(name, data=None):
        if name == EVENT_PUBLICATION_COMPLETED:
            raise OSError("disk")
        return real(name, data)

    s.audit.record = fail_completion
    [o] = s.recover(pair)
    s.audit.record = real
    assert o.status is RecoveryStatus.PUBLISHED_UNAUDITED
    return pair, o.authorization_seq


@pytest.mark.parametrize("forge", ["wrong_sha", "wrong_report", "not_int", "unknown_auth"])
def test_forged_or_mismatched_completion_cannot_close_an_authorization(s, forge):
    (seq, sha), auth = _authorized_but_open(s)
    data = {"report_generated_seq": seq, "report_file": "x", "sha256": sha,
            "recovery_authorized_seq": auth}
    if forge == "wrong_sha":
        data["sha256"] = "b" * 64
    elif forge == "wrong_report":
        data["report_generated_seq"] = seq + 100
    elif forge == "not_int":
        data["recovery_authorized_seq"] = str(auth)
    else:
        data["recovery_authorized_seq"] = auth + 1000
    s.audit.record(EVENT_PUBLICATION_COMPLETED, data)
    assert unfinished_recoveries(s.audit) == [auth], forge
    assert report_states(s.audit, s.dir)[0].state is \
        PublicationState.PUBLISHED_RECOVERY_UNAUDITED


def test_completion_recorded_before_its_authorization_does_not_close_it(s):
    (seq, sha), auth = _authorized_but_open(s)
    next_seq = s.audit.read_all()[-1].seq + 1
    # A completion that names the authorization which will be written right after it.
    s.audit.record(EVENT_PUBLICATION_COMPLETED, {"report_generated_seq": seq, "sha256": sha,
                                                 "recovery_authorized_seq": next_seq + 1})
    later = s.audit.record(EVENT_RECOVERY_AUTHORIZED, {"report_generated_seq": seq,
                                                       "sha256": sha})
    assert later.seq == next_seq + 1
    assert unfinished_recoveries(s.audit) == [auth, later.seq]


def test_matching_completion_closes_the_authorization(s):
    (seq, sha), auth = _authorized_but_open(s)
    s.audit.record(EVENT_PUBLICATION_COMPLETED, {"report_generated_seq": seq, "sha256": sha,
                                                 "recovery_authorized_seq": auth})
    assert unfinished_recoveries(s.audit) == []
    assert report_states(s.audit, s.dir)[0].state is PublicationState.PUBLISHED


def test_cli_lists_unaudited_recovery_as_untouched(s, monkeypatch):
    _authorized_but_open(s)
    before = s.tree()
    r = _cli(s, monkeypatch)
    assert r.exit_code == 2 and "published_recovery_unaudited" in r.output
    assert "has no completion or failure record" in r.output
    assert s.tree() == before


def test_link_failure_is_audited_and_later_recoverable(s, monkeypatch):
    pair = s.pair()
    monkeypatch.setattr(store, "_link", _no_link)
    [o] = s.recover(pair)
    assert o.status is RecoveryStatus.FAILED and s.temp().exists()
    [failed] = s.events(EVENT_RECOVERY_FAILED)
    assert failed.data["recovery_authorized_seq"] == o.authorization_seq
    assert unfinished_recoveries(s.audit) == []  # a recorded failure resolves it
    assert report_states(s.audit, s.dir)[0].state is PublicationState.RECOVERABLE
    monkeypatch.undo()
    assert recovery_candidates(s.audit, s.dir)[0].event_seq == pair[0]
    [again] = s.recover(pair)
    assert again.status is RecoveryStatus.PUBLISHED


def test_crash_after_authorization_before_link(s, monkeypatch):
    pair = s.pair()

    def crash(*a, **k):
        raise Crash()

    monkeypatch.setattr(store, "_link", crash)
    with pytest.raises(Crash):
        s.recover(pair)
    monkeypatch.undo()
    assert len(unfinished_recoveries(s.audit)) == 1 and not s.final().exists()
    [o] = s.recover(pair)  # owner re-approves: works, nothing was half-done
    assert o.status is RecoveryStatus.PUBLISHED


def test_crash_after_link_before_completion(s):
    pair = s.pair()
    _fail_record_on(s.audit, EVENT_PUBLICATION_COMPLETED, Crash())
    with pytest.raises(Crash):
        s.recover(pair)
    assert hashlib.sha256(s.final().read_bytes()).hexdigest() == pair[1]
    assert len(unfinished_recoveries(s.audit)) == 1  # visible, never claimed as audited
    st = report_states(s.audit, s.dir)[0]
    assert st.state is PublicationState.PUBLISHED_RECOVERY_UNAUDITED
    assert "no matching completion" in st.detail


def test_partial_recovery_stops_at_first_problem(tmp_path):
    s = Session(tmp_path, n=3)
    pairs = [s.pair(i) for i in range(3)]
    s.temp(1).write_bytes(b"tampered")
    outcomes = s.recover(*pairs)
    assert [o.status for o in outcomes] == [RecoveryStatus.PUBLISHED, RecoveryStatus.REFUSED,
                                            RecoveryStatus.NOT_ATTEMPTED]
    assert s.final(0).exists() and not s.final(1).exists() and not s.final(2).exists()
    assert recovery_candidates(s.audit, s.dir)[0].event_seq == pairs[2][0]


def test_repeated_recovery_is_idempotent(s):
    pair = s.pair()
    assert s.recover(pair)[0].status is RecoveryStatus.PUBLISHED
    before, events = s.tree(), len(s.audit.read_all())
    for _ in range(2):
        [o] = s.recover(pair)
        assert o.status is RecoveryStatus.REFUSED and "now published" in o.detail
    assert s.tree() == before and len(s.audit.read_all()) == events


# --- CLI ------------------------------------------------------------------------------------

def _cli(s, monkeypatch, answers=None, interactive=True, args=None):
    monkeypatch.setenv("AVRA_DATA_DIR", str(s.root))
    monkeypatch.setattr(cli, "_interactive", lambda: interactive)
    return CliRunner().invoke(cli.app, args or ["report", "recover", str(s.sid)],
                              input=answers)


def test_cli_requires_a_terminal(s, monkeypatch):
    before = s.tree()
    r = _cli(s, monkeypatch, answers="y\n", interactive=False)
    assert r.exit_code == 2 and "interactive terminal" in r.output
    assert s.tree() == before


def test_cli_real_non_tty_is_refused(s, monkeypatch):
    monkeypatch.setenv("AVRA_DATA_DIR", str(s.root))
    r = CliRunner().invoke(cli.app, ["report", "recover", str(s.sid)], input="y\n")
    assert r.exit_code == 2 and not s.final().exists()


@pytest.mark.parametrize("answer", ["\n", "n\n", "no\n"])
def test_cli_default_and_explicit_no_publish_nothing(s, monkeypatch, answer):
    before = s.tree()
    r = _cli(s, monkeypatch, answers=answer)
    assert r.exit_code == 2 and "Nothing approved; nothing done." in r.output
    assert s.tree() == before


def test_cli_has_no_yes_option(s, monkeypatch):
    r = _cli(s, monkeypatch, args=["report", "recover", "--yes", str(s.sid)])
    assert r.exit_code == 2 and not s.final().exists()


def test_cli_per_report_confirmation_shows_full_hash(tmp_path, monkeypatch):
    s = Session(tmp_path, n=2)
    r = _cli(s, monkeypatch, answers="y\nn\n")
    assert r.exit_code == 0, r.output
    for st in s.pending:
        assert f"sha256: {st.sha256}" in r.output and st.report_file in r.output
    assert s.final(0).exists() and not s.final(1).exists()
    assert "PUBLISHED" in r.output
    assert recovery_candidates(s.audit, s.dir)[0].event_seq == s.pending[1].event_seq


def test_cli_entry_changed_after_approval_is_refused(s, monkeypatch):
    real_confirm = cli.typer.confirm

    def confirm_then_tamper(*a, **k):
        answer = real_confirm(*a, **k)
        s.temp().write_bytes(b"changed after the owner said yes")
        return answer

    monkeypatch.setattr(cli.typer, "confirm", confirm_then_tamper)
    r = _cli(s, monkeypatch, answers="y\n")
    assert r.exit_code == 1 and "REFUSED" in r.output and not s.final().exists()


def test_cli_lists_unrecoverable_entries_untouched(s, monkeypatch):
    s.audit.record(EVENT_GENERATED, {"report_file": "../x.json"})
    before = s.tree()
    r = _cli(s, monkeypatch, answers="n\n")
    assert "Not recoverable (left untouched)" in r.output and "invalid_event" in r.output
    assert s.tree() == before


def test_cli_nothing_to_recover(s, monkeypatch):
    s.recover(s.pair())
    r = _cli(s, monkeypatch)
    assert r.exit_code == 2 and "Nothing to recover." in r.output


def test_cli_reports_unfinished_recovery(s, monkeypatch):
    pair = s.pair()
    _fail_record_on(s.audit, EVENT_PUBLICATION_COMPLETED, OSError("disk"))
    s.recover(pair)
    s.audit = AuditLog(s.audit.path)
    r = _cli(s, monkeypatch)
    assert "has no completion or failure record" in r.output


# --- compatibility and read-only guarantees --------------------------------------------------

def test_legacy_report_is_never_touched(s, monkeypatch):
    legacy = s.dir / f"{s.sid}.report.json"
    legacy.write_bytes(b'{\r\n  "legacy": true\r\n}')
    _cli(s, monkeypatch, answers="y\n")
    assert legacy.read_bytes() == b'{\r\n  "legacy": true\r\n}'


def test_verify_never_recovers_and_stays_read_only(s):
    before = s.tree()
    sc = verify_session(s.dir, s.root / "evidence", s.sid)
    assert not sc.verified
    assert s.tree() == before and not s.final().exists()
    assert recovery_candidates(s.audit, s.dir)[0].state is PublicationState.RECOVERABLE
