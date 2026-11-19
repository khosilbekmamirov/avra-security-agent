"""M7.9.1: attested, immutable report storage (D2, D6).

Synthetic reports and audit logs in tmp_path only; faults are injected
through the store module's own indirections (``_open``/``_write``/``_fsync``
/``_link``) — never by touching real project data.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path

import pytest
import typer

from avra.cli import main as cli
from avra.core.research import ResearchResult, StopReason
from avra.core.snapshot import scope_snapshot, snapshot_sha256
from avra.llm.config import Spend
from avra.reporting import (
    EvidenceConfidence,
    ExecutionStatus,
    Note,
    ReportScope,
    ReportTarget,
    ResearchCoverage,
    ResearchReport,
    ValidationResult,
    Verdict,
    store,
)
from avra.reporting.store import (
    EVENT_GENERATED,
    EVENT_PUBLICATION_COMPLETED,
    EVENT_PUBLISH_FAILED,
    PublicationState,
    ReportStoreError,
    complete_publication,
    report_filename,
    report_states,
    serialize_report,
    store_report,
)
from avra.schemas.scope import Scope
from avra.storage.audit import AuditLog

PASS = ValidationResult(verdict=Verdict.PASS)


class Crash(BaseException):
    """Simulates the process dying (not an OSError the store could handle)."""


def _report(sid: uuid.UUID, summary: str = "done") -> ResearchReport:
    return ResearchReport(
        session_id=str(sid), objective="Which services are exposed?",
        scope=ReportScope(session_name="lab", expires_at="2026-12-31T23:59:59+00:00",
                          targets=(ReportTarget(host="10.66.7.103", ports=(3000,),
                                                tiers=("active-safe",),
                                                tools=("nmap_connect_scan",),
                                                description="Juice Shop — lab VM"),)),
        tool_runs=(), verified_facts=(), model_observations=(),
        hypotheses=(Note(step=1, text="line one\r\nline two ü"),),
        errors_and_limitations=(), execution_status=ExecutionStatus.COMPLETED,
        coverage=ResearchCoverage.NOT_EVALUATED,
        evidence_confidence=EvidenceConfidence.INCONCLUSIVE, model_summary=summary)


def _run(audit: AuditLog, sid: uuid.UUID) -> None:
    """Append one synthetic research run (as ResearchSession.run would)."""
    audit.record("research_started", {"session_id": str(sid), "prompt_version": "m7-v2"})
    audit.record("llm_call", {"step": 1, "cost_usd": 0.01})
    audit.record("research_stopped", {"stop_reason": "finished", "total_cost_usd": 0.01})


@pytest.fixture
def session(tmp_path):
    sid = uuid.uuid4()
    directory = tmp_path / "sessions"
    audit = AuditLog(directory / f"{sid}.jsonl")
    audit.record("session_created", {"session_id": str(sid)})
    _run(audit, sid)
    return sid, audit, directory


def _events(audit, name):
    return [r for r in audit.read_all() if r.event == name]


def _files(directory):
    return sorted(p.name for p in directory.iterdir() if not p.name.endswith(".jsonl"))


def _recover_all(audit, directory):
    """Authorize exactly the entries that are RECOVERABLE right now (what an
    owner approving everything shown would do); return the published names."""
    from avra.reporting.store import RecoveryStatus, recovery_candidates
    approved = frozenset((st.event_seq, st.sha256)
                         for st in recovery_candidates(audit, directory))
    outcomes = complete_publication(audit, directory, authorized=approved,
                                    confirmation="test: approve all shown")
    return [o.report_file for o in outcomes if o.status is RecoveryStatus.PUBLISHED]


# --- serialization (D6) -------------------------------------------------------

def test_serialization_is_deterministic_utf8_lf_only():
    sid = uuid.uuid4()
    a, b = serialize_report(_report(sid)), serialize_report(_report(sid))
    assert a == b
    assert b"\r" not in a  # a CRLF inside a field is JSON-escaped, never raw
    assert a.endswith(b"}\n")
    assert "—".encode() in a and "ü".encode() in a  # real UTF-8, not \u escapes
    assert json.loads(a) == _report(sid).canonical_dict()
    assert "port_exposure" not in json.loads(a)  # schema-1 report: no schema-3 keys


def test_stored_bytes_and_hash_are_exact(session):
    sid, audit, directory = session
    stored = store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    raw = stored.path.read_bytes()
    assert raw == serialize_report(_report(sid))
    assert b"\r\n" not in raw  # the Windows text-mode CRLF bug (D6) is gone
    assert hashlib.sha256(raw).hexdigest() == stored.sha256
    assert stored.size == len(raw)
    assert stored.path.name == report_filename(sid, 2) == f"{sid}.run2.report.json"
    assert stored.temp_left is None
    assert _files(directory) == [stored.path.name]  # temp name dropped


def test_report_generated_event_and_chain(session):
    sid, audit, directory = session
    v = ValidationResult(verdict=Verdict.INCOMPLETE, reasons=("coverage gap",))
    stored = store_report(_report(sid), v, audit=audit, session_id=sid, directory=directory)
    assert audit.verify()
    recs = audit.read_all()
    ev = recs[-1]
    assert ev.event == EVENT_GENERATED and ev.seq == stored.audit_seq
    stopped = recs[-2]
    assert stopped.event == "research_stopped"
    assert ev.data == {
        "report_file": stored.path.name, "temp_file": ev.data["temp_file"],
        "sha256": stored.sha256, "size": stored.size, "store_format": 1,
        "serialization": store.SERIALIZATION, "verdict": "INCOMPLETE",
        "reasons": ["coverage gap"], "research_started_seq": 2,
        "research_stopped_seq": stopped.seq, "research_stopped_hash": stopped.hash,
    }
    assert ev.data["temp_file"].startswith(f".{stored.path.name}.")
    assert report_states(audit, directory)[0].state is PublicationState.PUBLISHED


# --- no overwrite, one report per run ------------------------------------------

def test_existing_report_is_never_overwritten(session):
    sid, audit, directory = session
    final = directory / report_filename(sid, 2)
    final.write_bytes(b"someone else's bytes")
    with pytest.raises(ReportStoreError, match="already exists"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    assert final.read_bytes() == b"someone else's bytes"
    assert not _events(audit, EVENT_GENERATED)
    assert _files(directory) == [final.name]


def test_publish_race_never_overwrites(session, monkeypatch):
    sid, audit, directory = session
    final = directory / report_filename(sid, 2)
    real_link = store._link

    def racing_link(src, dst, **kw):
        final.write_bytes(b"raced in")  # appears between the check and the link
        return real_link(src, dst)

    monkeypatch.setattr(store, "_link", racing_link)
    with pytest.raises(ReportStoreError, match="NOT published"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    assert final.read_bytes() == b"raced in"
    assert len(_events(audit, EVENT_PUBLISH_FAILED)) == 1
    [st] = report_states(audit, directory)
    assert st.state is PublicationState.CONFLICT
    assert (directory / st.temp_file).read_bytes() == serialize_report(_report(sid))
    assert _recover_all(audit, directory) == []  # never resolves a conflict by force
    assert final.read_bytes() == b"raced in"


def test_second_report_for_the_same_run_is_refused(session):
    sid, audit, directory = session
    store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    # A report_generated record is now last, so the run is no longer "just finished".
    with pytest.raises(ReportStoreError, match="not research_stopped"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)


def test_already_reported_run_is_refused_even_if_stopped_is_last(tmp_path):
    sid = uuid.uuid4()
    audit = AuditLog(tmp_path / f"{sid}.jsonl")
    audit.record("research_started", {})
    audit.record(EVENT_GENERATED, {"research_started_seq": 1})
    audit.record("research_stopped", {})
    with pytest.raises(ReportStoreError, match="already generated"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=tmp_path)


def test_resumed_session_gets_a_separate_report(session):
    sid, audit, directory = session
    first = store_report(_report(sid, "run 1"), PASS, audit=audit, session_id=sid,
                         directory=directory)
    _run(audit, sid)  # `avra research --session <sid>` again
    second = store_report(_report(sid, "run 2"), PASS, audit=audit, session_id=sid,
                          directory=directory)
    assert first.path != second.path
    assert first.path.name == f"{sid}.run2.report.json"
    assert second.path.name == f"{sid}.run6.report.json"
    assert json.loads(first.path.read_bytes())["model_summary"] == "run 1"
    assert json.loads(second.path.read_bytes())["model_summary"] == "run 2"
    assert audit.verify()
    assert [s.state for s in report_states(audit, directory)] == [PublicationState.PUBLISHED] * 2


# --- fail closed before anything is written -----------------------------------

def test_broken_chain_refuses(session):
    sid, audit, directory = session
    text = audit.path.read_text(encoding="utf-8").replace('"m7-v2"', '"m7-v9"')
    audit.path.write_text(text, encoding="utf-8")
    with pytest.raises(ReportStoreError, match="does not verify"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    assert _files(directory) == []


def test_run_must_have_finished(session):
    sid, audit, directory = session
    audit.record("llm_call", {"step": 2})
    with pytest.raises(ReportStoreError, match="not research_stopped"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    assert _files(directory) == []


def test_session_id_mismatch_refused(session):
    sid, audit, directory = session
    with pytest.raises(ReportStoreError, match="session_id"):
        store_report(_report(uuid.uuid4()), PASS, audit=audit, session_id=sid,
                     directory=directory)
    assert _files(directory) == []


# --- failures before attestation: no claim, nothing published, temp kept ------

def test_temp_create_failure(session, monkeypatch):
    sid, audit, directory = session

    def boom(*a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(store, "_open", boom)
    with pytest.raises(ReportStoreError, match="NOT attested"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    assert _files(directory) == [] and not _events(audit, EVENT_GENERATED)


@pytest.mark.parametrize("fault", ["_write", "_fsync"])
def test_write_or_fsync_failure_keeps_temp_and_makes_no_claim(session, monkeypatch, fault):
    sid, audit, directory = session

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(store, fault, boom)
    with pytest.raises(ReportStoreError, match="NOT attested.*temp file kept"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    left = _files(directory)
    assert len(left) == 1 and left[0].endswith(".tmp")  # kept, not silently deleted
    assert not (directory / report_filename(sid, 2)).exists()
    assert not _events(audit, EVENT_GENERATED)
    assert report_states(audit, directory) == []


def test_audit_append_failure_means_not_attested_and_not_published(session, monkeypatch):
    sid, audit, directory = session
    real = audit.record

    def failing(event, data=None):
        if event == EVENT_GENERATED:
            raise OSError("audit disk error")
        return real(event, data)

    monkeypatch.setattr(audit, "record", failing)
    with pytest.raises(ReportStoreError, match="audit append failed.*NOT attested"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    assert not (directory / report_filename(sid, 2)).exists()
    assert not _events(audit, EVENT_GENERATED)
    assert audit.verify()
    assert len(_files(directory)) == 1  # the temp file, kept


# --- failures after attestation: recoverable from the fsynced temp ------------

def test_publish_failure_is_attested_and_recoverable(session, monkeypatch):
    sid, audit, directory = session

    def boom(src, dst, **kw):
        raise OSError("link not supported")

    monkeypatch.setattr(store, "_link", boom)
    with pytest.raises(ReportStoreError, match="attested .* but NOT published"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    final = directory / report_filename(sid, 2)
    assert not final.exists()
    assert len(_events(audit, EVENT_GENERATED)) == 1
    assert len(_events(audit, EVENT_PUBLISH_FAILED)) == 1
    assert report_states(audit, directory)[0].state is PublicationState.RECOVERABLE

    monkeypatch.undo()
    assert _recover_all(audit, directory) == [final.name]
    assert final.read_bytes() == serialize_report(_report(sid))
    assert report_states(audit, directory)[0].state is PublicationState.PUBLISHED
    assert len(_events(audit, EVENT_PUBLICATION_COMPLETED)) == 1
    assert audit.verify()
    assert _files(directory) == [final.name]


def test_crash_between_attestation_and_publication_is_recoverable(session, monkeypatch):
    sid, audit, directory = session

    def crash(src, dst, **kw):
        raise Crash()

    monkeypatch.setattr(store, "_link", crash)
    with pytest.raises(Crash):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    monkeypatch.undo()
    assert not _events(audit, EVENT_PUBLISH_FAILED)  # the process "died"
    assert report_states(audit, directory)[0].state is PublicationState.RECOVERABLE
    assert _recover_all(audit, directory) == [report_filename(sid, 2)]
    assert audit.verify()


def test_audit_written_but_append_reported_failure_is_recoverable(session, monkeypatch):
    sid, audit, directory = session
    real = audit.record

    def written_then_raise(event, data=None):
        rec = real(event, data)
        if event == EVENT_GENERATED:
            raise OSError("error after the line was written")
        return rec

    monkeypatch.setattr(audit, "record", written_then_raise)
    with pytest.raises(ReportStoreError, match="NOT attested"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    monkeypatch.undo()
    # The message was conservative; the chain shows the claim exists, so it is recoverable.
    assert report_states(audit, directory)[0].state is PublicationState.RECOVERABLE
    assert _recover_all(audit, directory) == [report_filename(sid, 2)]


def test_tampered_temp_is_never_published(session, monkeypatch):
    sid, audit, directory = session

    def boom(src, dst, **kw):
        raise OSError("no link")

    monkeypatch.setattr(store, "_link", boom)
    with pytest.raises(ReportStoreError):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    monkeypatch.undo()
    [st] = report_states(audit, directory)
    (directory / st.temp_file).write_bytes(b'{"forged": true}\n')
    assert report_states(audit, directory)[0].state is PublicationState.MISSING
    assert _recover_all(audit, directory) == []
    assert not (directory / st.report_file).exists()


def test_recovery_refuses_on_broken_chain(session, monkeypatch):
    sid, audit, directory = session
    monkeypatch.setattr(store, "_link", lambda s, d, **kw: (_ for _ in ()).throw(OSError("x")))
    with pytest.raises(ReportStoreError):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    monkeypatch.undo()
    audit.path.write_text(audit.path.read_text(encoding="utf-8").replace("0.01", "0.02"),
                          encoding="utf-8")
    with pytest.raises(ReportStoreError, match="does not verify"):
        _recover_all(audit, directory)


def test_published_mismatch_is_detected(session, monkeypatch):
    sid, audit, directory = session

    def bad_link(src, dst, **kw):
        with open(dst, "xb") as fh:
            fh.write(b"not the attested bytes")

    monkeypatch.setattr(store, "_link", bad_link)
    with pytest.raises(ReportStoreError, match="does not match its attested hash"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    assert report_states(audit, directory)[0].state is PublicationState.CONFLICT


# --- compatibility, privacy ----------------------------------------------------

def test_historical_report_is_untouched(session):
    sid, audit, directory = session
    legacy = directory / f"{sid}.report.json"
    legacy_bytes = b'{\r\n  "session_id": "legacy"\r\n}'  # pre-M7.9.1 CRLF file
    legacy.write_bytes(legacy_bytes)
    stored = store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    assert legacy.read_bytes() == legacy_bytes
    assert stored.path != legacy
    assert [s.report_file for s in report_states(audit, directory)] == [stored.path.name]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_temp_file_is_private(session, monkeypatch):
    sid, audit, directory = session
    monkeypatch.setattr(store, "_link", lambda s, d, **kw: (_ for _ in ()).throw(OSError("x")))
    with pytest.raises(ReportStoreError):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    [st] = report_states(audit, directory)
    assert (directory / st.temp_file).stat().st_mode & 0o777 == 0o600


# --- CLI: an unattested report is never shown as a verified result ------------

def _scope() -> Scope:
    return Scope.model_validate({
        "session_name": "lab", "expires_at": "2026-12-31T23:59:59Z",
        "targets": [{"host": "10.66.7.103", "ports": [3000],
                     "allowed_tiers": ["active-safe"], "allowed_tools": ["nmap_connect_scan"]}]})


def _result() -> ResearchResult:
    return ResearchResult(stop_reason=StopReason.FINISHED, detail="finished", steps=1,
                          tool_runs=0, spend=Spend(), final_summary="nothing ran")


@pytest.fixture
def v2_session(tmp_path):
    """A record_format-2 run (M7.9.2): the CLI takes scope/objective/metadata
    from the audit log, so the run must carry a scope snapshot."""
    sid = uuid.uuid4()
    audit = AuditLog(tmp_path / "sessions" / f"{sid}.jsonl")
    audit.record("session_created", {"session_id": str(sid)})
    snap = scope_snapshot(_scope())
    audit.record("research_started", {
        "session_id": str(sid), "model": "claude-opus-5-5", "effort": "medium",
        "max_tokens": 4096, "prompt_version": "m7-v2", "objective": "obj",
        "limits": {"budget_usd": 0.5, "max_steps": 5, "max_tool_runs": 5,
                   "max_duration_seconds": 1800},
        "fallbacks": "disabled", "record_format": 2, "avra_version": "0.0.0",
        "scope_snapshot": snap, "scope_snapshot_sha256": snapshot_sha256(snap),
        "scope_file_sha256": None,
        "prices_usd_per_mtok": {"input": 4.0, "output": 20.0, "cache_write": 5.0,
                                "cache_read": 0.2}})
    usage = {"input_tokens": 10, "output_tokens": 100, "cache_creation_input_tokens": 0,
             "cache_read_input_tokens": 0}
    audit.record("llm_call", {"step": 1, "model": "claude-opus-5-5", "usage": usage,
                              "cost_usd": 0.00204})
    audit.record("research_stopped", {"stop_reason": "finished", "detail": "finished",
                                      "steps": 1, "tool_runs": 0, "proposals": 0,
                                      "total_cost_usd": 0.00204, "tokens": usage,
                                      "final_summary": "nothing ran"})
    return sid, audit


def test_cli_prints_attested_report(v2_session, capsys):
    sid, audit = v2_session
    cli._finish_report(_result(), session_id=sid, audit=audit)
    out = capsys.readouterr().out
    assert f"{sid}.run2.report.json" in out
    assert "attested in audit, seq 5" in out
    assert "Report validation: " in out
    assert len(_events(audit, EVENT_GENERATED)) == 1
    stored = json.loads((audit.path.parent / f"{sid}.run2.report.json").read_bytes())
    assert stored["schema_version"] == 2 and stored["metadata"]["cost_consistent"] is True


def test_cli_without_scope_snapshot_builds_no_report(session, capsys):
    sid, audit, directory = session  # legacy-shaped run: no snapshot
    with pytest.raises(typer.Exit) as exc:
        cli._finish_report(_result(), session_id=sid, audit=audit)
    assert exc.value.exit_code == 3
    assert "Report NOT built" in capsys.readouterr().err
    assert _files(directory) == [] and not _events(audit, EVENT_GENERATED)


def test_cli_unattested_report_exits_3_and_is_labelled(v2_session, capsys, monkeypatch):
    sid, audit = v2_session

    def boom(src, dst, **kw):
        raise OSError("no link")

    monkeypatch.setattr(store, "_link", boom)
    with pytest.raises(typer.Exit) as exc:
        cli._finish_report(_result(), session_id=sid, audit=audit)
    assert exc.value.exit_code == cli.EXIT_REPORT_NOT_PUBLISHED == 3
    captured = capsys.readouterr()
    assert "Report NOT published" in captured.err and "attested (audit seq 5)" in captured.err
    assert "in-memory only, NOT a verified result" in captured.out
    assert "Report validation: " not in captured.out
    assert "Report: " not in captured.out


# --- security: every report_generated field is untrusted input -----------------
#
# The audit chain detects edits but is not keyed: anyone who can write the
# sessions directory can append a well-formed event. These tests forge such
# events and check that status/recovery never touch a file they must not.

_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_DEL = object()


def _no_link(src, dst, **kw):
    raise OSError("link unavailable")


def _snapshot(root: Path) -> dict[str, str]:
    """Every entry under root, without following links or junctions."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + filenames:
            p = Path(dirpath) / name
            st = os.lstat(p)
            linky = stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE
            if stat.S_ISREG(st.st_mode) and not linky:
                out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
            else:
                out[str(p.relative_to(root))] = f"other:{st.st_mode}:{bool(linky)}"
            if linky and name in dirnames:
                dirnames.remove(name)  # never descend through a link/junction
    return out


@pytest.fixture
def pending(session, monkeypatch, tmp_path):
    """An attested-but-unpublished report, plus a file outside the sessions dir."""
    sid, audit, directory = session
    monkeypatch.setattr(store, "_link", _no_link)
    with pytest.raises(ReportStoreError):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    monkeypatch.undo()
    legit = next(r for r in audit.read_all() if r.event == EVENT_GENERATED)
    (tmp_path / "outside.txt").write_bytes(b"a file OUTSIDE the sessions directory")
    return sid, audit, directory, dict(legit.data), tmp_path


def _forge(audit: AuditLog, base: dict, **changes) -> int:
    data = dict(base)
    for key, value in changes.items():
        if value is _DEL:
            data.pop(key, None)
        else:
            data[key] = value
    return audit.record(EVENT_GENERATED, data).seq


def _state_of(audit, directory, seq):
    return next(s for s in report_states(audit, directory) if s.event_seq == seq)


def _invalid_cases(sid, legit, root):
    report = legit["report_file"]
    good_temp = legit["temp_file"]
    hex32 = "a" * 32
    return {
        "dotdot_report": ({"report_file": "../moved.json"}, "report_file"),
        "dotdot_temp": ({"temp_file": "../outside.txt"}, "temp_file"),
        "absolute_report": ({"report_file": str(root / "x.report.json")}, "report_file"),
        "absolute_temp": ({"temp_file": str(root / "outside.txt")}, "temp_file"),
        "backslash_dotdot_report": ({"report_file": "..\\moved.json"}, "report_file"),
        "backslash_dotdot_temp": ({"temp_file": "..\\outside.txt"}, "temp_file"),
        "windows_drive_temp": ({"temp_file": "C:\\Windows\\win.ini"}, "temp_file"),
        "unc_temp": ({"temp_file": "\\\\server\\share\\x.tmp"}, "temp_file"),
        "nested_report": ({"report_file": f"sub/{report}"}, "report_file"),
        "nested_temp": ({"temp_file": f"sub\\{good_temp}"}, "temp_file"),
        "temp_with_dir_part": ({"temp_file": good_temp[:-4] + "/../../x.tmp"}, "temp_file"),
        "legacy_report_name": ({"report_file": f"{sid}.report.json"}, "report_file"),
        "wrong_run_seq_name": ({"report_file": f"{sid}.run3.report.json"}, "report_file"),
        "other_session_name": ({"report_file": f"{uuid.uuid4()}.run2.report.json"},
                               "report_file"),
        "temp_bad_suffix": ({"temp_file": f".{report}.{hex32}.tmp.exe"}, "temp_file"),
        "temp_upper_hex": ({"temp_file": f".{report}.{'A' * 32}.tmp"}, "temp_file"),
        "temp_short_hex": ({"temp_file": f".{report}.{'a' * 31}.tmp"}, "temp_file"),
        "temp_other_report": ({"temp_file": f".{sid}.run9.report.json.{hex32}.tmp"},
                              "temp_file"),
        "missing_report_file": ({"report_file": _DEL}, "missing"),
        "missing_temp_file": ({"temp_file": _DEL}, "missing"),
        "missing_sha": ({"sha256": _DEL}, "missing"),
        "missing_started_seq": ({"research_started_seq": _DEL}, "missing"),
        "missing_stopped_hash": ({"research_stopped_hash": _DEL}, "missing"),
        "seq_as_string": ({"research_started_seq": "2"}, "not int"),
        "seq_as_bool": ({"research_started_seq": True}, "not int"),
        "sha_as_int": ({"sha256": 123}, "not str"),
        "size_none": ({"size": None}, "not int"),
        "report_as_list": ({"report_file": ["x"]}, "not str"),
        "sha_not_hex": ({"sha256": "g" * 64}, "64 lowercase hex"),
        "sha_short": ({"sha256": "a" * 63}, "64 lowercase hex"),
        "sha_upper": ({"sha256": "A" * 64}, "64 lowercase hex"),
        "negative_size": ({"size": -1}, "negative"),
        "started_points_elsewhere": ({"research_started_seq": 3}, "research_started"),
        "stopped_hash_mismatch": ({"research_stopped_hash": "0" * 64}, "research_stopped"),
        "stopped_before_started": ({"research_stopped_seq": 2}, "inconsistent"),
        "started_seq_zero": ({"research_started_seq": 0}, "inconsistent"),
        "seq_from_the_future": ({"research_stopped_seq": 999}, "inconsistent"),
        "duplicate_of_legit": ({}, "duplicate"),
    }


CASE_NAMES = list(_invalid_cases(uuid.uuid4(), {"report_file": "r", "temp_file": "t.tmp"},
                                 Path("x")))


@pytest.mark.parametrize("case", CASE_NAMES)
def test_untrusted_event_is_invalid_and_touches_nothing(pending, case):
    sid, audit, directory, legit, root = pending
    assert _recover_all(audit, directory) == [legit["report_file"]]  # legit one done
    changes, why = _invalid_cases(sid, legit, root)[case]
    seq = _forge(audit, legit, **changes)
    assert audit.verify()  # the forged event is chain-valid on purpose
    before = _snapshot(root)
    st = _state_of(audit, directory, seq)
    assert st.state is PublicationState.INVALID_EVENT
    assert why in st.detail
    assert st.report_file == st.temp_file == ""  # nothing from the event is echoed as a name
    assert _recover_all(audit, directory) == []
    assert _snapshot(root) == before  # no file inside or outside the dir changed


def test_original_traversal_repro_no_longer_moves_files(pending):
    _sid, audit, directory, legit, root = pending
    outside = root / "outside.txt"
    seq = _forge(audit, legit, report_file="../moved-here.json", temp_file="../outside.txt",
                 sha256=hashlib.sha256(outside.read_bytes()).hexdigest())
    before = _snapshot(root)
    assert _state_of(audit, directory, seq).state is PublicationState.INVALID_EVENT
    assert _recover_all(audit, directory) == [legit["report_file"]]  # only the legit one
    after = _snapshot(root)
    assert outside.exists() and not (root / "moved-here.json").exists()
    # Outside the sessions dir: byte-identical, nothing added or removed.
    def outside_of(snap):
        return {k: v for k, v in snap.items() if not k.startswith("sessions")}
    assert outside_of(after) == outside_of(before)
    # Inside: only the legitimate publication happened.
    legit_temp = str(Path("sessions") / legit["temp_file"])
    legit_final = str(Path("sessions") / legit["report_file"])
    log = str(Path("sessions") / audit.path.name)
    assert set(after) - set(before) == {legit_final}
    assert set(before) - set(after) == {legit_temp}
    assert {k: v for k, v in after.items() if k not in (legit_final, log)} == \
        {k: v for k, v in before.items() if k not in (legit_temp, log)}


def test_event_data_not_an_object_is_invalid(session):
    _sid, audit, directory = session
    seq = audit.record(EVENT_GENERATED, ["not", "an", "object"]).seq
    st = _state_of(audit, directory, seq)
    assert st.state is PublicationState.INVALID_EVENT and "not an object" in st.detail


def test_audit_log_not_named_by_session_uuid(tmp_path):
    sid = uuid.uuid4()
    audit = AuditLog(tmp_path / "not-a-session.jsonl")
    _run(audit, sid)
    with pytest.raises(ReportStoreError, match="session audit log"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=tmp_path)
    name = report_filename(sid, 1)
    seq = audit.record(EVENT_GENERATED, {
        "report_file": name, "temp_file": f".{name}.{'a' * 32}.tmp", "sha256": "a" * 64,
        "size": 1, "research_started_seq": 1, "research_stopped_seq": 3,
        "research_stopped_hash": audit.read_all()[2].hash}).seq
    st = _state_of(audit, tmp_path, seq)
    assert st.state is PublicationState.INVALID_EVENT and "session UUID" in st.detail


def test_wrong_directory_is_refused(session, tmp_path):
    sid, audit, _directory = session
    other = tmp_path / "elsewhere"
    other.mkdir()
    calls = (lambda: report_states(audit, other),
             lambda: _recover_all(audit, other),
             lambda: store_report(_report(sid), PASS, audit=audit, session_id=sid,
                                  directory=other))
    for call in calls:
        with pytest.raises(ReportStoreError, match="directory"):
            call()
    assert list(other.iterdir()) == []


def test_broken_chain_marks_events_invalid_without_crashing(pending):
    _sid, audit, directory, _legit, root = pending
    text = audit.path.read_text(encoding="utf-8").replace('"m7-v2"', '"m7-vX"')
    audit.path.write_text(text, encoding="utf-8")
    before = _snapshot(root)
    [st] = report_states(audit, directory)
    assert st.state is PublicationState.INVALID_EVENT and "chain" in st.detail
    with pytest.raises(ReportStoreError, match="does not verify"):
        _recover_all(audit, directory)
    assert _snapshot(root) == before


def test_unreadable_audit_log_raises_store_error_not_keyerror(pending):
    _sid, audit, directory, _legit, _root = pending
    with audit.path.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 99}\n')  # parses as JSON but is not an audit record
    with pytest.raises(ReportStoreError, match="unreadable"):
        report_states(audit, directory)
    with pytest.raises(ReportStoreError):
        _recover_all(audit, directory)


def _swap_temp_for(directory: Path, legit: dict, make) -> Path:
    """Move the real temp aside and put `make(temp, aside)` in its place."""
    temp = directory / legit["temp_file"]
    aside = temp.with_name("aside.bin")
    os.replace(temp, aside)
    make(temp, aside)
    return temp


def test_hardlinked_temp_is_unsafe(pending):
    _sid, audit, directory, legit, root = pending
    outside = root / "outside-copy.bin"

    def make(temp, aside):
        outside.write_bytes(aside.read_bytes())  # same attested bytes, outside the dir
        os.link(outside, temp)

    _swap_temp_for(directory, legit, make)
    before = _snapshot(root)
    [st] = report_states(audit, directory)
    assert st.state is PublicationState.UNSAFE_PATH and "hard link" in st.detail
    assert _recover_all(audit, directory) == []
    assert _snapshot(root) == before


def test_symlinked_temp_is_unsafe(pending):
    _sid, audit, directory, legit, root = pending
    outside = root / "outside-copy.bin"

    def make(temp, aside):
        outside.write_bytes(aside.read_bytes())
        try:
            os.symlink(outside, temp)
        except OSError:
            pytest.skip("creating symlinks needs a privilege on this system")

    _swap_temp_for(directory, legit, make)
    before = _snapshot(root)
    [st] = report_states(audit, directory)
    assert st.state is PublicationState.UNSAFE_PATH and "symlink" in st.detail
    assert _recover_all(audit, directory) == []
    assert _snapshot(root) == before


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions")
def test_junction_temp_is_unsafe(pending):
    import _winapi

    _sid, audit, directory, legit, root = pending
    target = root / "outside-dir"
    target.mkdir()
    (target / "keep.txt").write_bytes(b"keep")

    def make(temp, aside):
        _winapi.CreateJunction(str(target), str(temp))

    _swap_temp_for(directory, legit, make)
    before = _snapshot(root)
    [st] = report_states(audit, directory)
    assert st.state is PublicationState.UNSAFE_PATH and "reparse" in st.detail
    assert _recover_all(audit, directory) == []
    assert _snapshot(root) == before
    assert (target / "keep.txt").read_bytes() == b"keep"


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions")
def test_junction_at_final_name_is_unsafe(pending):
    import _winapi

    _sid, audit, directory, legit, root = pending
    target = root / "outside-dir"
    target.mkdir()
    _winapi.CreateJunction(str(target), str(directory / legit["report_file"]))
    before = _snapshot(root)
    [st] = report_states(audit, directory)
    assert st.state is PublicationState.UNSAFE_PATH and "report_file" in st.detail
    assert _recover_all(audit, directory) == []
    assert _snapshot(root) == before


def test_dangling_symlink_at_final_name_blocks_store(session, tmp_path):
    sid, audit, directory = session
    final = directory / report_filename(sid, 2)
    try:
        os.symlink(tmp_path / "does-not-exist", final)
    except OSError:
        pytest.skip("creating symlinks needs a privilege on this system")
    with pytest.raises(ReportStoreError, match="already exists"):
        store_report(_report(sid), PASS, audit=audit, session_id=sid, directory=directory)
    assert not (tmp_path / "does-not-exist").exists()


def test_repeated_recovery_is_idempotent(pending):
    _sid, audit, directory, legit, root = pending
    assert _recover_all(audit, directory) == [legit["report_file"]]
    events = len(audit.read_all())
    before = _snapshot(root)
    for _ in range(3):
        assert _recover_all(audit, directory) == []
    assert len(audit.read_all()) == events
    assert _snapshot(root) == before
    assert [s.state for s in report_states(audit, directory)] == [PublicationState.PUBLISHED]


def test_valid_recovery_after_interrupted_publication(pending):
    sid, audit, directory, legit, root = pending
    [st] = report_states(audit, directory)
    assert st.state is PublicationState.RECOVERABLE
    assert (st.report_file, st.temp_file, st.sha256) == (legit["report_file"],
                                                         legit["temp_file"], legit["sha256"])
    assert _recover_all(audit, directory) == [legit["report_file"]]
    final = directory / legit["report_file"]
    assert final.read_bytes() == serialize_report(_report(sid))
    assert os.lstat(final).st_nlink == 1  # temp name dropped
    assert (root / "outside.txt").read_bytes() == b"a file OUTSIDE the sessions directory"
    assert audit.verify()
