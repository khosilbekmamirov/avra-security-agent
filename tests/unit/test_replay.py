"""M7.9.2: trusted scope snapshot, schema-2 metadata, deterministic replay and
read-only verification.

Runs the REAL research loop and the REAL M6 pipeline (only the SSH tunnel,
the Runner and the model are faked), stores the report through the real CLI
path, then rebuilds it offline and checks it byte for byte. Everything lives
in tmp_path; no network, no API, no scans.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from avra.cli import main as cli
from avra.core.research import ResearchSession
from avra.core.snapshot import (
    SnapshotError,
    canonical_json,
    scope_from_snapshot,
    scope_snapshot,
    snapshot_sha256,
)
from avra.llm.config import LLMConfig, SessionLimits, TokenUsage
from avra.llm.provider import LLMResponse, ToolUse
from avra.llm.tools import FINISH, PROPOSE_SCAN, RECORD_HYPOTHESIS, RECORD_OBSERVATION
from avra.policy.scope import ScopeChecker
from avra.reporting import ReportMetadata, Verdict, validate_report
from avra.reporting.replay import (
    LegacyRunError,
    ReplayError,
    find_runs,
    rebuild_report,
    run_metadata,
    verify_session,
)
from avra.reporting.store import (
    EVENT_GENERATED,
    report_filename,
    serialize_report,
    store_report,
)
from avra.runner.schemas import (
    RejectionStage,
    RunnerRejection,
    ToolRunResult,
    ToolRunStatus,
)
from avra.runner_client.client import RunnerToken, RunOutcome
from avra.runner_client.scan import run_nmap_connect_scan
from avra.runner_client.tunnel import TunnelConfig, TunnelError
from avra.schemas.scope import Scope
from avra.storage.audit import AuditLog

ROOT = Path(__file__).resolve().parents[2]
OPEN_XML = (ROOT / "tests/fixtures/nmap/m5-juice-shop-3000-open.xml").read_text(encoding="utf-8")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _scope() -> Scope:
    return Scope.model_validate({
        "session_name": "lab", "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        "description": "Owner's isolated VirtualBox lab — training targets only.",
        "targets": [{"host": "10.66.7.103", "ports": [3000], "description": "Juice Shop",
                     "allowed_tiers": ["active-safe"], "allowed_tools": ["nmap_connect_scan"]}]})


# --- fakes: model, tunnel, Runner ---------------------------------------------------

def _resp(stop, uses=(), text="", model="claude-opus-5-5", usage=None):
    return LLMResponse(stop_reason=stop, text=text, tool_uses=tuple(uses),
                       usage=usage or TokenUsage(input_tokens=5, output_tokens=200,
                                                 cache_creation_input_tokens=1000,
                                                 cache_read_input_tokens=2000),
                       model=model, request_id="req_test",
                       history_content=[{"type": "text", "text": text or "."}])


def _use(name, i, **inp):
    return ToolUse(id=f"toolu_{i}", name=name, input=inp)


PROPOSE = {"host": "10.66.7.103", "ports": [3000], "timeout_seconds": 60,
           "explanation": "Check which service the allowed Juice Shop port exposes."}


def _standard_script(observe=True):
    def observation(messages):
        ids = UUID_RE.findall(json.dumps(messages[-1]["content"]))
        return _resp("tool_use", [_use(RECORD_OBSERVATION, 2, summary="3000/tcp open.",
                                       evidence_request_id=ids[0] if ids else None)])
    steps = [_resp("tool_use", [_use(PROPOSE_SCAN, 1, **PROPOSE)])]
    if observe:
        steps.append(observation)
    steps += [_resp("tool_use", [_use(RECORD_HYPOTHESIS, 3, statement="It is Juice Shop.",
                                      basis="Scope description; default port.")]),
              _resp("tool_use", [_use(FINISH, 4, summary="Port 3000 open; identity unverified.")])]
    return steps


class FakeProvider:
    def __init__(self, script):
        self.config = LLMConfig()
        self.script = list(script)

    def count_input_tokens(self, *, system, messages, tools):
        return 3000

    def complete(self, *, system, messages, tools):
        step = self.script.pop(0)
        return step(messages) if callable(step) else step


class FakeTunnel:
    def __init__(self, cfg, fail=False):
        self.fail = fail

    def __enter__(self):
        if self.fail:
            raise TunnelError("SSH tunnel did not come up")
        return "http://127.0.0.1:50000"

    def __exit__(self, *a):
        pass


def _client(answer):
    class C:
        def __init__(self, base, token):
            pass

        def health(self):
            return {"status": "ok"}

        def run(self, request):
            return answer(request)
    return C


def completed(request, raw=OPEN_XML, sha=None):
    return RunOutcome(200, result=ToolRunResult(
        request_id=request.request_id, tool="nmap_connect_scan", status=ToolRunStatus.COMPLETED,
        started_at=datetime.now(UTC), finished_at=datetime.now(UTC), exit_code=0,
        raw_output=raw, output_sha256=sha or hashlib.sha256(raw.encode()).hexdigest()),
        hash_verified=sha is None)


def denied_by_runner(request):
    return RunOutcome(200, result=ToolRunResult(
        request_id=request.request_id, tool="nmap_connect_scan", status=ToolRunStatus.DENIED,
        reason="runner scope: port not allowed"))


def rejected(request):
    return RunOutcome(403, rejection=RunnerRejection(stage=RejectionStage.SCOPE,
                                                     reason="out of scope",
                                                     request_id=request.request_id))


# --- harness -------------------------------------------------------------------------

class Lab:
    """A session directory + evidence directory, as AVRA_DATA_DIR lays them out."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path / "data"
        self.sessions = self.root / "sessions"
        self.evidence = self.root / "evidence"
        self.sid = uuid.uuid4()
        self.audit = AuditLog(self.sessions / f"{self.sid}.jsonl")
        self.audit.record("session_created", {"session_id": str(self.sid)})
        self.scope = _scope()

    def research(self, script, answer=completed, tunnel_fail=False, scope_file_sha256="f" * 64):
        checker = ScopeChecker(self.scope)

        def execute(p):
            return run_nmap_connect_scan(
                checker=checker, audit=self.audit, session_id=self.sid, host=p.host,
                ports=list(p.ports), timeout_seconds=p.timeout_seconds,
                token=RunnerToken("s" * 43), evidence_root=self.evidence,
                tunnel_cfg=TunnelConfig(),
                tunnel_factory=lambda cfg: FakeTunnel(cfg, fail=tunnel_fail),
                client_factory=_client(answer))

        return ResearchSession(
            provider=FakeProvider(script), checker=checker, audit=self.audit,
            session_id=self.sid, limits=SessionLimits(max_steps=6), approve=lambda v: True,
            execute=execute, scope_file_sha256=scope_file_sha256).run("  Which services?  ")

    def finish_report(self, result):
        # the CLI reads evidence from AVRA_DATA_DIR, as in production
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("AVRA_DATA_DIR", str(self.root))
            cli._finish_report(result, session_id=self.sid, audit=self.audit)

    def verify(self):
        return verify_session(self.sessions, self.evidence, self.sid)

    def report_path(self, seq=2):
        return self.sessions / report_filename(self.sid, seq)


def _tree(root: Path) -> dict[str, str]:
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            out[str(p.relative_to(root))] = (hashlib.sha256(p.read_bytes()).hexdigest()
                                             if p.is_file() else "dir")
    return out


@pytest.fixture
def lab(tmp_path):
    return Lab(tmp_path)


# --- Stage 1: scope snapshot ----------------------------------------------------------

def test_scope_snapshot_is_canonical_and_round_trips():
    scope = _scope()
    snap = scope_snapshot(scope)
    reordered = json.loads(json.dumps(dict(reversed(list(snap.items())))))
    assert snapshot_sha256(snap) == snapshot_sha256(reordered)  # key order never matters
    assert canonical_json(snap) == canonical_json(reordered)
    rebuilt = scope_from_snapshot(snap, snapshot_sha256(snap))
    assert scope_snapshot(rebuilt) == snap
    assert rebuilt.expires_at.isoformat() == scope.expires_at.isoformat()


@pytest.mark.parametrize("mutate,why", [
    (lambda s: s["targets"][0].update(ports=[3000, 22]), "hash"),
    (lambda s: s.update(description="something else"), "hash"),
    (lambda s: s.pop("targets"), "hash"),
])
def test_altered_snapshot_is_rejected(mutate, why):
    snap = scope_snapshot(_scope())
    recorded = snapshot_sha256(snap)
    mutate(snap)
    with pytest.raises(SnapshotError, match=why):
        scope_from_snapshot(snap, recorded)


def test_non_canonical_or_invalid_snapshot_is_rejected():
    snap = scope_snapshot(_scope())
    snap["targets"][0]["ports"] = ["3000"]  # would be coerced to int: not canonical
    with pytest.raises(SnapshotError, match="canonical"):
        scope_from_snapshot(snap, snapshot_sha256(snap))
    bad = {"session_name": "x"}
    with pytest.raises(SnapshotError, match="not a valid scope"):
        scope_from_snapshot(bad, snapshot_sha256(bad))
    with pytest.raises(SnapshotError, match="missing"):
        scope_from_snapshot(None, None)


def test_research_started_records_trusted_snapshot_and_context(lab):
    lab.research(_standard_script())
    started = next(r for r in lab.audit.read_all() if r.event == "research_started").data
    assert started["record_format"] == 2
    assert started["scope_snapshot"] == scope_snapshot(lab.scope)
    assert started["scope_snapshot_sha256"] == snapshot_sha256(started["scope_snapshot"])
    assert started["scope_file_sha256"] == "f" * 64
    assert started["prices_usd_per_mtok"] == {"input": 4.0, "output": 20.0,
                                              "cache_write": 5.0, "cache_read": 0.2}
    assert started["avra_version"] and started["objective"] == "Which services?"
    stopped = lab.audit.read_all()[-1].data
    assert stopped["final_summary"] == "Port 3000 open; identity unverified."


# --- Stage 2 + 3: metadata and deterministic replay --------------------------------------

def test_live_report_is_reproduced_byte_for_byte_and_verifies(lab):
    result = lab.research(_standard_script())
    lab.finish_report(result)
    published = lab.report_path().read_bytes()
    report = json.loads(published)
    assert report["schema_version"] == 5
    assert report["claim_checks"]["reference_mismatches"] == []
    # D1: the open port is confirmed, but a port-table label is no identification
    assert report["port_exposure"] == "confirmed"
    assert report["service_identity"] == "unidentified"
    assert report["evidence_confidence"] == "partially_supported"
    assert report["objective"] == "Which services?"  # the audited (stripped) objective
    md = report["metadata"]
    assert md["session_id"] == str(lab.sid) and md["run_started_seq"] == 2
    assert md["model"] == "claude-opus-5-5" and md["models_reported"] == ["claude-opus-5-5"]
    assert md["model_consistent"] and md["tokens_consistent"] and md["cost_consistent"]
    assert md["llm_calls"] == 4 and md["tool_runs"] == 1 and md["stop_reason"] == "finished"
    assert md["scope_file_sha256"] == "f" * 64

    [run] = find_runs(lab.audit.read_all())
    rebuilt, replayed = rebuild_report(run, lab.sid, lab.evidence, lab.sessions)
    assert serialize_report(rebuilt) == published
    assert validate_report(rebuilt, replayed).verdict is Verdict.PASS

    sc = lab.verify()
    assert sc.verified, sc.problems
    assert sc.audit.startswith("PASS") and sc.evidence.startswith("PASS (1 file")
    [rc] = sc.runs
    assert rc.attestation.startswith("ATTESTED") and rc.publication == "PUBLISHED"
    assert rc.reproduction.startswith("IDENTICAL") and rc.validator == "PASS (matches attested)"


def test_metadata_matches_audit_and_reconciles_cost(lab):
    result = lab.research(_standard_script())
    records = lab.audit.read_all()
    [run] = find_runs(records)
    md = run_metadata(run, lab.sid)
    stopped = records[-1]
    calls = [r.data for r in records if r.event == "llm_call"]
    assert md.run_stopped_hash == stopped.hash and md.finished_at == stopped.ts
    assert md.cost_usd == stopped.data["total_cost_usd"] == round(result.spend.usd, 6)
    assert md.cost_sum_of_calls_usd == round(sum(c["cost_usd"] for c in calls), 6)
    assert abs(md.cost_from_tokens_usd - md.cost_usd) <= 1e-6 * (len(calls) + 1)
    assert md.tokens.model_dump() == stopped.data["tokens"]
    assert md.limits.max_steps == 6


def _mismatched_model_script():
    script = _standard_script()
    script[-1] = _resp("tool_use", [_use(FINISH, 4, summary="done")], model="some-other-model")
    return script


def _tamper_on_record(lab, event, mutate):
    """Simulate a buggy recorder: the record is altered BEFORE it is hashed, so
    the chain stays valid but the audit evidence contradicts itself."""
    real = lab.audit.record

    def record(name, data=None):
        if name == event:
            data = json.loads(json.dumps(data))
            mutate(data)
        return real(name, data)

    lab.audit.record = record


def _integrity_ok_but_not_verified(sc):
    [rc] = sc.runs
    assert rc.integrity.startswith("PASS") and rc.integrity_ok
    assert sc.integrity_verified and not rc.ok and not sc.verified
    return rc


def test_model_mismatch_is_not_verified(lab):
    lab.finish_report(lab.research(_mismatched_model_script()))
    [run] = find_runs(lab.audit.read_all())
    md = run_metadata(run, lab.sid)
    assert not md.model_consistent and md.models_reported == ("claude-opus-5-5",
                                                              "some-other-model")
    report, result = rebuild_report(run, lab.sid, lab.evidence, lab.sessions)
    v = validate_report(report, result)
    assert v.verdict is Verdict.INCOMPLETE and any("model" in r for r in v.reasons)
    rc = _integrity_ok_but_not_verified(lab.verify())
    assert rc.metadata.startswith("FAIL") and "some-other-model" in rc.metadata
    # a matched INCOMPLETE verdict is shown as such, never as clean
    assert rc.validator.startswith("INCOMPLETE (matches attested)")


def test_cost_inconsistency_is_not_verified(lab):
    _tamper_on_record(lab, "research_stopped",
                      lambda d: d.update(total_cost_usd=d["total_cost_usd"] + 0.01))
    lab.finish_report(lab.research(_standard_script()))
    rc = _integrity_ok_but_not_verified(lab.verify())
    assert rc.metadata.startswith("FAIL") and "cost does not reconcile" in rc.metadata
    assert "token totals" not in rc.metadata
    assert rc.validator.startswith("INCOMPLETE")


def test_token_inconsistency_is_not_verified(lab):
    _tamper_on_record(lab, "research_stopped",
                      lambda d: d["tokens"].update(output_tokens=d["tokens"]["output_tokens"] + 1))
    lab.finish_report(lab.research(_standard_script()))
    rc = _integrity_ok_but_not_verified(lab.verify())
    assert "token totals do not equal" in rc.metadata


def test_matched_invalid_verdict_is_not_verified(lab):
    script = _standard_script(observe=False)
    script.insert(1, _resp("tool_use", [_use(
        RECORD_OBSERVATION, 9, summary="made up",
        evidence_request_id="00000000-0000-4000-8000-000000000000")]))
    lab.finish_report(lab.research(script))
    rc = _integrity_ok_but_not_verified(lab.verify())
    assert rc.metadata == "PASS"
    assert rc.validator.startswith("INVALID (matches attested)")
    assert "neither a tool run of this run nor verified earlier evidence" in rc.validator


def test_cost_and_token_inconsistency_detected(tmp_path):
    sid = uuid.uuid4()
    audit = AuditLog(tmp_path / f"{sid}.jsonl")
    snap = scope_snapshot(_scope())
    audit.record("research_started", {
        "model": "claude-opus-5-5", "effort": "medium", "max_tokens": 4096,
        "prompt_version": "m7-v2", "objective": "o", "record_format": 2,
        "avra_version": "0.0.0", "scope_snapshot": snap,
        "scope_snapshot_sha256": snapshot_sha256(snap), "scope_file_sha256": None,
        "limits": {"budget_usd": 0.5, "max_steps": 5, "max_tool_runs": 5,
                   "max_duration_seconds": 1800},
        "prices_usd_per_mtok": {"input": 4.0, "output": 20.0, "cache_write": 5.0,
                                "cache_read": 0.2}})
    usage = {"input_tokens": 10, "output_tokens": 100, "cache_creation_input_tokens": 0,
             "cache_read_input_tokens": 0}
    audit.record("llm_call", {"model": "claude-opus-5-5", "usage": usage, "cost_usd": 0.00204})
    audit.record("research_stopped", {"stop_reason": "finished", "detail": "", "steps": 1,
                                      "tool_runs": 0, "proposals": 0,
                                      "total_cost_usd": 0.5,  # does not reconcile
                                      "tokens": {**usage, "output_tokens": 999}})
    md = run_metadata(find_runs(audit.read_all())[0], sid)
    assert not md.cost_consistent and not md.tokens_consistent


def test_multi_run_session_needs_every_run_to_pass(lab):
    lab.finish_report(lab.research(_standard_script()))
    lab.finish_report(lab.research(_mismatched_model_script()))
    sc = lab.verify()
    assert [rc.ok for rc in sc.runs] == [True, False]
    assert all(rc.integrity_ok for rc in sc.runs) and sc.integrity_verified
    assert not sc.verified


def test_end_turn_summary_is_reproduced(lab):
    script = [_resp("end_turn", text="I could not decide on a scan.")]
    result = lab.research(script)
    assert result.final_summary == "I could not decide on a scan."
    lab.finish_report(result)
    assert json.loads(lab.report_path().read_bytes())["model_summary"] == result.final_summary
    assert lab.verify().verified


@pytest.mark.parametrize("answer,tunnel_fail", [
    (completed, True),                                    # tool_request_failed
    (rejected, False),                                    # tool_request_rejected
    (denied_by_runner, False),                            # DENIED result (reason recorded)
    (lambda r: completed(r, sha="0" * 64), False),        # hash mismatch -> errors
])
def test_failure_outcomes_replay_identically(lab, answer, tunnel_fail):
    result = lab.research(_standard_script(observe=False), answer=answer,
                          tunnel_fail=tunnel_fail)
    lab.finish_report(result)
    sc = lab.verify()
    assert sc.runs[0].reproduction.startswith("IDENTICAL"), sc.runs[0].reproduction
    assert sc.verified, sc.problems


def test_resumed_session_verifies_each_run(lab):
    lab.finish_report(lab.research(_standard_script()))
    lab.finish_report(lab.research(_standard_script()))
    sc = lab.verify()
    assert len(sc.runs) == 2 and all(rc.ok for rc in sc.runs) and sc.verified


# --- Stage 4: failure states are explicit ------------------------------------------------

@pytest.fixture
def verified_lab(lab):
    lab.finish_report(lab.research(_standard_script()))
    assert lab.verify().verified
    return lab


def _evidence_file(lab):
    [f] = list((lab.evidence / str(lab.sid)).iterdir())
    return f


def test_corrupted_evidence_fails_verification(verified_lab):
    lab = verified_lab
    f = _evidence_file(lab)
    f.write_bytes(f.read_bytes().replace(b'state="open"', b'state="closed"'))
    sc = lab.verify()
    assert not sc.verified and sc.evidence.startswith("FAIL")
    assert any("mismatch" in p for p in sc.problems)
    assert sc.runs[0].reproduction.startswith("FAIL")


def test_missing_evidence_fails_verification(verified_lab):
    lab = verified_lab
    _evidence_file(lab).unlink()
    sc = lab.verify()
    assert not sc.verified and any("missing" in p for p in sc.problems)


def test_corrupted_audit_stops_everything(verified_lab):
    lab = verified_lab
    text = lab.audit.path.read_text(encoding="utf-8").replace("Which services?", "Other?")
    lab.audit.path.write_text(text, encoding="utf-8")
    sc = lab.verify()
    assert not sc.verified and sc.audit.startswith("FAIL")
    assert sc.evidence == "NOT CHECKED" and sc.runs == []


def test_published_report_altered_is_a_conflict(verified_lab):
    lab = verified_lab
    lab.report_path().write_bytes(b'{"forged": true}\n')
    sc = lab.verify()
    assert not sc.verified and sc.runs[0].publication.startswith("CONFLICT")
    assert sc.runs[0].reproduction.startswith("IDENTICAL")  # the audit still pins the truth


def test_attested_report_that_does_not_match_the_audit_fails(lab):
    result = lab.research(_standard_script())
    run = find_runs(lab.audit.read_all())[-1]
    honest, replayed = rebuild_report(run, lab.sid, lab.evidence, lab.sessions)
    forged = honest.model_copy(update={"model_summary": "Critical vulnerability confirmed!"})
    store_report(forged, validate_report(forged, replayed), audit=lab.audit,
                 session_id=lab.sid, directory=lab.sessions)
    sc = lab.verify()
    assert not sc.verified
    assert sc.runs[0].publication == "PUBLISHED"  # the file matches what was attested...
    assert sc.runs[0].reproduction.startswith("FAIL: rebuilt report differs")  # ...not the audit
    assert result.final_summary != forged.model_summary


def test_invalid_report_event_is_a_problem(verified_lab):
    lab = verified_lab
    lab.audit.record(EVENT_GENERATED, {"report_file": "../x.json"})
    sc = lab.verify()
    assert not sc.verified and any("invalid report_generated" in p for p in sc.problems)


def test_missing_session_is_reported_and_creates_nothing(tmp_path):
    root = tmp_path / "data"
    sc = verify_session(root / "sessions", root / "evidence", uuid.uuid4())
    assert not sc.verified and sc.audit == "FAIL: audit log not found"
    assert not root.exists()


def test_verify_is_read_only(verified_lab):
    lab = verified_lab
    before = _tree(lab.root)
    for _ in range(2):
        lab.verify()
    assert _tree(lab.root) == before


# --- legacy sessions ----------------------------------------------------------------------

def _legacy_session(lab):
    """A pre-M7.9.2 run: research_started without a snapshot, plus the old
    single <session>.report.json the pre-M7.9.1 CLI wrote."""
    a = lab.audit
    a.record("research_started", {"model": "claude-opus-5-5", "objective": "o",
                                  "prompt_version": "m7-v2"})
    a.record("llm_finish", {"step": 1, "summary": "legacy summary"})
    a.record("research_stopped", {"stop_reason": "finished", "detail": "", "steps": 1,
                                  "tool_runs": 0, "proposals": 0, "total_cost_usd": 0.01,
                                  "tokens": {"input_tokens": 1, "output_tokens": 1,
                                             "cache_creation_input_tokens": 0,
                                             "cache_read_input_tokens": 0}})


def test_legacy_run_is_marked_and_never_uses_current_scope(lab, monkeypatch):
    _legacy_session(lab)
    legacy = {"session_id": str(lab.sid), "objective": "o",
              "scope": {"session_name": "lab", "expires_at": "2026-12-31T23:59:59+00:00",
                        "environment_description": "", "targets": []},
              "tool_runs": [], "verified_facts": [], "model_observations": [],
              "hypotheses": [], "errors_and_limitations": [], "execution_status": "completed",
              "coverage": "not_evaluated", "evidence_confidence": "inconclusive",
              "model_summary": "legacy summary", "model_summary_is_authoritative": False}
    legacy_file = lab.sessions / f"{lab.sid}.report.json"
    legacy_bytes = json.dumps(legacy, indent=2).replace("\n", "\r\n").encode()
    legacy_file.write_bytes(legacy_bytes)

    def no_scope_files(*a, **k):
        raise AssertionError("verification must never load a scope file")

    monkeypatch.setattr("avra.policy.scope.load_scope", no_scope_files)
    [run] = find_runs(lab.audit.read_all())
    with pytest.raises(LegacyRunError):
        rebuild_report(run, lab.sid, lab.evidence, lab.sessions)
    sc = lab.verify()
    assert not sc.verified
    assert sc.runs[0].reproduction.startswith("NOT POSSIBLE: legacy run")
    assert sc.runs[0].attestation == "NONE"
    assert "legacy file" in sc.runs[0].validator
    assert any("legacy report" in n for n in sc.notes)
    assert legacy_file.read_bytes() == legacy_bytes


def test_schema_v1_files_still_load():
    from avra.reporting import ResearchReport
    r = ResearchReport.model_validate({
        "session_id": "s", "objective": "o",
        "scope": {"session_name": "x", "expires_at": "2026", "targets": []},
        "tool_runs": [], "verified_facts": [], "model_observations": [], "hypotheses": [],
        "errors_and_limitations": [], "execution_status": "completed",
        "coverage": "not_evaluated", "evidence_confidence": "inconclusive"})
    assert r.schema_version == 1 and r.metadata is None


def test_validator_requires_consistent_v2_metadata(lab):
    lab.finish_report(lab.research(_standard_script()))
    [run] = find_runs(lab.audit.read_all())
    report, result = rebuild_report(run, lab.sid, lab.evidence, lab.sessions)
    no_md = report.model_copy(update={"metadata": None})
    assert validate_report(no_md, result).verdict is Verdict.INVALID
    other: ReportMetadata = report.metadata.model_copy(update={"session_id": "other"})
    assert validate_report(report.model_copy(update={"metadata": other}),
                           result).verdict is Verdict.INVALID


def test_replay_rejects_malformed_tool_events(lab):
    lab.research(_standard_script())
    lab.audit.record("research_started", {"record_format": 2})
    lab.audit.record("tool_result_received", {"request_id": "../../etc/passwd"})
    lab.audit.record("research_stopped", {})
    run = find_runs(lab.audit.read_all())[-1]
    with pytest.raises(ReplayError):
        rebuild_report(run, lab.sid, lab.evidence, lab.sessions)


# --- Stage 4 CLI + Stage 5 gate --------------------------------------------------------------

def test_cli_report_verify(verified_lab, monkeypatch):
    lab = verified_lab
    monkeypatch.setenv("AVRA_DATA_DIR", str(lab.root))
    r = CliRunner().invoke(cli.app, ["report", "verify", str(lab.sid)])
    assert r.exit_code == 0, r.output
    for label in ("Audit integrity:    PASS", "Evidence integrity: PASS",
                  "Attestation:          ATTESTED", "Publication:          PUBLISHED",
                  "Reproduction:         IDENTICAL", "Integrity:            PASS",
                  "Metadata consistency: PASS",
                  "Report validation:    PASS (matches attested)", "Result: VERIFIED"):
        assert label in r.output
    _evidence_file(lab).unlink()
    r = CliRunner().invoke(cli.app, ["report", "verify", str(lab.sid)])
    assert r.exit_code == 1 and "Result: NOT VERIFIED" in r.output
    r = CliRunner().invoke(cli.app, ["report", "verify", "not-a-uuid"])
    assert r.exit_code == 2


@pytest.mark.parametrize("make", ["model", "cost", "tokens", "invalid"])
def test_cli_separates_integrity_from_report_validity(lab, monkeypatch, make):
    script = _standard_script()
    if make == "model":
        script = _mismatched_model_script()
    elif make == "cost":
        _tamper_on_record(lab, "research_stopped",
                          lambda d: d.update(total_cost_usd=d["total_cost_usd"] + 0.01))
    elif make == "tokens":
        _tamper_on_record(lab, "research_stopped",
                          lambda d: d["tokens"].update(input_tokens=d["tokens"]["input_tokens"]
                                                       + 1))
    else:
        script = _standard_script(observe=False)
        script.insert(1, _resp("tool_use", [_use(
            RECORD_OBSERVATION, 9, summary="made up",
            evidence_request_id="00000000-0000-4000-8000-000000000000")]))
    lab.finish_report(lab.research(script))
    monkeypatch.setenv("AVRA_DATA_DIR", str(lab.root))
    r = CliRunner().invoke(cli.app, ["report", "verify", str(lab.sid)])
    assert r.exit_code == 1, r.output
    assert "Integrity:            PASS" in r.output
    assert "Result: NOT VERIFIED - integrity holds" in r.output
    assert "Result: VERIFIED" not in r.output
    if make == "invalid":
        assert "Metadata consistency: PASS" in r.output
        assert "Report validation:    INVALID (matches attested)" in r.output
    else:
        assert "Metadata consistency: FAIL" in r.output
        assert "Report validation:    INCOMPLETE (matches attested)" in r.output


def test_schema4_claim_mismatch_replays_but_is_not_verified(lab):
    """M7.9.4: an unresolved reference in the model's summary is reproduced
    byte-for-byte (integrity holds) and makes the report INCOMPLETE, so the
    session is NOT VERIFIED; suspicious prose alone would not."""
    script = _standard_script()
    script[-1] = _resp("tool_use", [_use(
        FINISH, 4, summary="Done; see request 00000000-0000-4000-8000-000000000000. "
                           "The service is definitely Express.")])
    lab.finish_report(lab.research(script))
    report = json.loads(lab.report_path().read_bytes())
    assert report["schema_version"] == 5
    cc = report["claim_checks"]
    assert [m["kind"] for m in cc["reference_mismatches"]] == ["request_id"]
    assert [a["category"] for a in cc["suspicious_assertions"]] == ["service_identity"]
    sc = lab.verify()
    [rc] = sc.runs
    assert rc.reproduction.startswith("IDENTICAL") and rc.integrity_ok
    assert rc.validator.startswith("INCOMPLETE (matches attested)")
    assert not sc.verified and sc.integrity_verified


def test_pre_m793_run_rebuilds_as_schema_2_and_verifies(lab):
    """A record_format-2 run without report_schema_version (made before M7.9.3)
    is built and replayed with the schema-2 rules: no schema-3 keys, the old
    headline, identical bytes, VERIFIED."""
    _tamper_on_record(lab, "research_started", lambda d: d.pop("report_schema_version"))
    lab.finish_report(lab.research(_standard_script()))
    published = json.loads(lab.report_path().read_bytes())
    assert published["schema_version"] == 2
    assert "port_exposure" not in published and "service_identity" not in published
    assert published["evidence_confidence"] == "supported"  # the schema-2 rule, frozen
    sc = lab.verify()
    assert sc.runs[0].reproduction.startswith("IDENTICAL") and sc.verified, sc.problems


@pytest.mark.parametrize("bad", [7, "3", True, None])
def test_malformed_recorded_schema_version_is_refused(lab, bad, capsys):
    _tamper_on_record(lab, "research_started",
                      lambda d: d.update(report_schema_version=bad))
    import typer

    result = lab.research(_standard_script())
    with pytest.raises(typer.Exit) as exc:  # report NOT built
        lab.finish_report(result)
    assert getattr(exc.value, "exit_code", None) == 3
    assert "report_schema_version" in capsys.readouterr().err
    assert not lab.report_path().exists()


def test_cli_outcome_line_shows_exposure_and_identity(lab, capsys):
    lab.finish_report(lab.research(_standard_script()))
    out = capsys.readouterr().out
    assert "evidence=partially_supported" in out
    assert "port exposure=confirmed, service identity=unidentified" in out


def test_unaudited_recovery_is_never_verified(lab, monkeypatch):
    """M7.9.2R review: publish succeeded, completion record failed -> the
    open authorization must keep the session NOT VERIFIED (read-only)."""
    from avra.reporting import store
    from avra.reporting.store import (
        EVENT_PUBLICATION_COMPLETED,
        PublicationState,
        RecoveryStatus,
        complete_publication,
        recovery_candidates,
        report_states,
    )

    result = lab.research(_standard_script())
    monkeypatch.setattr(store, "_link", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    import typer

    with pytest.raises(typer.Exit) as exc:  # attested, not published
        lab.finish_report(result)
    assert exc.value.exit_code == 3
    monkeypatch.undo()
    [cand] = recovery_candidates(lab.audit, lab.sessions)
    real = lab.audit.record

    def fail_completion(name, data=None):
        if name == EVENT_PUBLICATION_COMPLETED:
            raise OSError("audit disk error")
        return real(name, data)

    lab.audit.record = fail_completion
    [o] = complete_publication(lab.audit, lab.sessions,
                               authorized=frozenset({(cand.event_seq, cand.sha256)}),
                               confirmation="test")
    lab.audit.record = real
    assert o.status is RecoveryStatus.PUBLISHED_UNAUDITED
    before = _tree(lab.root)
    sc = lab.verify()
    assert not sc.verified
    assert sc.runs[0].publication.startswith("PUBLISHED_RECOVERY_UNAUDITED")
    assert sc.runs[0].reproduction.startswith("IDENTICAL")  # the bytes are right...
    assert sc.runs[0].integrity.startswith("FAIL")           # ...the publication is not audited
    assert _tree(lab.root) == before                          # verify stayed read-only
    # Once a matching completion is recorded, the same session verifies.
    lab.audit.record(EVENT_PUBLICATION_COMPLETED, {
        "report_generated_seq": cand.event_seq, "sha256": cand.sha256,
        "recovery_authorized_seq": o.authorization_seq})
    assert report_states(lab.audit, lab.sessions)[0].state is PublicationState.PUBLISHED
    assert lab.verify().verified


def test_report_commands_and_recover_is_never_automatic():
    """M7.9.2R added `recover` (interactive, owner-confirmed); nothing else.
    Without a terminal it refuses and does nothing."""
    names = {c.name for c in cli.report_app.registered_commands}
    assert names == {"verify", "recover"}
    r = CliRunner().invoke(cli.app, ["report", "recover", str(uuid.uuid4())])
    assert r.exit_code == 2
