"""M14.1 (ADR 0022): investigation state machine - offline, no network, no model."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from avra.research.investigation import (
    TERMINAL,
    TRANSITIONS,
    ActionStatus,
    Investigation,
    InvestigationError,
    InvState,
)

SID = "7e868faf-768d-49af-aea6-81dc9d435e20"
HOST, PORT = "10.66.7.103", 3000


def allow_main_js(tool, host, port, path):
    return (tool, host, port, path) == ("http_get_path", HOST, PORT, "/main.js")


class Clock:
    def __init__(self):
        self.t = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


def new(tmp_path, clock):
    return Investigation.create(tmp_path, objective="investigate Juice Shop", session_id=SID,
                                scope_name="juice-shop-chat", clock=clock)


def to_planning(inv):
    for s in (InvState.OBSERVING, InvState.ANALYZING, InvState.PLANNING):
        inv.transition(s)


def proposed(tmp_path, clock):
    inv = new(tmp_path, clock)
    to_planning(inv)
    act = inv.propose(tool="http_get_path", host=HOST, port=PORT, path="/main.js",
                      reason="bundle may list API routes", expected_evidence="JS bundle",
                      scope_check=allow_main_js)
    inv.transition(InvState.WAITING_APPROVAL)
    return inv, act


# --- state graph -----------------------------------------------------------------------------

def test_graph_is_closed_and_terminals_are_final():
    assert set(TRANSITIONS) == set(InvState)
    for t in TERMINAL:
        assert TRANSITIONS[t] == frozenset()


@pytest.mark.parametrize("to", [InvState.PLANNING, InvState.VERIFYING, InvState.COMPLETED,
                                InvState.WAITING_APPROVAL])
def test_illegal_transitions_from_created_are_refused_and_not_written(tmp_path, clock, to):
    inv = new(tmp_path, clock)
    before = len(inv._log.read_all())
    with pytest.raises(InvestigationError):
        inv.transition(to)
    assert inv.state is InvState.CREATED
    assert len(inv._log.read_all()) == before  # nothing was recorded


def test_executing_cannot_be_entered_by_transition(tmp_path, clock):
    inv, _ = proposed(tmp_path, clock)
    with pytest.raises(InvestigationError, match="begin_execution"):
        inv.transition(InvState.EXECUTING)


def test_waiting_approval_needs_a_pending_proposal(tmp_path, clock):
    inv = new(tmp_path, clock)
    to_planning(inv)
    with pytest.raises(InvestigationError, match="pending"):
        inv.transition(InvState.WAITING_APPROVAL)


def test_terminal_state_is_final(tmp_path, clock):
    inv = new(tmp_path, clock)
    inv.transition(InvState.CANCELLED, "owner stopped")
    for s in InvState:
        if s is not InvState.EXECUTING:
            with pytest.raises(InvestigationError):
                inv.transition(s)


# --- proposals -------------------------------------------------------------------------------

def test_proposal_records_every_required_field(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    assert act.status is ActionStatus.PROPOSED
    assert act.investigation_id == inv.investigation_id
    assert (act.tool, act.host, act.port, act.path, act.tier) == (
        "http_get_path", HOST, PORT, "/main.js", "passive")
    assert act.risk == "low" and act.scope_allowed is True
    assert len(act.fingerprint) == 64 and act.expected_evidence


def test_proposal_only_in_planning(tmp_path, clock):
    inv = new(tmp_path, clock)
    with pytest.raises(InvestigationError, match="PLANNING"):
        inv.propose(tool="http_get_path", host=HOST, port=PORT, path="/main.js",
                    scope_check=allow_main_js)


@pytest.mark.parametrize("host,port,path", [
    ("192.168.56.104", PORT, "/main.js"),   # wrong host
    ("8.8.8.8", PORT, "/main.js"),          # external
    (HOST, 3001, "/main.js"),               # wrong port
    (HOST, PORT, "/admin"),                 # wrong path
])
def test_out_of_scope_is_refused_never_pending(tmp_path, clock, host, port, path):
    inv = new(tmp_path, clock)
    to_planning(inv)
    act = inv.propose(tool="http_get_path", host=host, port=port, path=path,
                      scope_check=allow_main_js)
    assert act.status is ActionStatus.REFUSED and not inv.pending()


def test_no_scope_check_means_default_deny(tmp_path, clock):
    inv = new(tmp_path, clock)
    to_planning(inv)
    act = inv.propose(tool="http_get_path", host=HOST, port=PORT, path="/main.js")
    assert act.status is ActionStatus.REFUSED


def test_a_raising_scope_check_is_a_denial(tmp_path, clock):
    def boom(*a):
        raise RuntimeError("scope file unreadable")
    inv = new(tmp_path, clock)
    to_planning(inv)
    assert inv.propose(tool="http_get_path", host=HOST, port=PORT, path="/main.js",
                       scope_check=boom).status is ActionStatus.REFUSED


def test_unknown_tool_and_bad_port_are_rejected(tmp_path, clock):
    inv = new(tmp_path, clock)
    to_planning(inv)
    with pytest.raises(InvestigationError, match="unknown tool"):
        inv.propose(tool="shell", host=HOST, port=PORT, scope_check=lambda *a: True)
    with pytest.raises(InvestigationError, match="integer"):
        inv.propose(tool="http_get_path", host=HOST, port="3000", path="/main.js",
                    scope_check=allow_main_js)


def test_duplicate_proposal_is_refused(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    inv.transition(InvState.PLANNING)  # back, with A still pending
    dup = inv.propose(tool="http_get_path", host=HOST, port=PORT, path="/main.js",
                      scope_check=allow_main_js)
    assert dup.status is ActionStatus.REFUSED and dup.action_id != act.action_id


# --- approvals -------------------------------------------------------------------------------

def test_approval_must_quote_the_exact_fingerprint(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    with pytest.raises(InvestigationError, match="does not match"):
        inv.approve(act.action_id, "0" * 64, scope_check=allow_main_js)
    assert act.status is ActionStatus.PROPOSED


def test_approval_is_single_use(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    inv.approve(act.action_id, act.fingerprint, scope_check=allow_main_js)
    with pytest.raises(InvestigationError, match="not PROPOSED"):
        inv.approve(act.action_id, act.fingerprint, scope_check=allow_main_js)


def test_stale_approval_expires(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    clock.t += timedelta(minutes=16)
    with pytest.raises(InvestigationError, match="expired"):
        inv.approve(act.action_id, act.fingerprint, scope_check=allow_main_js)
    assert act.status is ActionStatus.EXPIRED
    with pytest.raises(InvestigationError):
        inv.begin_execution(act.action_id)


def test_scope_recheck_at_approval(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    with pytest.raises(InvestigationError, match="no longer allows"):
        inv.approve(act.action_id, act.fingerprint, scope_check=lambda *a: False)
    assert act.status is ActionStatus.DENIED


def test_denied_action_cannot_run(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    inv.deny(act.action_id)
    with pytest.raises(InvestigationError, match="not APPROVED"):
        inv.begin_execution(act.action_id)
    inv.transition(InvState.INCONCLUSIVE, "owner denied the only useful action")
    assert inv.terminal


def test_unapproved_action_cannot_run(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    with pytest.raises(InvestigationError, match="not APPROVED"):
        inv.begin_execution(act.action_id)


# --- execution -------------------------------------------------------------------------------

def run_ok(inv, act, sha="a" * 64):
    inv.approve(act.action_id, act.fingerprint, scope_check=allow_main_js)
    rid = inv.begin_execution(act.action_id)
    inv.finish_execution(act.action_id, ok=True, request_id=rid, evidence_sha256=sha)
    return rid


def test_full_happy_path_and_reload(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    rid = run_ok(inv, act)
    assert inv.state is InvState.VERIFYING and act.status is ActionStatus.SUCCEEDED
    inv.transition(InvState.ANALYZING)
    inv.transition(InvState.COMPLETED, "evidence sufficient")
    again = Investigation.load(tmp_path, inv.investigation_id, clock=clock)
    assert again.snapshot() == inv.snapshot()
    assert again.actions[act.action_id].request_id == rid and again.verify()


def test_executed_action_cannot_run_or_be_proposed_again(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    run_ok(inv, act)
    with pytest.raises(InvestigationError):
        inv.begin_execution(act.action_id)
    inv.transition(InvState.ANALYZING)
    inv.transition(InvState.PLANNING)
    again = inv.propose(tool="http_get_path", host=HOST, port=PORT, path="/main.js",
                        scope_check=allow_main_js)
    assert again.status is ActionStatus.REFUSED


def test_result_must_correlate_with_request_id(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    inv.approve(act.action_id, act.fingerprint, scope_check=allow_main_js)
    inv.begin_execution(act.action_id)
    with pytest.raises(InvestigationError, match="correlate"):
        inv.finish_execution(act.action_id, ok=True, request_id="other", evidence_sha256="a")


def test_success_without_evidence_is_a_failure(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    inv.approve(act.action_id, act.fingerprint, scope_check=allow_main_js)
    rid = inv.begin_execution(act.action_id)
    inv.finish_execution(act.action_id, ok=True, request_id=rid, evidence_sha256=None)
    assert act.status is ActionStatus.FAILED and "no evidence recorded" in act.errors


def test_error_text_is_redacted(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    inv.approve(act.action_id, act.fingerprint, scope_check=allow_main_js)
    rid = inv.begin_execution(act.action_id)
    inv.finish_execution(act.action_id, ok=False, request_id=rid,
                         errors=["RunnerAuthError: token sk-ant-api03-SECRETSECRETSECRET"])
    assert "SECRETSECRET" not in inv._log.path.read_text(encoding="utf-8")


def test_interrupted_execution_is_never_rerun_after_restart(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    inv.approve(act.action_id, act.fingerprint, scope_check=allow_main_js)
    inv.begin_execution(act.action_id)        # ... process dies here
    again = Investigation.load(tmp_path, inv.investigation_id, clock=clock)
    a = again.actions[act.action_id]
    assert a.status is ActionStatus.INTERRUPTED and again.state is InvState.FAILED
    with pytest.raises(InvestigationError):
        again.begin_execution(act.action_id)
    # recovery is itself recorded and a second load is stable
    third = Investigation.load(tmp_path, inv.investigation_id, clock=clock)
    assert third.snapshot() == again.snapshot() and third.verify()


def test_pending_proposal_survives_restart_but_still_expires(tmp_path, clock):
    inv, act = proposed(tmp_path, clock)
    clock.t += timedelta(hours=2)
    again = Investigation.load(tmp_path, inv.investigation_id, clock=clock)
    with pytest.raises(InvestigationError, match="expired"):
        again.approve(act.action_id, act.fingerprint, scope_check=allow_main_js)


# --- tampering -------------------------------------------------------------------------------

def test_edited_log_refuses_to_load(tmp_path, clock):
    inv, _ = proposed(tmp_path, clock)
    p = inv._log.path
    p.write_text(p.read_text(encoding="utf-8").replace("/main.js", "/admin"), encoding="utf-8")
    with pytest.raises(InvestigationError, match="hash-chain"):
        Investigation.load(tmp_path, inv.investigation_id)


def test_validly_chained_but_illegal_history_refuses_to_load(tmp_path, clock):
    from avra.storage.audit import AuditLog

    inv = new(tmp_path, clock)
    AuditLog(inv._log.path).record("state_changed", {"to": "COMPLETED"})  # skips the graph
    with pytest.raises(InvestigationError, match="illegal transition"):
        Investigation.load(tmp_path, inv.investigation_id)


def test_forged_approval_record_for_unknown_action_refuses_to_load(tmp_path, clock):
    from avra.storage.audit import AuditLog

    inv = new(tmp_path, clock)
    AuditLog(inv._log.path).record("action_approved", {"action_id": "x", "by": "model"})
    with pytest.raises(InvestigationError, match="unknown action"):
        Investigation.load(tmp_path, inv.investigation_id)


def test_bad_ids_are_rejected(tmp_path):
    with pytest.raises(InvestigationError, match="valid"):
        Investigation.load(tmp_path, "../../etc/passwd")
    with pytest.raises(InvestigationError, match="no investigation"):
        Investigation.load(tmp_path, "00000000-0000-4000-8000-000000000000")


def test_snapshot_is_json_serialisable(tmp_path, clock):
    inv, _ = proposed(tmp_path, clock)
    json.dumps(inv.snapshot())
