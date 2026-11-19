"""M11 (ADR 0019): conversational agent - store, knowledge, agent, approvals, REPL, CLI.

A scripted provider stands in for the model; data is a COPY of the synthetic lab
sessions in tests/fixtures/synthetic-sessions. No network, no model, no Runner."""

from __future__ import annotations

import itertools
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avra.chat import knowledge as kb
from avra.chat.agent import READ_ONLY, ChatAgent
from avra.chat.repl import Repl
from avra.chat.store import ChatStoreError, Conversation, list_conversations, redact
from avra.llm.config import LLMConfig, TokenUsage
from avra.llm.provider import LLMProviderError, LLMResponse, ToolUse
from avra.policy.scope import ScopeChecker
from avra.schemas.scope import ActionTier, Scope, Target

REPO = Path(__file__).resolve().parents[2]
HTTP_SID = "7e868faf-768d-49af-aea6-81dc9d435e20"
NMAP_SID = "4460bea8-d974-406c-bb65-75c3be0a899f"
FIXTURES = REPO / "tests" / "fixtures" / "validation"


@pytest.fixture
def data(tmp_path, monkeypatch):
    root = tmp_path / "data"
    shutil.copytree(REPO / "tests" / "fixtures" / "synthetic-sessions", root)
    monkeypatch.setenv("AVRA_DATA_DIR", str(root))
    return root


def _checker(tools=("http_probe", "http_get_path"), paths=("/main.js",)):
    return ScopeChecker(Scope(session_name="chat-test",
                              expires_at=datetime.now(UTC) + timedelta(days=1),
                              targets=[Target(host="10.66.7.103", ports=[3000],
                                              allowed_tiers=[ActionTier.PASSIVE],
                                              allowed_tools=list(tools),
                                              http_paths=list(paths))]))


class Model:
    def __init__(self, script):
        self.config = LLMConfig(provider="local-openai-compatible", model="scripted")
        self.script, self.seen = list(script), []

    def count_input_tokens(self, *, system, messages, tools):
        return 500

    def complete(self, *, system, messages, tools):
        self.seen.append({"system": system[0]["text"],
                          "messages": json.loads(json.dumps(messages, default=str)),
                          "tools": [t["name"] for t in tools]})
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, str):
            return _resp("end_turn", text=step)
        return _resp("tool_use", uses=step)

    def last_tool_result(self, call=-1):
        return self.seen[call]["messages"][-1]["content"][0]


def _resp(stop, uses=(), text=""):
    return LLMResponse(stop_reason=stop, text=text, tool_uses=tuple(uses),
                       usage=TokenUsage(input_tokens=500, output_tokens=40), model="scripted",
                       request_id=None,
                       history_content=([{"type": "text", "text": text}] if text else [])
                       + [{"type": "tool_use", "id": u.id, "name": u.name, "input": u.input}
                          for u in uses])


def _use(tool, i=1, **inp):
    return ToolUse(id=f"c{i}", name=tool, input=inp)


def _agent(data, script, **kw):
    model = Model(script)
    # M14.5: the scripted model reports no window; give it a roomy one so these M11 tests
    # keep testing chat behaviour. The 4096-token budget is covered in test_m145_chat.py.
    kw.setdefault("context_tokens", 32768)
    return ChatAgent(model, Conversation(data, kw.pop("name", "t")), fixtures_dir=FIXTURES,
                     **kw), model


# --- store ---------------------------------------------------------------------------------

def test_store_roundtrip_and_redaction(data):
    c = Conversation(data, "Work-1")
    assert c.name == "work-1"
    c.append("user", "my key is sk-ant-api03-abcdefghijklmnopqrstuvwx and password=hunter2")
    c.append("assistant", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123")
    text = c.path.read_text(encoding="utf-8")
    assert "hunter2" not in text and "sk-ant-api03" not in text and "abcdefghijklmnopq" not in text
    assert [m.role for m in c.messages()] == ["user", "assistant"]
    assert redact("token: abc123") == "token: [REDACTED]"
    for bad in ("", "../x", "a b", "x" * 50, "/etc"):
        with pytest.raises(ChatStoreError):
            Conversation(data, bad)


def test_history_is_bounded_compacted_and_alternating(data):
    c = Conversation(data, "long")
    for i in range(12):
        c.append("user", f"question {i} " + "x" * 400)
        c.append("assistant", f"answer {i}")
    c.append("avra_note", "Action A1 was declined by the owner; nothing ran.")
    h = c.model_history(max_chars=3000, keep_turns=4)
    assert h[0]["role"] == "user" and "compacted" in h[0]["content"]
    assert "question 0" in h[0]["content"]  # older questions survive as a short note
    assert sum(len(m["content"]) for m in h) < 5000
    assert all(a["role"] != b["role"] for a, b in itertools.pairwise(h))
    assert "[AVRA record, not the user]" in h[-2]["content"]


def test_list_conversations(data):
    Conversation(data, "a").append("user", "hello there")
    rows = list_conversations(data)
    assert rows[0]["name"] == "a" and rows[0]["first_question"] == "hello there"


# --- knowledge -------------------------------------------------------------------------------

def test_list_and_resolve(data):
    inv = kb.list_investigations()
    assert {r["session_id"] for r in inv["investigations"]} == {HTTP_SID, NMAP_SID}
    row = next(r for r in inv["investigations"] if r["session_id"] == HTTP_SID)
    assert row["audit_valid"] and row["tool_runs"] == {"http_probe": 1}
    assert kb.resolve_session("7e868f") == HTTP_SID
    with pytest.raises(kb.KnowledgeError):
        kb.resolve_session("7e8")
    with pytest.raises(kb.KnowledgeError):
        kb.investigation("../../etc")


def test_investigation_groups_verdicts(data):
    d = kb.investigation(HTTP_SID)
    weak = {w["rule"] for w in d["configuration_weaknesses"]}
    assert weak == {"http.cors_wildcard_origin", "http.missing_content_security_policy"}
    assert d["confirmed_vulnerabilities"] == []
    assert "http.cookie_missing_httponly" in {r["rule"] for r in d["rejected"]}
    assert d["http_responses"][0]["status_code"] == 200
    assert "not a proven exploitable" in d["legend"]


def test_explain_cors(data):
    e = kb.explain(HTTP_SID, "http.cors_wildcard_origin")
    r = e["results"][0]
    assert r["verdict"] == "CONFIRMED" and r["evidence"][0]["request_id"].startswith("5c746502")
    assert len(r["evidence"][0]["sha256"]) == 64
    assert "configuration weakness" in e["classification"] and e["remediation"]
    with pytest.raises(kb.KnowledgeError):
        kb.explain(HTTP_SID, "rce.everything")


def test_plan_marks_what_needs_approval(data):
    p = kb.plan(HTTP_SID, _checker())
    gets = [s for s in p["steps"] if s["kind"] == "http_get_path"]
    main = next(s for s in gets if s["path"] == "/main.js")
    assert main["readiness"] == "ready_to_propose"           # in scope, still needs /approve
    assert any(s["readiness"] == "needs_scope_change" for s in gets if s["path"] != "/main.js")
    assert any(s["kind"] == "validation_check" and s["readiness"] == "needs_capability"
               for s in p["steps"])
    assert "nothing has been run" in p["note"] and "/approve" in p["conclusion"]
    nmap_only = kb.plan(NMAP_SID)  # http evidence missing, no scope bound
    assert any(s["kind"] == "http_probe" and s["readiness"] == "needs_scope"
               for s in nmap_only["steps"])


# --- agent -----------------------------------------------------------------------------------

def test_answer_from_evidence_and_persist(data):
    a, m = _agent(data, [[_use("get_investigation", session_id="latest")],
                         "CSP missing and CORS * are configuration weaknesses."])
    r = a.ask("Summarize the last Juice Shop investigation.")
    assert r.text.startswith("CSP missing") and r.tool_calls == ["get_investigation"]
    res = m.last_tool_result()
    assert res["content"].startswith("<avra_data>") and "configuration_weaknesses" in res["content"]
    assert [x.role for x in a.conv.messages()] == ["user", "assistant"]
    events = [x.event for x in a.audit.read_all()]
    assert events.count("llm_call") == 2 and "chat_tool" in events and a.audit.verify()


def test_request_action_tool_omitted_without_scope(data):
    # M13 Goal 4: no scope bound -> request_action schema is not sent (it would only refuse),
    # but every read-only tool still is, and the read-only chat answers normally.
    a, m = _agent(data, [[_use("get_investigation", session_id="latest")], "answer"])
    a.ask("Summarize.")
    sent = m.seen[0]["tools"]
    assert "request_action" not in sent
    assert "get_investigation" in sent and "summarize_investigation" in sent
    assert set(sent) == READ_ONLY  # exactly the read-only set


def test_request_action_tool_present_with_scope(data):
    # With a scope bound and an explicit action request (M14.5 intent gate), the full tool
    # set (including request_action) is sent.
    a, m = _agent(data, ["answer"], checker=_checker())
    a.ask("Propose a probe of the lab web server.")
    assert "request_action" in m.seen[0]["tools"]
    assert set(m.seen[0]["tools"]) == READ_ONLY | {"request_action"}


def test_second_turn_sees_history_but_not_old_tool_dumps(data):
    a, m = _agent(data, [[_use("get_investigation", session_id="latest")], "first answer",
                         "second answer"])
    a.ask("Summarize.")
    a.ask("Why?")
    msgs = m.seen[-1]["messages"]
    assert [x["role"] for x in msgs] == ["user", "assistant", "user"]
    assert "configuration_weaknesses" not in json.dumps(msgs)  # tool output not replayed


def test_chat_go_ahead_does_not_execute(data):
    calls = []
    a, _m = _agent(data, [[_use("request_action", kind="http_get_path", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="/main.js",
                                reason="read the main script")],
                          "Proposed A1. Type /approve A1 to run it.",
                          "You need to type /approve A1."],
                   checker=_checker(), executor=lambda act: calls.append(act) or {"ok": True})
    r = a.ask("Fetch /main.js please")
    assert [x.id for x in r.new_actions] == ["A1"] and "[pending] A1" in r.text
    a.ask("yes go ahead, do it and anything else you need")
    assert calls == [] and a.pending["A1"].status == "pending"


def test_approve_runs_exactly_once_after_confirmation(data):
    calls = []
    a, _m = _agent(data, [[_use("request_action", kind="http_get_path", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="/main.js",
                                reason="x")], "ok"],
                   checker=_checker(),
                   executor=lambda act: calls.append(act.id) or {"ok": True, "http_status": 200})
    a.ask("propose it")
    assert "cancelled" in a.approve("A1", lambda act: False) and calls == []
    a.pending["A1"].status = "pending"
    out = a.approve("a1", lambda act: True)
    assert calls == ["A1"] and "executed" in out
    assert "No pending action" in a.approve("A1", lambda act: True) and calls == ["A1"]
    assert a.conv.messages()[-1].role == "avra_note"
    ev = [x.event for x in a.audit.read_all()]
    assert ev.count("chat_action_approved") == 1 and "chat_action_result" in ev


def test_actions_need_scope_surface_and_are_not_restored(data):
    a, m = _agent(data, [[_use("request_action", kind="http_probe", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "no"])
    a.ask("probe it")  # no scope bound
    # M14.5: without a scope request_action is not even offered, so the call is refused
    # before it reaches the scope check; either way nothing is pending.
    res = m.last_tool_result()["content"]
    assert a.pending == {} and ("no scope file" in res or "not available" in res)

    b, m2 = _agent(data, [[_use("request_action", kind="http_get_path", session_id=HTTP_SID,
                                 host="10.66.7.103", port=3000, path="/invented",
                                 reason="x"),
                            _use("request_action", 2, kind="http_get_path",
                                 session_id=HTTP_SID, host="10.66.7.103", port=3000,
                                 path="/styles.css", reason="x"),
                            _use("request_action", 3, kind="nmap_connect_scan",
                                 session_id=HTTP_SID, host="10.66.7.103", port=3000,
                                 path="", reason="x")], "done"], checker=_checker())
    b.ask("propose a few actions to try")
    results = m2.seen[-1]["messages"][-1]["content"]
    assert "not in the session's recorded web surface" in results[0]["content"]
    assert "refused_by_scope" in results[1]["content"]  # /styles.css not in http_paths
    assert "refused_by_scope" in results[2]["content"]  # nmap not allowed by this scope
    assert b.pending == {}

    c, _ = _agent(data, [[_use("request_action", kind="http_probe", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok"],
                  checker=_checker(), name="resume")
    c.ask("propose")
    assert "A1" in c.pending
    resumed, _ = _agent(data, [], checker=_checker(), name="resume")
    assert resumed.pending == {}
    assert "No pending action" in resumed.approve("A1", lambda act: True)


def test_approve_without_executor_or_after_scope_change(data):
    a, _ = _agent(data, [[_use("request_action", kind="http_probe", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok"],
                  checker=_checker())
    a.ask("propose a probe")
    assert "not available" in a.approve("A1", lambda act: True)
    b, _ = _agent(data, [[_use("request_action", kind="http_probe", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok"],
                  checker=_checker(), executor=lambda act: {"ok": True}, name="b")
    b.ask("propose a probe")
    b.checker = _checker(tools=("nmap_connect_scan",))
    assert "no longer allows" in b.approve("A1", lambda act: True)


def test_fixture_tool_and_errors(data):
    a, m = _agent(data, [[_use("evaluate_validation_fixture", name="idor-cross-account-read"),
                          _use("evaluate_validation_fixture", 2, name="../../secrets"),
                          _use("delete_everything", 3)], "done"])
    a.ask("show the IDOR check")
    res = m.seen[-1]["messages"][-1]["content"]
    assert "cross_account_read" in res[0]["content"] and "SIMULATED" in res[0]["content"]
    assert res[1]["is_error"] and res[2]["is_error"]


def test_interrupt_provider_error_killswitch_and_round_limit(data):
    from avra.control.killswitch import KillSwitchEngaged

    a, _ = _agent(data, [KeyboardInterrupt()])
    assert a.ask("x").stopped == "interrupted"
    b, _ = _agent(data, [LLMProviderError("server down")], name="b")
    assert "server down" in b.ask("x").text

    class Engaged:
        def check(self, op):
            raise KillSwitchEngaged.__new__(KillSwitchEngaged)

    c, m = _agent(data, ["never"], name="c", killswitch=Engaged())
    assert c.ask("x").stopped == "kill_switch" and m.seen == []
    d, _ = _agent(data, [[_use("list_investigations")]] * 4, name="d", max_rounds=4)
    assert d.ask("x").stopped == "max_rounds"


def test_system_prompt_states_the_rules(data):
    a, m = _agent(data, ["hi"])
    a.ask("Salom AVRA!")
    sysmsg = m.seen[0]["system"]
    assert "Uzbek" in sysmsg and "/approve" in sysmsg and "approve nothing" in sysmsg
    assert "none bound" in sysmsg


# --- REPL + CLI ------------------------------------------------------------------------------

def test_repl_commands(data):
    a, _ = _agent(data, ["Hello! I can explain your investigations."])
    out, lines = [], iter(["/help", "hello", "/pending", "/approve A1", "/history 5",
                           "/status", "/bogus", "/exit"])
    repl = Repl(a, read=lambda p: next(lines), write=out.append, interactive=False,
                confirm=lambda q: True, data_root=data,
                status={"model": "scripted", "provider": "local", "local": True,
                        "messages": 0, "scope": None})
    assert repl.run() == 0
    text = "\n".join(out)
    assert "/approve <id>" in text and "AVRA" in text and "Hello!" in text
    assert "no proposed actions" in text and "needs a real terminal" in text
    assert "you: hello" in text and "Unknown command" in text and "Bye." in text


def test_repl_ctrl_c_at_prompt_exits(data):
    a, _ = _agent(data, [])

    def read(prompt):
        raise KeyboardInterrupt

    out = []
    assert Repl(a, read=read, write=out.append, interactive=True, confirm=lambda q: True,
                data_root=data, status={"model": "m", "provider": "p", "local": True,
                                        "messages": 0, "scope": None}).run() == 0


def test_cli_list_show_new(data):
    from typer.testing import CliRunner

    from avra.cli.main import app

    Conversation(data, "demo").append("user", "hello")
    r = CliRunner().invoke(app, ["chat", "--list"])
    assert r.exit_code == 0 and "demo" in r.output
    r = CliRunner().invoke(app, ["chat", "demo", "--show"])
    assert "user: hello" in r.output
    r = CliRunner().invoke(app, ["chat", "demo", "--new"])
    assert r.exit_code == 1 and "already exists" in r.output
    r = CliRunner().invoke(app, ["chat", "bad name!"])
    assert r.exit_code == 1 and "Refused" in r.output


def test_resume_marks_earlier_proposals_expired(data):
    a, _ = _agent(data, [[_use("request_action", kind="http_probe", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok"],
                  checker=_checker(), name="exp")
    a.ask("propose")
    b, m = _agent(data, ["It expired; I can propose it again."], checker=_checker(), name="exp")
    note = b.conv.messages()[-1]
    assert note.role == "avra_note" and "A1" in note.content and "EXPIRED" in note.content
    b.ask("can I approve A1?")
    assert "EXPIRED" in json.dumps(m.seen[0]["messages"])
    assert "anything mentioned earlier" in m.seen[0]["system"]
    assert "Pending actions approvable right now" in m.seen[0]["system"]


def test_ids_continue_after_expired_ones(data):
    a, _ = _agent(data, [[_use("request_action", kind="http_probe", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok"],
                  checker=_checker(), name="ids")
    a.ask("propose")
    b, _ = _agent(data, [[_use("request_action", kind="http_probe", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok"],
                  checker=_checker(), name="ids")
    b.ask("propose again")
    assert list(b.pending) == ["A2"]
    assert "No pending action" in b.approve("A1", lambda act: True)


# --- M12.3: scope-aware natural-language -> proposal -> /approve -> Runner ------------------

def _nmap_checker():
    """A scope that authorizes exactly an nmap connect scan of 10.66.7.103:3000."""
    return ScopeChecker(Scope(session_name="chat-nmap",
                              expires_at=datetime.now(UTC) + timedelta(days=1),
                              targets=[Target(host="10.66.7.103", ports=[3000],
                                              allowed_tiers=[ActionTier.ACTIVE_SAFE],
                                              allowed_tools=["nmap_connect_scan"])]))


def _expired_checker():
    return ScopeChecker(Scope(session_name="chat-expired",
                              expires_at=datetime.now(UTC) - timedelta(minutes=1),
                              targets=[Target(host="10.66.7.103", ports=[3000],
                                              allowed_tiers=[ActionTier.ACTIVE_SAFE],
                                              allowed_tools=["nmap_connect_scan"])]))


def test_nmap_proposal_port_3000_happy_path(data):
    calls = []
    a, _ = _agent(data, [[_use("request_action", kind="nmap_connect_scan", session_id=NMAP_SID,
                                host="10.66.7.103", port=3000, path="",
                                reason="confirm the port is open")], "ok"],
                  checker=_nmap_checker(),
                  executor=lambda act: calls.append((act.kind, act.host, act.port))
                  or {"ok": True, "request_id": "r1", "evidence_sha256": "abc123"})
    r = a.ask("Scan my Ubuntu lab VM at 10.66.7.103 using Nmap.")
    assert [x.id for x in r.new_actions] == ["A1"]
    assert a.pending["A1"].kind == "nmap_connect_scan" and a.pending["A1"].scope_allows
    out = a.approve("A1", lambda act: True)
    assert calls == [("nmap_connect_scan", "10.66.7.103", 3000)]
    assert "executed" in out and a.pending["A1"].status == "executed"


def test_refuse_out_of_scope_host_and_port(data):
    a, m = _agent(data, [[_use("request_action", kind="nmap_connect_scan", session_id=NMAP_SID,
                                host="192.168.56.1", port=3000, path="", reason="x"),
                          _use("request_action", 2, kind="nmap_connect_scan",
                               session_id=NMAP_SID, host="10.66.7.103", port=8080,
                               path="", reason="x")], "done"], checker=_nmap_checker())
    a.ask("scan the gateway and an alt port")
    res = m.seen[-1]["messages"][-1]["content"]
    assert "refused_by_scope" in res[0]["content"]   # wrong host
    assert "refused_by_scope" in res[1]["content"]   # wrong port
    assert a.pending == {}


def test_expired_scope_refuses_proposal_and_approval(data):
    a, _ = _agent(data, [[_use("request_action", kind="nmap_connect_scan", session_id=NMAP_SID,
                                host="10.66.7.103", port=3000, path="",
                                reason="x")], "ok"], checker=_expired_checker(),
                  executor=lambda act: {"ok": True})
    a.ask("scan it")
    assert a.pending == {}  # an expired scope authorizes nothing


def test_runner_down_and_auth_failure_are_actionable(data):
    from avra.runner_client.client import RunnerClientError

    # pipeline folds the transport error into a structured result with an actionable message
    a, _ = _agent(data, [[_use("request_action", kind="nmap_connect_scan", session_id=NMAP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok"],
                  checker=_nmap_checker(),
                  executor=lambda act: {"ok": False, "stage": "runner",
                                        "message": "could not reach the Runner. Check the SSH "
                                                   "tunnel is up."})
    a.ask("scan it")
    note = a.approve("A1", lambda act: True)
    assert a.pending["A1"].status == "failed" and "could not reach the Runner" in note

    # an executor that raises must not crash the chat; it yields an actionable message
    def boom(act):
        raise RunnerClientError("cannot reach the Runner: ConnectionRefusedError")

    b, _ = _agent(data, [[_use("request_action", kind="nmap_connect_scan", session_id=NMAP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok"],
                  checker=_nmap_checker(), executor=boom, name="b")
    b.ask("scan it")
    out = b.approve("A1", lambda act: True)
    assert b.pending["A1"].status == "failed" and "kill switch" in out
    assert "ConnectionRefusedError" not in out  # raw exception text is not leaked to the note
    assert b.pending["A1"].result["error"] == "RunnerClientError"


def test_evidence_and_audit_integrity(data):
    a, _ = _agent(data, [[_use("request_action", kind="nmap_connect_scan", session_id=NMAP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok"],
                  checker=_nmap_checker(),
                  executor=lambda act: {"ok": True, "request_id": "r9",
                                        "evidence_sha256": "deadbeef" * 8})
    a.ask("scan it")
    a.approve("A1", lambda act: True)
    recs = a.audit.read_all()
    assert a.audit.verify()  # the conversation audit chain stays valid
    result = [r for r in recs if r.event == "chat_action_result"][-1]
    assert result.data["status"] == "executed"
    assert result.data["result"]["evidence_sha256"] == "deadbeef" * 8
    approved = [r for r in recs if r.event == "chat_action_approved"]
    assert len(approved) == 1 and approved[0].data["kind"] == "nmap_connect_scan"


def test_runner_failure_hint_messages():
    from avra.cli.main import _runner_failure_hint

    assert "authentication failed" in _runner_failure_hint(["RunnerAuthError: rejected (401)"])
    assert "could not reach the Runner" in _runner_failure_hint(
        ["RunnerClientError: cannot reach the Runner: ConnectionRefusedError"])
    assert "SSH tunnel" in _runner_failure_hint(["TunnelError: ssh client not found"])
    assert "kill switch" in _runner_failure_hint(["KillSwitchEngaged: kill switch engaged"])
    assert "did not complete" in _runner_failure_hint([])
    # the hint names only the env var AVRA_RUNNER_TOKEN, never a token value
    assert "AVRA_RUNNER_TOKEN" in _runner_failure_hint(["RunnerAuthError: rejected (401)"])


def test_chat_runner_status_wraps_unexpected_error_secret_free(monkeypatch):
    # M12.3 F1: _chat_runner_status promises a secret-free RuntimeError on ANY failure. An
    # UNEXPECTED exception (not one of the three known types) must still be wrapped, surfacing
    # only its type name - never its message, which could carry a secret.
    from avra.cli.main import _chat_runner_status

    def boom(**_kw):
        raise OSError("sk-ant-secret-token-value-should-not-appear")

    # load_token is imported inside the function from this module, so patch it there.
    monkeypatch.setattr("avra.runner_client.client.load_token", boom)
    with pytest.raises(RuntimeError) as ei:
        _chat_runner_status(kali="192.168.56.104", key=None)
    msg = str(ei.value)
    assert "OSError" in msg and "unexpectedly" in msg
    assert "sk-ant-secret-token-value" not in msg  # the raw message is never surfaced


def test_chat_execute_redacts_pipeline_errors(data, monkeypatch):
    # M13.2 F2: a pipeline error string that happened to carry a secret must be redacted
    # before it enters act.result (persisted to the conversation) and the audit record.
    import types

    from avra.chat.agent import PendingAction
    from avra.cli.main import _chat_execute

    fake = types.SimpleNamespace(
        ok=False, request=types.SimpleNamespace(request_id="r1"), evidence=None,
        errors=["RunnerClientError: leaked token=sk-ant-supersecretvalue0123456789 here"])
    monkeypatch.setattr("avra.runner_client.scan.run_nmap_connect_scan", lambda **kw: fake)

    act = PendingAction(id="A1", kind="nmap_connect_scan", session_id=NMAP_SID,
                        host="10.66.7.103", port=3000, path="", reason="x", scope_allows=True)
    result = _chat_execute(act, checker=_nmap_checker(), kali="192.168.56.104", key=None)
    blob = json.dumps(result)
    assert "sk-ant-supersecretvalue" not in blob and "[REDACTED]" in blob


def test_env_file_resolution(monkeypatch, tmp_path):
    # M13.2 F3: explicit override wins; otherwise .env is anchored to the project root
    # (the dir with pyproject.toml), never silently taken from an arbitrary CWD.
    from avra.cli.main import _env_file

    monkeypatch.setenv("AVRA_ENV_FILE", str(tmp_path / "custom.env"))
    assert _env_file() == tmp_path / "custom.env"
    monkeypatch.delenv("AVRA_ENV_FILE", raising=False)
    p = _env_file()
    assert p.name == ".env" and (p.parent / "pyproject.toml").is_file()


def test_scope_summary_lines():
    assert "read-only" in kb.scope_summary(None)[0]
    lines = kb.scope_summary(_nmap_checker())
    assert "chat-nmap" in lines[0]
    assert any("10.66.7.103" in ln and "nmap_connect_scan" in ln for ln in lines)
    assert "[EXPIRED" in kb.scope_summary(_expired_checker())[0]


def test_repl_scope_and_runner_commands(data):
    a, _ = _agent(data, [], checker=_nmap_checker(), name="repl2")
    status = {"model": "scripted", "provider": "local", "local": True, "messages": 0,
              "scope": "chat-nmap"}

    # /scope prints the authorized target and tools
    out, lines = [], iter(["/scope", "/exit"])
    Repl(a, read=lambda p: next(lines), write=out.append, interactive=True,
         confirm=lambda q: True, data_root=data, status=status).run()
    assert any("nmap_connect_scan" in ln for ln in out)

    # /runner non-interactive is refused and contacts nothing
    out2, lines2 = [], iter(["/runner", "/exit"])
    Repl(a, read=lambda p: next(lines2), write=out2.append, interactive=False,
         confirm=lambda q: True, data_root=data, status=status,
         runner_status=lambda: {"tools": ["nmap_connect_scan"]}).run()
    assert any("needs a real terminal" in ln for ln in out2)

    # /runner interactive shows the Windows/Kali intersection (stubbed health)
    out3, lines3 = [], iter(["/runner", "/exit"])
    Repl(a, read=lambda p: next(lines3), write=out3.append, interactive=True,
         confirm=lambda q: True, data_root=data, status=status,
         runner_status=lambda: {"status": "ok",
                                "tools": ["nmap_connect_scan", "http_probe"]}).run()
    text3 = "\n".join(out3)
    assert "Kali-registered tools" in text3 and "Usable here" in text3
    assert "nmap_connect_scan" in text3

    # /runner failure surfaces the actionable message, not a traceback
    def fail():
        raise RuntimeError("could not reach the Runner (cannot reach). Check avra-runner.")

    out4, lines4 = [], iter(["/runner", "/exit"])
    Repl(a, read=lambda p: next(lines4), write=out4.append, interactive=True,
         confirm=lambda q: True, data_root=data, status=status, runner_status=fail).run()
    assert any("Runner status failed" in ln and "avra-runner" in ln for ln in out4)


# --- M13: deterministic summaries, natural approval, prompt version ------------------------

_STATUS = {"model": "scripted", "provider": "local", "local": True, "messages": 0,
           "scope": "chat-nmap"}


def _repl(agent, lines, data, interactive=True, confirm=True, **kw):
    out = []
    it = iter(list(lines) + ["/exit"])
    r = Repl(agent, read=lambda p: next(it), write=out.append, interactive=interactive,
             confirm=lambda q: confirm, data_root=data, status=_STATUS, **kw)
    r.run()
    return out


def test_summary_matches_engine_verdict_and_is_smaller(data):
    sid = kb.resolve_session(NMAP_SID)
    s = kb.summary(sid)
    inv = kb.investigation(sid)
    tcp = next(r for grp in ("verified_observations", "inconclusive", "rejected")
               for r in inv[grp] if r["rule"] == "net.tcp_port_open")
    # the digest carries the engine verdict verbatim - it never computes or upgrades one
    assert s["port_status"]["verdict"] == tcp["verdict"]
    assert s["port_status"]["state_counts"] == {"open": 1}
    assert len(json.dumps(s, default=str)) < len(json.dumps(inv, default=str))


def test_render_summary_uz_preserves_inconclusive():
    r = Repl.__new__(Repl)  # render is pure; no agent needed
    synthetic = {"session_id": "abcd1234-0000-0000-0000-000000000000",
                 "audit_chain_valid": True, "evidence_trusted": True,
                 "port_status": {"targets": ["10.66.7.103:3000"], "latest_state": "closed",
                                 "state_counts": {"open": 4, "closed": 1}, "scan_count": 5,
                                 "conflicting": True, "verdict": "INCONCLUSIVE",
                                 "reason": "conflict"},
                 "http": [], "verdict_counts": {"verified_observations": 0,
                 "configuration_weaknesses": 0, "confirmed_vulnerabilities": 0, "rejected": 0,
                 "inconclusive": 1}, "configuration_weaknesses": [],
                 "confirmed_vulnerabilities": []}
    text = "\n".join(r._render_summary_uz(synthetic))
    assert "NOANIQ" in text and "zid" in text
    assert "TASDIQLANGAN" not in text  # INCONCLUSIVE is never shown as confirmed
    assert "4 marta OCHIQ" in text and "Oxirgi holat: YOPIQ" in text


def test_summary_and_details_commands_touch_no_model(data):
    a, m = _agent(data, [])  # empty script: any model call would raise (IndexError on pop)
    out = _repl(a, [f"/summary {NMAP_SID[:8]}", "/details latest"], data)
    text = "\n".join(out)
    assert "Tekshiruv natijasi" in text and "Manzil:" in text and "Umumiy xulosa:" in text
    assert m.seen == []  # no model call at all


def test_interpret_yes_no():
    f = Repl._interpret_yes_no
    # clean affirmations
    assert f("ha") == "yes" and f("Ha, tasdiqlayman.") == "yes" and f("yes") == "yes"
    assert f("y") == "yes" and f("roziman") == "yes" and f("ha iltimos") == "yes"
    assert f("yes please") == "yes" and f("ok") == "yes"
    # denials (fail-safe: a no-token with no yes-token is a decline)
    assert f("yo'q") == "no" and f("Yo‘q, bekor qil") == "no" and f("no") == "no"
    assert f("yoq") == "no" and f("n") == "no" and f("bekor") == "no" and f("stop") == "no"
    # not an answer
    assert f("nima qilyapsan") is None and f("bu haqida gapir") is None and f("") is None


def test_interpret_yes_no_rejects_ambiguous():
    """M13 security: no qualified or contradictory reply may read as 'yes'."""
    f = Repl._interpret_yes_no
    for ambiguous in ["Ha, lekin bajarma", "ha lekin hozircha yo'q", "ha yo'q",
                      "yes but not now", "ha bajarma", "ok lekin keyin",
                      "ha, ammo faqat 3000-portni", "tasdiqlayman, lekin yo'q",
                      "balki ha", "yaxshi"]:
        assert f(ambiguous) != "yes", ambiguous  # never authorizes
    # a contradictory reply is fully ambiguous (not even a safe 'no' is assumed from "ha yo'q")
    assert f("ha yo'q") is None


def _nmap_agent(data, extra_script=(), **kw):
    calls = []
    a, m = _agent(data, [[_use("request_action", kind="nmap_connect_scan", session_id=NMAP_SID,
                                host="10.66.7.103", port=3000, path="", reason="x")], "ok",
                         *extra_script], checker=_nmap_checker(),
                  executor=lambda act: calls.append(act.id) or {"ok": True}, **kw)
    return a, m, calls


def test_natural_yes_approves_single_pending(data):
    a, _m, calls = _nmap_agent(data)
    out = _repl(a, ["scan it", "ha"], data)
    assert calls == ["A1"] and a.pending["A1"].status == "executed"
    assert any("APPROVAL REQUIRED" in ln for ln in out)
    assert any("A1" in ln and "ID" in ln for ln in out)


def test_natural_no_denies_single_pending(data):
    a, _m, calls = _nmap_agent(data)
    _repl(a, ["scan it", "yo'q"], data)
    assert calls == [] and a.pending["A1"].status == "denied"


def test_ordinary_text_clears_context_and_never_approves(data):
    # after a proposal, a non-yes/no sentence is ordinary chat: it must not approve, and the
    # one-shot context must not persist to a later "ha"
    a, _m, calls = _nmap_agent(data, extra_script=["more info", "later reply"])
    out = _repl(a, ["scan it", "tell me more about it", "ha"], data)
    assert calls == []  # "ha" came after the context was already consumed by ordinary chat
    assert a.pending["A1"].status == "pending"
    assert "more info" in "\n".join(out)


def _both_checker():
    return ScopeChecker(Scope(session_name="chat-both",
                              expires_at=datetime.now(UTC) + timedelta(days=1),
                              targets=[Target(host="10.66.7.103", ports=[3000],
                                              allowed_tiers=[ActionTier.PASSIVE,
                                                             ActionTier.ACTIVE_SAFE],
                                              allowed_tools=["http_probe", "nmap_connect_scan"])]))


def test_multiple_pending_requires_explicit_id(data):
    calls = []
    a, _m = _agent(data, [[_use("request_action", kind="nmap_connect_scan", session_id=NMAP_SID,
                                 host="10.66.7.103", port=3000, path="", reason="x"),
                           _use("request_action", 2, kind="http_probe", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="", reason="y")], "ok",
                          "ignored"],
                  checker=_both_checker(),
                  executor=lambda act: calls.append(act.id) or {"ok": True})
    out = _repl(a, ["propose both actions", "ha"], data)
    assert calls == []  # bare "ha" never runs when the choice is ambiguous
    assert any("Bir nechta taklif" in ln for ln in out)
    assert sorted(a.pending) == ["A1", "A2"]


def test_slash_approve_still_works_and_clears_natural_context(data):
    a, _m, calls = _nmap_agent(data)
    _repl(a, ["scan it", "/approve A1"], data)  # backward compatibility
    assert calls == ["A1"] and a.pending["A1"].status == "executed"


def test_non_interactive_natural_yes_does_not_run(data):
    # interactive=False: no approval context is armed, and a bare "ha" cannot execute
    a, _m, calls = _nmap_agent(data, extra_script=["ignored"], name="ni")
    out = _repl(a, ["scan it", "ha"], data, interactive=False)
    assert calls == []
    assert not any("APPROVAL REQUIRED" in ln for ln in out)


def test_prompt_version_is_v4():
    from avra.chat.agent import PROMPT_VERSION
    assert PROMPT_VERSION == "chat-v4"  # M14.5


def test_ambiguous_reply_in_context_does_not_execute(data):
    # "ha, lekin bajarma" arrives while A1's approval context is active: it must NOT run,
    # the context is consumed, and the phrase is handled as ordinary chat.
    a, _m, calls = _nmap_agent(data, extra_script=["understood"])
    _repl(a, ["scan it", "ha, lekin bajarma"], data)
    assert calls == [] and a.pending["A1"].status == "pending"


def test_natural_yes_binds_to_newly_proposed_not_older_pending(data):
    # A1 (nmap) stays pending from turn 1; turn 2 proposes A2 (http_probe). A bare "ha" then
    # approves exactly A2 - the just-proposed action named in the prompt - never the older A1.
    calls = []
    a, _m = _agent(data, [[_use("request_action", kind="nmap_connect_scan", session_id=NMAP_SID,
                                 host="10.66.7.103", port=3000, path="", reason="x")], "ok",
                          [_use("request_action", 2, kind="http_probe", session_id=HTTP_SID,
                                host="10.66.7.103", port=3000, path="", reason="y")], "ok2"],
                  checker=_both_checker(),
                  executor=lambda act: calls.append(act.id) or {"ok": True})
    out = _repl(a, ["scan it", "probe it", "ha"], data)
    assert calls == ["A2"]  # only the freshly proposed action ran
    assert a.pending["A1"].status == "pending" and a.pending["A2"].status == "executed"
    assert any("APPROVAL REQUIRED" in ln for ln in out)
    assert any("A2" in ln and "ID" in ln for ln in out)


# --- M13.1: presentation wiring in the REPL (colour never affects state) -------------------

def _styler(enabled=True):
    from avra.chat.style import Styler
    return Styler(enabled=enabled, unicode_ok=True)


def test_repl_colours_roles_when_enabled(data):
    a, _m = _agent(data, ["Salom! Natijalarni tushuntiraman."])
    out = _repl(a, ["salom"], data, styler=_styler())
    text = "\n".join(out)
    assert "\x1b[32m" in text        # AVRA / banner green
    assert "\x1b[90m" in text        # SYSTEM stats gray
    assert "AVRA" in text and "Salom!" in text


def test_repl_plain_when_styler_disabled(data):
    a, _m = _agent(data, ["Salom!"])
    out = _repl(a, ["salom"], data, styler=_styler(enabled=False))
    assert "\x1b" not in "\n".join(out)   # no ANSI at all in plain mode


def test_repl_strips_injected_escapes_from_model_reply(data):
    a, _m = _agent(data, ["ok\x1b[2J\x1b[31mWIPE\x1b[0m done"])
    out = _repl(a, ["hi"], data, styler=_styler())
    text = "\n".join(out)
    assert "\x1b[2J" not in text and "\x1b[31mWIPE" not in text  # injection neutralised
    assert "WIPE" in text and "done" in text                    # content still shown


def test_approval_block_keeps_exact_action_target_id(data):
    a, _m, _calls = _nmap_agent(data)
    out = _repl(a, ["scan it"], data, styler=_styler())
    text = "\n".join(out)
    assert "APPROVAL REQUIRED" in text
    assert "10.66.7.103:3000" in text          # exact target preserved under colour
    assert "A1" in text and "\x1b[33m" in text     # yellow approval styling


def test_summary_command_colours_header_and_verdict(data):
    a, m = _agent(data, [])
    out = _repl(a, [f"/summary {NMAP_SID[:8]}"], data, styler=_styler())
    text = "\n".join(out)
    assert "\x1b[1;32m" in text              # heading bold-green
    assert "Umumiy xulosa:" in text and m.seen == []  # still zero model calls
