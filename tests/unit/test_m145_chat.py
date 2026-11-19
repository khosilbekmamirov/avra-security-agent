"""M14.5: local AI reliability & conversation quality - regression tests T01-T19.

Deterministic: a scripted provider stands in for the model, data is a COPY of the recorded
lab sessions, the "server" for provider tests is a loopback fake. No model, no Runner, no
network, no lab target. (T20 = the existing M13/M14 suites, run unchanged.)
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avra.chat import capabilities
from avra.chat import knowledge as kb
from avra.chat.agent import READ_ONLY, TOOLS, ChatAgent
from avra.chat.context import (
    ContextBudget,
    ContextBudgetError,
    compact_data,
    estimate_tokens,
    protected_values,
)
from avra.chat.intent import Intent, classify, tools_for
from avra.chat.repl import Repl
from avra.chat.store import Conversation
from avra.llm.config import LLMConfig, TokenUsage
from avra.llm.local import (
    ContextOverflowError,
    LocalOpenAICompatibleProvider,
    parse_chat_completion,
    to_openai_tools,
)
from avra.llm.provider import LLMProviderError, LLMResponse, ToolUse
from avra.policy.scope import ScopeChecker
from avra.schemas.scope import ActionTier, Scope, Target
from tests.fakes_local_llm import FakeOpenAIServer, completion

REPO = Path(__file__).resolve().parents[2]
NMAP_SID = "4460bea8-d974-406c-bb65-75c3be0a899f"
HTTP_SID = "7e868faf-768d-49af-aea6-81dc9d435e20"


@pytest.fixture
def data(tmp_path, monkeypatch):
    root = tmp_path / "data"
    shutil.copytree(REPO / "tests" / "fixtures" / "synthetic-sessions", root)
    monkeypatch.setenv("AVRA_DATA_DIR", str(root))
    return root


def _scope(minutes=60 * 24, tools=("nmap_connect_scan",)):
    return ScopeChecker(Scope(session_name="m145",
                              expires_at=datetime.now(UTC) + timedelta(minutes=minutes),
                              targets=[Target(host="10.66.7.103", ports=[3000],
                                              allowed_tiers=[ActionTier.ACTIVE_SAFE],
                                              allowed_tools=list(tools))]))


class Model:
    """Scripted provider: each step is a reply text, a list of ToolUse, or an exception."""

    def __init__(self, script, window=None):
        self.config = LLMConfig(provider="local-openai-compatible", model="scripted")
        self.script, self.seen, self.window = list(script), [], window

    def context_window(self):
        return self.window

    def count_input_tokens(self, *, system, messages, tools):
        return 100

    def complete(self, *, system, messages, tools):
        self.seen.append({"system": system[0]["text"],
                          "messages": json.loads(json.dumps(messages, default=str)),
                          "tools": [t["name"] for t in tools]})
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        uses = () if isinstance(step, str) else tuple(step)
        text = step if isinstance(step, str) else ""
        return LLMResponse(stop_reason="tool_use" if uses else "end_turn", text=text,
                           tool_uses=uses, usage=TokenUsage(input_tokens=300, output_tokens=20),
                           model="scripted", request_id=None,
                           history_content=([{"type": "text", "text": text}] if text else [])
                           + [{"type": "tool_use", "id": u.id, "name": u.name,
                               "input": u.input} for u in uses])


def _use(tool, i=1, **inp):
    return ToolUse(id=f"c{i}", name=tool, input=inp)


def _nmap(i=1):
    return _use("request_action", i, kind="nmap_connect_scan", session_id=NMAP_SID,
                host="10.66.7.103", port=3000, path="", reason="re-check port 3000")


def _agent(data, script, *, window=16384, name="t", **kw):
    m = Model(script, window)
    return ChatAgent(m, Conversation(data, name), **kw), m


def _tokens(seen: dict) -> int:
    return estimate_tokens([{"type": "text", "text": seen["system"]}], seen["messages"],
                           [t for t in TOOLS if t["name"] in seen["tools"]])


# --- T01 greeting ----------------------------------------------------------------------------

def test_t01_greeting_is_small_and_offers_no_tools(data):
    a, m = _agent(data, ["Salom! Qanday yordam kerak?"], checker=_scope(),
                  executor=lambda act: {"ok": True})
    r = a.ask("Salom!")
    assert r.intent == "GREETING" and m.seen[0]["tools"] == [] and r.new_actions == []
    assert "intent GREETING" in m.seen[0]["system"]
    # the whole request (system + message, no schemas) is far below the old ~2100 tokens
    assert _tokens(m.seen[0]) < 1300


# --- T02 / T17 long conversations stay inside the budget ------------------------------------

def _long_history(conv: Conversation, turns: int, size: int = 1800) -> None:
    for i in range(turns):
        conv.append("user", f"{i}-savol: " + "port holati haqida batafsil gapir. " * (size // 36))
        conv.append("assistant", f"{i}-javob: " + "Port 3000 holati noaniq bo‘ldi. " * (size // 32))


def test_t02_long_conversation_fits_a_4096_window(data):
    conv = Conversation(data, "long")
    _long_history(conv, 30)
    a, m = _agent(data, ["ok"], window=4096, name="long")  # summary-only tools fit
    r = a.ask("Oxirgi natijani tushuntir.")
    assert r.stopped == "answered"
    b = a.budget()
    assert b.context_tokens == 4096 and b.input_limit + b.output_tokens <= 4096
    assert _tokens(m.seen[0]) <= b.input_limit
    ev = [x for x in a.audit.read_all() if x.event == "context_compacted"]
    assert ev and ev[0].data["input_tokens_estimate"] <= b.input_limit


def test_t02_oversized_own_message_fails_before_the_provider(data):
    a, m = _agent(data, ["never"], window=4096)
    r = a.ask("Tushuntir: " + "juda uzun matn " * 2000)
    assert r.stopped == "context_budget" and "Not sent" in r.text and "Nothing was run" in r.text
    assert m.seen == []                              # nothing reached the model
    assert a.conv.messages()[0].content.startswith("Tushuntir: ")  # owner text kept whole


def test_t17_history_for_the_model_is_bounded(data):
    conv = Conversation(data, "huge")
    _long_history(conv, 200)
    h = conv.model_history(3000, keep_turns=4, reply_chars=600)
    assert sum(len(x["content"]) for x in h) < 3000 + 1800 + 2000  # recent + note + current
    tight = conv.model_history(0, keep_turns=1, reply_chars=300, include_note=False)
    assert "omitted to fit" in tight[0]["content"] and len(json.dumps(tight)) < 2600
    assert len(conv.messages()) == 400                # stored conversation unchanged


# --- T03 / T04 / T05 compaction --------------------------------------------------------------

def _big_record():
    states = ["open", "open", "open", "open", "closed"] * 8
    return {"session_id": "4594b234-c24d-4089-8aab-189126a56bcc", "audit_chain_valid": True,
            "services": [{"target": "10.66.7.103:3000", "tcp_state": st,
                          "evidence": f"req-{i:04d}-0000-0000", "banner": "x" * 400}
                         for i, st in enumerate(states)],
            "inconclusive": [{"rule": "net.tcp_port_open", "verdict": "INCONCLUSIVE",
                              "target": "10.66.7.103:3000",
                              "evidence_sha256": "a" * 64, "reason": "y" * 900}],
            "port_status": {"verdict": "INCONCLUSIVE", "conflicting": True,
                            "state_counts": {"open": 32, "closed": 8}, "latest_state": "closed"},
            "legend": "Verdicts come only from the engine."}


def test_t03_oversized_tool_result_is_compacted_and_marked(data, monkeypatch):
    monkeypatch.setattr(kb, "investigation", lambda sid: _big_record())
    a, m = _agent(data, [[_use("get_investigation", session_id=NMAP_SID)], "done"],
                  window=8192)
    a.ask("Sessiyani to'liq ko'rsat")
    content = m.seen[1]["messages"][-1]["content"][0]["content"]
    assert content.startswith("<avra_data>") and len(content) <= ChatAgent.RESULT_CHARS + 40
    body = json.loads(content.split("\n", 1)[1].rsplit("\n", 1)[0])
    assert body["_compacted"]["full_record"].startswith("/details ")
    assert body["port_status"] == _big_record()["port_status"]   # verdict block untouched


def test_t04_identifiers_and_hashes_survive_compaction():
    rec = _big_record()
    small, info = compact_data(rec, 1500)
    assert info["level"] > 0
    kept = protected_values(small)
    # every kept identifier is byte-identical to the original; nothing is re-worded
    assert kept <= protected_values(rec)
    assert f"evidence_sha256={'a' * 64}" in kept
    assert "session_id=4594b234-c24d-4089-8aab-189126a56bcc" in kept
    assert "verdict=INCONCLUSIVE" in kept and "target=10.66.7.103:3000" in kept


def test_t05_contradiction_stays_visible_after_compaction():
    small, _ = compact_data(_big_record(), 1200)
    assert small["port_status"]["verdict"] == "INCONCLUSIVE"
    assert small["port_status"]["conflicting"] is True
    kept_states = [s.get("tcp_state") for s in small["services"] if "tcp_state" in s]
    tally = next(s for s in small["services"] if "_omitted_items" in s)
    counts = dict(tally["_omitted_tcp_state_counts"])
    for st in kept_states:
        counts[st] = counts.get(st, 0) + 1
    assert counts == {"open": 32, "closed": 8}     # nothing lost: kept + tallied = original


# --- T06 / T07 intent gate -------------------------------------------------------------------

@pytest.mark.parametrize("text,intent,action", [
    ("Salom!", Intent.GREETING, False),
    ("Oldingi Nmap natijalarini tushuntir.", Intent.EXPLAIN, False),
    ("Port 3000 nima sababdan INCONCLUSIVE?", Intent.EXPLAIN, False),
    ("Qanday tekshiruv qilish mumkin?", Intent.PLAN, False),
    ("Yangi Nmap tekshiruvini taklif qil.", Intent.LIVE_ACTION_REQUEST, True),
    ("No live scans. Explain the evidence.", Intent.EXPLAIN, False),
    ("Ha, lekin bajarma.", Intent.AMBIGUOUS, False),
    ("Nmap tekshiruvini taklif qil, lekin skanerlama.", Intent.AMBIGUOUS, False),
    ("Propose an Nmap connect scan of 10.66.7.103 port 3000. Do not execute it yet.",
     Intent.LIVE_ACTION_REQUEST, True),
    ("Run an nmap scan now, do not run it.", Intent.AMBIGUOUS, False),
    ("Oxirgi sessiyani xulosala.", Intent.SUMMARIZE, False),
    ("Oldingi va yangi natijani solishtir.", Intent.COMPARE, False),
    ("Sening vazifang nima?", Intent.GENERAL_QUESTION, False),
    ("ha", Intent.AMBIGUOUS, False),
])
def test_t06_t07_intent_examples(text, intent, action):
    r = classify(text)
    assert r.intent is intent, (text, r)
    assert ("request_action" in tools_for(r)) is action


def test_t06_read_only_request_cannot_propose_even_if_model_tries(data):
    calls = []
    a, m = _agent(data, [[_nmap()], "Mana tushuntirish."], checker=_scope(),
                  executor=lambda act: calls.append(act) or {"ok": True})
    r = a.ask("Oldingi Nmap natijalarini tushuntir.")
    assert "request_action" not in m.seen[0]["tools"]
    assert "not available for this message" in m.seen[1]["messages"][-1]["content"][0]["content"]
    assert a.pending == {} and r.new_actions == [] and calls == []
    assert "NOT offered this turn" in m.seen[0]["system"]


def test_t07_ambiguous_reply_to_a_proposal_does_not_execute(data):
    calls = []
    a, _ = _agent(data, [[_nmap()], "Taklif A1.", "Tushunarli."], checker=_scope(),
                  executor=lambda act: calls.append(act.id) or {"ok": True})
    out, it = [], iter(["Nmap tekshiruvini taklif qil.", "Ha, lekin bajarma.", "/exit"])
    Repl(a, read=lambda p: next(it), write=out.append, interactive=True,
         confirm=lambda q: True, data_root=data,
         status={"model": "s", "provider": "l", "local": True, "messages": 0,
                 "scope": "m145"}).run()
    assert calls == [] and a.pending["A1"].status == "pending"


# --- T08 expired scope -----------------------------------------------------------------------

def test_t08_expired_scope_refuses_the_proposal_and_the_approval(data):
    calls = []
    a, m = _agent(data, [[_nmap()], "ok"], checker=_scope(minutes=-1),
                  executor=lambda act: calls.append(act) or {"ok": True})
    a.ask("Nmap tekshiruvini taklif qil.")
    assert "refused_by_scope" in m.seen[1]["messages"][-1]["content"][0]["content"]
    assert a.pending == {} and calls == []
    assert "No pending action" in a.approve("A1", lambda act: True)


# --- T09 / T15 / T16 failures, retries and duplicates ----------------------------------------

def test_t09_model_timeout_runs_nothing(data):
    calls = []
    a, _ = _agent(data, [LLMProviderError("local model call timed out after 600s",
                                          retryable=True)],
                  checker=_scope(), executor=lambda act: calls.append(act) or {"ok": True})
    r = a.ask("Nmap tekshiruvini taklif qil.")
    assert r.stopped == "provider_error" and "timed out" in r.text
    assert a.pending == {} and calls == [] and r.model_calls == 0


def test_t15_server_context_error_is_parsed():
    body = {"error": {"code": 400, "message": "request (4352 tokens) exceeds the available "
                      "context size (4096 tokens), try increasing it",
                      "type": "exceed_context_size_error", "n_prompt_tokens": 4352,
                      "n_ctx": 4096}}
    with FakeOpenAIServer([(400, body)]) as srv:
        p = LocalOpenAICompatibleProvider(LLMConfig(provider="local-openai-compatible",
                                                    model="fake-model", base_url=srv.base_url))
        with pytest.raises(ContextOverflowError) as ei:
            p.complete(system=[], messages=[{"role": "user", "content": "x"}], tools=[])
    assert ei.value.prompt_tokens == 4352 and ei.value.context_tokens == 4096
    # text-only form (no structured fields) is recognised too
    with FakeOpenAIServer([(400, {"error": {"message": "request (5000 tokens) exceeds the "
                                            "available context size (4096 tokens)"}})]) as srv:
        p = LocalOpenAICompatibleProvider(LLMConfig(provider="local-openai-compatible",
                                                    model="fake-model", base_url=srv.base_url))
        with pytest.raises(ContextOverflowError) as ei:
            p.complete(system=[], messages=[{"role": "user", "content": "x"}], tools=[])
    assert (ei.value.prompt_tokens, ei.value.context_tokens) == (5000, 4096)


def test_t15_one_bounded_retry_then_a_clear_error(data):
    over = ContextOverflowError("too big", prompt_tokens=4300, context_tokens=4096)
    a, m = _agent(data, [over, "Javob."], window=8192)
    r = a.ask("Salom!")
    assert r.stopped == "answered" and r.text == "Javob." and len(m.seen) == 2
    assert a.budget().context_tokens == 4096           # learned from the server
    ev = [x.event for x in a.audit.read_all()]
    assert ev.count("context_overflow") == 1
    b, m2 = _agent(data, [over, over, "never"], window=8192, name="b")
    r2 = b.ask("Salom!")
    assert r2.stopped == "provider_error" and len(m2.seen) == 2   # exactly one retry


def test_t16_no_duplicate_action_after_retry_and_restart(data):
    calls = []
    over = ContextOverflowError("too big", prompt_tokens=None, context_tokens=16384)
    a, _ = _agent(data, [over, [_nmap(), _nmap(2)], "Taklif."], checker=_scope(),
                  executor=lambda act: calls.append(act.id) or {"ok": True}, name="dup")
    r = a.ask("Nmap tekshiruvini taklif qil.")
    assert [x.id for x in r.new_actions] == ["A1"] and list(a.pending) == ["A1"]
    assert "executed" in a.approve("A1", lambda act: True)
    assert "No pending action" in a.approve("A1", lambda act: True)
    assert calls == ["A1"]
    again, _ = _agent(data, [], checker=_scope(), executor=lambda act: calls.append(act.id),
                      name="dup")
    assert again.pending == {} and "No pending action" in again.approve("A1", lambda a_: True)
    assert calls == ["A1"]


# --- T10 / T11 grounded facts ----------------------------------------------------------------

def test_t10_missing_session_is_reported_not_invented(data):
    a, m = _agent(data, [[_use("summarize_investigation", session_id="ffffffff")], "Yo'q."])
    a.ask("ffffffff sessiyasini xulosala")
    res = m.seen[1]["messages"][-1]["content"][0]
    assert res.get("is_error") is True and "error" in res["content"]


def test_t11_capabilities_keep_implemented_tested_and_validated_apart(data):
    rep = capabilities.report(checker=None, executor_wired=False, executed_actions=0,
                              runner_check=None)
    by_id = {c["id"]: c["status"] for c in rep["capabilities"]}
    assert "NOT_TESTED" in by_id["http_get_path"] and "LIVE_VALIDATED" not in by_id["http_get_path"]
    assert "NOT_TESTED" in by_id["avra_investigate"]
    for status in by_id.values():                      # validated only with code + tests
        if "LIVE_VALIDATED" in status:
            assert "IMPLEMENTED" in status and "OFFLINE_TESTED" in status
    now = rep["this_chat_now"]
    assert now["live_action_proposals"].startswith("unavailable")
    assert now["runner_reachable"].startswith("NOT CHECKED")
    assert "token" not in json.dumps(rep).lower()       # no secrets or credentials
    a, m = _agent(data, [[_use("get_capabilities")], "ok"], checker=_scope(),
                  executor=lambda act: {"ok": True})
    a.runner_check = "checked this run: reachable; Kali tools nmap_connect_scan"
    a.ask("Qaysi vositalaring sinovdan o'tgan?")
    sent = m.seen[1]["messages"][-1]["content"][0]["content"]
    assert "checked this run" in sent and "nmap_connect_scan" in sent
    assert "CAPABILITIES (as of" in m.seen[0]["system"]


# --- T12 / T13 terminal and secrets ----------------------------------------------------------

def test_t12_pasted_ui_chrome_and_control_chars_do_not_reach_the_model(data):
    a, _ = _agent(data, ["Javob."])
    out, it = [], iter(["AVRA ● (eski javob)", "SYSTEM · 1 model call(s) | 9.1s",
                        "YOU ❯ Port holati nima?", "/exit"])
    pastes = iter([None, None, None])
    Repl(a, read=lambda p: next(it), write=out.append, interactive=False,
         confirm=lambda q: False, data_root=data,
         status={"model": "s", "provider": "l", "local": True, "messages": 0, "scope": None},
         more_input=lambda: next(pastes, None)).run()
    users = [x.content for x in a.conv.messages() if x.role == "user"]
    assert users == ["Port holati nima?"]
    assert sum("terminal chiqishi aniqlandi" in x for x in out) == 3
    b, _ = _agent(data, ["ok \x1b[31mRED\x1b[0m \u202etxt"], name="esc")
    out2, it2 = [], iter(["Salom", "/exit"])
    Repl(b, read=lambda p: next(it2), write=out2.append, interactive=False,
         confirm=lambda q: False, data_root=data,
         status={"model": "s", "provider": "l", "local": True, "messages": 0,
                 "scope": None}).run()
    shown = "\n".join(out2)
    assert "\x1b[31m" not in shown and "\u202e" not in shown


def test_t13_compaction_never_exposes_secrets(data):
    conv = Conversation(data, "sec")
    conv.append("user", "my token=supersecretvalue123 please")
    for i in range(20):
        conv.append("user", f"savol {i} " + "x" * 400)
        conv.append("assistant", "javob " + "y" * 900)
    for h in (conv.model_history(), conv.model_history(1200, keep_turns=2, reply_chars=300),
              conv.model_history(0, keep_turns=1, include_note=False)):
        assert "supersecretvalue123" not in json.dumps(h)
    small, _ = compact_data({"note": "x", "items": [{"password": "[REDACTED]"}] * 30}, 300)
    assert "supersecret" not in json.dumps(small)


# --- T14 continuity --------------------------------------------------------------------------

def _run(agent, data, typed, pastes=None):
    out, it = [], iter(typed + ["/exit"])
    queue = list(pastes or [])

    def more():
        return queue.pop(0) if queue else None

    Repl(agent, read=lambda p: next(it), write=out.append, interactive=False,
         confirm=lambda q: False, data_root=data,
         status={"model": "s", "provider": "l", "local": True, "messages": 0, "scope": None},
         more_input=more).run()
    return out


def test_t14_a_pasted_multi_part_message_is_one_turn(data):
    a, m = _agent(data, ["1) ... 2) ..."])
    _run(a, data, ["Senga ikkita vazifa:"],
         pastes=["1. Oxirgi sessiyani xulosala.", "2. Port 3000 holatini tushuntir."])
    assert len(m.seen) == 1
    users = [x.content for x in a.conv.messages() if x.role == "user"]
    assert users == [("Senga ikkita vazifa:\n1. Oxirgi sessiyani xulosala.\n"
                      "2. Port 3000 holatini tushuntir.")]


def test_t14_unfinished_message_waits_for_its_continuation(data):
    a, m = _agent(data, ["ok", "ok2"])
    out = _run(a, data, ["Vazifalar:", "1. Oxirgi sessiyani xulosala.",
                         "Ikkinchi gap va", ""])
    users = [x.content for x in a.conv.messages() if x.role == "user"]
    assert users == ["Vazifalar:\n1. Oxirgi sessiyani xulosala.", "Ikkinchi gap va"]
    assert len(m.seen) == 2 and any("tugallanmagan" in x for x in out)


def test_t14_explicit_block_and_follow_up_turns_keep_history(data):
    a, m = _agent(data, ["Birinchi javob.", "Ikkinchi javob."])
    _run(a, data, ['"""', "Birinchi qator", "Ikkinchi qator", '"""', "Ulardan nechtasi ochiq?"])
    assert [x.content for x in a.conv.messages() if x.role == "user"] == [
        "Birinchi qator\nIkkinchi qator", "Ulardan nechtasi ochiq?"]
    roles = [x["role"] for x in m.seen[1]["messages"]]
    assert roles == ["user", "assistant", "user"]     # the follow-up sees the first exchange


# --- T18 / T19 schemas and invalid output ----------------------------------------------------

def test_t18_tool_schemas_are_valid_for_the_local_provider():
    names = [t["name"] for t in TOOLS]
    assert len(names) == len(set(names)) and set(names) - {"request_action"} == READ_ONLY
    for fn in to_openai_tools(TOOLS):
        p = fn["function"]["parameters"]
        assert fn["type"] == "function" and p["type"] == "object"
        assert p["additionalProperties"] is False and set(p["required"]) <= set(p["properties"])
    json.dumps(to_openai_tools(TOOLS))
    for text in ("Salom!", "Sening vazifang nima?", "Tushuntir.", "Nmap taklif qil.", "x"):
        assert set(tools_for(classify(text))) <= set(names)


def test_t19_invalid_model_output_crosses_no_boundary(data):
    calls = []
    bad = [_use("request_action", 1, kind="nmap_connect_scan", session_id=NMAP_SID,
                host="10.66.7.103", port="3000", path="", reason="x"),
           _use("request_action", 2, kind="shell", session_id=NMAP_SID, host="1.2.3.4",
                port=22, path="", reason="x"),
           _use("run_shell", 3, cmd="id")]
    a, m = _agent(data, [bad, "done"], checker=_scope(),
                  executor=lambda act: calls.append(act) or {"ok": True})
    a.ask("Nmap tekshiruvini taklif qil.")
    res = m.seen[1]["messages"][-1]["content"]
    assert all(b.get("is_error") for b in res) and a.pending == {} and calls == []
    assert "unknown tool" in res[2]["content"]
    r = parse_chat_completion(completion(tool_calls=[{"id": "x", "type": "function",
                                                      "function": {"name": "request_action",
                                                                   "arguments": "{oops"}}]),
                              "m")
    assert r.tool_uses[0].input == {}


# --- budget / provider details ---------------------------------------------------------------

def test_budget_reserves_output_and_margin():
    b = ContextBudget.for_window(4096, 4096, exact_count=True)
    assert b.output_tokens == 1365 and b.input_limit == 4096 - 1365 - 122
    assert ContextBudget.for_window(200_000, 4096, exact_count=True).output_tokens == 4096
    with pytest.raises(ContextBudgetError):
        ContextBudget.for_window(512, 4096, exact_count=True)


def test_local_provider_caps_output_and_degrades_without_tokenizer():
    with FakeOpenAIServer([completion("hi")]) as srv:
        p = LocalOpenAICompatibleProvider(LLMConfig(provider="local-openai-compatible",
                                                    model="fake-model", base_url=srv.base_url))
        assert p.context_window() is None                       # no /props on this server
        assert p.exact_input_tokens(system=[], messages=[], tools=[]) is None
        assert p.exact_input_tokens(system=[], messages=[], tools=[]) is None  # not retried
        p.complete(system=[], messages=[{"role": "user", "content": "x"}], tools=[],
                   max_tokens=700)
        sent = [r for r in srv.requests if r["path"] == "/v1/chat/completions"]
    assert sent[0]["body"]["max_tokens"] == 700
    assert "response_format" in sent[0]["body"]          # assess-style call: JSON object
    assert [r["path"] for r in srv.requests].count("/apply-template") == 1


def test_t01_chat_greeting_without_tools_is_not_forced_into_json(data):
    """Regression (found in the M14.5 live eval): a tool-less chat call must not carry
    response_format=json_object, or the model answers "Salom!" with a JSON object."""
    with FakeOpenAIServer([completion("Salom!")]) as srv:
        p = LocalOpenAICompatibleProvider(LLMConfig(provider="local-openai-compatible",
                                                    model="fake-model", base_url=srv.base_url))
        a = ChatAgent(p, Conversation(data, "plain"), context_tokens=8192)
        r = a.ask("Salom!")
        body = next(x["body"] for x in srv.requests if x["path"] == "/v1/chat/completions")
    assert r.text == "Salom!" and "response_format" not in body and "tools" not in body
    assert body["max_tokens"] == a.budget().output_tokens
