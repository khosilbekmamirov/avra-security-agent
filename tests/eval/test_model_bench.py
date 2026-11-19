"""Validates the local-model benchmark harness itself (no model, no GPU needed).

1. Every card's reference reply passes all its checks; every known-bad reply fails
   exactly the check it was written for (so the graders demonstrably work).
2. The full runner, over real loopback HTTP via AVRA's LocalOpenAICompatibleProvider,
   scores a scripted perfect model 100% and a scripted bad model 0%.
3. facts.json is reproducible from the recorded evidence (modulo random ids).
"""

from __future__ import annotations

import argparse
import json

import pytest

from tests.eval.model_bench import build_facts
from tests.eval.model_bench.cards import FACTS, Reply, build_cards, grade
from tests.eval.model_bench.run import compare, render, run
from tests.fakes_local_llm import FakeOpenAIServer, completion, tool_call

CARDS = build_cards()


def test_there_are_24_cards_in_four_categories():
    cats = [c.category for c in CARDS]
    assert len(CARDS) == 24
    assert {k: cats.count(k) for k in set(cats)} == {"analysis": 8, "extract": 6, "tools": 5,
                                                     "injection": 5}
    assert all(c.bad for c in CARDS)


@pytest.mark.parametrize("card", CARDS, ids=[c.id for c in CARDS])
def test_reference_reply_passes_every_check(card):
    g = grade(card, card.good)
    assert g["passed"] and g["score"] == 1.0, g


@pytest.mark.parametrize("card,bad,check", [(c, b, n) for c in CARDS for b, n in c.bad],
                         ids=[f"{c.id}-{n}-{i}" for c in CARDS for i, (_, n) in enumerate(c.bad)])
def test_known_bad_reply_fails_its_check(card, bad, check):
    g = grade(card, bad)
    assert g["checks"][check] is False, (check, g)
    if next(c for c in card.checks if c.name == check).critical:
        assert not g["passed"]


def test_negated_statements_are_not_claims():
    card = next(c for c in CARDS if c.id == "A01")
    ok = json.loads(card.good.text)
    ok["executive_summary"] = "No vulnerability was confirmed; nothing is verified as exploitable."
    assert grade(card, Reply(json.dumps(ok)))["checks"]["no_unverified_confirmation"]


def _completion(reply: Reply) -> dict:
    if reply.tool_calls:
        return completion("", [tool_call(n, a, f"call_{i}") for i, (n, a) in enumerate(reply.tool_calls)],
                          finish="tool_calls", completion_tokens=40)
    return completion(reply.text, completion_tokens=120)


def _args(base_url, **kw):
    a = {"model": "fake-model", "provider": "local-openai-compatible", "base_url": base_url,
         "label": None, "repeat": 1, "cards": "", "max_tokens": 1024, "timeout": 30, "no_gpu": True,
         "extra_body": None}
    return argparse.Namespace(**{**a, **kw})


def test_runner_scores_a_perfect_scripted_model_100_percent():
    script = [completion('{"ok": true}')] + [_completion(c.good) for c in CARDS]
    with FakeOpenAIServer(script) as srv:
        res = run(_args(srv.base_url))
        bodies = [r["body"] for r in srv.requests]
    s = res["summary"]
    assert s["cards_run"] == 24 and s["pass_rate"] == 1.0 and s["errors"] == 0
    assert s["injection_resistance"] == 1.0 and s["tool_selection_rate"] == 1.0
    assert s["tokens_per_s_mean"] and res["cold_start_s"] is not None
    # the tool cards really sent AVRA's research tools; analysis cards asked for JSON
    assert sum(1 for b in bodies if "tools" in b) == 6 and bodies[1]["response_format"]
    assert "Pass rate: **100%**" in render(res)


def test_runner_scores_a_bad_scripted_model_zero_and_reports_why(tmp_path):
    script = [completion('{"ok": true}')] + [_completion(c.bad[0][0]) for c in CARDS]
    with FakeOpenAIServer(script) as srv:
        res = run(_args(srv.base_url))
    s = res["summary"]
    assert s["pass_rate"] == 0.0 and s["injection_resistance"] == 0.0
    assert all(r["failed_critical"] for r in res["results"])
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps({**res, "label": "bad"}))
    with FakeOpenAIServer([completion('{"ok": true}')] + [_completion(c.good) for c in CARDS]) as srv:
        b.write_text(json.dumps({**run(_args(srv.base_url)), "label": "good"}))
    table = compare([str(a), str(b)])
    assert "| pass_rate | 0.0 | 1.0 |" in table and "| A01 | 0/1 | 1/1 |" in table


def test_server_errors_count_as_failures_not_crashes():
    with FakeOpenAIServer([completion('{"ok": true}')] + [(500, "boom")] * 2) as srv:
        res = run(_args(srv.base_url, cards="A01,E01"))
    assert res["summary"]["errors"] == 2 and res["summary"]["pass_rate"] == 0.0


def test_benchmark_refuses_non_loopback_servers():
    from avra.llm.config import LLMConfigError

    with pytest.raises(LLMConfigError, match="not loopback"):
        run(_args("http://192.168.56.104:8080"))


def _strip_ids(o):
    if isinstance(o, dict):
        return {k: _strip_ids(v) for k, v in o.items()
                if k not in ("request_id", "session_id", "sessions")}
    if isinstance(o, list):
        return [_strip_ids(x) for x in o]
    return o


def test_facts_json_is_reproducible_from_recorded_evidence():
    assert _strip_ids(build_facts.build()["sheets"]) == _strip_ids(FACTS)


def test_extra_body_reaches_the_server_and_cannot_override_core_fields():
    from avra.llm.config import LLMConfigError

    body = '{"reasoning_effort": "medium", "chat_template_kwargs": {"enable_thinking": false}}'
    with FakeOpenAIServer([completion('{"ok": true}'), _completion(CARDS[0].good)]) as srv:
        res = run(_args(srv.base_url, cards="A01", extra_body=body))
        sent = srv.requests[1]["body"]
    assert res["summary"]["pass_rate"] == 1.0
    assert sent["reasoning_effort"] == "medium" and sent["chat_template_kwargs"]["enable_thinking"] is False
    assert res["settings"]["extra_body"]["reasoning_effort"] == "medium"
    with pytest.raises(LLMConfigError, match="may not override"):
        run(_args("http://127.0.0.1:9", extra_body='{"model": "other"}'))


def test_extra_body_can_come_from_a_file(tmp_path):
    f = tmp_path / "medium.json"
    f.write_text('{"reasoning_effort": "medium"}', encoding="utf-8-sig")  # PowerShell writes a BOM
    with FakeOpenAIServer([completion('{"ok": true}'), _completion(CARDS[0].good)]) as srv:
        run(_args(srv.base_url, cards="A01", extra_body=f"@{f}"))
        assert srv.requests[1]["body"]["reasoning_effort"] == "medium"
