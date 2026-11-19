"""ADR 0015: the loopback OpenAI-compatible provider (Ollama, LM Studio, llama.cpp).

No model, no network beyond 127.0.0.1: a scripted fake server answers over real HTTP."""

from __future__ import annotations

import json
import socket

import pytest

from avra.llm.config import LLMConfig, LLMConfigError
from avra.llm.local import (
    LocalOpenAICompatibleProvider,
    parse_chat_completion,
    to_openai_messages,
    to_openai_tools,
    validate_base_url,
)
from avra.llm.provider import LLMProviderError
from avra.llm.tools import PROPOSE_SCAN
from tests.fakes_local_llm import FakeOpenAIServer, completion, tool_call


def _cfg(url: str, **kw) -> LLMConfig:
    return LLMConfig(provider="local-openai-compatible", model="fake-model", base_url=url, **kw)


# ----------------------------------------------------------------- configuration

@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:8080/",
                                 "http://[::1]:1234", "https://127.0.0.5:9"])
def test_loopback_urls_are_accepted(url):
    assert validate_base_url(url) == url.rstrip("/")


@pytest.mark.parametrize("url,msg", [
    ("http://192.168.56.104:11434", "not loopback"),
    ("http://10.0.0.1:11434", "not loopback"),
    ("http://example.com:11434", "not loopback"),
    ("http://user:pw@127.0.0.1:11434", "credentials"),
    ("ftp://127.0.0.1", "http"),
    ("127.0.0.1:11434", "http"),
])
def test_non_loopback_or_odd_urls_are_refused(url, msg):
    with pytest.raises(LLMConfigError, match=msg):
        validate_base_url(url)
    with pytest.raises(LLMConfigError, match=msg):
        LLMConfig(provider="ollama", model="m", base_url=url)


def test_local_config_rules_and_defaults():
    cfg = LLMConfig(provider="ollama", model="qwen2.5:7b-instruct")
    assert cfg.is_local and cfg.resolved_base_url == "http://127.0.0.1:11434"
    assert cfg.price.input == cfg.price.output == 0.0
    with pytest.raises(LLMConfigError, match="model name"):
        LLMConfig(provider="ollama", model="has space")
    with pytest.raises(LLMConfigError, match="apply to local providers only"):
        LLMConfig(base_url="http://127.0.0.1:1")


def test_from_env_precedence():
    env = {"AVRA_LLM_PROVIDER": "ollama", "AVRA_LLM_MODEL": "llama3.2:3b",
           "AVRA_LLM_BASE_URL": "http://127.0.0.1:11500"}
    cfg = LLMConfig.from_env(env)
    assert (cfg.provider, cfg.model, cfg.resolved_base_url) == (
        "ollama", "llama3.2:3b", "http://127.0.0.1:11500")
    assert LLMConfig.from_env(env, model="qwen2.5:7b").model == "qwen2.5:7b"  # flag wins
    default = LLMConfig.from_env({})
    assert (default.provider, default.model) == ("anthropic", "claude-opus-5-5")
    with pytest.raises(LLMConfigError, match="needs a model name"):
        LLMConfig.from_env({"AVRA_LLM_PROVIDER": "ollama"})


# ----------------------------------------------------------------- translation

def test_anthropic_shaped_history_translates_to_openai_messages():
    system = [{"type": "text", "text": "SYS"}]
    messages = [
        {"role": "user", "content": "objective"},
        {"role": "assistant", "content": [{"type": "text", "text": "thinking aloud"},
                                          {"type": "tool_use", "id": "call_9", "name": "t",
                                           "input": {"a": 1}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_9",
                                      "content": "DENIED: out of scope"},
                                     {"type": "text", "text": "continue"}]},
    ]
    out = to_openai_messages(system, messages)
    assert out[0] == {"role": "system", "content": "SYS"}
    assert out[1] == {"role": "user", "content": "objective"}
    assert out[2]["role"] == "assistant" and out[2]["content"] == "thinking aloud"
    assert out[2]["tool_calls"][0]["id"] == "call_9"
    assert json.loads(out[2]["tool_calls"][0]["function"]["arguments"]) == {"a": 1}
    assert out[3] == {"role": "tool", "tool_call_id": "call_9", "content": "DENIED: out of scope"}
    assert out[4] == {"role": "user", "content": "continue"}


def test_tools_translate_to_functions():
    tools = to_openai_tools([{"name": "x", "description": "d", "input_schema": {"type": "object"}}])
    assert tools == [{"type": "function", "function": {"name": "x", "description": "d",
                                                       "parameters": {"type": "object"}}}]


def test_completion_parsing_maps_stop_reasons_and_tool_calls():
    r = parse_chat_completion(completion("hello"), "m")
    assert (r.stop_reason, r.text, r.tool_uses) == ("end_turn", "hello", ())
    assert r.history_content == [{"type": "text", "text": "hello"}]
    assert r.usage.input_tokens == 100 and r.usage.output_tokens == 50

    r = parse_chat_completion(completion("", [tool_call("t", {"host": "h"}, "c1")],
                                         finish="tool_calls"), "m")
    assert r.stop_reason == "tool_use" and r.tool_uses[0].input == {"host": "h"}
    assert r.history_content == [{"type": "tool_use", "id": "c1", "name": "t", "input": {"host": "h"}}]

    # some servers say "stop" with tool calls; bad JSON arguments become {} (validated later)
    r = parse_chat_completion(completion("", [tool_call("t", "{not json")]), "m")
    assert r.stop_reason == "tool_use" and r.tool_uses[0].input == {}
    assert parse_chat_completion(completion("x", finish="length"), "m").stop_reason == "max_tokens"
    assert parse_chat_completion(completion("", finish="content_filter"), "m").stop_reason == "refusal"
    with pytest.raises(LLMProviderError, match="no choices"):
        parse_chat_completion({"choices": []}, "m")


# ----------------------------------------------------------------- real HTTP

def test_complete_over_http_sends_the_expected_request():
    with FakeOpenAIServer([completion('{"ok": true}')]) as srv:
        prov = LocalOpenAICompatibleProvider(_cfg(srv.base_url))
        r = prov.complete(system=[{"type": "text", "text": "S"}],
                          messages=[{"role": "user", "content": "U"}], tools=[])
        assert r.text == '{"ok": true}' and r.stop_reason == "end_turn"
        body = srv.requests[0]["body"]
        assert srv.requests[0]["path"] == "/v1/chat/completions"
        assert body["model"] == "fake-model" and body["stream"] is False
        assert body["response_format"] == {"type": "json_object"} and "tools" not in body
        assert prov.list_models() == ["fake-model"]


def test_tools_are_sent_and_json_mode_is_not_forced_with_tools():
    with FakeOpenAIServer([completion("done")]) as srv:
        prov = LocalOpenAICompatibleProvider(_cfg(srv.base_url))
        prov.complete(system=[], messages=[{"role": "user", "content": "x"}],
                      tools=[{"name": "t", "input_schema": {"type": "object"}}])
        body = srv.requests[0]["body"]
        assert body["tools"][0]["function"]["name"] == "t" and "response_format" not in body


def test_server_down_gives_a_clear_retryable_error():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # nothing listens after the socket closes
    prov = LocalOpenAICompatibleProvider(_cfg(f"http://127.0.0.1:{port}", timeout_seconds=5))
    with pytest.raises(LLMProviderError, match="cannot reach the local model server") as exc:
        prov.complete(system=[], messages=[{"role": "user", "content": "x"}], tools=[])
    assert exc.value.retryable


def test_http_errors_are_translated():
    with FakeOpenAIServer([(404, {"error": "model 'x' not found"}), (500, "boom"),
                           (200, "not json")]) as srv:
        prov = LocalOpenAICompatibleProvider(_cfg(srv.base_url))
        call = {"system": [], "messages": [{"role": "user", "content": "x"}], "tools": []}
        with pytest.raises(LLMProviderError, match="HTTP 404.*pulled"):
            prov.complete(**call)
        with pytest.raises(LLMProviderError, match="HTTP 500") as e500:
            prov.complete(**call)
        assert e500.value.retryable
        with pytest.raises(LLMProviderError, match="invalid JSON"):
            prov.complete(**call)


def test_kill_switch_blocks_before_any_request():
    from avra.control.killswitch import KillSwitch

    KillSwitch().engage("local provider test")
    with FakeOpenAIServer([completion("x")]) as srv:
        prov = LocalOpenAICompatibleProvider(_cfg(srv.base_url))
        with pytest.raises(LLMProviderError, match="no model request was made"):
            prov.complete(system=[], messages=[{"role": "user", "content": "x"}], tools=[])
        assert srv.requests == []


# ----------------------------------------------------------------- research loop

def test_research_loop_runs_on_the_local_provider_and_keeps_every_control(tmp_path):
    """Tool calls round-trip through the loop; scope and approval still apply."""
    from tests.unit.test_llm_research import PROPOSAL, _session

    out_of_scope = {**PROPOSAL, "host": "10.0.0.5"}
    script = [completion("", [tool_call(PROPOSE_SCAN, out_of_scope, "c1")], "tool_calls"),
              completion("", [tool_call(PROPOSE_SCAN, PROPOSAL, "c2")], "tool_calls"),
              completion("Nothing more to do.")]
    with FakeOpenAIServer(script) as srv:
        s, _p, audit, calls = _session(tmp_path, [], approve=lambda v: False)
        s.provider = LocalOpenAICompatibleProvider(_cfg(srv.base_url))
        result = s.run("check the lab")
        events = [r.event for r in audit.read_all()]
        assert "llm_proposal_denied" in events                     # scope enforced
        assert len(calls["approve"]) == 1 and calls["execute"] == []  # approval still asked
        assert result.stop_reason.value == "end_turn" and audit.verify()
        started = next(r for r in audit.read_all() if r.event == "research_started")
        assert started.data["provider"] == "local-openai-compatible"
        # the second request carried the first tool call AND its tool result back
        second = srv.requests[1]["body"]["messages"]
        assert any(m.get("tool_calls") for m in second if m["role"] == "assistant")
        assert any(m["role"] == "tool" and m["tool_call_id"] == "c1" for m in second)


def test_inline_reasoning_is_stripped_from_the_answer():
    r = parse_chat_completion(completion('<think>step 1 {not json}</think>\n{"ok": true}'), "m")
    assert r.text == '{"ok": true}'


def test_extra_body_from_env_reaches_the_server(tmp_path):
    from avra.llm.factory import create_provider

    f = tmp_path / "x.json"
    f.write_text('{"reasoning_effort": "medium", "min_p": 0.05}', encoding="utf-8-sig")
    with FakeOpenAIServer([completion("{}")]) as srv:
        cfg = LLMConfig.from_env({"AVRA_LLM_PROVIDER": "local-openai-compatible",
                                  "AVRA_LLM_MODEL": "m", "AVRA_LLM_BASE_URL": srv.base_url,
                                  "AVRA_LLM_EXTRA_BODY": f"@{f}"})
        assert cfg.timeout_seconds == 600.0  # local default
        create_provider(cfg).complete(system=[], messages=[{"role": "user", "content": "x"}], tools=[])
        body = srv.requests[0]["body"]
    assert body["reasoning_effort"] == "medium" and body["min_p"] == 0.05
    with pytest.raises(LLMConfigError, match="JSON object"):
        LLMConfig(provider="ollama", model="m", extra_body_json="[1]")
    with pytest.raises(LLMConfigError, match="local providers only"):
        LLMConfig(extra_body_json="{}")


def test_offline_research_with_a_local_model_needs_no_runner_token(tmp_path, monkeypatch):
    """`avra research --provider ... --max-tool-runs 0`: no API key, no Runner token."""
    from datetime import UTC, datetime, timedelta

    from typer.testing import CliRunner

    from avra.cli.main import app
    from avra.llm.tools import FINISH
    from avra.runner_client import client as client_mod

    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.chdir(tmp_path)  # no .env here
    monkeypatch.setattr(client_mod, "load_token",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("token needed?")))
    scope = tmp_path / "scope.yaml"
    scope.write_text(f'session_name: t\nexpires_at: "{(datetime.now(UTC) + timedelta(days=1)).isoformat()}"\n'
                     'targets:\n  - host: "10.66.7.103"\n    ports: [3000]\n'
                     '    allowed_tiers: ["active-safe"]\n    allowed_tools: ["nmap_connect_scan"]\n')
    script = [completion("", [tool_call(FINISH, {"summary": "Offline: nothing to scan."})], "tool_calls")]
    with FakeOpenAIServer(script) as srv:
        r = CliRunner().invoke(app, ["research", "--scope", str(scope), "--objective", "Review evidence",
                                     "--provider", "local-openai-compatible", "--model", "m",
                                     "--base-url", srv.base_url, "--max-tool-runs", "0"], input="y\n")
    assert r.exit_code == 0, r.output
    assert "local, no API cost" in r.output and "no API cost)?" in r.output
