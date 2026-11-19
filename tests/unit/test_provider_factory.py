"""ADR 0013 (M8.7 Stage 8): explicit, validated model-provider selection.

No real API call, no local model: fake providers only."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import pytest

from avra.llm import factory as factory_mod
from avra.llm import provider as provider_mod
from avra.llm.config import (
    DEFAULT_PROVIDER,
    FUTURE_PROVIDERS,
    IMPLEMENTED_PROVIDERS,
    LLMConfig,
    LLMConfigError,
)
from avra.llm.factory import create_provider
from avra.llm.provider import ApiKey, ClaudeProvider, LLMProviderError
from avra.llm.tools import PROPOSE_SCAN
from tests.unit.test_llm_research import PROPOSAL, _resp, _session, _use

KEY = ApiKey("sk-ant-" + "x" * 40)


def test_default_is_the_anthropic_provider():
    # ADR 0015 adds the two loopback local providers; Anthropic stays the default.
    assert DEFAULT_PROVIDER == "anthropic"
    assert IMPLEMENTED_PROVIDERS == {"anthropic", "ollama", "local-openai-compatible"}
    cfg = LLMConfig()
    assert cfg.provider == "anthropic" and cfg.model == "claude-opus-5-5"
    assert isinstance(create_provider(cfg, api_key=KEY), ClaudeProvider)


def test_unknown_provider_is_rejected_by_config():
    with pytest.raises(LLMConfigError, match="unknown model provider"):
        LLMConfig(provider="gpt-something")


def test_recognized_but_unbuilt_provider_fails_without_fallback(monkeypatch):
    """The ADR 0013 rule still holds for any future name: recognized, no builder
    -> explicit error, never a silent switch to another provider."""
    from avra.llm import config as config_mod

    built = []
    monkeypatch.setattr(provider_mod, "ClaudeProvider", lambda *a, **k: built.append(a))
    monkeypatch.setattr(config_mod, "FUTURE_PROVIDERS", frozenset({"future-x"}))
    cfg = LLMConfig(provider="future-x", model="m")
    with pytest.raises(LLMConfigError, match="not implemented yet.*no fallback"):
        create_provider(cfg, api_key=KEY)
    assert built == [] and FUTURE_PROVIDERS == frozenset()


def test_local_provider_is_built_without_any_api_key(monkeypatch):
    from avra.llm.local import LocalOpenAICompatibleProvider

    monkeypatch.setattr(provider_mod, "load_api_key",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no key needed")))
    prov = create_provider(LLMConfig(provider="ollama", model="qwen2.5:7b"))
    assert isinstance(prov, LocalOpenAICompatibleProvider)
    assert prov.base_url == "http://127.0.0.1:11434" and prov.config.price.output == 0.0


def test_anthropic_keeps_its_price_and_option_checks():
    with pytest.raises(LLMConfigError, match="no price configured"):
        LLMConfig(model="claude-unknown")
    with pytest.raises(LLMConfigError, match="effort"):
        LLMConfig(effort="turbo")


def test_factory_built_provider_still_honours_the_kill_switch():
    from avra.control.killswitch import KillSwitch
    from tests.unit.test_llm_research import FakeClient, _sdk_message

    KillSwitch().engage("provider test")
    prov = create_provider(LLMConfig(), api_key=KEY)
    prov._client = FakeClient(_sdk_message())
    with pytest.raises(LLMProviderError, match="no API request was made"):
        prov.complete(system=[], messages=[], tools=[])
    assert prov._client.messages.calls == []


def test_research_started_records_the_provider(tmp_path):
    s, _prov, audit, _calls = _session(tmp_path, [_resp("end_turn", text="done")])
    s.run("check the lab")
    started = next(r for r in audit.read_all() if r.event == "research_started")
    assert started.data["provider"] == "anthropic" and started.data["model"] == "claude-opus-5-5"


@dataclass
class _OtherConfig:
    """What a future provider's config could look like (not Anthropic)."""

    model: str = "local-test-model"
    effort: str = "medium"
    provider: str = "local-openai-compatible"
    max_tokens: int = 1024

    @property
    def price(self):  # a local model costs no money, but budgets still apply
        from avra.llm.config import ModelPrice

        return ModelPrice(input=0.0, output=0.0, cache_write=0.0, cache_read=0.0)


class _NonAnthropicProvider:
    """Implements the LLMProvider protocol without any Anthropic code."""

    def __init__(self, script):
        self.config = _OtherConfig()
        self.script, self.calls = list(script), 0

    def count_input_tokens(self, *, system, messages, tools):
        return 1000

    def complete(self, *, system, messages, tools):
        self.calls += 1
        return self.script.pop(0)


def test_core_is_provider_independent_and_keeps_every_control(tmp_path):
    out_of_scope = {**PROPOSAL, "host": "10.0.0.5"}
    s, _p, audit, calls = _session(tmp_path, [], approve=lambda v: False)
    s.provider = _NonAnthropicProvider([
        _resp("tool_use", [_use(PROPOSE_SCAN, 1, **out_of_scope)]),
        _resp("tool_use", [_use(PROPOSE_SCAN, 2, **PROPOSAL)]),
        _resp("end_turn", text="done")])
    result = s.run("check the lab")
    events = [r.event for r in audit.read_all()]
    assert "llm_proposal_denied" in events  # scope still enforced
    assert len(calls["approve"]) == 1 and calls["execute"] == []  # approval still required
    started = next(r for r in audit.read_all() if r.event == "research_started")
    assert started.data["provider"] == "local-openai-compatible"
    assert result.stop_reason.value == "end_turn" and audit.verify()


@pytest.mark.parametrize("name,msg", [("ollama", "needs a model name"),
                                      ("bogus", "unknown model provider")])
def test_cli_refuses_a_bad_provider_before_any_prompt_or_key(name, msg, monkeypatch):
    from pathlib import Path

    from typer.testing import CliRunner

    from avra.cli.main import app

    def no_key(*a, **k):
        raise AssertionError("the API key must not be needed to refuse")

    monkeypatch.setattr(provider_mod, "load_api_key", no_key)
    scope = str(Path(__file__).resolve().parents[2] / "scope" / "example.scope.yaml")
    r = CliRunner().invoke(app, ["research", "--scope", scope, "--objective", "x",
                                 "--provider", name], input="y\n")
    assert r.exit_code == 1 and msg in r.output and "Start this session" not in r.output


def test_factory_has_a_builder_for_exactly_the_implemented_names():
    assert set(factory_mod._BUILDERS) == IMPLEMENTED_PROVIDERS
    assert uuid  # (module import used by future tests)
