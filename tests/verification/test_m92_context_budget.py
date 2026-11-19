"""M9.2 (ADR 0016): the research loop keeps the prompt inside a local model's context."""

from __future__ import annotations

import json
import uuid

from conftest import HOST, PORT, http_response, nmap_xml
from test_m91_http_probe_action import ScriptedModel, _use

from avra.core.research import ResearchSession, StopReason
from avra.llm.config import SessionLimits
from avra.llm.tools import FINISH, VERIFY_HYPOTHESIS
from avra.verification.loop import LoopConfig, VerificationLoop
from avra.verification.rules import web_registry

RULES = ["http.missing_content_security_policy", "http.missing_clickjacking_protection",
         "http.cors_wildcard_origin", "http.version_disclosure",
         "http.missing_x_content_type_options"]


class SizedModel(ScriptedModel):
    """Counts tokens like the local provider (~3 chars/token) and keeps what it was sent."""

    def count_input_tokens(self, *, system, messages, tools):
        return len(json.dumps([system, messages, tools], default=str)) // 3

    def complete(self, *, system, messages, tools):
        self.sent = json.loads(json.dumps(messages, default=str))
        self.sizes = getattr(self, "sizes", []) + [self.count_input_tokens(
            system=system, messages=messages, tools=tools)]
        return super().complete(system=system, messages=messages, tools=tools)


def _run(lab, budget):
    sid, audit = lab.new_session()
    lab.nmap(sid, audit, nmap_xml("open"))
    lab.http(sid, audit, chunks=[http_response(headers=(("Content-Type", "text/html"),))])
    script = [("tool_use", [_use(VERIFY_HYPOTHESIS, i, rule_id=r, host=HOST, port=PORT,
                                 rationale="Check this rule against the recorded response.")])
              for i, r in enumerate(RULES, 1)]
    script.append(("tool_use", [_use(FINISH, 99, summary="All header rules checked.")]))
    model = SizedModel(script)
    s = ResearchSession(provider=model, checker=lab.checker, audit=audit, session_id=uuid.UUID(sid),
                        limits=SessionLimits(max_tool_runs=0, max_steps=10),
                        approve=lambda v: False, execute=lambda p: None,
                        verification=VerificationLoop(LoopConfig(evidence_root=lab.evidence_root, no_progress_steps=10),
                                                      registry=web_registry()),
                        context_budget_tokens=budget)
    return s.run("Verify the recorded web evidence."), model, audit


def _results(messages):
    return [b for m in messages if m["role"] == "user" and isinstance(m["content"], list)
            for b in m["content"] if b.get("type") == "tool_result"]


def test_older_tool_results_are_elided_to_fit_the_budget(lab):
    result, model, audit = _run(lab, budget=4000)
    assert result.stop_reason is StopReason.FINISHED
    compactions = [r.data for r in audit.read_all() if r.event == "context_compacted"]
    assert compactions and all(c["input_tokens_after"] < c["input_tokens_before"] for c in compactions)
    sent = _results(model.sent)
    elided = [b for b in sent if b["content"] == ResearchSession.ELIDED]
    assert elided and all(b["content"] != ResearchSession.ELIDED for b in sent[-2:])  # newest kept
    # every tool call still has its result (valid conversation for any provider)
    uses = [b["id"] for m in model.sent if m["role"] == "assistant" for b in m["content"]
            if b.get("type") == "tool_use"]
    assert [b["tool_use_id"] for b in sent] == uses
    assert audit.verify()


def test_without_a_budget_nothing_is_elided(lab):
    result, model, audit = _run(lab, budget=None)
    assert result.stop_reason is StopReason.FINISHED
    assert not any(r.event == "context_compacted" for r in audit.read_all())
    assert all(b["content"] != ResearchSession.ELIDED for b in _results(model.sent))
    # and the unbudgeted prompt really was larger than the budgeted one
    _r, budgeted, _a = _run(lab, budget=4000)
    assert max(budgeted.sizes) < max(model.sizes)
