"""ADR 0015: `avra assess` - scope -> evidence -> Verification Engine -> AI analysis -> report.

Uses the byte-exact REAL lab sessions in tests/fixtures/synthetic-sessions (nmap scan
4460bea8, HTTP probe 7e868faf) and a scripted loopback model server. No Kali,
no target, no paid API."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from avra import assessment as asm
from avra.cli.main import app
from avra.llm.config import LLMConfig, TokenUsage
from avra.llm.provider import LLMProviderError, LLMResponse
from avra.storage.audit import AuditLog
from tests.fakes_local_llm import FakeOpenAIServer, completion

REAL = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic-sessions"
NMAP_SESSION = "4460bea8-d974-406c-bb65-75c3be0a899f"
HTTP_SESSION = "7e868faf-768d-49af-aea6-81dc9d435e20"

ANALYSIS = {
    "executive_summary": "Port 3000 is open and answers. The service is likely a web app.",
    "service_notes": [{"host": "10.66.7.103", "port": 3000, "note": "nmap's 'ppp' is a port guess"}],
    "hypotheses": [
        {"title": "Web application on 3000", "host": "10.66.7.103", "port": 3000,
         "rationale": "open port, scope says Juice Shop", "confidence": "medium",
         "suggested_check": "fetch the page headers with http_probe"},
        {"title": "SSH exposed", "host": "10.66.7.103", "port": 22,
         "rationale": "invented", "confidence": "high", "suggested_check": "x"},
        {"title": "Other host", "host": "10.0.0.9", "port": 3000,
         "rationale": "invented", "confidence": "low", "suggested_check": "x"}],
    "remediation": ["Restrict port 3000 to the lab network", {"step": "patch"}],
}


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    d = tmp_path / "data"
    shutil.copytree(REAL / "sessions", d / "sessions")
    shutil.copytree(REAL / "evidence", d / "evidence")
    monkeypatch.setenv("AVRA_DATA_DIR", str(d))
    for k in ("AVRA_LLM_PROVIDER", "AVRA_LLM_MODEL", "AVRA_LLM_BASE_URL"):
        monkeypatch.delenv(k, raising=False)
    return d


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.yaml"
    exp = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    p.write_text(f"""session_name: assess-test
expires_at: "{exp}"
targets:
  - host: "10.66.7.103"
    ports: [3000]
    allowed_tiers: ["active-safe"]
    allowed_tools: ["nmap_connect_scan"]
""")
    return p


def _assess(scope_file, *extra):
    return CliRunner().invoke(app, ["assess", "--scope", str(scope_file), "--target",
                                    "10.66.7.103", "--port", "3000", *extra])


# ----------------------------------------------------------------- parsing

@pytest.mark.parametrize("wrap", ["{}", "```json\n{}\n```", "Here you go:\n{}\nThanks"])
def test_parse_analysis_tolerates_fences_and_prose(wrap):
    a = asm.parse_analysis(wrap.replace("{}", json.dumps(ANALYSIS)))
    assert a.executive_summary.startswith("Port 3000") and len(a.hypotheses) == 3
    assert a.remediation[1] == '{"step": "patch"}'  # object coerced to text


@pytest.mark.parametrize("text,msg", [("no json here", "no JSON object"),
                                      ("{not json}", "not valid JSON"),
                                      ('{"hypotheses": []}', "schema")])
def test_parse_analysis_rejects_bad_replies(text, msg):
    with pytest.raises(ValueError, match=msg):
        asm.parse_analysis(text)


# ----------------------------------------------------------------- analysis step

class _Prov:
    def __init__(self, reply=None, exc=None, stop="end_turn"):
        self.config = LLMConfig(provider="ollama", model="m")
        self.reply, self.exc, self.stop, self.calls = reply, exc, stop, []

    def complete(self, *, system, messages, tools):
        self.calls.append({"system": system, "messages": messages, "tools": tools})
        if self.exc:
            raise self.exc
        return LLMResponse(stop_reason=self.stop, text=self.reply or "", tool_uses=(),
                           usage=TokenUsage(input_tokens=10, output_tokens=5), model="m",
                           request_id=None, history_content=[])


FACTS = {"targets": [{"host": "10.66.7.103", "port": 3000, "tcp": [], "service": None, "http": []}],
         "verified": [], "confirmed_findings": [], "inconclusive": [], "next_actions": [],
         "session_id": NMAP_SESSION, "session_trusted": True, "scope": "t"}


def test_analysis_drops_targets_outside_the_evidence_and_is_audited(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    prov = _Prov(json.dumps(ANALYSIS))
    out = asm.run_analysis(prov, FACTS, audit)
    assert out.status == "ok" and [h.port for h in out.analysis.hypotheses] == [3000]
    assert len(out.dropped) == 2 and all("not in the evidence" in d for d in out.dropped)
    assert prov.calls[0]["tools"] == []  # the model gets no tools here
    events = [r.event for r in audit.read_all()]
    assert events == ["assessment_llm_request", "assessment_llm_response",
                      "assessment_analysis_accepted"] and audit.verify()


@pytest.mark.parametrize("prov,status", [
    (_Prov(exc=LLMProviderError("cannot reach the local model server")), "failed"),
    (_Prov("", stop="refusal"), "refused"),
    (_Prov("garbage"), "invalid"),
])
def test_analysis_problems_never_raise(tmp_path, prov, status):
    out = asm.run_analysis(prov, FACTS, AuditLog(tmp_path / "a.jsonl"))
    assert out.status == status and out.analysis is None and out.detail


# ----------------------------------------------------------------- CLI end to end

def test_assess_out_of_scope_target_is_refused_before_anything(data_dir, scope_file):
    r = CliRunner().invoke(app, ["assess", "--scope", str(scope_file), "--target", "10.66.7.103",
                                 "--port", "22", "--session", NMAP_SESSION, "--no-ai"])
    assert r.exit_code == 1 and "DENIED" in r.output and "not in the scope" in r.output
    assert not (data_dir / "verification").exists() and not (data_dir / "assessments").exists()


def test_assess_deterministic_only_report(data_dir, scope_file):
    r = _assess(scope_file, "--session", NMAP_SESSION, "--no-ai")
    assert r.exit_code == 0, r.output
    md = next((data_dir / "assessments" / NMAP_SESSION).glob("assessment-*.md")).read_text(encoding="utf-8")
    assert "TCP port accepts connections" in md and "open (syn-ack)" in md
    assert "guess from the port number only" in md and "not requested" in md
    assert "No vulnerability was confirmed" in md


def test_assess_with_local_model_end_to_end(data_dir, scope_file):
    with FakeOpenAIServer([completion(json.dumps(ANALYSIS))]) as srv:
        r = _assess(scope_file, "--session", NMAP_SESSION, "--provider", "local-openai-compatible",
                    "--model", "fake-model", "--base-url", srv.base_url)
        assert r.exit_code == 0, r.output
        sent = srv.requests[0]["body"]
    facts = json.loads(sent["messages"][1]["content"].split("\n", 1)[1])
    assert facts["targets"][0]["tcp"][0]["state"] == "open"  # real evidence reached the model
    assert facts["targets"][0]["service"]["method"] == "table"
    out_dir = data_dir / "assessments" / NMAP_SESSION
    md = next(out_dir.glob("assessment-*.md")).read_text(encoding="utf-8")
    assert "AI-assisted analysis (UNVERIFIED)" in md and "Web application on 3000" in md
    assert "| UNVERIFIED |" in md and "SSH exposed" not in md.split("Dropped by AVRA")[0]
    assert "no API cost (local)" in md
    doc = json.loads(next(out_dir.glob("assessment-*.json")).read_text(encoding="utf-8"))
    assert doc["analysis"]["status"] == "ok" and len(doc["analysis"]["dropped"]) == 2
    audit = AuditLog(out_dir / asm.AUDIT_NAME)
    assert audit.verify() and [r.event for r in audit.read_all()][-1] == "assessment_written"


def test_assess_http_session_shows_http_facts(data_dir, scope_file):
    r = _assess(scope_file, "--session", HTTP_SESSION, "--no-ai")
    assert r.exit_code == 0, r.output
    md = next((data_dir / "assessments" / HTTP_SESSION).glob("assessment-*.md")).read_text(encoding="utf-8")
    assert "200 OK" in md and "OWASP Juice Shop" in md  # title is a server claim, shown as such


def test_assess_model_server_down_still_writes_the_report(data_dir, scope_file):
    r = _assess(scope_file, "--session", NMAP_SESSION, "--provider", "ollama", "--model", "m",
                "--base-url", "http://127.0.0.1:9", "--llm-timeout", "5")
    assert r.exit_code == 0, r.output
    assert "Analysis: failed" in r.output and "cannot reach" in r.output
    md = next((data_dir / "assessments" / NMAP_SESSION).glob("assessment-*.md")).read_text(encoding="utf-8")
    assert "**failed**" in md and "TCP port accepts connections" in md


def test_assess_refuses_a_non_loopback_model_server(data_dir, scope_file):
    r = _assess(scope_file, "--session", NMAP_SESSION, "--provider", "ollama", "--model", "m",
                "--base-url", "http://192.168.56.104:11434")
    assert r.exit_code == 1 and "not loopback" in r.output


def test_assess_needs_scan_or_session(data_dir, scope_file):
    r = _assess(scope_file, "--no-ai")
    assert r.exit_code == 1 and "--scan" in r.output


def test_assess_combines_sessions_and_resolves_open_questions(data_dir, scope_file):
    """nmap session alone: 'does HTTP answer?' is INCONCLUSIVE and an http_probe is
    proposed. With the real HTTP-probe session added, both are resolved."""
    r = _assess(scope_file, "--session", NMAP_SESSION, "--session", HTTP_SESSION, "--no-ai")
    assert r.exit_code == 0, r.output
    out = data_dir / "assessments" / NMAP_SESSION
    doc = json.loads(next(out.glob("assessment-*.json")).read_text(encoding="utf-8"))
    facts = doc["facts"]
    assert facts["sessions"] == [NMAP_SESSION, HTTP_SESSION] and facts["session_trusted"]
    t = facts["targets"][0]
    assert t["tcp"] and t["http"]  # both kinds of evidence, each with its own citation
    assert {e["evidence"]["tool"] for e in t["tcp"] + t["http"]} == {"nmap_connect_scan", "http_probe"}
    assert not any(q["rule"] == "http.service_observed" for q in facts["inconclusive"])
    assert not any(a["tool"] == "http_probe" for a in facts["next_actions"])
    md = next(out.glob("assessment-*.md")).read_text(encoding="utf-8")
    assert NMAP_SESSION in md and HTTP_SESSION in md


def test_merge_facts_untrusted_session_taints_the_whole_sheet():
    a = {**FACTS, "session_trusted": True}
    b = {**FACTS, "session_id": HTTP_SESSION, "session_trusted": False}
    assert asm.merge_facts([a, b])["session_trusted"] is False


def test_report_shows_recorded_security_headers_as_observations(data_dir, scope_file):
    r = _assess(scope_file, "--session", HTTP_SESSION, "--no-ai")
    assert r.exit_code == 0, r.output
    md = next((data_dir / "assessments" / HTTP_SESSION).glob("assessment-*.md")).read_text(encoding="utf-8")
    sec = md.split("### HTTP security headers (recorded response)")[1].split("##")[0]
    assert "Raw observations" in sec
    assert "`content-security-policy` | absent" in sec
    assert "`x-content-type-options` | present: `nosniff`" in sec
    assert "any web origin may read responses" in sec  # the real response sends ACAO: *
    assert "server header —" in md  # empty Server header shown as a dash, not ""


def test_assess_web_rules_confirm_header_findings_on_synthetic_juice_shop_evidence(data_dir, scope_file):
    r = _assess(scope_file, "--session", HTTP_SESSION, "--no-ai")
    assert r.exit_code == 0, r.output
    doc = json.loads(next((data_dir / "assessments" / HTTP_SESSION).glob("assessment-*.json"))
                     .read_text(encoding="utf-8"))
    # header rules are configuration weaknesses, NOT proven exploitable vulnerabilities
    assert doc["facts"]["confirmed_findings"] == []
    weak = doc["facts"]["confirmed_weaknesses"]
    assert {f["rule"] for f in weak} == {"http.missing_content_security_policy",
                                         "http.cors_wildcard_origin"}
    assert all("not a proven exploitable" in f["exploitability"] for f in weak)
    md = next((data_dir / "assessments" / HTTP_SESSION).glob("assessment-*.md")).read_text(encoding="utf-8")
    assert "0 confirmed vulnerability(ies)" in md and "No vulnerability was confirmed" in md
    assert "Confirmed configuration weaknesses (not proven exploitable)" in md
    assert "### Confirmed vulnerabilities" not in md
    r2 = _assess(scope_file, "--session", HTTP_SESSION, "--no-ai", "--rules", "default")
    assert r2.exit_code == 0
    docs = list((data_dir / "assessments" / HTTP_SESSION).glob("assessment-*.json"))
    assert len(docs) == 2  # same-second runs get distinct, write-once files
    found = sorted(len(json.loads(d.read_text(encoding="utf-8"))["facts"]["confirmed_weaknesses"])
                   for d in docs)
    assert found == [0, 2]  # default rules: no finding; web pack: CSP + CORS


def test_confirmed_findings_get_deterministic_fixes_and_ai_advice_is_labelled(data_dir, scope_file):
    reply = {**ANALYSIS, "hypotheses": [], "remediation": ["Rotate the admin password"]}
    with FakeOpenAIServer([completion(json.dumps(reply))]) as srv:
        r = _assess(scope_file, "--session", HTTP_SESSION, "--provider", "local-openai-compatible",
                    "--model", "fake-model", "--base-url", srv.base_url)
    assert r.exit_code == 0, r.output
    md = next((data_dir / "assessments" / HTTP_SESSION).glob("assessment-*.md")).read_text(encoding="utf-8")
    assert "*Fix:* Add a Content-Security-Policy" in md and "CWE-942" in md
    recs = md.split("## Recommendations")[1].split("##")[0]
    assert recs.index("Content-Security-Policy") < recs.index("(AI, unverified) Rotate the admin password")
