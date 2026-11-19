"""M10.5 (ADR 0018): read-only GET of one discovered same-origin path (http_get_path).

Everything runs over scripted sockets and stand-in tunnel/Runner (conftest). SIMULATED-FIXTURE
target 192.168.56.250:8080 - never a lab VM; no network traffic."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import HOST, PORT, _client, _Sock, _Tunnel, http_response, nmap_xml
from pydantic import ValidationError

from avra.core.research import ResearchSession, StopReason
from avra.llm.config import LLMConfig, SessionLimits, TokenUsage
from avra.llm.provider import LLMResponse, ToolUse
from avra.llm.tools import FINISH, PROPOSE_HTTP_GET_PATH
from avra.policy.scope import ScopeChecker, path_allowed
from avra.policy.tools import authorize_tool_request
from avra.recon.http_probe import HttpProbeError, parse_envelope
from avra.recon.web_surface import surfaces_from_evidence
from avra.runner.policy import RunnerPolicy
from avra.runner.registry import get_tool
from avra.runner.schemas import HttpGetPathRequest, HttpProbeRequest, validate_http_path
from avra.runner.tools import http_probe as child
from avra.runner_client.client import RunnerToken
from avra.runner_client.http_probe import APPROVAL_INTERACTIVE_TTY, run_http_probe
from avra.runner_client.tunnel import TunnelConfig
from avra.schemas.scope import ActionTier, Scope, Target
from avra.verification.loop import LoopConfig, VerificationLoop
from avra.verification.rules import validation_registry

NIL = uuid.UUID(int=0)
ROOT = http_response(headers=(("Content-Type", "text/html"),),
                     body=(b'<script src="/main.js"></script><a href="/app/page">p</a>'
                           b'<a href="/admin/panel">a</a>'))
MAIN = http_response(headers=(("Content-Type", "application/javascript"),),
                     body=b'fetch("/rest/products/search");fetch("/api/Users")')
PAGE = http_response(headers=(("Content-Type", "text/html"),),
                     body=b'<a href="detail">d</a><a href="../other">o</a>')


def _scope(tools=("http_probe", "http_get_path", "nmap_connect_scan"),
           paths=("/main.js", "/app/", "/rest")):
    return Scope(session_name="SIMULATED-FIXTURE",
                 expires_at=datetime.now(UTC) + timedelta(days=1),
                 targets=[Target(host=HOST, ports=[PORT],
                                 allowed_tiers=[ActionTier.PASSIVE, ActionTier.ACTIVE_SAFE],
                                 allowed_tools=list(tools), http_paths=list(paths))])


def _get(path, host=HOST, port=PORT):
    return HttpGetPathRequest(request_id=NIL, session_id=NIL, host=host, port=port, path=path)


# --- path validation and scope -------------------------------------------------------------

@pytest.mark.parametrize("ok", ["/", "/main.js", "/rest/products/1", "/a-b_c~d", "/x%20y",
                                "/api/v1/"])
def test_valid_paths(ok):
    assert validate_http_path(ok) == ok


@pytest.mark.parametrize("bad", ["", "main.js", "/a?b=1", "/a#frag", "/../etc/passwd",
                                 "/a/./b", "/a/..", "//evil.example/x", "/a\\b", "/%2e%2e/x",
                                 "/%2F", "/a%5cb", "/a b", "/%zz", "/%4", "/a%00",
                                 "http://192.168.56.250/x", "/" + "a" * 250, "/\x00", "/é"])
def test_invalid_paths(bad):
    with pytest.raises(ValueError):
        validate_http_path(bad)
    with pytest.raises(ValidationError):
        _get(bad)


def test_path_prefix_semantics():
    assert path_allowed("/api", ["/api"]) and path_allowed("/api/x", ["/api"])
    assert not path_allowed("/apix", ["/api"])
    assert path_allowed("/app/x", ["/app/"]) and not path_allowed("/app", ["/app/"])
    assert path_allowed("/anything", ["/"])
    assert not path_allowed("/x", [])


def test_scope_rejects_bad_path_prefix():
    with pytest.raises(ValidationError):
        Target(host=HOST, ports=[PORT], allowed_tiers=[ActionTier.PASSIVE],
               allowed_tools=["http_get_path"], http_paths=["/../x"])


@pytest.mark.parametrize("policy", ["windows", "runner"])
def test_both_scope_checks_need_tool_and_prefix(policy):
    def allowed(scope, req):
        if policy == "windows":
            return authorize_tool_request(ScopeChecker(scope), req).allowed
        return RunnerPolicy(scope).check(get_tool(req.tool.value), req).allowed

    assert allowed(_scope(), _get("/main.js"))
    assert allowed(_scope(), _get("/rest/products"))
    assert not allowed(_scope(), _get("/admin/panel"))          # no prefix
    assert not allowed(_scope(), _get("/restx"))                # prefix boundary
    assert not allowed(_scope(paths=()), _get("/main.js"))      # default deny
    assert not allowed(_scope(tools=("http_probe",)), _get("/main.js"))  # tool not listed
    assert not allowed(_scope(), _get("/main.js", port=9999))
    # http_probe is unaffected by http_paths (always GET /)
    probe = HttpProbeRequest(request_id=NIL, session_id=NIL, host=HOST, port=PORT)
    assert allowed(_scope(paths=()), probe)


def test_metadata_and_other_hosts_are_not_valid_targets():
    for host in ("169.254.169.254", "127.0.0.1", "0.0.0.0", "evil.example"):
        with pytest.raises(ValidationError):
            _get("/x", host=host)


# --- child program -------------------------------------------------------------------------

def test_child_sends_exactly_one_fixed_get_of_the_path():
    sent = []

    class S(_Sock):
        def sendall(self, data):
            sent.append(data)

    env = child.probe(HOST, PORT, 5, socket_factory=lambda: S([MAIN]), path="/main.js")
    assert sent == [child.request_bytes(HOST, PORT, "/main.js")]
    assert sent[0].startswith(b"GET /main.js HTTP/1.0\r\n")
    assert env["format"] == child.GET_PATH_FORMAT and env["path"] == "/main.js"


def test_child_argv():
    assert child._parse_argv(["--host", HOST, "--port", "80", "--timeout", "5"])[3] is None
    assert child._parse_argv(["--host", HOST, "--port", "80", "--timeout", "5", "--path",
                              "/a"])[3] == "/a"
    for bad in (["--path", "/../x"], ["--path", "/a?x=1"], ["--method", "POST"], ["--path"]):
        with pytest.raises(ValueError):
            child._parse_argv(["--host", HOST, "--port", "80", "--timeout", "5", *bad])
    args = get_tool("http_get_path").build_command(_get("/main.js")).argv
    assert args == ("http_probe", "--host", HOST, "--port", "8080", "--timeout", "10",
                    "--path", "/main.js")


def test_envelope_pairing():
    env = child.encode_envelope(child.probe(HOST, PORT, 5, socket_factory=lambda: _Sock([MAIN]),
                                            path="/main.js"))
    assert parse_envelope(env, host=HOST, port=PORT, path="/main.js")[0].path == "/main.js"
    for kwargs in ({"path": "/other.js"}, {"path": None}):
        with pytest.raises(HttpProbeError):
            parse_envelope(env, host=HOST, port=PORT, **kwargs)
    probe_env = child.encode_envelope(child.probe(HOST, PORT, 5,
                                                  socket_factory=lambda: _Sock([ROOT])))
    with pytest.raises(HttpProbeError):
        parse_envelope(probe_env, host=HOST, port=PORT, path="/")


# --- pipeline + evidence + surface ---------------------------------------------------------

def _fetch(lab, sid, audit, path, resp, checker=None, approval=APPROVAL_INTERACTIVE_TTY):
    env = child.probe(HOST, PORT, 5, socket_factory=lambda: _Sock([resp]), path=path)
    return run_http_probe(checker=checker or ScopeChecker(_scope(paths=("/",))), audit=audit,
                          session_id=uuid.UUID(sid), host=HOST, port=PORT, timeout_seconds=5,
                          token=RunnerToken("t" * 43), evidence_root=lab.evidence_root,
                          tunnel_cfg=TunnelConfig(), approval=approval, tunnel_factory=_Tunnel,
                          client_factory=_client(child.encode_envelope(env), "http_get_path"),
                          path=path)


def test_pipeline_evidence_and_surface(lab):
    sid, audit = lab.new_session()
    lab.http(sid, audit, chunks=[ROOT])
    out = _fetch(lab, sid, audit, "/main.js", MAIN)
    assert out.ok and out.request.tool.value == "http_get_path"
    out2 = _fetch(lab, sid, audit, "/app/page", PAGE)
    assert out2.ok
    sent = [r.data for r in audit.read_all() if r.event == "tool_request_sent"]
    assert [d.get("path") for d in sent] == [None, "/main.js", "/app/page"]
    res = [r.data for r in audit.read_all() if r.event == "tool_result_received"]
    assert res[1]["http_status_code"] == 200 and res[1]["path"] == "/main.js"

    ev = lab.evidence(sid)
    assert ev.trusted and {getattr(o, "path", "/") for o in ev.observations} == {
        "/", "/main.js", "/app/page"}
    s = surfaces_from_evidence(ev, lab.evidence_root)[0][0]
    by = {e.path: e for e in s.endpoints}
    assert by["/main.js"].status == "fetched" and by["/main.js"].fetches[0][1] == 200
    assert by["/admin/panel"].status == "referenced_not_fetched"
    # references inside fetched content: script strings, and links relative to /app/page
    assert "api_candidate" in by["/api/Users"].kinds
    assert "/app/detail" in by and "/other" in by


def test_header_rules_only_judge_get_root(lab):
    sid, audit = lab.new_session()
    _fetch(lab, sid, audit, "/main.js", http_response(headers=(("Content-Type", "text/html"),),
                                                      body=b"<p>no csp</p>"))
    from avra.verification.engine import VerificationEngine
    from avra.verification.models import Hypothesis, Origin, Verdict

    h = Hypothesis.create(rule_id="http.missing_content_security_policy", host=HOST,
                          port=PORT, origin=Origin.OWNER)
    r = VerificationEngine(validation_registry()).verify(h, lab.evidence(sid))
    assert r.verdict is Verdict.INCONCLUSIVE and "not the GET / response" in r.reason


def test_redirect_off_scope_is_recorded_never_followed(lab):
    sid, audit = lab.new_session()
    redirect = http_response(status="302 Found", headers=(
        ("Location", "http://169.254.169.254/latest/meta-data/"),
        ("Content-Type", "text/html")), body=b"moved")
    connects = []

    class S(_Sock):
        def connect(self, addr):
            connects.append(addr)

    env = child.probe(HOST, PORT, 5, socket_factory=lambda: S([redirect]), path="/main.js")
    assert connects == [(HOST, PORT)]  # one connection to the in-scope target only
    out = run_http_probe(
        checker=ScopeChecker(_scope(paths=("/",))), audit=audit, session_id=uuid.UUID(sid),
        host=HOST, port=PORT, timeout_seconds=5, token=RunnerToken("t" * 43),
        evidence_root=lab.evidence_root, tunnel_cfg=TunnelConfig(),
        approval=APPROVAL_INTERACTIVE_TTY, tunnel_factory=_Tunnel,
        client_factory=_client(child.encode_envelope(env), "http_get_path"), path="/main.js")
    assert out.ok and out.facts.is_redirect
    s = surfaces_from_evidence(lab.evidence(sid), lab.evidence_root)[0][0]
    assert "http://169.254.169.254" in s.external_origins


def test_pipeline_refuses_out_of_prefix_and_without_approval(lab):
    sid, audit = lab.new_session()
    out = _fetch(lab, sid, audit, "/admin/panel", MAIN, checker=ScopeChecker(_scope()))
    assert not out.allowed_locally
    out = _fetch(lab, sid, audit, "/main.js", MAIN, checker=ScopeChecker(_scope()),
                 approval=None)
    assert not out.allowed_locally and out.local_reason == "no interactive owner approval"
    assert not any(r.event == "tool_request_sent" for r in audit.read_all())


# --- research loop -------------------------------------------------------------------------

class ScriptedModel:
    def __init__(self, script):
        self.config = LLMConfig(provider="local-openai-compatible", model="scripted")
        self.script, self.seen = list(script), []

    def count_input_tokens(self, *, system, messages, tools):
        return 1000

    def complete(self, *, system, messages, tools):
        self.seen.append({"tools": [t["name"] for t in tools], "system": system[0]["text"],
                          "messages": json.loads(json.dumps(messages, default=str))})
        stop, uses = self.script.pop(0)
        return LLMResponse(stop_reason=stop, text="", tool_uses=tuple(uses),
                           usage=TokenUsage(input_tokens=1000, output_tokens=50),
                           model="scripted", request_id=None,
                           history_content=[{"type": "tool_use", "id": u.id, "name": u.name,
                                             "input": u.input} for u in uses])

    def result(self, n):
        return json.loads(self.seen[n]["messages"][-1]["content"][0]["content"].split("\n")[1])


def _use(name, i, **inp):
    return ToolUse(id=f"call_{i}", name=name, input=inp)


def _get_use(i, path):
    return _use(PROPOSE_HTTP_GET_PATH, i, host=HOST, port=PORT, path=path,
                explanation="Confirm the referenced script exists and read its API calls.")


def _session(lab, script, *, scope=None, approve=True, allow=True):
    sid, audit = lab.new_session()
    lab.nmap(sid, audit, nmap_xml("open"))
    lab.http(sid, audit, chunks=[ROOT])
    checker = ScopeChecker(scope or _scope())
    approvals, runs = [], []

    def execute_get(p):
        runs.append(p.path)
        return _fetch(lab, sid, audit, p.path, MAIN, checker=checker)

    model = ScriptedModel(script)
    s = ResearchSession(
        provider=model, checker=checker, audit=audit, session_id=uuid.UUID(sid),
        limits=SessionLimits(max_tool_runs=2, max_steps=8),
        approve=lambda v: (approvals.append(v), approve)[1],
        execute=lambda p: (_ for _ in ()).throw(AssertionError("no scan expected")),
        verification=VerificationLoop(LoopConfig(evidence_root=lab.evidence_root),
                                      registry=validation_registry()),
        web_research=True, http_get=execute_get if allow else None)
    return s, model, audit, approvals, runs


def test_loop_fetches_a_surface_path_and_updates_state(lab):
    script = [("tool_use", [_get_use(1, "/main.js")]),
              ("tool_use", [_get_use(2, "/main.js")]),          # duplicate
              ("tool_use", [_use(FINISH, 3, summary="done")])]
    s, model, audit, approvals, runs = _session(lab, script)
    result = s.run("Research the web app.")
    assert result.stop_reason is StopReason.FINISHED
    assert PROPOSE_HTTP_GET_PATH in model.seen[0]["tools"]
    assert "Read-only path fetch (enabled" in model.seen[0]["system"]
    started = next(r.data for r in audit.read_all() if r.event == "research_started")
    assert started["prompt_version"].endswith("+web+get")
    assert len(approvals) == 1 and approvals[0].tool == "http_get_path" \
        and approvals[0].path == "/main.js"
    assert runs == ["/main.js"]
    r1 = model.result(1)
    assert r1["path"] == "/main.js" and r1["response"]["status_code"] == 200
    endpoints = {e["path"]: e for s_ in r1["web_surface"]["surfaces"] for e in s_["endpoints"]}
    assert endpoints["/main.js"]["status"] == "fetched"
    assert "/api/Users" in endpoints  # new references from the fetched script
    dup = model.seen[2]["messages"][-1]["content"][0]
    assert dup["is_error"] and "already proposed" in dup["content"]


def test_path_not_in_surface_is_refused_before_scope_and_owner(lab):
    script = [("tool_use", [_get_use(1, "/rest/secret-invented")]),
              ("tool_use", [_use(FINISH, 2, summary="done")])]
    s, _model, audit, approvals, runs = _session(lab, script)
    s.run("x")
    assert approvals == [] and runs == []
    rej = next(r.data for r in audit.read_all() if r.event == "llm_proposal_rejected")
    assert rej["reason"] == "not_in_web_surface"


def test_scope_without_prefix_denies_before_owner(lab):
    script = [("tool_use", [_get_use(1, "/admin/panel")]),
              ("tool_use", [_use(FINISH, 2, summary="done")])]
    s, _m, audit, approvals, runs = _session(lab, script)
    s.run("x")
    assert approvals == [] and runs == []
    assert any(r.event == "llm_proposal_denied" for r in audit.read_all())


def test_owner_decline_runs_nothing(lab):
    script = [("tool_use", [_get_use(1, "/main.js")]),
              ("tool_use", [_use(FINISH, 2, summary="done")])]
    s, _m, _audit, approvals, runs = _session(lab, script, approve=False)
    s.run("x")
    assert len(approvals) == 1 and runs == []


def test_tool_not_offered_without_the_flag_and_needs_web_research(lab):
    s, model, _a, _ap, _r = _session(lab, [("tool_use", [_use(FINISH, 1, summary="x")])],
                                     allow=False)
    s.run("x")
    assert PROPOSE_HTTP_GET_PATH not in model.seen[0]["tools"]
    sid, audit = lab.new_session()
    with pytest.raises(ValueError, match="web_research"):
        ResearchSession(provider=ScriptedModel([]), checker=lab.checker, audit=audit,
                        session_id=uuid.UUID(sid), limits=SessionLimits(),
                        approve=lambda v: False, execute=lambda p: None,
                        verification=VerificationLoop(LoopConfig(evidence_root=lab.evidence_root)),
                        http_get=lambda p: None)


def test_board_suggests_fetch_for_observed_unfetched_endpoint(lab):
    from avra.research.hypotheses import HypothesisBoard

    s, _m, audit, _ap, _r = _session(lab, [("tool_use", [_use(FINISH, 1, summary="x")])])
    s.run("x")
    board = HypothesisBoard(loop=s.verification, audit=audit, surfaces=s._surfaces,
                            agent_tools=s.verification.agent_tools)
    p = board.propose(step=1, vuln_class="broken_access_control", host=HOST, port=PORT,
                      endpoint="/admin/panel", statement="Admin panel may lack auth",
                      supporting_evidence=[], confidence="low", uncertainty="",
                      required_evidence=[], verification_rule="")
    assert p.entry.next_action.kind == "http_get_path" and p.entry.next_action.available
