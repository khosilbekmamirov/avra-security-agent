"""Tools the model may call — proposals and notes only (M7.2, ADR 0005).

The model can PROPOSE one executable action (``propose_nmap_connect_scan``)
and write notes; it can never run anything itself. Every tool input is
validated here with strict Pydantic models before the Orchestrator looks
at it; an invalid input becomes an ``is_error`` tool result.

The JSON schemas sent to the API use ``strict: true`` and only features
strict mode supports (types, ``format``, ``required``,
``additionalProperties: false``). Numeric/length limits are not supported
there, so the Pydantic models below enforce them client-side.

Hypotheses and observations are recorded as UNVERIFIED notes; nothing the
model says can set a finding's status (CLAUDE.md).
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
)

from avra.runner.schemas import validate_ipv4_target

PROPOSE_SCAN = "propose_nmap_connect_scan"
RECORD_OBSERVATION = "record_observation"
RECORD_HYPOTHESIS = "record_hypothesis"
FINISH = "finish_session"
VERIFY_HYPOTHESIS = "verify_hypothesis"  # M8.5 verification mode only (ADR 0010)

MAX_PROPOSAL_PORTS = 8
MIN_SCAN_TIMEOUT = 10
MAX_SCAN_TIMEOUT = 120

Text = Annotated[StrictStr, Field(min_length=1)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProposeScan(_Strict):
    host: StrictStr
    ports: list[StrictInt] = Field(min_length=1, max_length=MAX_PROPOSAL_PORTS)
    timeout_seconds: StrictInt = Field(ge=MIN_SCAN_TIMEOUT, le=MAX_SCAN_TIMEOUT)
    explanation: Annotated[StrictStr, Field(min_length=10, max_length=400)]

    @field_validator("host")
    @classmethod
    def ipv4(cls, v: str) -> str:
        return validate_ipv4_target(v)

    @field_validator("ports")
    @classmethod
    def ports_ok(cls, v: list[int]) -> list[int]:
        if any(not 1 <= p <= 65535 for p in v) or len(set(v)) != len(v):
            raise ValueError("ports must be unique integers in 1..65535")
        return v


class RecordObservation(_Strict):
    summary: Annotated[StrictStr, Field(min_length=1, max_length=1000)]
    evidence_request_id: StrictStr | None = None


class RecordHypothesis(_Strict):
    statement: Annotated[StrictStr, Field(min_length=1, max_length=1000)]
    basis: Annotated[StrictStr, Field(min_length=1, max_length=1000)]


class VerifyHypothesis(_Strict):
    """A structured hypothesis for the Verification Engine (M8.5). There is
    deliberately no verdict/status field: the engine alone decides."""

    rule_id: Annotated[StrictStr, Field(min_length=3, max_length=80)]
    host: StrictStr
    port: StrictInt = Field(ge=1, le=65535)
    rationale: Annotated[StrictStr, Field(min_length=1, max_length=500)]

    @field_validator("host")
    @classmethod
    def ipv4(cls, v: str) -> str:
        return validate_ipv4_target(v)


class FinishSession(_Strict):
    summary: Annotated[StrictStr, Field(min_length=1, max_length=2000)]


MODELS: dict[str, type[_Strict]] = {
    PROPOSE_SCAN: ProposeScan,
    RECORD_OBSERVATION: RecordObservation,
    RECORD_HYPOTHESIS: RecordHypothesis,
    FINISH: FinishSession,
}
# M8.5 verification mode: the m7-v2 tools plus verify_hypothesis. In m7-v2
# mode verify_hypothesis stays an unknown tool (MODELS is unchanged).
MODELS_VERIFY: dict[str, type[_Strict]] = {**MODELS, VERIFY_HYPOTHESIS: VerifyHypothesis}
EXECUTABLE = frozenset({PROPOSE_SCAN})


class ToolInputError(Exception):
    pass


def validate_tool_input(name: str, data: Any,
                        models: dict[str, type[_Strict]] | None = None) -> _Strict:
    model = (MODELS if models is None else models).get(name)
    if model is None:
        raise ToolInputError(f"unknown tool {name!r}")
    if not isinstance(data, dict):
        raise ToolInputError("tool input must be a JSON object")
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise ToolInputError(f"invalid input for {name}: {details}"[:600]) from None


def _obj(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required,
            "additionalProperties": False}


TOOL_DEFINITIONS: list[dict] = [
    {
        "name": PROPOSE_SCAN,
        "description": (
            "Propose ONE TCP connect scan (nmap -sT, fixed safe flags) of an in-scope lab host. "
            "This does not run anything: the owner sees your explanation and must approve it, and "
            "two independent scope checks must allow it. Limits: 1-8 unique ports, "
            f"timeout_seconds {MIN_SCAN_TIMEOUT}-{MAX_SCAN_TIMEOUT}, explanation 10-400 characters "
            "in plain language saying what you want to learn and why it is needed."
        ),
        "strict": True,
        "input_schema": _obj({
            "host": {"type": "string", "format": "ipv4",
                     "description": "Target IPv4 address; must be in the session scope."},
            "ports": {"type": "array", "items": {"type": "integer"},
                      "description": "1-8 unique TCP ports."},
            "timeout_seconds": {"type": "integer", "description": "10-120 seconds."},
            "explanation": {"type": "string",
                            "description": "Short, owner-readable reason for this scan."},
        }, ["host", "ports", "timeout_seconds", "explanation"]),
    },
    {
        "name": RECORD_OBSERVATION,
        "description": ("Record a factual observation from tool results (max 1000 characters). "
                        "Reference the evidence request_id when there is one. Recorded as unverified."),
        "strict": True,
        "input_schema": _obj({
            "summary": {"type": "string"},
            "evidence_request_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        }, ["summary", "evidence_request_id"]),
    },
    {
        "name": RECORD_HYPOTHESIS,
        "description": ("Record a hypothesis to be verified later (statement and basis, max 1000 "
                        "characters each). It is never treated as a confirmed finding."),
        "strict": True,
        "input_schema": _obj({
            "statement": {"type": "string"},
            "basis": {"type": "string"},
        }, ["statement", "basis"]),
    },
    {
        "name": FINISH,
        "description": "End the session with a short summary (max 2000 characters) for the owner.",
        "strict": True,
        "input_schema": _obj({"summary": {"type": "string"}}, ["summary"]),
    },
]

VERIFY_TOOL_DEFINITION: dict = {
    "name": VERIFY_HYPOTHESIS,
    "description": (
        "Ask AVRA's deterministic Verification Engine to check ONE structured hypothesis "
        "against the session's hash-checked evidence: one rule_id from the verification "
        "rule catalogue and one in-scope host and port. Returns the engine's verdict "
        "(CONFIRMED, REJECTED or INCONCLUSIVE), the criteria, the missing evidence and the "
        "updated research state. You cannot set a verdict. Never touches the target."),
    "strict": True,
    "input_schema": _obj({
        "rule_id": {"type": "string", "description": "A rule id from the catalogue."},
        "host": {"type": "string", "format": "ipv4", "description": "In-scope IPv4 host."},
        "port": {"type": "integer", "description": "In-scope TCP port."},
        "rationale": {"type": "string",
                      "description": "Why this is worth checking (max 500 characters)."},
    }, ["rule_id", "host", "port", "rationale"]),
}
TOOL_DEFINITIONS_VERIFY: list[dict] = [*TOOL_DEFINITIONS, VERIFY_TOOL_DEFINITION]


# --- M9.1 (ADR 0016): HTTP probe as a proposable next action, OPT-IN ----------------
# Only offered when the owner starts `avra research --allow-http-probe`. Like a scan
# proposal it runs nothing by itself: scope (tool http_probe, tier passive) is checked,
# the owner approves each call in a real terminal, and the audited http_probe pipeline
# (ADR 0007: one fixed GET / HTTP/1.0) executes it.
PROPOSE_HTTP_PROBE = "propose_http_probe"


class ProposeHttpProbe(_Strict):
    host: StrictStr
    port: StrictInt = Field(ge=1, le=65535)
    explanation: Annotated[StrictStr, Field(min_length=10, max_length=400)]

    @field_validator("host")
    @classmethod
    def ipv4(cls, v: str) -> str:
        return validate_ipv4_target(v)


HTTP_PROBE_TOOL_DEFINITION: dict = {
    "name": PROPOSE_HTTP_PROBE,
    "description": (
        "Propose ONE passive HTTP probe of an in-scope lab host:port: a single fixed "
        "'GET / HTTP/1.0' that records the status line, headers and title. Use it when the "
        "Verification Engine lists http_probe evidence as missing. It runs nothing by itself: "
        "scope must allow tool http_probe and the owner must approve. Explanation 10-400 "
        "characters saying what you want to learn."),
    "strict": True,
    "input_schema": _obj({
        "host": {"type": "string", "format": "ipv4", "description": "In-scope IPv4 host."},
        "port": {"type": "integer", "description": "In-scope TCP port."},
        "explanation": {"type": "string", "description": "Short, owner-readable reason."},
    }, ["host", "port", "explanation"]),
}


# --- M10.3 (ADR 0017): structured research hypotheses, OPT-IN (--web-research) ---------
# Only offered in verification mode with --web-research. It records a hypothesis on the
# HypothesisBoard; there is deliberately NO state/verdict field: the engine decides.
RECORD_RESEARCH_HYPOTHESIS = "record_research_hypothesis"
VULN_CLASSES = ("missing_security_header", "cors_misconfiguration", "information_disclosure",
                "security_misconfiguration", "sensitive_endpoint_exposure",
                "broken_access_control", "authentication_weakness", "injection", "xss",
                "network_exposure", "other")


class RecordResearchHypothesis(_Strict):
    vuln_class: Annotated[StrictStr, Field(min_length=2, max_length=40)]
    host: StrictStr
    port: StrictInt = Field(ge=1, le=65535)
    endpoint: Annotated[StrictStr, Field(max_length=300)]
    statement: Annotated[StrictStr, Field(min_length=5, max_length=500)]
    supporting_evidence: list[Annotated[StrictStr, Field(max_length=64)]] = Field(max_length=10)
    confidence: Annotated[StrictStr, Field(min_length=3, max_length=6)]
    uncertainty: Annotated[StrictStr, Field(max_length=500)]
    required_evidence: list[Annotated[StrictStr, Field(max_length=200)]] = Field(max_length=5)
    verification_rule: Annotated[StrictStr, Field(max_length=80)]

    @field_validator("host")
    @classmethod
    def ipv4(cls, v: str) -> str:
        return validate_ipv4_target(v)


RESEARCH_HYPOTHESIS_TOOL_DEFINITION: dict = {
    "name": RECORD_RESEARCH_HYPOTHESIS,
    "description": (
        "Record ONE structured vulnerability hypothesis on AVRA's research board. You cannot "
        "set its state: the deterministic Verification Engine decides confirmed/rejected; "
        "AVRA checks your cited evidence ids and whether the endpoint was really observed. "
        "Use endpoint \"\" for the service as a whole (required when you name a "
        "verification_rule) or a same-origin path from the web surface. verification_rule: "
        "a catalogue rule id, or \"\" if none applies. confidence: low | medium | high."),
    "strict": True,
    "input_schema": _obj({
        "vuln_class": {"type": "string", "enum": list(VULN_CLASSES)},
        "host": {"type": "string", "format": "ipv4", "description": "In-scope IPv4 host."},
        "port": {"type": "integer", "description": "In-scope TCP port."},
        "endpoint": {"type": "string", "description": "\"\" or a path such as /rest/products."},
        "statement": {"type": "string", "description": "The hypothesis (max 500 chars)."},
        "supporting_evidence": {"type": "array", "items": {"type": "string"},
                                "description": "Evidence request ids (max 10)."},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "uncertainty": {"type": "string", "description": "What you do not know (max 500)."},
        "required_evidence": {"type": "array", "items": {"type": "string"},
                              "description": "What would decide it (max 5 items)."},
        "verification_rule": {"type": "string", "description": "Catalogue rule id or \"\"."},
    }, ["vuln_class", "host", "port", "endpoint", "statement", "supporting_evidence",
        "confidence", "uncertainty", "required_evidence", "verification_rule"]),
}


# --- M10.5 (ADR 0018): read-only GET of ONE discovered same-origin path, OPT-IN ---------
# Only offered with `avra research --web-research --allow-http-get`. The path must already
# appear in the recorded web surface; scope (tool http_get_path + http_paths prefix) and the
# owner's approval decide; the audited pipeline sends one fixed "GET <path> HTTP/1.0".
PROPOSE_HTTP_GET_PATH = "propose_http_get_path"


class ProposeHttpGetPath(_Strict):
    host: StrictStr
    port: StrictInt = Field(ge=1, le=65535)
    path: Annotated[StrictStr, Field(min_length=1, max_length=200)]
    explanation: Annotated[StrictStr, Field(min_length=10, max_length=400)]

    @field_validator("host")
    @classmethod
    def ipv4(cls, v: str) -> str:
        return validate_ipv4_target(v)

    @field_validator("path")
    @classmethod
    def safe_path(cls, v: str) -> str:
        from avra.runner.schemas import validate_http_path

        return validate_http_path(v)


HTTP_GET_PATH_TOOL_DEFINITION: dict = {
    "name": PROPOSE_HTTP_GET_PATH,
    "description": (
        "Propose ONE read-only GET of a same-origin path that already appears in the web "
        "surface (a referenced link, script, form action or API candidate). It confirms "
        "whether the endpoint exists and records its status, headers and content as evidence. "
        "No query string, no body, no credentials, no redirects followed. It runs nothing by "
        "itself: scope must allow tool http_get_path for that path and the owner must "
        "approve. Explanation 10-400 characters: what gap it closes."),
    "strict": True,
    "input_schema": _obj({
        "host": {"type": "string", "format": "ipv4", "description": "In-scope IPv4 host."},
        "port": {"type": "integer", "description": "In-scope TCP port."},
        "path": {"type": "string", "description": "A path from the web surface, e.g. /main.js"},
        "explanation": {"type": "string", "description": "Short, owner-readable reason."},
    }, ["host", "port", "path", "explanation"]),
}
