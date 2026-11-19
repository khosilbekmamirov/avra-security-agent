"""Typed models of the Verification Engine (M8.4, ADR 0009).

Four kinds of things are kept strictly apart:

* **Observations** (``evidence.py``) — facts re-derived from hash-checked
  evidence files. They carry no opinion.
* **Hypotheses** — *proposals* (from the model, a deterministic generator or
  the owner). A hypothesis names exactly one verification rule and one
  target; its free-text ``rationale`` is opaque and never interpreted.
* **Verification results** — produced only by ``VerificationEngine`` from a
  rule's deterministic evaluation of observations. Nothing else can create
  a ``Verdict``.
* **Findings** — a CONFIRMED result of a *vulnerability* rule. A CONFIRMED
  *observation* rule (e.g. "TCP port open") is a verified observation, not
  a finding.

Everything here is frozen, ``extra="forbid"`` and serializes canonically
(sorted keys, no whitespace, ASCII), so the same inputs give the same bytes
and the same SHA-256 on every run and platform.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator

from avra.runner.schemas import validate_ipv4_target

ENGINE_VERSION = "1"
MAX_RATIONALE = 1_000
MAX_PARAM_VALUE = 200
_PARAM_KEY = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_RULE_ID = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    def canonical(self) -> str:
        return canonical_json(self.model_dump(mode="json"))


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class RuleKind(str, Enum):
    OBSERVATION = "observation"      # a network/protocol fact, never a vulnerability
    VULNERABILITY = "vulnerability"  # a security weakness; CONFIRMED = finding


class EvidenceKind(str, Enum):
    NMAP_XML = "nmap_xml"            # nmap_connect_scan evidence (<request_id>.xml)
    HTTP_ENVELOPE = "http_envelope"  # http_probe evidence (<request_id>.json)


class Origin(str, Enum):
    GENERATOR = "generator"  # deterministic rule-based proposer
    MODEL = "model"          # the LLM (via the ModelProposer)
    OWNER = "owner"          # an owner-supplied hypotheses file


class Target(_Frozen):
    host: StrictStr
    port: StrictInt = Field(ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def _ipv4(cls, v: str) -> str:
        return validate_ipv4_target(v)

    def label(self) -> str:
        return f"{self.host}:{self.port}"


class EvidenceRef(_Frozen):
    """Points at one verified evidence file through the audit chain."""

    session_id: StrictStr
    request_id: StrictStr
    tool: StrictStr
    kind: EvidenceKind
    sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    audit_seq: StrictInt = Field(ge=1)  # seq of the tool_result_received record

    def key(self) -> tuple[str, str]:
        return (self.session_id, self.request_id)


class Criterion(_Frozen):
    id: StrictStr
    polarity: str = Field(pattern=r"^(positive|negative)$")
    description: StrictStr


class Hypothesis(_Frozen):
    """A proposal to verify ONE rule against ONE target. ``id`` is derived
    from (rule, target, params) only, so the same proposal from two sources
    is the same hypothesis (dedup) and the rationale cannot change it."""

    id: StrictStr
    rule_id: StrictStr
    target: Target
    params: dict[str, str] = Field(default_factory=dict)
    origin: Origin
    rationale: str = Field(default="", max_length=MAX_RATIONALE)
    cited_evidence: tuple[str, ...] = ()  # request_ids the proposer cites (checked, never trusted)

    @staticmethod
    def make_id(rule_id: str, target: Target, params: dict[str, str]) -> str:
        key = canonical_json({"rule": rule_id, "target": target.label(), "params": params})
        return "H-" + sha256_hex(key)[:16]

    @classmethod
    def create(cls, *, rule_id: str, host: str, port: int, origin: Origin,
               params: dict[str, str] | None = None, rationale: str = "",
               cited_evidence: tuple[str, ...] = ()) -> Hypothesis:
        if not _RULE_ID.fullmatch(rule_id):
            raise ValueError("rule_id must look like 'family.name'")
        params = dict(params or {})
        for k, v in params.items():
            if not _PARAM_KEY.fullmatch(k) or not isinstance(v, str) or len(v) > MAX_PARAM_VALUE:
                raise ValueError("params must be short string values with snake_case keys")
        target = Target(host=host, port=port)
        return cls(id=cls.make_id(rule_id, target, params), rule_id=rule_id, target=target,
                   params=params, origin=origin, rationale=rationale[:MAX_RATIONALE],
                   cited_evidence=tuple(sorted(set(cited_evidence)))[:20])


class CriterionCheck(_Frozen):
    criterion_id: StrictStr
    outcome: str = Field(pattern=r"^(met|not_met|unknown)$")
    detail: StrictStr = ""


class EvidenceIssue(_Frozen):
    """Why a piece of evidence was NOT trusted (it then supports nothing)."""

    label: StrictStr       # request_id or file/record label
    code: StrictStr        # e.g. hash_mismatch, missing_file, unpaired_request
    detail: StrictStr = ""


class ProposedAction(_Frozen):
    """A next step that needs NEW evidence. Never executed by the engine or
    the cycle: a live request needs scope + owner approval (M8.3 path)."""

    tool: StrictStr
    target: Target
    reason: StrictStr
    requires_owner_approval: bool = True

    def key(self) -> tuple[str, str]:
        return (self.tool, self.target.label())


class VerificationResult(_Frozen):
    hypothesis_id: StrictStr
    rule_id: StrictStr
    rule_version: StrictStr
    rule_kind: RuleKind | None  # None only for an unsupported rule
    target: Target
    verdict: Verdict
    reason_code: StrictStr
    reason: StrictStr
    checks: tuple[CriterionCheck, ...] = ()
    evidence_used: tuple[EvidenceRef, ...] = ()
    evidence_excluded: tuple[EvidenceIssue, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    engine_version: StrictStr = ENGINE_VERSION

    @property
    def is_finding(self) -> bool:
        return self.verdict is Verdict.CONFIRMED and self.rule_kind is RuleKind.VULNERABILITY

    def sha256(self) -> str:
        return sha256_hex(self.canonical())
