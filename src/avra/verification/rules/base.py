"""Verification-rule interface and registry (M8.4, ADR 0009).

A rule is a small deterministic plugin. It declares:

* ``id``/``version``/``kind`` — kind ``observation`` (a network/protocol
  fact) or ``vulnerability`` (a security weakness; CONFIRMED = finding);
* ``evidence_kinds`` — which typed observations it may look at;
* ``criteria`` — positive and negative conditions, in plain words;
* ``confirmed_requires`` — exactly what evidence produces CONFIRMED.

``evaluate`` sees ONLY trusted observations for the hypothesis' target and
returns a ``RuleEvaluation``. It must be pure: no I/O, no clock, no model,
no randomness. The engine (not the rule) builds the final result and
enforces the invariants (a decision must cite trusted evidence).

``suggest`` lets a rule propose follow-up hypotheses from the current
research state (deterministic generator); ``next_actions`` says which NEW
evidence would resolve an INCONCLUSIVE result — proposals only, never run.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from avra.verification.models import (
    Criterion,
    CriterionCheck,
    EvidenceKind,
    Hypothesis,
    ProposedAction,
    RuleKind,
    Target,
    Verdict,
    VerificationResult,
)

if TYPE_CHECKING:
    from avra.verification.evidence import Observation, SessionEvidence


@dataclass(frozen=True)
class RuleEvaluation:
    verdict: Verdict
    reason_code: str
    reason: str
    checks: tuple[CriterionCheck, ...] = ()
    used: tuple[Observation, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class Suggestion:
    target: Target
    rationale: str
    params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SuggestContext:
    """What a rule may look at to suggest follow-ups: the session's trusted
    evidence and the verdicts reached so far (by rule id and target)."""

    evidence: SessionEvidence
    verdicts: dict[tuple[str, Target], Verdict]

    def confirmed(self, rule_id: str) -> list[Target]:
        return sorted((t for (r, t), v in self.verdicts.items()
                       if r == rule_id and v is Verdict.CONFIRMED),
                      key=lambda t: (t.host, t.port))


class VerificationRule(ABC):
    id: str
    version: str
    kind: RuleKind
    title: str
    description: str
    evidence_kinds: frozenset[EvidenceKind]
    criteria: tuple[Criterion, ...]
    confirmed_requires: str
    severity: str = "none"  # vulnerability rules: informational | low | medium | high
    references: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def validate_params(self, params: dict[str, str]) -> None:
        if params:
            raise ValueError(f"rule {self.id} takes no parameters")

    @abstractmethod
    def evaluate(self, hypothesis: Hypothesis,
                 observations: list[Observation]) -> RuleEvaluation: ...

    def suggest(self, ctx: SuggestContext) -> Iterable[Suggestion]:
        return ()

    def next_actions(self, hypothesis: Hypothesis,
                     result: VerificationResult) -> Iterable[ProposedAction]:
        return ()

    def describe(self) -> dict:
        return {"id": self.id, "version": self.version, "kind": self.kind.value,
                "title": self.title, "severity": self.severity,
                "evidence_kinds": sorted(k.value for k in self.evidence_kinds),
                "confirmed_requires": self.confirmed_requires,
                "criteria": [c.model_dump() for c in self.criteria]}


class RuleRegistry:
    def __init__(self, rules: Iterable[VerificationRule] = ()) -> None:
        self._rules: dict[str, VerificationRule] = {}
        for r in rules:
            self.register(r)

    def register(self, rule: VerificationRule) -> None:
        if rule.id in self._rules:
            raise ValueError(f"duplicate rule id {rule.id!r}")
        self._rules[rule.id] = rule

    def get(self, rule_id: str) -> VerificationRule | None:
        return self._rules.get(rule_id)

    def rules(self) -> list[VerificationRule]:
        return [self._rules[k] for k in sorted(self._rules)]

    def ids(self) -> list[str]:
        return sorted(self._rules)


def check(criterion: Criterion, met: bool | None, detail: str = "") -> CriterionCheck:
    outcome = "unknown" if met is None else ("met" if met else "not_met")
    return CriterionCheck(criterion_id=criterion.id, outcome=outcome, detail=detail[:300])
