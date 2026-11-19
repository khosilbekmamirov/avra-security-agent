"""Verification Engine (M8.4, ADR 0009).

AI reasoning proposes; this package decides. Observations come only from
hash-checked evidence (``evidence``), hypotheses are proposals
(``models.Hypothesis``), verdicts come only from ``VerificationEngine``
running a registered deterministic rule (``rules``), and the bounded
offline research cycle (``cycle``) turns verdicts into the next step.
"""

from avra.verification.engine import VerificationEngine
from avra.verification.evidence import SessionEvidence, load_session_evidence
from avra.verification.models import (
    ENGINE_VERSION,
    Hypothesis,
    Origin,
    ProposedAction,
    RuleKind,
    Target,
    Verdict,
    VerificationResult,
)
from avra.verification.rules import RuleRegistry, VerificationRule, default_registry

__all__ = [
    "ENGINE_VERSION",
    "Hypothesis",
    "Origin",
    "ProposedAction",
    "RuleKind",
    "RuleRegistry",
    "SessionEvidence",
    "Target",
    "Verdict",
    "VerificationEngine",
    "VerificationResult",
    "VerificationRule",
    "default_registry",
    "load_session_evidence",
]
