"""Regression gate for the offline evaluation harness (M7.8 Stage 4).

Runs every scenario through the real research loop and compares the scorecard
to the committed m7-v2 baseline. A change in AVRA's workflow behaviour that
moves any scenario's outcome shows up here as a failing diff. No network, no
API, no scans.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework import METRIC_KEYS, run_all
from prompt_registry import active_matches_production
from scenarios import SCENARIOS

BASELINE = json.loads((Path(__file__).parent / "baseline.json").read_text(encoding="utf-8"))


def test_active_prompt_is_production_m7_v2():
    # Guard: no experimental prompt has been activated.
    assert active_matches_production()
    assert BASELINE["prompt_version"] == "m7-v2"


def test_every_scenario_passes_its_metrics():
    current = run_all(SCENARIOS)
    failing = {n: [k for k, v in d["metrics"].items() if not v]
               for n, d in current["scenarios"].items() if not d["passed"]}
    assert not failing, f"scenarios failing their metrics: {failing}"
    assert current["summary"]["passed"] == current["summary"]["total"] == 28


def test_no_regression_against_baseline():
    current = run_all(SCENARIOS)
    assert set(current["scenarios"]) == set(BASELINE["scenarios"]), "scenario set changed"
    diffs = []
    for name, base in BASELINE["scenarios"].items():
        got = current["scenarios"][name]
        if got["actual"] != base["actual"] or got["metrics"] != base["metrics"]:
            diffs.append(name)
    assert not diffs, f"behaviour drifted from baseline for: {diffs}"


def test_security_and_evidence_invariants_hold():
    current = run_all(SCENARIOS)["scenarios"]
    # a refused session is diagnosed as a model safety refusal and runs nothing
    assert current["model_refusal"]["actual"]["diagnostic"] == "model_safety_refusal"
    assert current["model_refusal"]["actual"]["executed"] is False
    # out-of-scope is stopped by local policy, before the owner or the Runner
    assert current["out_of_scope_proposal_denied"]["actual"]["executed"] is False
    assert current["out_of_scope_proposal_denied"]["actual"]["diagnostic"] == \
        "local_policy_rejection"
    # a model-cited evidence id that never ran makes the report INVALID
    assert current["invalid_evidence_reference"]["actual"]["report_validation"] == "INVALID"
    # every metric is defined for every scenario
    for d in current.values():
        assert set(d["metrics"]) == set(METRIC_KEYS)
