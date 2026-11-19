"""M8.5 compatibility gate: the 28 M7 eval scenarios run in verification mode
(prompt m8.5-v1, verify_hypothesis offered, Verification Engine active).

These scripted scenarios never store evidence and never call
verify_hypothesis, so the engine has nothing to decide: every outcome and
every metric must equal the committed m7-v2 baseline. Any drift means the
verification mode changed M7 behaviour where no verification applies.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework import run_all
from scenarios import SCENARIOS

BASELINE = json.loads((Path(__file__).parent / "baseline.json").read_text(encoding="utf-8"))


def test_verification_mode_matches_the_m7_baseline_on_every_scenario():
    current = run_all(SCENARIOS, verification=True)
    assert current["summary"]["passed"] == current["summary"]["total"] == 28
    drift = [n for n, b in BASELINE["scenarios"].items()
             if current["scenarios"][n]["actual"] != b["actual"]
             or current["scenarios"][n]["metrics"] != b["metrics"]]
    assert drift == [], f"verification mode drifted from the m7-v2 baseline: {drift}"
