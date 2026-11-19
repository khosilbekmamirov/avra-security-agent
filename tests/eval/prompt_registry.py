"""Test-only prompt registry (M7.8 Stage 4).

A deliberately tiny versioned registry so the evaluation harness can name
the prompt under test without touching runtime interfaces. The ACTIVE
production prompt stays ``m7-v2`` (``avra.llm.prompts.SYSTEM_PROMPT``).

An experimental candidate (e.g. ``m7-v3``) may be added here ONLY as an
offline experiment and must never be wired into production without the
owner's explicit approval — activation means changing
``avra.llm.prompts`` itself, not this file.
"""

from __future__ import annotations

from avra.llm.prompts import PROMPT_VERSION, SYSTEM_PROMPT

ACTIVE = "m7-v2"

# version -> system prompt text. Only the production prompt is registered;
# candidates are added here per-experiment and removed once decided.
REGISTRY: dict[str, str] = {"m7-v2": SYSTEM_PROMPT}


def get_prompt(version: str = ACTIVE) -> str:
    if version not in REGISTRY:
        raise KeyError(f"prompt version {version!r} is not registered (candidates are "
                       "experiment-only and need owner approval to activate)")
    return REGISTRY[version]


def active_matches_production() -> bool:
    """The active prompt must be exactly the one the runtime ships."""
    return ACTIVE == PROMPT_VERSION and REGISTRY[ACTIVE] == SYSTEM_PROMPT
