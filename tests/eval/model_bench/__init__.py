"""AVRA local-model benchmark (ADR 0015 follow-up).

Model-agnostic: talks to any loopback OpenAI-compatible server through AVRA's own
``LocalOpenAICompatibleProvider``. Inputs are FROZEN fact sheets built from recorded
lab evidence by the real pipelines and Verification Engine (``facts.json``), so every
model sees byte-identical tasks. Grading is deterministic (``cards.py``).

    python -m tests.eval.model_bench --model <name> [--base-url http://127.0.0.1:8080]
"""
