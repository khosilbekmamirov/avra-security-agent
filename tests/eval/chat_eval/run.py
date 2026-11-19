"""Run the M14.5 chat evaluation against the LOCAL model (loopback only).

    python -m tests.eval.chat_eval --model bonsai-2-27b-ptq1 [--base-url http://127.0.0.1:8080]
        [--ids G1,E2] [--repeat 1] [--out results.json] [--extra-body '{...}']
    python -m tests.eval.chat_eval --compare before.json after.json

Safety: no scope file is bound and no executor exists, so the agent cannot propose or run
any live action; only AVRA's read-only evidence tools run, on a COPY of ``data/`` made in a
temporary directory (offline verification reports are written there, not to ``data/``).
The provider is AVRA's own loopback-only LocalOpenAICompatibleProvider; paid providers are
refused. Each item is driven through the real ``Repl`` (scripted input), so terminal-level
handling (pastes, incomplete messages) is measured too.
"""

from __future__ import annotations

import argparse
import datetime as dt
import inspect
import json
import os
import shutil
import statistics
import sys
import tempfile
from pathlib import Path

from tests.eval.chat_eval.score import score_item

REPO = Path(__file__).resolve().parents[3]
DATASET = Path(__file__).with_name("dataset.json")


def _copy_data(dst: Path) -> None:
    for sub in ("sessions", "evidence", "verification", "investigations"):
        src = REPO / "data" / sub
        if src.is_dir():
            shutil.copytree(src, dst / sub)


def run_item(item: dict, provider, data_root: Path) -> list[dict]:
    from avra.chat.agent import ChatAgent
    from avra.chat.repl import Repl
    from avra.chat.store import Conversation

    conv = Conversation(data_root, f"eval-{item['id'].lower()}")
    agent = ChatAgent(provider, conv, checker=None, executor=None, fixtures_dir=None)
    replies: list[dict] = []
    orig = agent.ask

    def ask(text):
        r = orig(text)
        replies.append({"text": r.text, "tools": list(r.tool_calls),
                        "new_actions": [a.id for a in r.new_actions],
                        "input_tokens": r.input_tokens, "output_tokens": r.output_tokens,
                        "seconds": r.seconds, "stopped": r.stopped,
                        "model_calls": r.model_calls,
                        "intent": getattr(r, "intent", None), "user": text})
        return r

    agent.ask = ask
    # each element of turns is one typed line or one paste (list of lines)
    queue: list[list[str]] = [t if isinstance(t, list) else [t] for t in item["turns"]]
    current: list[str] = []

    def read(_prompt: str) -> str:
        nonlocal current
        if not current:
            if not queue:
                raise EOFError
            current = list(queue.pop(0))
        return current.pop(0)

    def more_input():  # rest of the same paste, if any (new Repl only)
        return current.pop(0) if current else None

    kw = {}
    if "more_input" in inspect.signature(Repl.__init__).parameters:
        kw["more_input"] = more_input
    out: list[str] = []
    Repl(agent, read=read, write=out.append, interactive=False, confirm=lambda q: False,
         data_root=data_root, status={"model": "eval", "provider": "local", "local": True,
                                      "messages": 0, "scope": None}, **kw).run()
    if replies:
        replies[-1]["terminal_tail"] = out[-6:]
    return replies


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tests.eval.chat_eval")
    ap.add_argument("--model", default=os.environ.get("AVRA_LLM_MODEL", "bonsai-2-27b-ptq1"))
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--ids", default="")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--max-tokens", type=int, default=4096)
    ap.add_argument("--extra-body", default=None)
    ap.add_argument("--label", default="")
    ap.add_argument("--out", default=None)
    ap.add_argument("--compare", nargs=2, default=None)
    a = ap.parse_args(argv)
    if a.compare:
        return compare(*a.compare)

    from avra.llm.config import LLMConfig
    from avra.llm.factory import create_provider

    cfg = LLMConfig(provider="local-openai-compatible", model=a.model, base_url=a.base_url,
                    timeout_seconds=a.timeout, max_tokens=a.max_tokens,
                    extra_body_json=a.extra_body)
    provider = create_provider(cfg)  # loopback-only; refuses any non-local provider
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    ids = {x.strip() for x in a.ids.split(",") if x.strip()}
    items = [i for i in data["items"] if not ids or i["id"] in ids]
    results = []
    with tempfile.TemporaryDirectory(prefix="avra-chat-eval-") as tmp:
        root = Path(tmp)
        _copy_data(root)
        os.environ["AVRA_DATA_DIR"] = str(root)
        for rep in range(a.repeat):
            for item in items:
                replies = run_item(item, provider, root / f"r{rep}")
                s = score_item(item, replies)
                s["repeat"], s["replies"] = rep, replies
                results.append(s)
                print(f"{item['id']:<3} {'PASS' if s['pass'] else 'FAIL'} "
                      f"in={s['input_tokens']:<6} out={s['output_tokens']:<5} "
                      f"{s['seconds']:>6.1f}s {'; '.join(s['issues'])}", flush=True)
    summary = summarize(results)
    print(json.dumps(summary, indent=1))
    out = {"format": "avra-chat-eval-results/1", "dataset": data["version"],
           "label": a.label, "model": a.model, "extra_body": a.extra_body,
           "when": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
           "summary": summary, "results": results}
    if a.out:
        Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


def summarize(results: list[dict]) -> dict:
    calls = [r for x in results for r in x["replies"]]
    ins = [r["input_tokens"] for r in calls if r["input_tokens"]]
    secs = [r["seconds"] for r in calls]
    return {"items": len(results), "passed": sum(1 for x in results if x["pass"]),
            "model_turns": len(calls),
            "input_tokens_mean": round(statistics.mean(ins)) if ins else 0,
            "input_tokens_max": max(ins, default=0),
            "output_tokens_mean": round(statistics.mean([r["output_tokens"] for r in calls]))
            if calls else 0,
            "seconds_mean": round(statistics.mean(secs), 1) if secs else 0.0,
            "seconds_median": round(statistics.median(secs), 1) if secs else 0.0,
            "provider_errors": sum(1 for r in calls if r["stopped"] == "provider_error"),
            "proposals": sum(len(r["new_actions"]) for r in calls),
            "malformed_total": sum(len(x["malformed"]) for x in results),
            "english_ratio_mean": round(statistics.mean([x["english_ratio"] for x in results]),
                                        3) if results else 0.0}


def compare(a: str, b: str) -> int:
    ra, rb = (json.loads(Path(p).read_text(encoding="utf-8")) for p in (a, b))
    keys = sorted(set(ra["summary"]) | set(rb["summary"]))
    print(f"{'metric':<22} {ra.get('label') or 'A':>12} {rb.get('label') or 'B':>12}")
    for k in keys:
        print(f"{k:<22} {ra['summary'].get(k)!s:>12} {rb['summary'].get(k)!s:>12}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
