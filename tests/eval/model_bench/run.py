"""Run the 24-card benchmark against ONE local model and write a results file.

    python -m tests.eval.model_bench --model <name> [--base-url http://127.0.0.1:8080]
        [--provider local-openai-compatible|ollama] [--repeat 3] [--cards A01,T,I]
        [--max-tokens 2048] [--timeout 600] [--out <file.json>] [--no-gpu]
        [--extra-body '{"reasoning_effort": "medium"}']
    python -m tests.eval.model_bench --compare a.json b.json

Uses AVRA's own LocalOpenAICompatibleProvider (loopback only; paid providers are
refused). Measures, per call: latency, prompt/completion tokens and end-to-end
tokens/s (completion tokens / wall time, includes prompt processing). A background
sampler polls ``nvidia-smi`` for peak GPU memory. A warm-up call (excluded from the
statistics) loads the model first; its latency is reported as ``cold_start_s``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

from avra.llm.config import LLMConfig, LLMConfigError
from avra.llm.local import LocalOpenAICompatibleProvider
from avra.llm.provider import LLMProviderError
from tests.eval.model_bench.cards import Card, Reply, build_cards, grade

FORMAT = "avra-model-bench-results/1"
REPO = Path(__file__).resolve().parents[3]


class GpuSampler:
    """Polls nvidia-smi (MiB used, GPU 0 by default) in a daemon thread."""

    def __init__(self, interval: float = 0.25, index: int = 0) -> None:
        self.exe = shutil.which("nvidia-smi")
        self.interval, self.index = interval, index
        self.samples: list[int] = []
        self.total_mib: int | None = None
        self.name = ""
        self._stop = threading.Event()
        self._t: threading.Thread | None = None

    def _query(self) -> tuple[int, int, str] | None:
        if not self.exe:
            return None
        try:
            out = subprocess.run([self.exe, f"--id={self.index}",
                                  "--query-gpu=memory.used,memory.total,name",
                                  "--format=csv,noheader,nounits"],
                                 capture_output=True, text=True, timeout=5, check=False).stdout.strip()
            used, total, name = [x.strip() for x in out.split(",", 2)]
            return int(used), int(total), name
        except (OSError, ValueError, subprocess.SubprocessError):
            return None

    def start(self) -> None:
        q = self._query()
        if q is None:
            return
        self.samples.append(q[0])
        self.total_mib, self.name = q[1], q[2]

        def loop() -> None:
            while not self._stop.wait(self.interval):
                r = self._query()
                if r:
                    self.samples.append(r[0])
        self._t = threading.Thread(target=loop, daemon=True)
        self._t.start()

    def stop(self) -> dict:
        self._stop.set()
        if self._t:
            self._t.join(timeout=5)
        if not self.samples:
            return {"available": False}
        return {"available": True, "gpu": self.name, "total_mib": self.total_mib,
                "baseline_mib": self.samples[0], "peak_mib": max(self.samples),
                "samples": len(self.samples)}


def _reply(resp) -> Reply:
    return Reply(text=resp.text, tool_calls=[(u.name, dict(u.input)) for u in resp.tool_uses],
                 stop_reason=resp.stop_reason)


def run_card(provider, card: Card) -> dict:
    t0 = time.monotonic()
    err = None
    try:
        resp = provider.complete(system=[{"type": "text", "text": card.system}],
                                 messages=card.messages, tools=card.tools)
        reply, usage = _reply(resp), resp.usage
    except LLMProviderError as exc:
        reply, usage, err = Reply(), None, str(exc)[:300]
    secs = time.monotonic() - t0
    out_tok = usage.output_tokens if usage else 0
    g = grade(card, reply)
    return {**g, "id": card.id, "category": card.category, "latency_s": round(secs, 3),
            "prompt_tokens": usage.input_tokens if usage else 0, "completion_tokens": out_tok,
            "tokens_per_s": round(out_tok / secs, 2) if out_tok and secs > 0 else None,
            "stop_reason": reply.stop_reason, "error": err,
            "reply_excerpt": (reply.text or json.dumps(reply.tool_calls))[:400],
            "reply": {"text": reply.text[:20000], "tool_calls": reply.tool_calls}}


def summarize(rows: list[dict]) -> dict:
    def rate(pred, subset=None) -> float | None:
        pool = [r for r in rows if subset is None or subset(r)]
        return round(sum(1 for r in pool if pred(r)) / len(pool), 4) if pool else None

    def has(name):
        return lambda r: name in r["checks"]

    cats = sorted({r["category"] for r in rows})
    lat = [r["latency_s"] for r in rows if not r["error"]]
    tps = [r["tokens_per_s"] for r in rows if r["tokens_per_s"]]
    return {
        "cards_run": len(rows),
        "pass_rate": rate(lambda r: r["passed"]),
        "mean_score": round(statistics.mean(r["score"] for r in rows), 4) if rows else None,
        "by_category": {c: rate(lambda r: r["passed"], lambda r, c=c: r["category"] == c) for c in cats},
        "json_valid_rate": rate(lambda r: r["checks"].get("json_valid", r["checks"].get("json_object")),
                                lambda r: has("json_valid")(r) or has("json_object")(r)),
        "hallucination_free_rate": rate(
            lambda r: r["checks"].get("no_hallucinated_targets", True)
            and r["checks"].get("no_out_of_scope_ips", True)),
        "unverified_claim_free_rate": rate(lambda r: r["checks"]["no_unverified_confirmation"],
                                           has("no_unverified_confirmation")),
        "tool_selection_rate": rate(lambda r: r["passed"] and r["checks"].get("expected_tool", True),
                                    lambda r: r["category"] == "tools"),
        "injection_resistance": rate(lambda r: r["passed"], lambda r: r["category"] == "injection"),
        "errors": sum(1 for r in rows if r["error"]),
        "latency_median_s": round(statistics.median(lat), 3) if lat else None,
        "latency_p90_s": round(sorted(lat)[max(0, int(len(lat) * 0.9) - 1)], 3) if lat else None,
        "tokens_per_s_mean": round(statistics.mean(tps), 2) if tps else None,
        "prompt_tokens_total": sum(r["prompt_tokens"] for r in rows),
        "completion_tokens_total": sum(r["completion_tokens"] for r in rows),
    }


def run(args) -> dict:
    cfg = LLMConfig(provider=args.provider, model=args.model, base_url=args.base_url,
                    max_tokens=args.max_tokens, timeout_seconds=args.timeout)
    if not cfg.is_local:
        raise LLMConfigError("the benchmark runs local providers only (no paid API)")
    raw = getattr(args, "extra_body", None)
    if raw and raw.startswith("@"):  # PowerShell 5.1 mangles quotes in JSON arguments
        raw = Path(raw[1:]).read_text(encoding="utf-8-sig")
    extra = json.loads(raw) if raw else None
    provider = LocalOpenAICompatibleProvider(cfg, extra_body=extra)
    cards = build_cards()
    if args.cards:
        sel = [s.strip() for s in args.cards.split(",") if s.strip()]
        cards = [c for c in cards if any(c.id == s or c.id.startswith(s) for s in sel)]
    gpu = GpuSampler() if not args.no_gpu else None
    if gpu:
        gpu.start()
    t0 = time.monotonic()
    try:  # warm-up: loads the model; excluded from the statistics
        provider.complete(system=[{"type": "text", "text": "Reply with {\"ok\": true}."}],
                          messages=[{"role": "user", "content": "ping"}], tools=[])
        cold = round(time.monotonic() - t0, 2)
        warm_err = None
    except LLMProviderError as exc:
        cold, warm_err = None, str(exc)[:300]
    rows = []
    for rep in range(args.repeat):
        for card in cards:
            row = run_card(provider, card)
            row["repeat"] = rep + 1
            rows.append(row)
            mark = "PASS" if row["passed"] else "FAIL " + ",".join(row["failed_critical"])
            print(f"[{rep + 1}/{args.repeat}] {card.id:4} {mark:40.40} {row['latency_s']:7.2f}s "
                  f"{row['tokens_per_s'] or 0:7.1f} tok/s", flush=True)
    gpu_info = gpu.stop() if gpu else {"available": False, "disabled": True}
    return {"format": FORMAT, "model": args.model, "provider": args.provider,
            "base_url": provider.base_url, "label": args.label or args.model,
            "started_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "host": {"platform": platform.platform(), "python": platform.python_version()},
            "settings": {"repeat": args.repeat, "max_tokens": args.max_tokens,
                         "timeout_s": args.timeout, "temperature": 0.1,
                         "extra_body": provider.extra_body,
                         "cards": [c.id for c in cards]},
            "cold_start_s": cold, "warmup_error": warm_err, "gpu": gpu_info,
            "summary": summarize(rows), "results": rows}


def render(res: dict) -> str:
    s, g = res["summary"], res["gpu"]
    lines = [f"## {res['label']} ({res['model']} via {res['provider']})", "",
             f"- Pass rate: **{s['pass_rate']:.0%}** of {s['cards_run']} card runs; mean score {s['mean_score']:.2f}",
             "- By category: " + ", ".join(f"{k} {v:.0%}" for k, v in s["by_category"].items()),
             (f"- JSON valid {s['json_valid_rate']:.0%} | hallucination-free "
              f"{s['hallucination_free_rate']:.0%} | no unverified claims "
              f"{s['unverified_claim_free_rate']:.0%} | tool selection {s['tool_selection_rate']:.0%}"
              f" | injection resistance {s['injection_resistance']:.0%} | errors {s['errors']}"),
             (f"- Latency median {s['latency_median_s']}s, p90 {s['latency_p90_s']}s, "
              f"{s['tokens_per_s_mean']} tok/s (end-to-end), cold start {res['cold_start_s']}s"),
             (f"- GPU {g['gpu']}: peak {g['peak_mib']} MiB of {g['total_mib']} "
              f"(baseline {g['baseline_mib']})" if g.get("available") else "- GPU: not measured")]
    return "\n".join(lines)


def compare(paths: list[str]) -> str:
    rs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in paths]
    keys = ["pass_rate", "mean_score", "json_valid_rate", "hallucination_free_rate",
            "unverified_claim_free_rate", "tool_selection_rate", "injection_resistance", "errors",
            "latency_median_s", "latency_p90_s", "tokens_per_s_mean", "completion_tokens_total"]
    head = "| Metric | " + " | ".join(r["label"] for r in rs) + " |"
    out = [head, "|---" * (len(rs) + 1) + "|"]
    out += [f"| {k} | " + " | ".join(str(r["summary"].get(k)) for r in rs) + " |" for k in keys]
    out.append("| peak_gpu_mib | " + " | ".join(str(r["gpu"].get("peak_mib")) for r in rs) + " |")
    out.append("| cold_start_s | " + " | ".join(str(r["cold_start_s"]) for r in rs) + " |")
    out += ["", "| Card | " + " | ".join(r["label"] for r in rs) + " |", "|---" * (len(rs) + 1) + "|"]
    ids = list(dict.fromkeys(row["id"] for r in rs for row in r["results"]))
    for cid in ids:
        cells = []
        for r in rs:
            runs = [x for x in r["results"] if x["id"] == cid]
            cells.append(f"{sum(x['passed'] for x in runs)}/{len(runs)}" if runs else "-")
        out.append(f"| {cid} | " + " | ".join(cells) + " |")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tests.eval.model_bench")
    p.add_argument("--model")
    p.add_argument("--provider", default="local-openai-compatible",
                   choices=["local-openai-compatible", "ollama"])
    p.add_argument("--base-url", default=None)
    p.add_argument("--label", default=None)
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--cards", default="", help="Comma list of ids or prefixes (A,E,T,I or A01,...).")
    p.add_argument("--max-tokens", type=int, default=2048)
    p.add_argument("--timeout", type=float, default=600)
    p.add_argument("--out", default=None)
    p.add_argument("--no-gpu", action="store_true")
    p.add_argument("--extra-body", default=None,
                   help=('JSON merged into each request, e.g. {"reasoning_effort": "medium"} '
                         'or {"chat_template_kwargs": {"enable_thinking": false}}; or @file.json'))
    p.add_argument("--compare", nargs="+")
    a = p.parse_args(argv)
    if a.compare:
        print(compare(a.compare))
        return 0
    if not a.model or not 1 <= a.repeat <= 10:
        p.error("--model is required and --repeat must be 1-10")
    try:
        res = run(a)
    except (LLMConfigError, ValueError) as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 1
    out = Path(a.out) if a.out else (REPO / "data" / "eval" / "model-bench" /
                                     f"{a.model.replace('/', '_').replace(':', '_')}-"
                                     f"{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    print("\n" + render(res) + f"\n\nResults: {out}")
    return 0 if os.environ.get("AVRA_BENCH_STRICT") != "1" or res["summary"]["pass_rate"] == 1 else 2


if __name__ == "__main__":
    raise SystemExit(main())
