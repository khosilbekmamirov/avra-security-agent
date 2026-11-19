# Talking with AVRA (`avra chat`)

This guide covers starting the local model and having a conversation with AVRA about your
investigations. See ADR 0019 for the design.

## 1. Start the local model (Bonsai 2 27B)

In PowerShell:

```
E:\Tools\llama-prism\bin\llama-server.exe -m E:\Models\Ternary-Bonsai-2-27B-PTQ1_0.gguf `
  --alias bonsai-2-27b-ptq1 --host 127.0.0.1 --port 8080 -ngl 99 -fa on -c 16384 `
  -ctk q8_0 -ctv q8_0 -np 1 --jinja
```

**Keep `-np 1`.** `-c` is the TOTAL context, split across parallel slots. Without `-np 1`
llama.cpp may start 4 slots, so `-c 16384` gives each request only **4096** tokens - that was
the cause of the `exceeds the available context size (4096 tokens)` errors (M14.5). Check with
`curl http://127.0.0.1:8080/props`: `total_slots` should be `1` and
`default_generation_settings.n_ctx` the full window. AVRA reads that value itself and fits
every request into it (see 2b).

- Wait for `http://127.0.0.1:8080/health` to answer `ok` (about 10 s).
- It uses about 6.4 GB of the 8 GB GPU.
- Stop it with `taskkill /IM llama-server.exe /F`.
- It listens on loopback only.

Then, in the AVRA folder:

```
$env:AVRA_LLM_EXTRA_BODY = "@tests\eval\model_bench\profiles\bonsai-reasoning-medium.json"
```

This sets reasoning effort to medium.

## 2. Chat

```
avra chat juice-shop --provider local-openai-compatible --model bonsai-2-27b-ptq1 --base-url http://127.0.0.1:8080
```

- `juice-shop` is the conversation name. Use the same name later to resume it; `--new`
  refuses to resume an existing one.
- Add `--scope scope\<file>.scope.yaml` only if you want AVRA to be able to *propose* live
  actions. Without a scope the chat is read-only.
- English, Uzbek and Russian all work. AVRA replies in the language you write in. The
  model's Uzbek is understandable but not always fluent.

Things to ask:
- "What can you do?"
- "Summarize the last Juice Shop investigation."
- "Why is CORS flagged?"
- "Explain this in simpler language."
- "What should we investigate next?"
- "What happened in the last research run?"
- "Show the IDOR validation fixture."

Commands (typed at `you>`):

| Command | What it does |
|---|---|
| `/help` | list commands |
| `/status` | model, conversation, scope, context window/limits, file paths |
| `/history 20` | last 20 messages |
| `/list` | saved conversations |
| `/pending` | live actions AVRA proposed in this run |
| `/summary [id]` | concise, evidence-grounded digest of an investigation — no model call, Uzbek output |
| `/details [id]` | the full recorded evidence and engine verdicts — no model call |
| `/approve A1` | run ONE proposed action, once (asks y/N again and shows the exact request) |
| `/deny A1` | decline it |

**Natural approval (M13).** After AVRA proposes exactly one in-scope action, it asks in your
language and you may answer `ha` / `yes` (approve) or `yo'q` / `no` (decline) on the very next
line — a one-shot, owner-facing approval context. This is interpreted deterministically by the
local CLI, never by the model. It still shows the exact action and asks the terminal `y/N`
confirmation, runs once, and rechecks scope, expiry, kill switch and session first — identical
to `/approve`. Any other reply is treated as ordinary chat and approves nothing; if several
actions are pending, bare `ha` is refused and you must use `/approve <id>`. `/approve` and
`/deny` keep working unchanged.
| `/scope` | the authorized target(s) and the exact tools/ports/paths the bound scope permits |
| `/runner` | authenticated, read-only Runner health check — the **only** chat command that contacts Kali; shows the tools the Kali Runner registers and the overlap with your Windows scope (real terminal only) |
| `/exit` | leave (Ctrl+C at the prompt also leaves; Ctrl+C during an answer cancels only that answer) |

The banner and `/status` now also print the bound scope's authorized target(s) and permitted
operations, so you always see what a `/approve` could run before proposing anything.

`/runner` is for confirming the live picture on demand: the Windows scope is checked when an
action is proposed and again at `/approve`, and the Kali Runner independently re-checks its own
scope when it runs; `/runner` lets you see both sides and their intersection without running any
tool. A failed check prints a short, actionable message (tunnel down, Runner not running, or a
token mismatch) and never shows the token.

## 2b. Context, intent and pastes (M14.5)

- **Context budget.** AVRA asks the llama.cpp server for its per-request window, reserves a
  third of it (at most `max_tokens`) for the answer, counts the prompt exactly with the
  server's own tokenizer, and shortens old history and then tool results until the request
  fits. Shortened tool results keep every id, hash, target, port and verdict and say
  "full record: /details <id>". Nothing stored is changed. If your own message alone is too
  long, AVRA says so and sends nothing. Override the window with `--context-tokens 8192`
  (or `$env:AVRA_LLM_CONTEXT_TOKENS`). `/status` shows the window and limits in use.
- **Recommended:** `-c 16384 -np 1` (or at least 8192 per slot). 4096 works for greetings
  and summaries but leaves little room for evidence.
- **What AVRA may propose depends on what you asked.** Greetings get no tools; questions,
  explanations, summaries and plans get only read-only evidence tools. A live action is
  offered to the model only when you explicitly ask for one, e.g. "Yangi nmap tekshiruvini
  taklif qil" / "Propose an nmap scan of port 3000". "No live scans", "skanerlama",
  "faqat mavjud dalillar" always prevent a proposal. "Ha, lekin bajarma" approves nothing.
  `/approve <id>` + `y/N` are unchanged.
- **Capabilities.** "Nima qila olasan?" is answered from a dated status table that keeps
  *implemented*, *offline-tested*, *live-validated* and *not tested* apart, plus what this
  chat can do right now (scope bound? Runner checked with `/runner` in this run?).
- **Pasting several lines** sends them as ONE message. You can also type `"""`, then the
  lines, then `"""`. A short message ending in `:` (e.g. "Vazifalar:") waits for the rest;
  press Enter on an empty line to send it as it is. Lines copied from AVRA's own output
  (`YOU ❯`, `AVRA ●`, `SYSTEM ·`, `Model error:`) are not sent to the model.
- **Troubleshooting.** `Not sent: the request needs about N prompt tokens...` -> shorten the
  message, use `/summary` / `/details`, or start a new conversation name. `Model error: the
  request (N tokens) does not fit...` after one automatic smaller retry -> the server window
  is smaller than AVRA was told: check `/props` and `-np`. `(no answer: the model used its
  whole output budget...)` -> the model reasoned too long; ask more briefly or use
  `reasoning_effort` medium (see 1).

## 2a. Appearance (M13.1)

The chat uses restrained colour to tell roles apart: **you** cyan, **AVRA** green, **system**
lines gray, **approvals and warnings** yellow, **errors** red. Verdicts keep the engine's
meaning (INCONCLUSIVE yellow, CONFIRMED/verified green). Colour is presentation only — it
never changes a verdict, scope decision or approval. Common Markdown from the model
(`**bold**`, `` `code` ``, `- bullets`, `# headings`) is rendered readably.

Colour is used only on a real terminal. It is disabled automatically when output is piped or
redirected, when `TERM=dumb`, and whenever `NO_COLOR` is set (any value); then everything is
plain text. Model and tool text is sanitised before display, so it cannot inject terminal
escape sequences. On Windows, run in a UTF-8 console (PowerShell/Windows Terminal) for correct
Uzbek Latin text; the glyphs fall back to ASCII if the console encoding is not UTF-8.

## 3. What is and is not allowed

- AVRA answers from its own records. Verdicts come only from the Verification Engine.
- "Configuration weakness" means a hardening gap, not a proven exploitable vulnerability.
- Writing "yes, go ahead" approves **nothing**. Only `/approve <id>` in a real terminal
  runs a single action, and only if all of these hold:
  - the bound scope allows it (checked at proposal time and again at `/approve`);
  - the kill switch is disengaged;
  - the Runner is running. The Runner also checks its own scope.
- If the action cannot complete (Runner down, tunnel not up, token mismatch, kill switch on),
  AVRA reports a short, actionable message telling you what to check — it never leaks the token
  and never silently retries.
- Proposed actions expire when you leave the chat; a resumed chat can never run an old
  proposal.
- Read-only lookups and offline verification run immediately; they touch no target.

## 4. Where things are stored

- `data/chat/<name>.jsonl` — the conversation. Obvious secrets (API keys, tokens,
  passwords) are redacted before writing.
- `data/chat/<name>.audit.jsonl` — the hash-chained audit log: model calls with token
  usage and latency, tools used, and proposed, approved or declined actions.
- `avra chat <name> --show` prints a conversation; `avra chat --list` lists them.

## 5. Speed (measured 2026-11-13, RTX 4060 8 GB, 16K context)

- Median 22.7 s per answer (8.8–52.1 s).
- 1–3 model calls per answer.
- Peak VRAM 6405 MiB.
- Answers that need several evidence lookups take longest.
