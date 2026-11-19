# Testing

## Latest offline run

| | |
|---|---|
| Commit tested | `56c83fd` (this repository's first commit; same code as private development commit `6fdc34e`) |
| Date | 2026-11-19 |
| Platform | Windows 11 Pro, Python 3.12.13, pytest |
| Result | **2090 passed, 42 skipped, 0 failed** (about 2 min 50 s) |
| Skipped | 42 POSIX/systemd-only Runner tests (they run on Linux; they were run on the Kali VM during development) |
| Lint | `ruff check src tests runner`: 30 findings, all pre-existing and reviewed (mostly intentional broad `except` blocks in Runner cleanup paths and test helpers); no new findings in recent milestones |

Command:

```powershell
python -m pytest -q
```

No test contacts a network target, the Kali Runner or a model API. Model behaviour is
tested with scripted fake providers; the Runner HTTP service is tested in-process; the local
model client is tested against a loopback fake server.

## What the suites cover

| Folder | Focus |
|---|---|
| `tests/security/` | default-deny scope, Runner input validation and authentication, execution limits, cancellation and emergency stop, deployment files (LF line endings, restricted SSH tunnel config), audit concurrency |
| `tests/unit/` | CLI, audit logs and anchors, kill switch, research loop, local model provider, chat agent (approvals, prompt-injection handling, context budget, intent gate), investigation state machine |
| `tests/verification/` | Verification Engine rules, evidence integrity, research controller, adversarial cases (injection, timeouts, loop limits, tampered logs) |
| `tests/eval/` | offline evaluation harnesses for local models (run manually against a loopback model; their unit tests use fakes) |

## Live validation (lab, owner-approved)

Recorded in the private development log and audit files, not in this repository:

- nmap TCP connect scans of the lab target through the Kali Runner
- HTTP probe (`GET /`) of the lab Juice Shop instance
- Runner cancel API and bounded scan/probe after the M8.7 deployment
- `avra chat` with a local 27B model (llama.cpp), including one approved nmap scan

Not yet run live: `http_get_path`, `avra investigate`, the Runner's operational emergency
stop, cancelling an actively running job.
