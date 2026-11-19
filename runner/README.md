# AVRA Tool Runner

Small typed HTTP service that runs on the Kali VM and executes validated,
allowlisted security tools on behalf of the Orchestrator. Never accepts
raw shell input from the model.

In progress (Phase 2). Code lives in `src/avra/runner/`; this folder
will hold deployment notes for the Kali VM. Design, decisions and
milestone status: `docs/decisions/0003-tool-runner-design.md`.
