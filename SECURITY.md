# Security policy

## Intended use

AVRA is a research project for **authorized, isolated lab environments only**. It was built
and tested against OWASP Juice Shop on a VirtualBox host-only network. Do not use it against
systems you do not own or have no written permission to test.

## Built-in safeguards

- **Default-deny scope.** Nothing runs unless a scope file explicitly allows the exact host,
  port, tool, action tier and (for HTTP paths) path prefix, before its expiry time. The
  Windows client and the Kali Runner each check their own scope; an action needs both.
- **Human approval.** The model can only propose. A live action needs `/approve <id>` in a
  real terminal plus a second `y/N` confirmation, for one action, once.
- **No shell for the model.** Requests are strict typed models; the Runner executes fixed
  argument lists. Destructive actions are not implemented.
- **Restricted transport.** The Runner listens on loopback and requires a bearer token; it is
  reached only through an SSH tunnel account that can forward to that one port and nothing
  else.
- **Tamper-evident records.** Audit logs are hash-chained (optionally HMAC-anchored);
  evidence files are SHA-256 hashed and tied to request ids.
- **Kill switch.** `avra kill` engages a persistent local latch, then asks the Runner to
  engage its own emergency stop. Ctrl+C cancels the exact running Runner job.

## Secrets

No credentials are stored in this repository. `.env.example` and
`runner/deploy/runner.env.example` contain placeholders only; real `.env` files, Runner
tokens, SSH keys, scope files for a real lab, audit logs and evidence directories are
excluded by `.gitignore`. Test files contain only obviously fake values used to check that
AVRA redacts secrets.

## Reporting a problem

If you find a security issue in this code, please open a GitHub issue **without** exploit
details, or contact the author through the GitHub profile, and allow time for a fix before
public disclosure.
