# Scope files

Example / template scope files only — never a real target. Each actual
session's scope file stays local (see `.gitignore`) and is passed on the
command line with `--scope <path>` (e.g. `avra research --scope
scope\juice-shop.runner.scope.yaml ...`, `avra scan nmap-connect --scope ...`).
See `scope/example.scope.yaml` and
`docs/architecture.md` §8.
