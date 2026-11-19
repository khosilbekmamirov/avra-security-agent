#!/usr/bin/env bash
if grep -q $'\r' "$0"; then echo "install.sh: CRLF line endings — refusing to run" >&2; exit 1; fi #
# AVRA Tool Runner installer (ADR 0003, M4.3). Run manually by the owner,
# from a root-owned bundle directory built by make_bundle.py:
#
#   sudo bash /root/avra-deploy/install.sh
#
# Input integrity: the bundle directory must be root-owned and not
# group/other-writable; every input must be a root-owned regular file
# listed in SHA256SUMS, and all checksums must match. The owner confirms
# the SHA-256 of SHA256SUMS against the value printed on Windows.
#
# Creates: system user avra-runner; /opt/avra-runner (code, root-owned);
# /etc/avra-runner (config); /var/lib/avra-runner/audit with an empty,
# append-only (chattr +a) audit log; the systemd unit (not enabled).
# Does NOT: create the token, enable/start the service, touch SSH.
#
# Fail-closed and transactional: refuses if anything it would create
# already exists; resources are created atomically (mkdir without -p,
# useradd, noclobber writes — each fails if the target exists) and an undo
# step is registered only AFTER its creation succeeded, so rollback can
# never delete something this run didn't create. A crash between the two
# leaves a resource behind (the safe direction) rather than deleting one.
set -Eeuo pipefail
umask 077
PROG=install.sh

die() { echo "$PROG: $*" >&2; exit 1; }

# --- rollback (begin) — keep identical in install.sh / install-tunnel.sh ---
# Runs on ANY non-zero exit (set -e error, die, Ctrl+C/TERM); undoes in
# reverse order. Undo steps are named functions — no eval.
UNDO=()
on_undo() {
  declare -F "$1" >/dev/null || { echo "$PROG: unknown undo step $1" >&2; exit 70; }
  UNDO+=("$1")
}
rollback() {
  local rc=$? i
  trap '' INT TERM  # don't let a second Ctrl+C interrupt the rollback
  [ "$rc" -eq 0 ] && return 0
  if [ "${#UNDO[@]}" -gt 0 ]; then
    echo "$PROG: failed (exit $rc) — rolling back changes made by this run" >&2
    for (( i=${#UNDO[@]}-1; i>=0; i-- )); do
      "${UNDO[i]}" || echo "  rollback step failed: ${UNDO[i]}" >&2
    done
  fi
  exit "$rc"
}
trap rollback EXIT
trap 'exit 130' INT TERM
# --- rollback (end) ---

[ "$(id -u)" -eq 0 ] || die "must be run as root (sudo)"
[ "$(uname -s)" = "Linux" ] || die "Linux only"
[ "$#" -eq 0 ] || die "takes no arguments; run it from the verified bundle directory"

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
UNIT=avra-runner.service
ENVF=runner.env.example
REQS=requirements-runner.txt
SCOPE=scope.yaml
AUDIT=/var/lib/avra-runner/audit/runner-audit.jsonl

# --- input integrity ------------------------------------------------------
shopt -s nullglob
WHEELS=("$HERE"/avra-*.whl)
shopt -u nullglob
[ "${#WHEELS[@]}" -eq 1 ] || die "bundle must contain exactly one avra-*.whl"
WHEEL=$(basename "${WHEELS[0]}")

[ "$(stat -c %u "$HERE")" -eq 0 ] || die "bundle directory must be owned by root"
(( (8#$(stat -c %a "$HERE") & 8#022) == 0 )) || die "bundle directory is group/other-writable"
for f in SHA256SUMS install.sh "$UNIT" "$ENVF" "$REQS" "$SCOPE" "$WHEEL"; do
  p="$HERE/$f"
  [ -f "$p" ] && [ ! -L "$p" ] || die "missing or not a regular file: $f"
  [ "$(stat -c %u "$p")" -eq 0 ] || die "$f is not owned by root"
  (( (8#$(stat -c %a "$p") & 8#022) == 0 )) || die "$f is group/other-writable"
  [ "$f" = SHA256SUMS ] && continue
  awk -v f="$f" '$2 == f { found = 1 } END { exit !found }' "$HERE/SHA256SUMS" \
    || die "$f is not listed in SHA256SUMS"
done
for f in SHA256SUMS install.sh "$UNIT" "$ENVF" "$REQS" "$SCOPE"; do
  if grep -q $'\r' "$HERE/$f"; then die "$f has CRLF line endings"; fi
done
# Defense in depth only: this catches corruption and mixed-up bundles. It
# cannot vouch for this script itself — the trust anchor is the owner's
# manual check with the system sha256sum BEFORE running it (README step 2).
(cd "$HERE" && sha256sum --strict --quiet -c SHA256SUMS) || die "checksum mismatch — bundle altered"
echo "All bundle checksums match."
echo "SHA-256 of SHA256SUMS: $(sha256sum "$HERE/SHA256SUMS" | cut -d' ' -f1)"
[ -r /dev/tty ] || die "no terminal for confirmation"
read -r -p "Same value you verified manually against Windows? Type YES to continue: " ANSWER < /dev/tty
[ "$ANSWER" = "YES" ] || die "not confirmed"

# --- preconditions (nothing changed yet) ----------------------------------
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
  || die "python3 >= 3.12 required"
python3 -c 'import venv, ensurepip' 2>/dev/null || die "python3 venv/ensurepip missing"
[ -x /usr/lib/nmap/nmap ] || die "/usr/lib/nmap/nmap not found"
command -v systemctl >/dev/null || die "systemd required"
command -v chattr >/dev/null && command -v lsattr >/dev/null || die "chattr/lsattr required"
getent passwd avra-runner >/dev/null && die "user avra-runner already exists — refusing"
getent group avra-runner >/dev/null && die "group avra-runner already exists — refusing"
for p in /opt/avra-runner /etc/avra-runner /var/lib/avra-runner \
         /etc/systemd/system/avra-runner.service; do
  [ -e "$p" ] && die "$p already exists — refusing to overwrite (see README: upgrade/uninstall)"
done

# Undo steps: only ever called for resources this run created.
undo_user()   { userdel avra-runner; }
undo_opt()    { rm -rf -- /opt/avra-runner; }
undo_etc()    { rm -rf -- /etc/avra-runner; }
undo_varlib() {
  if [ -e "$AUDIT" ]; then chattr -a -- "$AUDIT"; fi
  rm -rf -- /var/lib/avra-runner
}
undo_unit()   { rm -f -- /etc/systemd/system/avra-runner.service; systemctl daemon-reload; }

# Each creation below fails if the target already exists; its undo step is
# registered only after it succeeded.
echo "[1/7] creating system user avra-runner"
useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin avra-runner
on_undo undo_user
passwd --lock avra-runner >/dev/null

echo "[2/7] creating directories"
mkdir -m 0755 /opt/avra-runner
on_undo undo_opt
chown root:root /opt/avra-runner
mkdir -m 0750 /etc/avra-runner
on_undo undo_etc
chown root:avra-runner /etc/avra-runner
mkdir -m 0700 /var/lib/avra-runner
on_undo undo_varlib
chown avra-runner:avra-runner /var/lib/avra-runner
install -d -o avra-runner -g avra-runner -m 0700 /var/lib/avra-runner/audit

echo "[3/7] creating venv and installing hash-verified dependencies"
python3 -m venv /opt/avra-runner/venv
PIP=(env PYTHONNOUSERSITE=1 /opt/avra-runner/venv/bin/python -m pip
     --isolated --no-input --disable-pip-version-check install --no-cache-dir)
"${PIP[@]}" --index-url https://pypi.org/simple --require-hashes --only-binary=:all: \
  -r "$HERE/$REQS"
"${PIP[@]}" --no-deps --no-index "$HERE/$WHEEL"
chown -R root:root /opt/avra-runner
chmod -R go-w,a+rX /opt/avra-runner
/opt/avra-runner/venv/bin/python -I -c 'import avra.runner.server' \
  || die "installed package does not import"

echo "[4/7] checking scope against the unit's IP allowlist"
ALLOW=$(sed -n 's/^IPAddressAllow=//p' "$HERE/$UNIT")
/opt/avra-runner/venv/bin/python -I - "$HERE/$SCOPE" "$ALLOW" <<'PY'
import sys
from avra.policy.scope import ScopeError, load_scope
try:
    scope = load_scope(sys.argv[1])
except ScopeError as exc:
    sys.exit(f"scope invalid: {exc}")
allowed = set(sys.argv[2].split())
missing = sorted({t.host for t in scope.targets} - allowed)
if missing:
    sys.exit(f"scope targets not in the unit's IPAddressAllow: {missing}")
PY

echo "[5/7] installing scope and runner.env (root-owned, runner can read only)"
install -o root -g avra-runner -m 0640 "$HERE/$SCOPE" /etc/avra-runner/scope.yaml
install -o root -g avra-runner -m 0640 "$HERE/$ENVF" /etc/avra-runner/runner.env

echo "[6/7] creating append-only audit log"
install -o avra-runner -g avra-runner -m 0600 /dev/null "$AUDIT"
chattr +a "$AUDIT"
lsattr "$AUDIT" | cut -d' ' -f1 | grep -q a || die "append-only attribute not set (filesystem support?)"

echo "[7/7] installing systemd unit (not enabled, not started)"
( set -C; cat -- "$HERE/$UNIT" > /etc/systemd/system/avra-runner.service )  # noclobber: fails if present
on_undo undo_unit
chown root:root /etc/systemd/system/avra-runner.service
chmod 0644 /etc/systemd/system/avra-runner.service
systemctl daemon-reload

UNDO=()  # success: nothing to roll back
echo "Installed. Nothing is running. Next (see README): place the token, then --check."
