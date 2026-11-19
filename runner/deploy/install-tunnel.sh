#!/usr/bin/env bash
if grep -q $'\r' "$0"; then echo "install-tunnel.sh: CRLF line endings — refusing to run" >&2; exit 1; fi #
# AVRA SSH tunnel account (ADR 0003, M4.4 — separate approval: changes SSH
# configuration). Run manually by the owner from the root-owned, verified
# bundle directory (make_bundle.py, including avra_runtime_ed25519.pub):
#
#   sudo bash /root/avra-deploy-tunnel/install-tunnel.sh
#
# Creates `avra-tunnel` (no password, no shell, root-owned empty home)
# whose only ability is one local port forward to 127.0.0.1:8765, only
# from the Windows host's host-only address. authorized_keys is root-owned.
#
# Before sshd is reloaded (reload, never restart — open sessions survive):
#   1. `sshd -t` must pass with the new drop-in;
#   2. the effective settings for avra-tunnel (`sshd -T -C …`) must contain
#      every required restriction;
#   3. the effective configuration of every OTHER login-capable user, and
#      the global configuration, must be byte-identical to a snapshot taken
#      before the drop-in was added (proves nothing leaked to e.g. `kali`).
# Any failure rolls back exactly what this run created; nothing
# pre-existing is touched. After a failed run nothing is left behind, so it
# can simply be rerun; after a successful run it refuses to run again
# (uninstall first — README).
set -Eeuo pipefail
umask 022
PROG=install-tunnel.sh

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
DROPIN_NAME=sshd-avra-tunnel.conf
PUBKEY_NAME=avra_runtime_ed25519.pub
DROPIN_DIR=/etc/ssh/sshd_config.d
DROPIN=$DROPIN_DIR/10-avra-tunnel.conf
OLD_DROPIN=$DROPIN_DIR/avra-tunnel.conf  # name used by earlier drafts
HOME_DIR=/var/lib/avra-tunnel
AUTH_KEYS=$HOME_DIR/.ssh/authorized_keys
WINDOWS_HOST=192.168.56.1
RUNNER_ADDR=127.0.0.1:8765
SSH_UNIT=ssh
# Second, non-lab source address for the effective-config checks (TEST-NET-3).
OTHER_ADDR=203.0.113.10

# --- input integrity ------------------------------------------------------
[ "$(stat -c %u "$HERE")" -eq 0 ] || die "bundle directory must be owned by root"
(( (8#$(stat -c %a "$HERE") & 8#022) == 0 )) || die "bundle directory is group/other-writable"
for f in SHA256SUMS install-tunnel.sh "$DROPIN_NAME" "$PUBKEY_NAME"; do
  p="$HERE/$f"
  [ -f "$p" ] && [ ! -L "$p" ] || die "missing or not a regular file: $f"
  [ "$(stat -c %u "$p")" -eq 0 ] || die "$f is not owned by root"
  (( (8#$(stat -c %a "$p") & 8#022) == 0 )) || die "$f is group/other-writable"
  if grep -q $'\r' "$p"; then die "$f has CRLF line endings"; fi
  [ "$f" = SHA256SUMS ] && continue
  awk -v f="$f" '$2 == f { found = 1 } END { exit !found }' "$HERE/SHA256SUMS" \
    || die "$f is not listed in SHA256SUMS"
done
# Defense in depth only (see install.sh): the trust anchor is the owner's
# manual system-sha256sum check before running this script (README step 2).
(cd "$HERE" && sha256sum --strict --quiet -c SHA256SUMS) || die "checksum mismatch — bundle altered"
echo "SHA-256 of SHA256SUMS: $(sha256sum "$HERE/SHA256SUMS" | cut -d' ' -f1)"
[ -r /dev/tty ] || die "no terminal for confirmation"
read -r -p "Same value you verified manually against Windows? Type YES to continue: " ANSWER < /dev/tty
[ "$ANSWER" = "YES" ] || die "not confirmed"

# --- key and drop-in validation -------------------------------------------
[ "$(grep -c . "$HERE/$PUBKEY_NAME")" -eq 1 ] || die "public key file must contain exactly one line"
if grep -q 'PRIVATE KEY' "$HERE/$PUBKEY_NAME"; then die "that is a private key — refusing"; fi
read -r KEYTYPE KEYDATA _ < "$HERE/$PUBKEY_NAME"
[ "$KEYTYPE" = "ssh-ed25519" ] || die "only ssh-ed25519 keys are accepted"
[[ "$KEYDATA" =~ ^[A-Za-z0-9+/=]+$ ]] || die "malformed key data"
ssh-keygen -l -f "$HERE/$PUBKEY_NAME" >/dev/null || die "ssh-keygen rejects the public key"
# The drop-in must be a single Match block for avra-tunnel and nothing else:
# its first directive is that Match line and no other Match line exists.
FIRST=$(grep -vE '^[[:space:]]*(#|$)' "$HERE/$DROPIN_NAME" | head -n 1)
[ "$FIRST" = "Match User avra-tunnel" ] || die "drop-in must start with 'Match User avra-tunnel'"
[ "$(grep -cE '^[[:space:]]*Match[[:space:]]' "$HERE/$DROPIN_NAME")" -eq 1 ] \
  || die "drop-in must contain exactly one Match block"

# --- preconditions (nothing changed yet) ----------------------------------
command -v sshd >/dev/null || die "sshd not found"
command -v diff >/dev/null || die "diff not found"
systemctl is-active --quiet "$SSH_UNIT" || die "$SSH_UNIT.service is not active — refusing"
grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config \
  || die "sshd_config does not include sshd_config.d — refusing"
sshd -t || die "current sshd configuration is already invalid — refusing"
getent passwd avra-tunnel >/dev/null && die "user avra-tunnel already exists — refusing"
getent group avra-tunnel >/dev/null && die "group avra-tunnel already exists — refusing"
[ -e "$HOME_DIR" ] && die "$HOME_DIR already exists — refusing"
[ -e "$DROPIN" ] && die "$DROPIN already exists — refusing"
[ -e "$OLD_DROPIN" ] && die "$OLD_DROPIN already exists — refusing"
if grep -RlsE 'avra-tunnel' /etc/ssh/sshd_config "$DROPIN_DIR" >/dev/null; then
  die "sshd configuration already mentions avra-tunnel — refusing (clean up first)"
fi

# Every login-capable account except avra-tunnel (it doesn't exist yet and
# has a nologin shell anyway); root is always included.
mapfile -t CHECK_USERS < <(getent passwd \
  | awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ && $7 != "" { print $1 }' \
  | grep -vx 'avra-tunnel' | sort -u)
HAVE_ROOT=no
for u in "${CHECK_USERS[@]}"; do
  if [ "$u" = root ]; then HAVE_ROOT=yes; fi
done
[ "$HAVE_ROOT" = yes ] || CHECK_USERS+=(root)

# Effective configuration: global, then each user from the lab host and from
# an unrelated address. Any difference after adding the drop-in = leak.
snapshot() {
  local u a
  echo "### global"
  sshd -T || return 1
  for u in "${CHECK_USERS[@]}"; do
    for a in "$WINDOWS_HOST" "$OTHER_ADDR"; do
      echo "### user=$u addr=$a"
      sshd -T -C "user=$u,host=avra-check,addr=$a" || return 1
    done
  done
}
BEFORE=$(snapshot) || die "could not read the effective sshd configuration"
echo "Baseline taken for: global + ${CHECK_USERS[*]}"

# --- effective-settings check (begin) ---
# Every line here must appear in `sshd -T -C user=avra-tunnel,…`.
REQUIRED_SETTINGS=(
  "authenticationmethods publickey"
  "pubkeyauthentication yes"
  "passwordauthentication no"
  "kbdinteractiveauthentication no"
  "authorizedkeysfile $AUTH_KEYS"
  "allowtcpforwarding local"
  "permitopen $RUNNER_ADDR"
  "permitlisten none"
  "gatewayports no"
  "allowstreamlocalforwarding no"
  "allowagentforwarding no"
  "x11forwarding no"
  "permittty no"
  "permittunnel no"
  "permituserrc no"
  "forcecommand /usr/sbin/nologin"
)
# Older OpenSSH releases print `sshd -T` keywords in lower case; OpenSSH
# 10.5 on Kali prints them in canonical case ("AuthenticationMethods
# publickey") — M4.4 stage 4 failed on exactly that. Keywords
# are case-insensitive in sshd_config, values are not: lower-case only the
# first field, then require each line verbatim (fixed string, whole line).
keywords_lower() { awk '{ $1 = tolower($1); print }'; }
# Prints the first missing setting and returns 1; returns 0 if all present.
check_effective() {
  local normalized want
  normalized=$(keywords_lower <<<"$1") || return 1
  for want in "${REQUIRED_SETTINGS[@]}"; do
    if ! grep -qxF -- "$want" <<<"$normalized"; then
      printf '%s\n' "$want"
      return 1
    fi
  done
}
# --- effective-settings check (end) ---

# Undo steps: only ever called for resources this run created.
undo_user()   { userdel avra-tunnel; }
undo_home()   { rm -rf -- "$HOME_DIR"; }
undo_dropin() {
  rm -f -- "$DROPIN"
  # Back to the original config. Harmless if sshd was never reloaded.
  if sshd -t; then systemctl reload "$SSH_UNIT"; fi
}

# Each creation below fails if the target already exists; its undo step is
# registered only after it succeeded.
echo "[1/5] creating user avra-tunnel (no password, no shell, root-owned empty home)"
useradd --system --user-group --no-create-home --home-dir "$HOME_DIR" \
        --shell /usr/sbin/nologin avra-tunnel
on_undo undo_user
passwd --lock avra-tunnel >/dev/null
mkdir -m 0755 "$HOME_DIR"
on_undo undo_home
chown root:root "$HOME_DIR"
install -d -o root -g root -m 0755 "$HOME_DIR/.ssh"

echo "[2/5] installing restricted authorized_keys (root-owned)"
OPTS="restrict,port-forwarding,permitopen=\"$RUNNER_ADDR\",from=\"$WINDOWS_HOST\",command=\"/usr/sbin/nologin\""
printf '%s %s %s avra-runtime\n' "$OPTS" "$KEYTYPE" "$KEYDATA" > "$AUTH_KEYS"
chown root:root "$AUTH_KEYS"
chmod 0644 "$AUTH_KEYS"

echo "[3/5] installing sshd drop-in $DROPIN and validating syntax"
( set -C; cat -- "$HERE/$DROPIN_NAME" > "$DROPIN" )  # noclobber: fails if present
on_undo undo_dropin
chown root:root "$DROPIN"
chmod 0644 "$DROPIN"
sshd -t || die "sshd -t failed with the drop-in"

echo "[4/5] checking effective settings (not reloaded yet)"
for a in "$WINDOWS_HOST" "$OTHER_ADDR"; do
  EFFECTIVE=$(sshd -T -C "user=avra-tunnel,host=avra-check,addr=$a") \
    || die "sshd -T failed for avra-tunnel"
  if ! MISSING=$(check_effective "$EFFECTIVE"); then
    die "effective sshd setting missing for avra-tunnel (addr=$a): $MISSING"
  fi
done
AFTER=$(snapshot) || die "could not read the effective sshd configuration"
if [ "$BEFORE" != "$AFTER" ]; then
  diff <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") >&2 || true
  die "the drop-in changed the effective configuration of other users or global settings"
fi
echo "Other users and global settings: unchanged."

echo "[5/5] reloading sshd (existing sessions are kept)"
systemctl reload "$SSH_UNIT"
systemctl is-active --quiet "$SSH_UNIT" || die "$SSH_UNIT.service is not active after reload"

UNDO=()  # success: nothing to roll back
echo "Done. Next (README §4): run the tunnel verification from Windows."
echo "  ssh -N -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no -o ExitOnForwardFailure=yes \\"
echo "      -i %USERPROFILE%\\.ssh\\avra_runtime_ed25519 -L 127.0.0.1:8765:127.0.0.1:8765 avra-tunnel@192.168.56.104"
