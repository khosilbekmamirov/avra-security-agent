# Tool Runner deployment (Kali VM) — M4

Manual, reviewable, fail-closed, transactional. Every step that needs root
is run by the owner with `sudo`; nothing starts automatically. Design and
accepted risks: `docs/decisions/0003-tool-runner-design.md`.

```
Windows (AVRA core)                          Kali
127.0.0.1:8765 ── SSH tunnel (avra-tunnel) ──▶ sshd ──▶ 127.0.0.1:8765  Runner (avra-runner)
                  encrypted, host key pinned            loopback only, systemd-sandboxed
```

## What gets installed

| Item | Location | Owner / mode |
|---|---|---|
| Code + venv | `/opt/avra-runner` | `root`, not writable by the Runner |
| `runner.env`, `scope.yaml` | `/etc/avra-runner/` | `root:avra-runner 0640` |
| Token | `/etc/avra-runner/token` | `avra-runner 0600` (placed by you) |
| Audit log | `/var/lib/avra-runner/audit/runner-audit.jsonl` | `avra-runner 0600`, **`chattr +a`** (append-only) |
| Unit | `/etc/systemd/system/avra-runner.service` | `root 0644`, not enabled |
| Tunnel (M4.4) | user `avra-tunnel`, `/var/lib/avra-tunnel/.ssh/authorized_keys`, `/etc/ssh/sshd_config.d/10-avra-tunnel.conf` | all `root`-owned |

Nmap: the Runner uses the real binary `/usr/lib/nmap/nmap`, not Kali's
`/usr/bin/nmap` wrapper (which adds `--privileged`), and always passes
`--unprivileged -sT`; the unit drops the binary's file capabilities.

Append-only audit log: the Runner can add records but not truncate,
rewrite, rename or delete the file; only root can lift it (`chattr -a`).
`AuditLog` only ever opens it in append mode, so this is compatible.

## 1. Build a verified bundle (Windows)

Line endings are forced to LF by `.gitattributes`; the bundle builder
refuses any CR anyway.

```
uv build --wheel
python runner/deploy/make_bundle.py C:\avra-bundle dist\avra-0.0.0-py3-none-any.whl scope\<your>.scope.yaml [%USERPROFILE%\.ssh\avra_runtime_ed25519.pub]
```

Note the printed `SHA256SUMS sha256: …` value. The builder validates every
input before writing anything, refuses CR in any text file (a Windows
`ssh-keygen` `.pub` line ending in CRLF is normalized — it is a single
line), refuses anything that looks like a private key or an assigned
`AVRA_RUNNER_TOKEN=`, and accepts only a one-line `ssh-ed25519` `.pub`.

## 2. Stage it root-owned on Kali (owner)

Copy `C:\avra-bundle` to Kali (e.g. `scp -r`), then move it out of any
user-writable location before anything runs as root:

```
sudo install -d -o root -g root -m 0700 /root/avra-deploy
sudo cp -- /tmp/avra-bundle/* /root/avra-deploy/
sudo chown root:root /root/avra-deploy/*; sudo chmod 0600 /root/avra-deploy/*
```

**Trust anchor — do this before running any script:** verify the bundle
with the system's own `sha256sum`, not with our scripts (a tampered
script could print whatever it likes):

```
sudo sh -c 'cd /root/avra-deploy && sha256sum SHA256SUMS && sha256sum --strict -c SHA256SUMS'
```

The first hash must equal the `SHA256SUMS sha256` printed on Windows, and
every file must report `OK`. Only then run the installers. They repeat
these checks as defense in depth (root-owned directory and files, every
input listed, checksums match, no CR) and ask you to type `YES`.

## 3. M4.3 — install (owner)

```
sudo bash /root/avra-deploy/install.sh
```

It refuses if anything it would create already exists, and on any failure
(or Ctrl+C) rolls back exactly what that run created. It also refuses a
scope whose targets aren't in the unit's `IPAddressAllow`.

Token — generate on Windows, never paste it into chat:
`python -c "import secrets; print(secrets.token_urlsafe(32))"` →
Windows `.env` as `AVRA_RUNNER_TOKEN=...`; on Kali (input not echoed):

```
sudo bash -c 'read -rs -p "token: " T; echo; printf "%s\n" "$T" | install -o avra-runner -g avra-runner -m 0600 /dev/stdin /etc/avra-runner/token'
```

Validate without starting anything:

```
sudo -u avra-runner bash -c 'set -a; . /etc/avra-runner/runner.env; exec /opt/avra-runner/venv/bin/python -m avra.runner --check'
```

## 4. M4.4 — tunnel account (owner, separate approval)

Changes SSH. Keep a **VirtualBox console logged in** and a **second SSH
session open** as fallbacks until the post-install checks pass.

### 4a. Key (Windows, once)

```
ssh-keygen -t ed25519 -N "" -C avra-runtime -f %USERPROFILE%\.ssh\avra_runtime_ed25519
```

No passphrase (owner decision, M4.4): AVRA must open the tunnel
unattended. The key can only forward to `127.0.0.1:8765` from
`192.168.56.1`, and the Runner still requires its token. Only the `.pub`
ever leaves Windows.

### 4b. Bundle with the public key (Windows) and staging (Kali)

Build into a **new** directory (the M4.3 bundle stays untouched):

```
python runner/deploy/make_bundle.py dist\avra-bundle-tunnel dist\avra-0.0.0-py3-none-any.whl scope\<your>.scope.yaml %USERPROFILE%\.ssh\avra_runtime_ed25519.pub
scp -r dist\avra-bundle-tunnel <runner-user>@<kali-host>:/tmp/
```

On Kali:

```
sudo install -d -o root -g root -m 0700 /root/avra-deploy-tunnel
sudo cp -- /tmp/avra-bundle-tunnel/* /root/avra-deploy-tunnel/
sudo chown root:root /root/avra-deploy-tunnel/*; sudo chmod 0600 /root/avra-deploy-tunnel/*
sudo sh -c 'cd /root/avra-deploy-tunnel && sha256sum SHA256SUMS && sha256sum --strict -c SHA256SUMS'
```

The first hash must equal the value printed on Windows; every file `OK`.

### 4c. Install (Kali)

```
sudo bash /root/avra-deploy-tunnel/install-tunnel.sh      # type YES
```

What it does, in order — any failure rolls back what this run created:

1. Re-verifies the bundle (root-owned, no CR, listed, checksums), the key
   (one `ssh-ed25519` line, not a private key) and the drop-in (exactly
   one `Match User avra-tunnel` block, nothing global).
2. Refuses if `ssh.service` isn't active, `sshd_config` doesn't
   `Include /etc/ssh/sshd_config.d/*.conf`, `sshd -t` already fails,
   the user/home/drop-in exist, or any sshd file already mentions
   `avra-tunnel`.
3. Snapshots the **effective** configuration (`sshd -T`): global, and
   every login-capable user (incl. `kali`, `root`) from `192.168.56.1`
   and from an unrelated address.
4. Creates `avra-tunnel` (locked, `nologin`, root-owned empty home) and a
   root-owned `authorized_keys`:
   `restrict,port-forwarding,permitopen="127.0.0.1:8765",from="192.168.56.1",command="/usr/sbin/nologin"`.
5. Writes `/etc/ssh/sshd_config.d/10-avra-tunnel.conf`, runs `sshd -t`,
   checks 16 effective settings for `avra-tunnel` (from both addresses;
   keyword case-insensitive, value exact — OpenSSH 10.5 prints
   `AuthenticationMethods`, older releases `authenticationmethods`),
   and re-takes the snapshot: **it must be byte-identical** — otherwise
   the drop-in affected someone else and the run is rolled back.
6. `systemctl reload ssh` (not restart — open sessions stay) and checks
   `ssh.service` is still active.

After a failure nothing is left, so it can be rerun. After a success it
refuses to run again (uninstall first).

Why no `AuthorizedKeysCommand none` and no trailing `Match all`: see the
comments in `sshd-avra-tunnel.conf` (verified against OpenSSH 10.5p1
source and, on Kali, by `tests/security/test_tunnel_sshd_effective.py`).

**Immediately after**, from Windows, a **new** dev session must work:

```
ssh <runner-user>@<kali-host> "echo dev-ssh OK"
```

If it doesn't, from the VirtualBox console:
`sudo rm /etc/ssh/sshd_config.d/10-avra-tunnel.conf && sudo sshd -t && sudo systemctl reload ssh`.

### 4d. Verify (Windows, no scans, Runner may be stopped)

```
python runner\deploy\verify_tunnel.py --bridged-ip <Kali eth0 IP>
```

Each forwarding check actually **connects** to the local listener so the
client sends the request to sshd, then reads the `ssh -v` log. A local
listener alone proves nothing. Layers reported per check:

| Layer | Evidence (client `-v` log) |
|---|---|
| auth | `Authenticated to … using "publickey"` / `Permission denied (publickey)` |
| listener | `Local forwarding listening on …` |
| request sent | `Connection to port N forwarding to … requested` |
| server verdict | `administratively prohibited` = refused; `open failed: connect failed` = allowed, nothing listening; no failure = allowed, backend up |

Expected:

| Check | Expected |
|---|---|
| `kali` dev SSH | works |
| `-L` → `127.0.0.1:8765` | allowed (`connect failed` while the Runner is stopped) |
| `-L` → `127.0.0.1:22`, → `192.168.56.103:3000`, → `localhost:8765`, → `[::1]:8765` | administratively prohibited |
| `-L` → `/var/run/docker.sock` | INCONCLUSIVE on the client (sshd answers a refused Unix-socket forward with the generic `connect failed: open failed`); PASS when the Kali journal shows `refused streamlocal port forward` |
| `-D` SOCKS → Juice Shop | administratively prohibited |
| `-R` | `remote port forwarding failed` |
| remote command, `-tt` PTY, SFTP | refused (nologin / PTY allocation failed / no SFTP session) |
| runtime key as `kali` | `Permission denied` |
| runtime key via the Bridged IP | `Permission denied`; Kali journal: `correct key but not from a permitted host` (uses `HostKeyAlias=192.168.56.104` so strict host-key checking still applies) |

On Kali (read-only) the effective settings can be inspected with:

```
sudo sshd -T -C user=avra-tunnel,host=x,addr=192.168.56.1 | grep -iE '^(allowtcpforwarding|permitopen|permitlisten|forcecommand|permittty|authorizedkeysfile|authenticationmethods) '
sudo journalctl -u ssh --since "-10 min" | grep -i avra-tunnel
```

Tunnel from Windows (what AVRA will use):

```
ssh -N -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no -o ExitOnForwardFailure=yes ^
    -i %USERPROFILE%\.ssh\avra_runtime_ed25519 -L 127.0.0.1:8765:127.0.0.1:8765 avra-tunnel@192.168.56.104
```

Exit code: 0 all PASS, 1 any FAIL, 2 no FAIL but INCONCLUSIVE (settle it as
the printed hint says). For a positive end-to-end test with the Runner
stopped, a temporary loopback-only listener on Kali `127.0.0.1:8765` (as
`kali`, port checked free first, auto-stops) can return a nonce through
the tunnel — done in M4.5 (dev-log 2026-11-06).

`IdentitiesOnly` keeps ssh-agent from offering the dev key. The client
must use the literal `127.0.0.1` — `permitopen` compares text, so
`localhost` is refused.

## M4.5 — verification checklist (no scans)

Status 2026-11-06: tunnel checks and the API checks (health 200/401, scope
403) done; the remaining items are deferred (ADR 0003 "M4.5 — Runner API
and completion").

- [ ] Full test suite on Kali in a throwaway venv (`/tmp`), removed after —
      includes the CRLF-guard test, which only runs with a Linux bash/grep.
- [ ] `--check` → exit 0.
- [ ] `lsattr` on the audit log shows `a`; as `avra-runner`, `: > runner-audit.jsonl` fails.
- [ ] `sudo systemctl start avra-runner`; `ss -ltnp` shows only `127.0.0.1:8765`;
      audit has `runner_started`.
- [ ] Through the tunnel: health with token → 200 (confirms `os.access` health
      check works with `chattr +a`); without → 401; `ports: [22]` → 403, no `execution_started`.
- [ ] Second instance while running → exit 3.
- [ ] `systemctl stop` → `runner_stopped`; lock free
      (`sudo -u avra-runner flock -n /var/lib/avra-runner/audit/runner-audit.jsonl.lock true`);
      `pgrep -u avra-runner` empty.
- [ ] `systemctl kill -s KILL avra-runner` → restart works; audit chain verifies.
- [ ] `pytest tests/security/test_tunnel_sshd_effective.py` on Kali (real `sshd -T`
      against a temp copy of the config: restrictions present, other users unchanged).
- [ ] `verify_tunnel.py` → ALL CHECKS PASSED (section 4d), with the Runner both
      stopped (`connect failed`) and running (allowed, backend up).
- [ ] `systemctl show avra-runner -p IPAddressAllow -p NoNewPrivileges -p CapabilityBoundingSet`.

## Uninstall / rollback (owner)

```
sudo systemctl stop avra-runner; sudo systemctl disable avra-runner
sudo rm /etc/systemd/system/avra-runner.service; sudo systemctl daemon-reload
sudo rm -rf /opt/avra-runner /etc/avra-runner
sudo userdel avra-runner
# Audit log is kept on purpose. To archive/remove it, root must first:
#   sudo chattr -a /var/lib/avra-runner/audit/runner-audit.jsonl
# Tunnel (if installed):
sudo rm /etc/ssh/sshd_config.d/10-avra-tunnel.conf; sudo sshd -t && sudo systemctl reload ssh
sudo userdel avra-tunnel; sudo rm -rf /var/lib/avra-tunnel
# Then confirm from Windows: ssh <runner-user>@<kali-host> "echo dev-ssh OK"
```

Full reinstall: the installer refuses to overwrite anything, including an
existing audit directory, and it downloads dependencies from PyPI (the lab
is host-only, so this does not work offline). Uninstall, then archive the
audit log out of the way (root: `chattr -a` the file, then move
`/var/lib/avra-runner` to e.g. `/root/avra-audit-archive-<date>`), then
install again. For a code-only upgrade use the procedure below instead.

## Emergency stop and cancellation (M8.7 Stage 4, ADR 0012) — deployed 2026-11-12

Deployed with the M8.7 wheel (sha256
`e5b39513f54f714569720f6c4259394ef166c63e91d50f865e0c083a651222aa`, from
`74f89b2`) through the wheel-only upgrade below. Backup:
`/root/avra-backup-m8.7-2026-11-12`; snapshot `AVRA-M8.7-S7-PreDeploy`.
The cancel API is live-verified. Not yet exercised on the operational
Runner: stopping an actually running job, and the emergency latch (it was
never engaged).

- `POST /v1/tools/cancel` and `POST /v1/emergency-stop`: same token, size
  and content-type rules as `/v1/tools/run`; stop-only; no reset route.
- The emergency latch lives at
  `/var/lib/avra-runner/audit/emergency-stop.json` (inside the existing
  `ReadWritePaths`; no `runner.env` or unit change). While it is not READY
  the Runner starts but runs nothing, and `/v1/health` returns 503 with
  `emergency_stop_clear: false`. Restarting the service does NOT clear it.
- Load `runner.env` ONLY through systemd's `EnvironmentFile=`, exactly as
  the unit does. Never `env $(cat runner.env | xargs)`, `export $(...)`,
  `source` or values typed on the command line: that word-splits and
  glob-expands values, puts configuration into process arguments
  (`ps`, `/proc/*/cmdline`) and shell history, and would leak a secret if
  one were ever placed there. (Today `runner.env` holds only paths; the token
  stays in `/etc/avra-runner/token`, read by the Runner itself.)
- **Inspect** (read-only; the Runner must be stopped because `--check` takes
  the audit owner lock):

  ```
  sudo systemd-run --pipe --wait --collect --quiet \
       --uid=avra-runner --gid=avra-runner \
       -p EnvironmentFile=/etc/avra-runner/runner.env \
       /opt/avra-runner/venv/bin/python -m avra.runner --check
  ```
- **Reset (owner, on Kali only, after investigating why it was engaged):**

  ```
  sudo systemctl stop avra-runner
  sudo systemd-run --pty --wait --collect --quiet \
       --uid=avra-runner --gid=avra-runner \
       -p EnvironmentFile=/etc/avra-runner/runner.env \
       /opt/avra-runner/venv/bin/python -m avra.runner --reset-emergency-stop
  # --pty gives the command the real terminal it requires; it asks for a
  # reason and the word RESET, records emergency_stop_reset in the
  # append-only audit log FIRST, then writes READY. Restarts nothing.
  ```

  `--check` via `systemd-run --pipe` was run on the operational Runner in
  Stage 7 (OK, latch READY). `--reset-emergency-stop` was verified on Linux
  only (Stage 6 harness); it was never needed operationally.
  `systemd-run --pty` needs systemd ≥ 235.

- **After any `systemctl start avra-runner`, wait before reading the
  audit** (lesson from Stage 7). The service is `Type=simple`, so
  `systemctl start` returns once the process is launched. The Runner writes
  `runner_started` about one second later, after loading its configuration.
  An audit read in between shows the previous `runner_stopped` as the last
  event. Wait until `ss -ltn` shows `127.0.0.1:8765`, or until
  `runner_started` follows the last `runner_stopped`.
- **Temporary scope changes** (Stage 7 pattern):
  - stop the service first;
  - copy root-owned copies into the existing file, which keeps owner and mode;
  - check the hash before and after;
  - run `--check`, then start;
  - restore from the root-owned backup right after use.

  The Runner reads its scope **only at startup**. Hashes used:
  `ac4b8b18…` (original), `ae45fcd8…` (temporary `http_probe` entry).
  Copy hashes from Linux `sha256sum` output: on Windows, `sha256sum` writes
  a leading `\` for paths with backslashes, and misreading that once cost
  the hash its first character (`ae45…` read as `e45…`).

  Refused (exit 5) for a CORRUPT/UNREADABLE latch: do not edit or delete
  it — it is evidence. Deleting the file does not help: the audit log still
  says "stopped", so the latch reads CORRUPT. Recovery from a corrupt latch
  is a manual owner decision (archive the file and the audit log, as in
  "Uninstall / rollback").
- **From Windows (Stage 5):** `avra kill` engages the Windows latch, then
  calls `/v1/emergency-stop` through a stop-only tunnel and prints the
  local and remote results separately (exit 0 both confirmed, 4 remote not
  confirmed, 1 local failure); `avra kill --local-only` skips the Runner.
  Ctrl+C during a scan/probe asks the Runner to cancel exactly that job.
  `avra kill --reset` resets ONLY the Windows latch — never this Runner
  latch. Against a Runner without these endpoints (the build deployed
  before Stage 7) Windows reports "REMOTE STOP UNSUPPORTED OR UNCONFIRMED".
- **Deploy order for Stage 4/5:** upgrade the Runner first (pre-Stage-4
  Windows clients fail closed against the new status values), then the
  Windows side. Take a VM snapshot first; re-run the offline test suite on
  Kali (incl. the POSIX-only grandchild/SIGTERM cancel tests) before
  installing.

## Offline wheel-only upgrade (owner) — M8.2

Replaces only the `avra` package inside the existing Runner venv. Use it
only when `requirements-runner.txt` is unchanged since the installed
version (otherwise: full reinstall above). It never touches the audit log,
the token, the scope file, the unit or the tunnel. Every Kali step below
is an owner step (`sudo`); Claude Code only builds, copies to `/tmp` and
verifies read-only.

**Preconditions**

- Service stopped: `systemctl is-active avra-runner` → `inactive`.
- The currently installed wheel is identified and kept as the rollback
  wheel (M4 deployment: `dist/avra-0.0.0-py3-none-any.whl`, sha256
  `15c8f60801dc33cb69270818ba2c371d60dede2daee21101cddf6e29823786e2`, also
  in `/root/avra-deploy-tunnel-r2/`). Never rebuild into `dist/` itself:
  `uv build` would overwrite it.
- A VirtualBox snapshot of the Kali VM taken just before (owner).
- If the new version adds a tool, `runner.env` needs its
  `AVRA_RUNNER_EXEC_<NAME>` line — the Runner refuses to start without one
  for every registered tool (M8.1 adds `AVRA_RUNNER_EXEC_HTTP_PROBE`).

**1. Build (Windows)** — from a clean LF export of the committed tree (the
Windows working copy has `core.autocrlf=true`, so building from it, or a
plain `git archive`, puts CRLF line endings into the wheel), into a new
directory; then record the hash. Building twice must give the same hash.

```
git -c core.autocrlf=false -c core.eol=lf archive HEAD -o %TEMP%\avra-src.tar
mkdir %TEMP%\avra-src && tar -xf %TEMP%\avra-src.tar -C %TEMP%\avra-src
cd /d %TEMP%\avra-src && uv build --wheel --out-dir E:\Projects\avra\dist\m8.2
certutil -hashfile E:\Projects\avra\dist\m8.2\avra-0.0.0-py3-none-any.whl SHA256
```

M8.2 wheel: sha256
`739e5bdffbea8dc543a4f0b22d87da8907cab7a0a725c18efc468575a72fbe63`
(49 modules, byte-identical to the committed `src/`, LF only; adds
`http_probe`, the `avra-http-probe` console script and the
`runner_stopped` fix).

**2. Stage (Windows → Kali `/tmp`, no sudo)**

```
scp dist\m8.2\avra-0.0.0-py3-none-any.whl <runner-user>@<kali-host>:/tmp/avra-m8.2.whl
```

**3. Upgrade (Kali, owner)** — set `NEW=<sha256 from step 1>` first:

```
D=/root/avra-backup-$(date +%F)
echo "$NEW  /tmp/avra-m8.2.whl" | sha256sum -c -     # must print OK
sudo install -d -m 0700 "$D" "$D/new"
# pip needs the canonical wheel file name:
sudo install -o root -g root -m 0644 /tmp/avra-m8.2.whl "$D/new/avra-0.0.0-py3-none-any.whl"
sudo sha256sum "$D/new/avra-0.0.0-py3-none-any.whl"  # must equal $NEW
sudo cp -a /opt/avra-runner "$D/opt-avra-runner"
sudo cp -a /etc/avra-runner/runner.env "$D/runner.env"
sudo env PYTHONNOUSERSITE=1 /opt/avra-runner/venv/bin/python -m pip --isolated \
  --no-input --disable-pip-version-check install --no-cache-dir \
  --no-deps --no-index --force-reinstall "$D/new/avra-0.0.0-py3-none-any.whl"
sudo chown -R root:root /opt/avra-runner
sudo chmod -R go-w,a+rX /opt/avra-runner
sudo grep -q '^AVRA_RUNNER_EXEC_HTTP_PROBE=' /etc/avra-runner/runner.env \
  || echo 'AVRA_RUNNER_EXEC_HTTP_PROBE=/opt/avra-runner/venv/bin/avra-http-probe' \
     | sudo tee -a /etc/avra-runner/runner.env >/dev/null
sudo stat -c '%U:%G %a %n' /etc/avra-runner/runner.env  # root:avra-runner 640
sudo -u avra-runner bash -c 'set -a; . /etc/avra-runner/runner.env; exec /opt/avra-runner/venv/bin/python -m avra.runner --check'
```

(`runner.env` is root-only for reading, so the `grep` must run under
`sudo`; otherwise it fails and the line would be appended twice.)

**4. Verify**

- `--check` → exit 0.
- Read-only (Claude Code): every installed `avra/**/*.py` hash equals the
  new wheel; `/opt/avra-runner/venv/bin/avra-http-probe` exists, is
  `root:root`, not group/other-writable.
- `systemctl show avra-runner -p NoNewPrivileges -p CapabilityBoundingSet
  -p IPAddressAllow -p RestrictAddressFamilies` unchanged (the unit is not
  touched by this procedure).
- Owner starts the service; authenticated `/v1/health` through the tunnel;
  owner stops it; the audit log now ends with a `runner_stopped` event.
- No tool runs are part of an upgrade. `http_probe` stays default-denied
  until a scope file lists it (separate approval).

**Rollback (owner), least to most drastic**

1. Code: `sudo systemctl stop avra-runner` (if running), then the same
   `pip install … --force-reinstall` line with the rollback wheel (sha256
   `15c8f608…`, from `/root/avra-deploy-tunnel-r2/` or staged again from
   `dist/avra-0.0.0-py3-none-any.whl`; check its hash first), then
   `sudo install -o root -g avra-runner -m 0640 "$D/runner.env" /etc/avra-runner/runner.env`,
   `chown`/`chmod` as above, `--check`. Verify installed hashes equal the
   rollback wheel.
2. Directory: `sudo rm -rf /opt/avra-runner && sudo cp -a "$D/opt-avra-runner" /opt/avra-runner`,
   then restore `runner.env` as in 1.
3. VM snapshot revert — separate explicit owner approval; it also discards
   audit events written after the snapshot.

None of these touches `/var/lib/avra-runner` (the audit log stays
append-only); events written by the new version stay in the log.
