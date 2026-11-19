# Lab setup (public summary)

_The detailed lab record (host network, adapter inventory, dated checks) is kept private.
This summary describes the topology AVRA was built and validated on._

## Layout

- **Host:** Windows 11 Pro with VirtualBox. Runs the `avra` CLI, the evidence store, the
  audit logs and (optionally) a local model server on loopback.
- **Kali Linux VM:** runs the AVRA Tool Runner (systemd service, non-root user, Python
  virtual environment) and nmap. The Runner listens only on `127.0.0.1:8765`.
- **Ubuntu VM:** runs Docker with OWASP Juice Shop (port 3000) — the only approved target.
- **Network:** a VirtualBox **host-only** network (default range `192.168.56.0/24`). All AVRA
  traffic — the SSH tunnel to the Runner and the Runner's tool runs against the target —
  stays on it. Any additional adapter used for package updates is kept disconnected (or on
  NAT) otherwise; see ADR 0002.

## Access

- Key-based SSH from the Windows host (ED25519, passphrase-protected key that never leaves
  the host) for development and deployment.
- AVRA itself reaches the Runner through a dedicated tunnel account that can only forward to
  the Runner's loopback port (`runner/deploy/sshd-avra-tunnel.conf`).

## Safety rules for the lab

- Targets come only from scope files; the Runner keeps its own scope file.
- VM snapshots are taken before deployments, so the lab can be reset to a known state.
- Before the host joins any untrusted network, both VMs are isolated first.

In this public repository the test fixtures use the synthetic range `10.66.7.0/24`
(`tests/fixtures/`).
