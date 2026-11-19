"""M8.7 Stage 6 (ADR 0012): systemd validation of a DISPOSABLE Runner.

Run on Linux as an unprivileged user with a user systemd manager:

    PYTHONPATH=<repo>/src:<runner-venv-site-packages> python3 tests/linux/systemd_stage6_harness.py

It never touches avra-runner.service, the operational audit log, latch,
token or scope. Everything lives in a fresh temporary directory: a
test-only token, a copy of the test scope, its own audit log and latch, a
private loopback port, and a harmless job (sleeps, spawns one grandchild in
its process group) mapped as the Runner's "nmap" executable - so no packet
is ever sent to any target. The Runner runs as a transient USER unit
(`systemd-run --user`) with KillMode=control-group, TimeoutStopSec=20,
MemoryMax and TasksMax. Prints PASS/FAIL lines; exit 1 if anything fails.
Not collected by pytest (file name does not start with test_)."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

RESULTS: list[tuple[bool, str]] = []
SCOPE = """session_name: "stage6-systemd-test"
expires_at: "2099-01-01T00:00:00Z"
targets:
  - host: "10.66.7.103"
    ports: [3000]
    allowed_tiers: ["active-safe"]
    allowed_tools: ["nmap_connect_scan"]
"""
JOB = """#!/usr/bin/env python3
import os, subprocess, sys, time
marker = os.environ.get("S6_MARKERS") or os.path.dirname(os.path.abspath(__file__)) + "/markers"
os.makedirs(marker, exist_ok=True)
gc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
open(os.path.join(marker, "job-%d" % os.getpid()), "w").write(str(gc.pid))
time.sleep(120)
"""
LAUNCHER = """import sys
from avra.runner import server as server_mod
from avra.runner.execution import SubprocessRunner
JOB = sys.argv[1]
server_mod.SubprocessRunner = lambda executables: SubprocessRunner({"nmap": JOB, "http_probe": JOB})
sys.exit(server_mod.main(argv=[] if len(sys.argv) < 3 else sys.argv[2:]))
"""


def check(ok: bool, what: str) -> bool:
    RESULTS.append((bool(ok), what))
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    return bool(ok)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Lab:
    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="avra-s6-systemd-"))
        os.chmod(self.dir, 0o700)
        self.unit = f"avra-s6-test-{uuid.uuid4().hex[:8]}"
        self.port = free_port()
        self.token = secrets.token_urlsafe(32)  # test-only, never the real one
        (self.dir / "token").write_text(self.token + "\n")
        os.chmod(self.dir / "token", 0o600)
        (self.dir / "scope.yaml").write_text(SCOPE)
        (self.dir / "audit").mkdir(mode=0o700)
        self.audit = self.dir / "audit" / "runner-audit.jsonl"
        self.job = self.dir / "job.py"
        self.job.write_text(JOB)
        os.chmod(self.job, 0o755)
        self.markers = self.dir / "markers"
        self.markers.mkdir()
        (self.dir / "launch.py").write_text(LAUNCHER)
        self.env = {"AVRA_RUNNER_SCOPE_FILE": str(self.dir / "scope.yaml"),
                    "AVRA_RUNNER_TOKEN_FILE": str(self.dir / "token"),
                    "AVRA_RUNNER_AUDIT_LOG": str(self.audit),
                    "AVRA_RUNNER_BIND_HOST": "127.0.0.1",
                    "AVRA_RUNNER_PORT": str(self.port),
                    # Validated by RunnerConfig (root-owned, harmless); the
                    # launcher maps the logical tools to the test job instead.
                    "AVRA_RUNNER_EXEC_NMAP": "/usr/bin/true",
                    "AVRA_RUNNER_EXEC_HTTP_PROBE": "/usr/bin/true",
                    "S6_MARKERS": str(self.markers),
                    "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                    "PYTHONDONTWRITEBYTECODE": "1"}

    # -- systemd -------------------------------------------------------------------------

    def start(self) -> None:
        cmd = ["systemd-run", "--user", "--unit", self.unit, "--collect", "--quiet",
               "-p", "KillMode=control-group", "-p", "TimeoutStopSec=20",
               "-p", "MemoryMax=512M", "-p", "TasksMax=64"]
        for k, v in self.env.items():
            cmd += ["-E", f"{k}={v}"]
        cmd += [sys.executable, str(self.dir / "launch.py"), str(self.job)]
        subprocess.run(cmd, check=True, timeout=30)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                self.get("/v1/health")
                return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("disposable Runner did not come up")

    def systemctl(self, *args: str, timeout: float = 60) -> float:
        t0 = time.monotonic()
        subprocess.run(["systemctl", "--user", *args, self.unit], check=False, timeout=timeout,
                       capture_output=True)
        return time.monotonic() - t0

    def active(self) -> bool:
        r = subprocess.run(["systemctl", "--user", "is-active", self.unit], capture_output=True,
                           text=True, check=False)
        return r.stdout.strip() == "active"

    def runner_cli(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        env = {**os.environ, **self.env}
        return subprocess.run([sys.executable, str(self.dir / "launch.py"), str(self.job),
                               *args], env=env, capture_output=True, text=True,
                              input=stdin, timeout=60, check=False)

    # -- http ----------------------------------------------------------------------------

    def _req(self, method: str, path: str, body=None, token: str | None = "", timeout=30):
        headers = {"Content-Type": "application/json"}
        tok = self.token if token == "" else token
        if tok is not None:
            headers["Authorization"] = f"Bearer {tok}"
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data,
                                     headers=headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def get(self, path, **kw):
        return self._req("GET", path, **kw)

    def post(self, path, body, **kw):
        return self._req("POST", path, body, **kw)

    # -- jobs ----------------------------------------------------------------------------

    def payload(self):
        return {"tool": "nmap_connect_scan", "request_id": str(uuid.uuid4()),
                "session_id": str(uuid.uuid4()), "host": "10.66.7.103", "ports": [3000],
                "timeout_seconds": 60}

    def start_job(self):
        before = set(self.markers.iterdir())
        p = self.payload()
        box: dict = {}

        def call():
            try:
                box["res"] = self.post("/v1/tools/run", p, timeout=90)
            except OSError as exc:
                box["err"] = type(exc).__name__

        t = threading.Thread(target=call, daemon=True)
        t.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            new = set(self.markers.iterdir()) - before
            if new:
                f = new.pop()
                return p, t, box, int(f.name.split("-")[1]), int(f.read_text() or 0)
            time.sleep(0.05)
        raise RuntimeError("job did not start")

    def events(self):
        out = []
        if self.audit.exists():
            for line in self.audit.read_text().splitlines():
                if line.strip():
                    out.append(json.loads(line))
        return out


def gone(pid: int, seconds: float = 10) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/stat") as fh:
                if fh.read().split(")")[-1].split()[0] == "Z":
                    return True
        except FileNotFoundError:
            return True
        time.sleep(0.05)
    return False


def main() -> int:
    lab = Lab()
    print(f"workspace {lab.dir} unit {lab.unit} port {lab.port}", flush=True)
    try:
        lab.start()
        check(lab.get("/v1/health")[0] == 200, "health 200 with the test token")
        check(lab.get("/v1/health", token=None)[0] == 401, "no token -> 401")
        check(lab.get("/v1/health", token="x" * 40)[0] == 401, "wrong token -> 401")

        # 1. graceful stop of the unit while a job runs
        p, t, box, job, gc = lab.start_job()
        took = lab.systemctl("stop")
        t.join(30)
        ev = [e["event"] for e in lab.events()]
        check(gone(job) and gone(gc), "systemctl stop: job and grandchild terminated")
        check("execution_finished" in ev and "runner_stopped" in ev
              and ev.index("execution_finished") < ev.index("runner_stopped"),
              "systemctl stop: execution_finished recorded before runner_stopped")
        fin = [e for e in lab.events() if e["event"] == "execution_finished"][-1]["data"]
        # KillMode=control-group: systemd SIGTERMs EVERY process of the unit at
        # once, so the job usually dies of systemd's signal (exit -15) before
        # the Runner's own shutdown cancel labels it. Both are truthful and
        # bounded; neither may look like a clean success (exit 0).
        check((fin["outcome"] == "cancelled" and fin["cancel_reason"] == "runner_shutdown")
              or (fin["outcome"] == "exited" and fin["exit_code"] == -15),
              f"systemctl stop: job ended by the shutdown, recorded truthfully "
              f"[outcome={fin['outcome']} exit={fin['exit_code']} reason={fin['cancel_reason']}]")
        check(fin["exit_code"] != 0, "systemctl stop: never recorded as a clean exit")
        check(took < 15, f"systemctl stop completed in {took:.1f}s (TimeoutStopSec=20)")

        # 2. exact cancel over HTTP
        lab.start()
        p, t, box, job, gc = lab.start_job()
        wrong = lab.post("/v1/tools/cancel", {"request_id": p["request_id"],
                                              "session_id": str(uuid.uuid4()),
                                              "reason": "operator_request"})
        check(wrong[1].get("outcome") == "identifier_mismatch" and not gone(job, 0.5),
              "cancel with wrong session_id: identifier_mismatch, job untouched")
        res = lab.post("/v1/tools/cancel", {"request_id": p["request_id"],
                                            "session_id": p["session_id"],
                                            "reason": "operator_request"})
        t.join(30)
        check(res[0] == 200 and res[1].get("outcome") == "cancellation_applied",
              "exact cancel: cancellation_applied")
        check(gone(job) and gone(gc), "exact cancel: job and grandchild terminated")
        run = box.get("res", (None, {}))[1]
        check(run.get("status") == "cancelled" and run.get("raw_output") is None,
              "exact cancel: run answered CANCELLED with no output")

        # 3. client disconnect while a job runs
        before = set(lab.markers.iterdir())
        body = json.dumps(lab.payload()).encode()
        s = socket.create_connection(("127.0.0.1", lab.port), timeout=10)
        s.sendall(b"POST /v1/tools/run HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                  + f"Authorization: Bearer {lab.token}\r\n".encode()
                  + b"Content-Type: application/json\r\n"
                  + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        deadline = time.monotonic() + 15
        while not (set(lab.markers.iterdir()) - before) and time.monotonic() < deadline:
            time.sleep(0.05)
        f = (set(lab.markers.iterdir()) - before).pop()
        job, gc = int(f.name.split("-")[1]), int(f.read_text() or 0)
        s.close()
        check(gone(job) and gone(gc), "client disconnect: job and grandchild terminated")
        time.sleep(0.5)
        reasons = [e["data"].get("cancel_reason") for e in lab.events()
                   if e["event"] == "execution_finished"]
        check(reasons[-1] == "client_disconnected", "client disconnect: recorded as such")

        # 4. emergency stop while a job runs
        p, t, box, job, gc = lab.start_job()
        es = lab.post("/v1/emergency-stop", {"reason": "operator_emergency_stop"})
        t.join(30)
        check(es[0] == 200 and es[1].get("durable") and es[1].get("latch") == "STOPPED"
              and es[1].get("active_job") == "cancelled",
              "emergency stop: durable STOPPED latch, running job cancelled")
        check(gone(job) and gone(gc), "emergency stop: job and grandchild terminated")
        nxt = lab.post("/v1/tools/run", lab.payload())
        check(nxt[0] == 503 and nxt[1].get("stage") == "emergency_stop",
              "emergency stop: new run refused (503 emergency_stop)")
        check(lab.post("/v1/emergency-stop", {"reason": "operator_emergency_stop"})[1]
              .get("outcome") == "already_engaged", "emergency stop: repeat is idempotent")
        check(lab.post("/v1/emergency-stop/reset", {})[0] == 404, "no HTTP reset route (404)")

        # 5. the latch survives a service restart
        lab.systemctl("restart")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                h = lab.get("/v1/health")
                break
            except OSError:
                time.sleep(0.2)
        check(h[0] == 503 and h[1].get("checks", {}).get("emergency_stop_clear") is False,
              "after restart: health 503, emergency_stop_clear false")
        check(lab.post("/v1/tools/run", lab.payload())[0] == 503,
              "after restart: runs still refused")
        started = [e for e in lab.events() if e["event"] == "runner_started"][-1]["data"]
        check(started.get("emergency_latch") == "STOPPED", "runner_started records STOPPED")

        # 6. local operator tools against the disposable instance
        r = lab.runner_cli("--reset-emergency-stop", stdin="x\nRESET\n")
        check(r.returncode == 3, "reset refused while the Runner runs (exit 3)")
        lab.systemctl("stop")
        r = lab.runner_cli("--check")
        check(r.returncode == 0 and "emergency latch STOPPED" in r.stdout,
              "--check reports the STOPPED latch")
        r = lab.runner_cli("--reset-emergency-stop", stdin="test\nRESET\n")
        check(r.returncode == 5 and "interactive" in r.stderr,
              "reset refused without a real terminal (exit 5)")
        # Test-only recovery of THIS disposable latch (never the operational one).
        sys.path.insert(0, os.environ.get("PYTHONPATH", "").split(":")[0])
        from avra.runner.emergency import RunnerLatch
        from avra.storage.audit import AuditLog

        latch = RunnerLatch.beside(AuditLog(lab.audit))
        latch.reset("stage6 disposable test", by="stage6-harness")
        lab.start()
        check(lab.get("/v1/health")[0] == 200, "after test-only reset: healthy again")

        # 7. forced termination (SIGKILL to the whole cgroup)
        p, t, box, job, gc = lab.start_job()
        lab.systemctl("kill", "--signal=SIGKILL")
        check(gone(job) and gone(gc), "SIGKILL to the unit: cgroup leaves no job processes")
        time.sleep(1)
        check(not lab.active(), "unit is down after SIGKILL")
        check(AuditLog(lab.audit).verify(), "audit chain intact after SIGKILL (no torn line)")
        lab.start()
        check(lab.get("/v1/health")[0] == 200, "restart after SIGKILL works")
    finally:
        if lab.active():
            lab.systemctl("stop")
        subprocess.run(["systemctl", "--user", "reset-failed", lab.unit], capture_output=True,
                       check=False)
        leftovers = subprocess.run(["pgrep", "-f", str(lab.job)], capture_output=True,
                                   text=True, check=False).stdout.split()
        check(not leftovers, f"no leftover job processes ({leftovers})")
        shutil.rmtree(lab.dir, ignore_errors=True)
    failed = [w for ok, w in RESULTS if not ok]
    print(f"{len(RESULTS) - len(failed)} passed, {len(failed)} failed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
