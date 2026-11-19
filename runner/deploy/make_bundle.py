"""Build a verified deployment bundle on Windows (ADR 0003, M4).

    python runner/deploy/make_bundle.py <out_dir> <avra-*.whl> <scope.yaml> [avra_runtime_ed25519.pub]

Copies the deploy files, the wheel, the scope (as ``scope.yaml``) and
optionally the tunnel public key into ``out_dir``, refuses any text file
containing CR, writes ``SHA256SUMS`` (sha256sum format, LF) and prints the
SHA-256 of ``SHA256SUMS`` itself. On Kali the installers verify every file
against ``SHA256SUMS``; the owner only compares that one printed hash.
Standard library only.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEPLOY_FILES = (
    "install.sh",
    "install-tunnel.sh",
    "avra-runner.service",
    "runner.env.example",
    "requirements-runner.txt",
    "sshd-avra-tunnel.conf",
)
PUBKEY_NAME = "avra_runtime_ed25519.pub"


# Anything that looks like a secret must never end up in a bundle: the
# private half of an SSH key, or a Runner token assigned in an env file.
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"^\s*AVRA_RUNNER_TOKEN\s*=", re.MULTILINE),
)
_PUBKEY_LINE = re.compile(rb"\Assh-ed25519 [A-Za-z0-9+/=]+( [!-~]+)?\n?\Z")


class BundleError(Exception):
    pass


def _refuse_secrets(name: str, data: bytes) -> None:
    for pattern in _SECRET_PATTERNS:
        if pattern.search(data):
            raise BundleError(f"{name}: looks like it contains a secret — refusing")


def _pubkey_bytes(pubkey: Path) -> bytes:
    """The public key as one LF-terminated line. Windows ssh-keygen writes
    CRLF; for this single-line file a trailing CRLF is normalized (any
    other CR is refused, as for every other text file)."""
    if pubkey.suffix != ".pub":
        raise BundleError("public key must be a .pub file (never the private key)")
    data = pubkey.read_bytes()
    if data.endswith(b"\r\n"):
        data = data[:-2] + b"\n"
    if b"\r" in data or not _PUBKEY_LINE.match(data):
        raise BundleError("public key must be exactly one ssh-ed25519 line")
    return data if data.endswith(b"\n") else data + b"\n"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(src: Path) -> bytes:
    data = src.read_bytes()
    if b"\r" in data:
        raise BundleError(f"{src.name}: contains CR (CRLF line endings) — refusing")
    return data


def build(out_dir: Path, wheel: Path, scope: Path, pubkey: Path | None = None) -> str:
    """Create the bundle and return the SHA-256 of its SHA256SUMS file.

    Every input is read and validated before anything is written, so a
    refused build leaves no partial bundle behind.
    """
    if out_dir.exists() and any(out_dir.iterdir()):
        raise BundleError(f"{out_dir} exists and is not empty")
    if wheel.suffix != ".whl" or not wheel.name.startswith("avra-") or not wheel.is_file():
        raise BundleError("wheel must be an existing avra-*.whl file")

    contents: dict[str, bytes] = {name: _text(HERE / name) for name in DEPLOY_FILES}
    contents["scope.yaml"] = _text(scope)
    if pubkey is not None:
        contents[PUBKEY_NAME] = _pubkey_bytes(pubkey)
    contents[wheel.name] = wheel.read_bytes()
    for name, data in contents.items():
        _refuse_secrets(name, data)

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in contents.items():
        (out_dir / name).write_bytes(data)

    names = sorted(contents)
    lines = "".join(f"{_sha256(out_dir / n)}  {n}\n" for n in names)
    (out_dir / "SHA256SUMS").write_bytes(lines.encode("ascii"))
    return _sha256(out_dir / "SHA256SUMS")


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    try:
        digest = build(
            Path(argv[0]), Path(argv[1]), Path(argv[2]), Path(argv[3]) if len(argv) == 4 else None
        )
    except (BundleError, OSError) as exc:
        print(f"make_bundle: {exc}", file=sys.stderr)
        return 1
    print(f"SHA256SUMS sha256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
