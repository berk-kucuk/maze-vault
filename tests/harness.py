"""Throwaway servers and clients for the interop tests.

A Vaultwarden is started on 127.0.0.1 with a random port and a temp data
folder, and torn down afterwards. It never touches a real server: the user's
own Vaultwarden is not contacted by any test.

Tools are found in this order:
    vaultwarden: $MAZE_VAULT_VAULTWARDEN, /usr/bin/vaultwarden, .devtools/vaultwarden
    bw (official Bitwarden CLI): $MAZE_VAULT_BW, .devtools/node_modules/.bin/bw, bw on PATH
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEVTOOLS = ROOT / ".devtools"


def find_vaultwarden() -> str | None:
    for cand in (os.environ.get("MAZE_VAULT_VAULTWARDEN"), "/usr/bin/vaultwarden",
                 str(DEVTOOLS / "vaultwarden")):
        if cand and os.access(cand, os.X_OK):
            return cand
    return None


def find_bw() -> str | None:
    for cand in (os.environ.get("MAZE_VAULT_BW"), str(DEVTOOLS / "node_modules/.bin/bw"),
                 shutil.which("bw")):
        if cand and os.access(cand, os.X_OK):
            return cand
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _self_signed(dir: Path) -> tuple[Path, Path]:
    """A throwaway certificate for 127.0.0.1, trusted only by the tests."""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    cp, kp = dir / "cert.pem", dir / "key.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return cp, kp


class Vaultwarden:
    def __init__(self, binary: str):
        self.binary = binary
        self.dir = Path(tempfile.mkdtemp(prefix="maze-vault-vw-"))
        self.port = _free_port()
        self.url = f"https://127.0.0.1:{self.port}"
        self.cert, self.key = _self_signed(self.dir)
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "Vaultwarden":
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin"),
            "DATA_FOLDER": str(self.dir),
            "ROCKET_ADDRESS": "127.0.0.1",
            "ROCKET_PORT": str(self.port),
            "DOMAIN": self.url,
            "WEB_VAULT_ENABLED": "false",
            "SIGNUPS_ALLOWED": "true",
            "SIGNUPS_VERIFY": "false",
            "LOGIN_RATELIMIT_MAX_BURST": "1000",
            "LOGIN_RATELIMIT_SECONDS": "1",
            "ADMIN_RATELIMIT_MAX_BURST": "1000",
            "LOG_LEVEL": os.environ.get("MAZE_VAULT_VW_LOG", "warn"),
            "I_REALLY_WANT_VOLATILE_STORAGE": "true",
            "ROCKET_TLS": f'{{certs="{self.cert}",key="{self.key}"}}',
        }
        self._log = open(self.dir / "vaultwarden.log", "wb")
        self.proc = subprocess.Popen([self.binary], env=env, cwd=self.dir,
                                     stdout=self._log, stderr=self._log)
        import ssl
        ctx = ssl.create_default_context(cafile=str(self.cert))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("vaultwarden exited:\n" + self.log())
            try:
                with urllib.request.urlopen(f"{self.url}/alive", timeout=1, context=ctx):
                    return self
            except OSError:
                time.sleep(0.2)
        self.__exit__()
        raise RuntimeError("vaultwarden did not start:\n" + self.log())

    def log(self) -> str:
        try:
            return (self.dir / "vaultwarden.log").read_text(errors="replace")[-3000:]
        except OSError:
            return ""

    def __exit__(self, *exc) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        log = getattr(self, "_log", None)
        if log is not None:
            log.close()
        shutil.rmtree(self.dir, ignore_errors=True)


class Bw:
    """The official Bitwarden CLI with its own throwaway app-data folder."""

    def __init__(self, binary: str, server_url: str, cafile: Path | None = None):
        self.binary = binary
        self.dir = Path(tempfile.mkdtemp(prefix="maze-vault-bw-"))
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin"), "HOME": str(self.dir),
                    **({"NODE_EXTRA_CA_CERTS": str(cafile)} if cafile else {}),
                    "BITWARDENCLI_APPDATA_DIR": str(self.dir / "appdata"),
                    "BW_NOINTERACTION": "true", "NODE_NO_WARNINGS": "1"}
        self.session: str | None = None
        self.run("config", "server", server_url)

    def run(self, *args: str, stdin: str | None = None, check: bool = True) -> str:
        env = dict(self.env)
        if self.session:
            env["BW_SESSION"] = self.session
        r = subprocess.run([self.binary, *args], input=stdin, env=env, capture_output=True,
                           text=True, timeout=180)
        if check and r.returncode != 0:
            raise RuntimeError(f"bw {' '.join(args[:2])} failed: {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout.strip()

    def login(self, email: str, password: str) -> None:
        env_pw = {"MAZE_TEST_PW": password}
        self.env.update(env_pw)
        self.session = self.run("login", email, "--passwordenv", "MAZE_TEST_PW", "--raw")

    def json(self, *args: str):
        return json.loads(self.run(*args))

    def create_item(self, item: dict) -> dict:
        encoded = self.run("encode", stdin=json.dumps(item))
        return json.loads(self.run("create", "item", encoded))

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)
