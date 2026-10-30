"""Bitwarden's client-side cryptography, byte-for-byte.

Everything that leaves this machine — to a Bitwarden server, a Vaultwarden
server or the local vault file — is encrypted here first. The layout is the
one every Bitwarden client uses, so the official mobile app, browser extension
and CLI read what Maze Vault writes and the other way round:

    master key  = KDF(master password, email)          PBKDF2-SHA256 or Argon2id
    auth hash   = PBKDF2-SHA256(master key, password, 1)  sent to the server
    stretched   = HKDF-Expand(master key, "enc"|"mac")  64 bytes
    user key    = decrypt(profile.key, stretched)        64 bytes: enc | mac
    item fields = EncString type 2 under the user key, an organisation key or
                  the item's own key (cipher.key)

EncString type 2 is "2.<iv>|<ciphertext>|<mac>": AES-256-CBC with PKCS#7,
authenticated with HMAC-SHA256 over iv || ciphertext. The MAC is always
checked, in constant time, before anything is decrypted.

The server chooses the KDF parameters. A malicious or compromised server could
offer weak ones to make the auth hash it receives cheap to brute-force, so
`check_kdf` refuses anything below Bitwarden's own minimums (and anything so
large it would only freeze the machine).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_PBKDF2 = 0
KDF_ARGON2ID = 1

# Bitwarden's limits (bitwarden/server KdfSettingsValidator). New accounts get
# 600 000 PBKDF2 iterations; older accounts may still have fewer, but never
# below 100 000 — below that, the server or the account is not to be trusted.
PBKDF2_MIN = 100_000
PBKDF2_RECOMMENDED = 600_000
PBKDF2_MAX = 2_000_000
ARGON2_MIN_ITER, ARGON2_MAX_ITER = 2, 10
ARGON2_MIN_MEM, ARGON2_MAX_MEM = 16, 1024        # MiB
ARGON2_MIN_PAR, ARGON2_MAX_PAR = 1, 16


class CryptoError(Exception):
    """reason: a short key the GUI translates."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as e:
        raise CryptoError("bad_encoding") from e


# ── KDF ──────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Kdf:
    type: int = KDF_PBKDF2
    iterations: int = PBKDF2_RECOMMENDED
    memory: int | None = None        # MiB, Argon2id only
    parallelism: int | None = None   # Argon2id only

    @classmethod
    def from_prelogin(cls, data: dict) -> "Kdf":
        """From a prelogin answer, token answer or profile, in any key case.
        Current servers also send a nested kdfSettings object; it wins."""
        low = {str(k).lower(): v for k, v in (data or {}).items()}
        nested = low.get("kdfsettings")
        if isinstance(nested, dict):
            n = {str(k).lower(): v for k, v in nested.items()}
            low = {"kdf": n.get("kdftype", low.get("kdf")), "kdfiterations": n.get("iterations"),
                   "kdfmemory": n.get("memory"), "kdfparallelism": n.get("parallelism")}
        mem, par = low.get("kdfmemory"), low.get("kdfparallelism")
        kdf = cls(type=int(low.get("kdf") or 0), iterations=int(low.get("kdfiterations") or 0),
                  memory=int(mem) if mem is not None else None,
                  parallelism=int(par) if par is not None else None)
        check_kdf(kdf)
        return kdf

    def to_json(self) -> dict:
        return {"kdf": self.type, "kdfIterations": self.iterations,
                "kdfMemory": self.memory, "kdfParallelism": self.parallelism}

    @property
    def weak(self) -> bool:
        """Allowed, but below what Bitwarden gives new accounts."""
        return self.type == KDF_PBKDF2 and self.iterations < PBKDF2_RECOMMENDED


def check_kdf(kdf: Kdf) -> None:
    if kdf.type == KDF_PBKDF2:
        if not PBKDF2_MIN <= kdf.iterations <= PBKDF2_MAX:
            raise CryptoError("kdf_unsafe", f"PBKDF2 iterations {kdf.iterations}")
    elif kdf.type == KDF_ARGON2ID:
        mem, par = kdf.memory or 0, kdf.parallelism or 0
        if not (ARGON2_MIN_ITER <= kdf.iterations <= ARGON2_MAX_ITER
                and ARGON2_MIN_MEM <= mem <= ARGON2_MAX_MEM
                and ARGON2_MIN_PAR <= par <= ARGON2_MAX_PAR):
            raise CryptoError("kdf_unsafe", f"Argon2id t={kdf.iterations} m={mem} p={par}")
    else:
        raise CryptoError("kdf_unsupported", str(kdf.type))


def master_key(password: str, email: str, kdf: Kdf) -> bytes:
    check_kdf(kdf)
    pw = password.encode()
    salt = email.strip().lower().encode()
    if kdf.type == KDF_PBKDF2:
        return PBKDF2HMAC(hashes.SHA256(), 32, salt, kdf.iterations).derive(pw)
    return Argon2id(salt=hashlib.sha256(salt).digest(), length=32,
                    iterations=kdf.iterations, lanes=int(kdf.parallelism),
                    memory_cost=int(kdf.memory) * 1024).derive(pw)


def master_password_hash(mkey: bytes, password: str, local: bool = False) -> str:
    """What the server checks (1 iteration), or the local unlock check (2)."""
    return b64(PBKDF2HMAC(hashes.SHA256(), 32, password.encode(), 2 if local else 1).derive(mkey))


# ── symmetric keys and EncStrings ────────────────────────────────────────────
@dataclass(frozen=True)
class SymmetricKey:
    enc: bytes
    mac: bytes | None    # None only for legacy type-0 keys

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SymmetricKey":
        if len(raw) == 64:
            return cls(raw[:32], raw[32:])
        if len(raw) == 32:
            return cls(raw, None)
        raise CryptoError("bad_key", f"{len(raw)} bytes")

    @classmethod
    def generate(cls) -> "SymmetricKey":
        return cls.from_bytes(os.urandom(64))

    def to_bytes(self) -> bytes:
        return self.enc + (self.mac or b"")


def stretch(mkey: bytes) -> SymmetricKey:
    enc = HKDFExpand(hashes.SHA256(), 32, b"enc").derive(mkey)
    mac = HKDFExpand(hashes.SHA256(), 32, b"mac").derive(mkey)
    return SymmetricKey(enc, mac)


_ENC_RE = re.compile(r"^[0-6]\.[A-Za-z0-9+/=]+(\|[A-Za-z0-9+/=]+){0,2}$")


def looks_encrypted(value: object) -> bool:
    return isinstance(value, str) and bool(_ENC_RE.match(value))


@dataclass(frozen=True)
class EncString:
    type: int
    iv: bytes | None
    data: bytes
    mac: bytes | None

    @classmethod
    def parse(cls, text: str) -> "EncString":
        if not isinstance(text, str) or not text:
            raise CryptoError("bad_encstring")
        if "." in text.split("|", 1)[0]:
            head, rest = text.split(".", 1)
            try:
                etype = int(head)
            except ValueError as e:
                raise CryptoError("bad_encstring") from e
        else:
            # Pre-2017 strings carry no type prefix.
            rest = text
            etype = 0 if text.count("|") == 1 else 2
        parts = rest.split("|")
        if etype in (0,) and len(parts) == 2:
            return cls(0, unb64(parts[0]), unb64(parts[1]), None)
        if etype in (1, 2) and len(parts) == 3:
            return cls(etype, unb64(parts[0]), unb64(parts[1]), unb64(parts[2]))
        if etype in (3, 4) and len(parts) == 1:
            return cls(etype, None, unb64(parts[0]), None)
        if etype in (5, 6) and len(parts) == 2:
            return cls(etype, None, unb64(parts[0]), unb64(parts[1]))
        raise CryptoError("bad_encstring", f"type {etype}")

    def __str__(self) -> str:
        if self.type == 2:
            return f"2.{b64(self.iv)}|{b64(self.data)}|{b64(self.mac)}"
        if self.type == 0:
            return f"0.{b64(self.iv)}|{b64(self.data)}"
        if self.type in (3, 4):
            return f"{self.type}.{b64(self.data)}"
        raise CryptoError("bad_encstring", f"type {self.type}")


def encrypt(plain: bytes, key: SymmetricKey) -> EncString:
    if key.mac is None:
        raise CryptoError("bad_key", "refusing to write without a MAC")
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    enc = Cipher(algorithms.AES(key.enc), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(key.mac, iv + ct, hashlib.sha256).digest()
    return EncString(2, iv, ct, mac)


def decrypt(es: EncString | str, key: SymmetricKey) -> bytes:
    if isinstance(es, str):
        es = EncString.parse(es)
    if es.type == 2:
        if key.mac is None or es.mac is None:
            raise CryptoError("mac_missing")
        want = hmac.new(key.mac, es.iv + es.data, hashlib.sha256).digest()
        if not hmac.compare_digest(want, es.mac):
            raise CryptoError("mac_mismatch")
    elif es.type == 0:
        # Legacy: no MAC. Only ever accepted for an old account's user key
        # wrapped directly by the master key (see unwrap_user_key).
        if key.mac is not None:
            raise CryptoError("legacy_refused")
    else:
        raise CryptoError("bad_encstring", f"type {es.type} is not symmetric")
    if len(es.data) % 16 or len(es.iv or b"") != 16:
        raise CryptoError("bad_ciphertext")
    dec = Cipher(algorithms.AES(key.enc), modes.CBC(es.iv)).decryptor()
    padded = dec.update(es.data) + dec.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as e:
        raise CryptoError("bad_padding") from e


def encrypt_text(text: str, key: SymmetricKey) -> str:
    return str(encrypt(text.encode(), key))


def decrypt_text(es: str, key: SymmetricKey) -> str:
    return decrypt(es, key).decode("utf-8", errors="replace")


# ── account keys ─────────────────────────────────────────────────────────────
def unwrap_user_key(protected: str, mkey: bytes) -> SymmetricKey:
    """The account's user key from profile.key and the master key.

    Wrong master password → CryptoError("mac_mismatch") (type 2), or a padding
    / length error (legacy type 0); both mean "wrong password" to the caller.
    """
    es = EncString.parse(protected)
    if es.type == 2:
        raw = decrypt(es, stretch(mkey))
    elif es.type == 0:
        raw = decrypt(es, SymmetricKey(mkey, None))
    else:
        raise CryptoError("bad_key")
    return SymmetricKey.from_bytes(raw)


def wrap_user_key(user_key: SymmetricKey, mkey: bytes) -> str:
    return str(encrypt(user_key.to_bytes(), stretch(mkey)))


def generate_rsa() -> tuple[str, bytes]:
    """(public key SPKI DER b64, private key PKCS#8 DER)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    return b64(pub), der


def rsa_decrypt(es: str, private_der: bytes) -> bytes:
    e = EncString.parse(es)
    if e.type not in (3, 4, 5, 6):
        raise CryptoError("bad_encstring", "not an RSA string")
    priv = serialization.load_der_private_key(private_der, None)
    algo = hashes.SHA256() if e.type in (3, 5) else hashes.SHA1()
    try:
        return priv.decrypt(e.data, apadding.OAEP(apadding.MGF1(algo), algo, None))
    except ValueError as ex:
        raise CryptoError("rsa_failed") from ex


def rsa_encrypt(plain: bytes, public_b64: str) -> str:
    pub = serialization.load_der_public_key(unb64(public_b64))
    ct = pub.encrypt(plain, apadding.OAEP(apadding.MGF1(hashes.SHA1()), hashes.SHA1(), None))
    return f"4.{b64(ct)}"
