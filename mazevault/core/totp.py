"""Two-factor codes for the "totp" field of a login, computed locally.

Accepts what Bitwarden clients accept: a bare base32 secret, an otpauth://totp
URI (secret, digits, period, algorithm), and steam:// secrets (Steam Guard's
5-character alphabet).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
import urllib.parse
from dataclasses import dataclass

STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY"
_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


class TotpError(ValueError):
    pass


@dataclass(frozen=True)
class Totp:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    steam: bool = False

    def code(self, at: float | None = None) -> str:
        counter = int((time.time() if at is None else at) // self.period)
        mac = hmac.new(self.secret, struct.pack(">Q", counter), _ALGOS[self.algorithm]).digest()
        off = mac[-1] & 0x0F
        value = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
        if self.steam:
            out = []
            for _ in range(5):
                out.append(STEAM_CHARS[value % len(STEAM_CHARS)])
                value //= len(STEAM_CHARS)
            return "".join(out)
        return str(value % 10 ** self.digits).zfill(self.digits)

    def remaining(self, at: float | None = None) -> int:
        now = time.time() if at is None else at
        return self.period - int(now) % self.period


def _b32(secret: str) -> bytes:
    s = "".join(secret.split()).replace("-", "").upper().rstrip("=")
    if not s:
        raise TotpError("empty secret")
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except (ValueError, TypeError) as e:
        raise TotpError("not base32") from e


def parse(value: str) -> Totp:
    value = (value or "").strip()
    if value.lower().startswith("steam://"):
        return Totp(_b32(value[8:]), digits=5, steam=True)
    if value.lower().startswith("otpauth://"):
        u = urllib.parse.urlsplit(value)
        if u.netloc.lower() != "totp":
            raise TotpError("only TOTP is supported")
        q = {k.lower(): v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        algo = q.get("algorithm", "SHA1").upper()
        if algo not in _ALGOS:
            raise TotpError("unsupported algorithm")
        try:
            digits = int(q.get("digits", 6))
            period = int(q.get("period", 30))
        except ValueError as e:
            raise TotpError("bad digits/period") from e
        if not 1 <= digits <= 10 or not 1 <= period <= 600:
            raise TotpError("bad digits/period")
        return Totp(_b32(q.get("secret", "")), digits, period, algo)
    return Totp(_b32(value))
