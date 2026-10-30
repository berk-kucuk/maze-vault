"""TOTP against the RFC 6238 test vectors."""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mazevault.core import totp  # noqa: E402


def b32(s: bytes) -> str:
    return base64.b32encode(s).decode()


class TotpTests(unittest.TestCase):
    # RFC 6238 Appendix B (8 digits)
    VECTORS = [(59, "94287082", "46119246", "90693936"),
               (1111111109, "07081804", "68084774", "25091201"),
               (1111111111, "14050471", "67062674", "99943326"),
               (1234567890, "89005924", "91819424", "93441116"),
               (2000000000, "69279037", "90698825", "38618901"),
               (20000000000, "65353130", "77737706", "47863826")]

    def test_rfc6238(self) -> None:
        keys = {"SHA1": b"12345678901234567890", "SHA256": b"12345678901234567890" * 1 + b"123456789012",
                "SHA512": b"1234567890" * 6 + b"1234"}
        for t, s1, s256, s512 in self.VECTORS:
            for algo, want in (("SHA1", s1), ("SHA256", s256), ("SHA512", s512)):
                uri = f"otpauth://totp/x?secret={b32(keys[algo])}&digits=8&algorithm={algo}"
                self.assertEqual(totp.parse(uri).code(t), want, (t, algo))

    def test_bare_secret_and_spaces(self) -> None:
        a = totp.parse("JBSW Y3DP EHPK 3PXP")
        b = totp.parse("jbswy3dpehpk3pxp")
        self.assertEqual(a.code(1000), b.code(1000))
        self.assertEqual(len(a.code()), 6)
        self.assertEqual(a.remaining(1000), 20)

    def test_steam(self) -> None:
        c = totp.parse("steam://JBSWY3DPEHPK3PXP").code(1000)
        self.assertEqual(len(c), 5)
        self.assertTrue(all(ch in totp.STEAM_CHARS for ch in c))

    def test_rejects_garbage(self) -> None:
        for bad in ("", "otpauth://hotp/x?secret=JBSWY3DP", "not!base32",
                    "otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5"):
            with self.assertRaises(totp.TotpError, msg=bad):
                totp.parse(bad)


if __name__ == "__main__":
    unittest.main()
