"""Bitwarden crypto: round trips, tamper detection, KDF limits.

Interoperability with the official clients is checked separately against a
real Vaultwarden and the Bitwarden CLI (test_interop.py); these tests pin the
primitives themselves.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand  # noqa: E402

from mazevault.core import crypto  # noqa: E402
from mazevault.core.crypto import CryptoError, EncString, Kdf, SymmetricKey  # noqa: E402

FAST = Kdf(crypto.KDF_PBKDF2, crypto.PBKDF2_MIN)


class KdfTests(unittest.TestCase):
    def test_pbkdf2_matches_hashlib(self) -> None:
        mk = crypto.master_key("hunter2", "  User@Example.COM ", FAST)
        want = hashlib.pbkdf2_hmac("sha256", b"hunter2", b"user@example.com", FAST.iterations, 32)
        self.assertEqual(mk, want)

    def test_auth_hash_is_one_more_round(self) -> None:
        mk = crypto.master_key("pw", "a@b.c", FAST)
        want = base64.b64encode(hashlib.pbkdf2_hmac("sha256", mk, b"pw", 1, 32)).decode()
        self.assertEqual(crypto.master_password_hash(mk, "pw"), want)
        self.assertNotEqual(crypto.master_password_hash(mk, "pw", local=True), want)

    def test_argon2id_salt_is_sha256_of_email(self) -> None:
        k = Kdf(crypto.KDF_ARGON2ID, 3, 16, 1)
        a = crypto.master_key("pw", "A@B.c", k)
        b = crypto.master_key("pw", "a@b.c", k)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)

    def test_unsafe_kdf_refused(self) -> None:
        for bad in (Kdf(0, 5000), Kdf(0, 99_999), Kdf(0, 10_000_000),
                    Kdf(1, 1, 64, 4), Kdf(1, 3, 8, 4), Kdf(1, 3, 4096, 4), Kdf(7, 1)):
            with self.assertRaises(CryptoError, msg=str(bad)):
                crypto.check_kdf(bad)
        self.assertTrue(Kdf(0, 100_000).weak)
        self.assertFalse(Kdf(0, 600_000).weak)

    def test_prelogin_parsing(self) -> None:
        k = Kdf.from_prelogin({"kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4})
        self.assertEqual(k, Kdf(1, 3, 64, 4))
        k = Kdf.from_prelogin({"Kdf": 0, "KdfIterations": 600000})
        self.assertEqual(k.iterations, 600000)


class StretchTests(unittest.TestCase):
    def test_hkdf_expand_only(self) -> None:
        mk = bytes(range(32))
        s = crypto.stretch(mk)
        # HKDF-Expand with one block is HMAC(prk, info || 0x01).
        self.assertEqual(s.enc, hmac.new(mk, b"enc\x01", hashlib.sha256).digest())
        self.assertEqual(s.mac, hmac.new(mk, b"mac\x01", hashlib.sha256).digest())
        self.assertEqual(s.enc, HKDFExpand(hashes.SHA256(), 32, b"enc").derive(mk))


class EncStringTests(unittest.TestCase):
    def test_round_trip_and_format(self) -> None:
        key = SymmetricKey.generate()
        for text in ("", "a", "x" * 16, "şifre 🔐 パスワード", "line\nbreak"):
            es = crypto.encrypt_text(text, key)
            self.assertTrue(es.startswith("2."))
            self.assertEqual(es.count("|"), 2)
            self.assertTrue(crypto.looks_encrypted(es))
            self.assertEqual(crypto.decrypt_text(es, key), text)
            self.assertEqual(str(EncString.parse(es)), es)

    def test_fresh_iv_every_time(self) -> None:
        key = SymmetricKey.generate()
        self.assertNotEqual(crypto.encrypt_text("same", key), crypto.encrypt_text("same", key))

    def test_tampering_detected(self) -> None:
        key = SymmetricKey.generate()
        es = EncString.parse(crypto.encrypt_text("secret", key))
        flipped = bytearray(es.data)
        flipped[0] ^= 1
        for bad in (EncString(2, es.iv, bytes(flipped), es.mac),
                    EncString(2, bytes(16), es.data, es.mac),
                    EncString(2, es.iv, es.data, bytes(32))):
            with self.assertRaises(CryptoError) as cm:
                crypto.decrypt(bad, key)
            self.assertEqual(cm.exception.reason, "mac_mismatch")

    def test_wrong_key(self) -> None:
        es = crypto.encrypt_text("secret", SymmetricKey.generate())
        with self.assertRaises(CryptoError):
            crypto.decrypt(es, SymmetricKey.generate())

    def test_never_writes_without_mac(self) -> None:
        with self.assertRaises(CryptoError):
            crypto.encrypt(b"x", SymmetricKey(bytes(32), None))

    def test_type0_refused_with_mac_key(self) -> None:
        key = SymmetricKey.generate()
        es = EncString.parse(crypto.encrypt_text("x", key))
        with self.assertRaises(CryptoError):
            crypto.decrypt(EncString(0, es.iv, es.data, None), key)

    def test_garbage(self) -> None:
        for bad in ("", "2.", "2.a|b", "9.AAAA|AAAA|AAAA", "2.!!!|AAAA|AAAA", "hello"):
            with self.assertRaises(CryptoError, msg=bad):
                EncString.parse(bad)
        self.assertFalse(crypto.looks_encrypted("3f6c0e1a-uuid-like"))
        self.assertFalse(crypto.looks_encrypted("2024-01-01T00:00:00Z"))


class AccountKeyTests(unittest.TestCase):
    def test_wrap_unwrap(self) -> None:
        mk = crypto.master_key("correct horse", "me@example.com", FAST)
        uk = SymmetricKey.generate()
        prot = crypto.wrap_user_key(uk, mk)
        self.assertEqual(crypto.unwrap_user_key(prot, mk), uk)
        wrong = crypto.master_key("wrong horse", "me@example.com", FAST)
        with self.assertRaises(CryptoError):
            crypto.unwrap_user_key(prot, wrong)

    def test_legacy_type0_user_key(self) -> None:
        # Accounts from before 2017: the user key wrapped by the master key
        # itself, AES-CBC without a MAC.
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import os
        mk = os.urandom(32)
        uk = os.urandom(64)
        iv = os.urandom(16)
        p = padding.PKCS7(128).padder()
        data = p.update(uk) + p.finalize()
        e = Cipher(algorithms.AES(mk), modes.CBC(iv)).encryptor()
        ct = e.update(data) + e.finalize()
        es = f"0.{crypto.b64(iv)}|{crypto.b64(ct)}"
        self.assertEqual(crypto.unwrap_user_key(es, mk).to_bytes(), uk)

    def test_rsa_round_trip(self) -> None:
        pub, der = crypto.generate_rsa()
        org = SymmetricKey.generate().to_bytes()
        es = crypto.rsa_encrypt(org, pub)
        self.assertTrue(es.startswith("4."))
        self.assertEqual(crypto.rsa_decrypt(es, der), org)


if __name__ == "__main__":
    unittest.main()


class StrictTextTests(unittest.TestCase):
    """V2: invalid UTF-8 is an error, not silently replaced characters that
    the next save would write back for good."""

    def test_invalid_utf8_raises(self):
        key = crypto.SymmetricKey.generate()
        es = str(crypto.encrypt(b"caf\xe9 \xff", key))
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_text(es, key)

    def test_valid_text_round_trips(self):
        key = crypto.SymmetricKey.generate()
        self.assertEqual(crypto.decrypt_text(crypto.encrypt_text("şifre ✓", key), key), "şifre ✓")

    def test_item_with_bad_text_is_read_only(self):
        from mazevault.core import items
        key = crypto.SymmetricKey.generate()
        raw = {"id": "i1", "type": 2, "name": str(crypto.encrypt(b"\xff\xfe", key)),
               "notes": crypto.encrypt_text("ok", key), "secureNote": {"type": 0}}
        it = items.decrypt_item(raw, lambda _org: key)
        self.assertIn("name", it.damaged)
        self.assertFalse(it.editable)
