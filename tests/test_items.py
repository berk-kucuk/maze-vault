"""Item codec: unknown fields survive edits, damage is detected, nothing is
written back from an item that could not be fully decrypted."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mazevault.core import crypto, items  # noqa: E402
from mazevault.core.crypto import CryptoError, SymmetricKey  # noqa: E402

UK = SymmetricKey.generate()
UID = "user-1"


def server_copy(body: dict, cid: str = "c1") -> dict:
    """What a server would send back for a create request."""
    out = dict(body)
    out.update({"id": cid, "revisionDate": "2026-10-30T10:00:00Z", "object": "cipherDetails",
                "edit": True, "viewPassword": True, "deletedDate": None})
    return out


def keys(_org):
    return UK


class ItemTests(unittest.TestCase):
    def test_new_item_round_trip_with_own_key(self) -> None:
        body = items.new_item(items.TYPE_LOGIN, {
            "name": "Mail", "notes": "n", "login": {"username": "u", "password": "p",
                                                     "uris": [{"uri": "https://x"}]}}, UK, UID)
        self.assertIn("key", body)
        it = items.decrypt_item(server_copy(body), keys)
        self.assertEqual(it.damaged, [])
        self.assertEqual(it.name, "Mail")
        self.assertEqual(it.section()["password"], "p")
        # The item's fields are under its own key, not the user key.
        with self.assertRaises(CryptoError):
            crypto.decrypt(body["name"], UK)

    def test_unknown_fields_survive_an_edit(self) -> None:
        body = items.new_item(items.TYPE_LOGIN, {"name": "X", "login": {"password": "old"}}, UK, UID)
        raw = server_copy(body)
        ik = items.item_key(raw, UK)
        passkey = {"credentialId": crypto.encrypt_text("cred", ik), "keyType": crypto.encrypt_text("public-key", ik),
                   "counter": crypto.encrypt_text("7", ik), "rpId": crypto.encrypt_text("x.com", ik)}
        raw["login"]["fido2Credentials"] = [passkey]
        raw["futureThing"] = {"nested": crypto.encrypt_text("keep", ik), "n": 3}
        raw["archivedDate"] = "2026-01-01T00:00:00Z"
        it = items.decrypt_item(raw, keys)
        out = items.apply_changes(it, {"login": {"password": "new"}}, UK, UID)
        self.assertEqual(out["login"]["fido2Credentials"], [passkey])   # byte-for-byte
        self.assertEqual(out["futureThing"], raw["futureThing"])
        self.assertEqual(out["archivedDate"], "2026-01-01T00:00:00Z")
        self.assertEqual(out["key"], raw["key"])
        self.assertEqual(out["name"], raw["name"])                      # untouched fields not re-encrypted
        self.assertEqual(crypto.decrypt_text(out["login"]["password"], ik), "new")
        self.assertEqual(crypto.decrypt_text(out["passwordHistory"][0]["password"], ik), "old")
        self.assertEqual(out["lastKnownRevisionDate"], "2026-10-30T10:00:00Z")
        for k in ("id", "object", "edit", "revisionDate"):
            self.assertNotIn(k, out)

    def test_damaged_item_is_read_only(self) -> None:
        body = items.new_item(items.TYPE_LOGIN, {"name": "X", "login": {"password": "p"}}, UK, UID)
        raw = server_copy(body)
        other = SymmetricKey.generate()
        raw["notes"] = crypto.encrypt_text("written with another key", other)
        it = items.decrypt_item(raw, keys)
        self.assertEqual(it.damaged, ["notes"])
        self.assertFalse(it.editable)
        with self.assertRaises(CryptoError):
            items.apply_changes(it, {"name": "Y"}, UK, UID)

    def test_wrong_user_key_marks_whole_item(self) -> None:
        body = items.new_item(items.TYPE_NOTE, {"name": "N", "notes": "x"}, UK, UID)
        it = items.decrypt_item(server_copy(body), lambda _o: SymmetricKey.generate())
        self.assertTrue(it.damaged)
        self.assertFalse(it.editable)

    def test_swapped_uri_detected(self) -> None:
        body = items.new_item(items.TYPE_LOGIN, {"name": "Bank", "login": {
            "uris": [{"uri": "https://bank.example"}]}}, UK, UID)
        raw = server_copy(body)
        ik = items.item_key(raw, UK)
        raw["login"]["uris"][0]["uri"] = crypto.encrypt_text("https://evil.example", ik)
        it = items.decrypt_item(raw, keys)
        self.assertIn("login.uris[0].uriChecksum", it.damaged)

    def test_uri_change_rewrites_checksum_and_legacy_uri(self) -> None:
        body = items.new_item(items.TYPE_LOGIN, {"name": "S", "login": {
            "uris": [{"uri": "https://a"}]}}, UK, UID)
        raw = server_copy(body)
        raw["login"]["uri"] = raw["login"]["uris"][0]["uri"]
        it = items.decrypt_item(raw, keys)
        out = items.apply_changes(it, {"login": {"uris": [{"uri": "https://b"}]}}, UK, UID)
        again = items.decrypt_item(server_copy(out), keys)
        self.assertEqual(again.damaged, [])
        self.assertEqual(again.section()["uris"][0]["uri"], "https://b")
        self.assertNotEqual(again.section().get("uri"), "https://a")

    def test_camel_case(self) -> None:
        self.assertEqual(items.camel({"Name": 1, "Login": {"Uris": [{"Uri": 2}]}}),
                         {"name": 1, "login": {"uris": [{"uri": 2}]}})

    def test_password_history_capped(self) -> None:
        body = items.new_item(items.TYPE_LOGIN, {"name": "X", "login": {"password": "p0"}}, UK, UID)
        raw = server_copy(body)
        for i in range(1, 8):
            it = items.decrypt_item(raw, keys)
            raw = server_copy(items.apply_changes(it, {"login": {"password": f"p{i}"}}, UK, UID))
        self.assertEqual(len(raw["passwordHistory"]), 5)


if __name__ == "__main__":
    unittest.main()
