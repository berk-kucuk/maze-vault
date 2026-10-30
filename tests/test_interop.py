"""Interoperability with the official Bitwarden client, through a real server.

A throwaway Vaultwarden runs on 127.0.0.1 (HTTPS, self-signed, trusted only
here) and the official Bitwarden CLI (`bw`) acts as "the phone": everything
Maze Vault writes must read back correctly in bw, and the other way round.
Vaultwarden alone could not prove this — it never decrypts anything, so a
Maze Vault bug that is consistent with itself would pass.

Skipped when vaultwarden or bw is missing (see harness.py).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness import Bw, Vaultwarden, find_bw, find_vaultwarden  # noqa: E402

from mazevault.core import api, crypto, items  # noqa: E402
from mazevault.core.crypto import Kdf, SymmetricKey  # noqa: E402

VW, BW = find_vaultwarden(), find_bw()
PW = "correct horse battery staple"


class Account:
    """A test account created by Maze Vault, logged in from Maze Vault."""

    def __init__(self, vw: Vaultwarden, email: str, kdf: Kdf):
        self.email = email
        self.client = api.Client(api.Server.custom(vw.url), cafile=str(vw.cert))
        mk = crypto.master_key(PW, email, kdf)
        self.user_key = SymmetricKey.generate()
        pub, der = crypto.generate_rsa()
        self.client.register(email, crypto.master_password_hash(mk, PW),
                             crypto.wrap_user_key(self.user_key, mk), kdf.to_json(), pub,
                             str(crypto.encrypt(der, self.user_key)))
        # Log in the way the app will: prelogin → KDF → hash → token → unwrap.
        k2 = Kdf.from_prelogin(self.client.prelogin(email))
        mk2 = crypto.master_key(PW, email, k2)
        tok = self.client.login_password(email, crypto.master_password_hash(mk2, PW))
        assert crypto.unwrap_user_key(tok.key, mk2) == self.user_key
        self.user_id = items.camel(self.client.sync())["profile"]["id"]

    def items(self) -> dict[str, items.Item]:
        s = items.camel(self.client.sync())
        return {c["id"]: items.decrypt_item(c, lambda _org: self.user_key) for c in s["ciphers"]}


@unittest.skipUnless(VW and BW, "vaultwarden and the Bitwarden CLI are needed")
class InteropTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vw = Vaultwarden(VW).__enter__()
        cls.n = 0

    @classmethod
    def tearDownClass(cls) -> None:
        cls.vw.__exit__()

    def _account(self, kdf: Kdf = Kdf(0, 600_000)) -> tuple[Account, Bw]:
        type(self).n += 1
        email = f"user{self.n}@example.com"
        acc = Account(self.vw, email, kdf)
        bw = Bw(BW, self.vw.url, self.vw.cert)
        self.addCleanup(bw.close)
        bw.login(email, PW)
        return acc, bw

    # accounts ---------------------------------------------------------------
    def test_official_client_logs_into_maze_account_pbkdf2(self) -> None:
        _acc, bw = self._account()
        self.assertEqual(bw.json("list", "items"), [])

    def test_official_client_logs_into_maze_account_argon2id(self) -> None:
        _acc, bw = self._account(Kdf(crypto.KDF_ARGON2ID, 3, 64, 4))
        self.assertEqual(bw.json("list", "items"), [])

    # official → Maze --------------------------------------------------------
    def test_reads_every_type_written_by_official_client(self) -> None:
        acc, bw = self._account()
        made = {
            "login": bw.create_item({
                "type": 1, "name": "Mail ✉ şifre", "notes": "multi\nline", "favorite": True,
                "login": {"username": "me@mail", "password": "p@ss wörd",
                          "totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
                          "uris": [{"uri": "https://mail.example.com", "match": None},
                                   {"uri": "androidapp://com.example.mail", "match": None}]},
                "fields": [{"name": "PIN", "value": "1234", "type": 1}]}),
            "note": bw.create_item({"type": 2, "name": "Note", "notes": "secret note",
                                    "secureNote": {"type": 0}}),
            "card": bw.create_item({"type": 3, "name": "Card", "card": {
                "cardholderName": "A B", "brand": "Visa", "number": "4111111111111111",
                "expMonth": "12", "expYear": "2030", "code": "123"}}),
            "identity": bw.create_item({"type": 4, "name": "Me", "identity": {
                "firstName": "Berk", "lastName": "K", "email": "x@y.z", "city": "İstanbul"}}),
        }
        got = acc.items()
        lg = got[made["login"]["id"]]
        self.assertEqual(lg.damaged, [])
        self.assertEqual(lg.name, "Mail ✉ şifre")
        self.assertEqual(lg.data["notes"], "multi\nline")
        self.assertTrue(lg.favorite)
        self.assertEqual(lg.section()["password"], "p@ss wörd")
        self.assertEqual([u["uri"] for u in lg.section()["uris"]],
                         ["https://mail.example.com", "androidapp://com.example.mail"])
        self.assertEqual(lg.data["fields"][0]["value"], "1234")
        self.assertEqual(got[made["note"]["id"]].data["notes"], "secret note")
        self.assertEqual(got[made["card"]["id"]].section()["number"], "4111111111111111")
        self.assertEqual(got[made["identity"]["id"]].section()["city"], "İstanbul")

    # Maze → official --------------------------------------------------------
    def test_official_client_reads_what_maze_writes(self) -> None:
        acc, bw = self._account()
        for own_key in (True, False):
            body = items.new_item(items.TYPE_LOGIN, {
                "name": f"From Maze {own_key}", "notes": "ñ",
                "login": {"username": "maze", "password": "s3cret!",
                          "uris": [{"uri": "https://maze.example"}]},
                "fields": [{"name": "k", "value": "v", "type": 0}]},
                acc.user_key, acc.user_id, own_key=own_key)
            created = acc.client.create_cipher(body)
            bw.run("sync")
            it = bw.json("get", "item", created["id"])
            self.assertEqual(it["name"], f"From Maze {own_key}")
            self.assertEqual(it["login"]["password"], "s3cret!")
            self.assertEqual(it["login"]["uris"][0]["uri"], "https://maze.example")
            self.assertEqual(it["fields"][0]["value"], "v")
            self.assertEqual(it["notes"], "ñ")
        card = acc.client.create_cipher(items.new_item(items.TYPE_CARD, {
            "name": "C", "card": {"number": "5555555555554444", "code": "999"}}, acc.user_key, acc.user_id))
        bw.run("sync")
        self.assertEqual(bw.json("get", "item", card["id"])["card"]["number"], "5555555555554444")
        note = acc.client.create_cipher(items.new_item(items.TYPE_NOTE, {
            "name": "N", "notes": "body"}, acc.user_key, acc.user_id))
        bw.run("sync")
        self.assertEqual(bw.json("get", "item", note["id"])["notes"], "body")

    # edits keep everything ----------------------------------------------------
    def test_edit_preserves_everything_else(self) -> None:
        acc, bw = self._account()
        made = bw.create_item({
            "type": 1, "name": "Bank", "notes": "keep me",
            "login": {"username": "u", "password": "old-password",
                      "uris": [{"uri": "https://bank.example", "match": None}]},
            "fields": [{"name": "Q", "value": "A", "type": 1}]})
        it = acc.items()[made["id"]]
        body = items.apply_changes(it, {"login": {"password": "new-password"}}, acc.user_key, acc.user_id)
        acc.client.update_cipher(it.id, body)
        bw.run("sync")
        after = bw.json("get", "item", made["id"])
        self.assertEqual(after["login"]["password"], "new-password")
        self.assertEqual(after["login"]["username"], "u")
        self.assertEqual(after["notes"], "keep me")
        self.assertEqual(after["fields"][0]["value"], "A")
        self.assertEqual(after["login"]["uris"][0]["uri"], "https://bank.example")
        self.assertEqual(after["passwordHistory"][0]["password"], "old-password")

    def test_edit_uris_checksums_valid_for_official_client(self) -> None:
        acc, bw = self._account()
        made = bw.create_item({"type": 1, "name": "S",
                               "login": {"uris": [{"uri": "https://a.example", "match": None}]}})
        it = acc.items()[made["id"]]
        body = items.apply_changes(it, {"login": {"uris": [{"uri": "https://b.example"}]}}, acc.user_key, acc.user_id)
        acc.client.update_cipher(it.id, body)
        bw.run("sync")
        self.assertEqual(bw.json("get", "item", made["id"])["login"]["uris"][0]["uri"], "https://b.example")
        again = acc.items()[made["id"]]
        self.assertEqual(again.damaged, [])

    def test_stale_edit_is_refused_not_overwritten(self) -> None:
        acc, bw = self._account()
        made = bw.create_item({"type": 1, "name": "X", "login": {"password": "v1"}})
        stale = acc.items()[made["id"]]
        # The "phone" edits it first.
        cur = bw.json("get", "item", made["id"])
        cur["login"]["password"] = "from-phone"
        bw.run("edit", "item", made["id"], bw.run("encode", stdin=__import__("json").dumps(cur)))
        body = items.apply_changes(stale, {"login": {"password": "from-maze"}}, acc.user_key, acc.user_id)
        with self.assertRaises(api.ApiError):
            acc.client.update_cipher(stale.id, body)
        bw.run("sync")
        self.assertEqual(bw.json("get", "item", made["id"])["login"]["password"], "from-phone")

    def test_soft_delete_goes_to_official_trash(self) -> None:
        acc, bw = self._account()
        made = bw.create_item({"type": 2, "name": "T", "notes": "x", "secureNote": {"type": 0}})
        acc.client.soft_delete_cipher(made["id"])
        bw.run("sync")
        trash = bw.json("list", "items", "--trash")
        self.assertEqual([t["id"] for t in trash], [made["id"]])
        acc.client.restore_cipher(made["id"])
        bw.run("sync")
        self.assertEqual(bw.json("list", "items", "--trash"), [])

    def test_folders_both_ways(self) -> None:
        acc, bw = self._account()
        f = acc.client.create_folder(crypto.encrypt_text("Banka & İş", acc.user_key))
        bw.run("sync")
        names = [x["name"] for x in bw.json("list", "folders")]
        self.assertIn("Banka & İş", names)
        bw_f = __import__("json").loads(bw.run("create", "folder", bw.run(
            "encode", stdin='{"name":"From phone"}')))
        s = items.camel(acc.client.sync())
        got = {x["id"]: items.folder_name(x, acc.user_key) for x in s["folders"]}
        self.assertEqual(got[bw_f["id"]], "From phone")
        self.assertEqual(got[f["id"]], "Banka & İş")

    def test_wrong_password_is_reported_as_such(self) -> None:
        acc, _bw = self._account()
        k = Kdf.from_prelogin(acc.client.prelogin(acc.email))
        mk = crypto.master_key("not the password", acc.email, k)
        with self.assertRaises(api.ApiError) as cm:
            acc.client.login_password(acc.email, crypto.master_password_hash(mk, "not the password"))
        self.assertEqual(cm.exception.reason, "wrong_password")


if __name__ == "__main__":
    unittest.main()
