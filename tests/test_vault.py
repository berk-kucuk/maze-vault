"""Accounts and sessions: local vaults, PIN, offline unlock, conflicts, KDF pinning.

Local-vault tests need nothing. Server tests use the throwaway Vaultwarden and
the official CLI from harness.py and are skipped without them.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness import Bw, Vaultwarden, find_bw, find_vaultwarden  # noqa: E402

from mazevault.core import api, crypto, items, vault  # noqa: E402
from mazevault.core.crypto import Kdf  # noqa: E402
from mazevault.core.vault import VaultError  # noqa: E402

PW = "correct horse battery staple"
FAST_ARGON = Kdf(crypto.KDF_ARGON2ID, 2, 16, 1)


class TempHome(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="maze-vault-test-"))
        self._env = {k: os.environ.get(k) for k in ("XDG_DATA_HOME", "XDG_CONFIG_HOME")}
        os.environ["XDG_DATA_HOME"] = str(self.tmp / "data")
        os.environ["XDG_CONFIG_HOME"] = str(self.tmp / "config")
        self._pin = dict(vault.PIN_KDF)
        vault.PIN_KDF.update(iterations=2, memory=16, parallelism=1)

    def tearDown(self) -> None:
        vault.PIN_KDF.clear()
        vault.PIN_KDF.update(self._pin)
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)


class LocalVaultTests(TempHome):
    def test_create_add_lock_unlock(self) -> None:
        s = vault.create_local("Home", PW, FAST_ARGON)
        s.create(items.TYPE_LOGIN, {"name": "Mail", "login": {"username": "u", "password": "p"}})
        info = vault.list_accounts()[0]
        self.assertEqual(info.mode, "local")
        # Nothing readable on disk.
        for f in info.dir.rglob("*.json"):
            text = f.read_text()
            self.assertNotIn("Mail", text)
            self.assertNotIn('"p"', text)
        with self.assertRaises(VaultError):
            vault.unlock(info, "wrong password")
        s2 = vault.unlock(info, PW)
        self.assertEqual([i.name for i in s2.visible()], ["Mail"])

    def test_trash_restore_purge(self) -> None:
        s = vault.create_local("Home", PW, FAST_ARGON)
        it = s.create(items.TYPE_NOTE, {"name": "N", "notes": "x"})
        with self.assertRaises(VaultError):
            s.purge(it)
        s.trash(it)
        self.assertEqual(s.visible(), [])
        self.assertEqual([i.name for i in s.visible(trash=True)], ["N"])
        s.restore(s.items[it.id])
        self.assertEqual([i.name for i in s.visible()], ["N"])
        s.trash(s.items[it.id])
        s.purge(s.items[it.id])
        self.assertEqual(s.items, {})

    def test_purge_leaves_nothing_on_disk(self) -> None:
        """V1: "delete forever" kept the item in up to ten history snapshots
        and in the vault file's .bak. Its id must be nowhere on disk after."""
        s = vault.create_local("Home", PW, FAST_ARGON)
        keep = s.create(items.TYPE_NOTE, {"name": "Keep", "notes": "k"})
        gone = s.create(items.TYPE_NOTE, {"name": "Gone", "notes": "g"})
        for i in range(3):          # several snapshots that contain it
            s.update(s.items[gone.id], {"name": "Gone", "notes": f"g{i}"})
        s.trash(s.items[gone.id])
        info = vault.list_accounts()[0]
        def holders():
            return [f.name for f in info.dir.rglob("*") if f.is_file()
                    and gone.id.encode() in f.read_bytes()]
        self.assertTrue(holders(), "test setup: the item should be on disk before")
        s.purge(s.items[gone.id])
        self.assertEqual(holders(), [], "the purged item is still on disk")
        # Everything else is untouched: the other item and history still work.
        self.assertTrue(any(keep.id.encode() in f.read_bytes() for f in vault.history(info)))
        s2 = vault.unlock(info, PW)
        self.assertEqual([i.name for i in s2.visible()], ["Keep"])

    def test_edit_keeps_history_and_snapshots(self) -> None:
        s = vault.create_local("Home", PW, FAST_ARGON)
        it = s.create(items.TYPE_LOGIN, {"name": "A", "login": {"password": "one"}})
        new, conflict = s.update(it, {"login": {"password": "two"}})
        self.assertFalse(conflict)
        self.assertEqual(new.section()["password"], "two")
        self.assertEqual(new.data["passwordHistory"][0]["password"], "one")
        self.assertGreaterEqual(len(vault.history(s.info)), 2)

    def test_stale_local_edit_becomes_a_copy(self) -> None:
        s = vault.create_local("Home", PW, FAST_ARGON)
        it = s.create(items.TYPE_LOGIN, {"name": "A", "login": {"password": "one"}})
        stale = it
        s.update(it, {"login": {"password": "two"}})
        copy_item, conflict = s.update(stale, {"login": {"password": "three"}})
        self.assertTrue(conflict)
        pw = sorted(i.section()["password"] for i in s.visible())
        self.assertEqual(pw, ["three", "two"])
        self.assertIn("Maze Vault", copy_item.name)

    def test_folder_delete_keeps_items(self) -> None:
        s = vault.create_local("Home", PW, FAST_ARGON)
        s.create_folder("Work")
        fid = next(iter(s.folders))
        it = s.create(items.TYPE_NOTE, {"name": "N", "notes": "x"}, folder_id=fid)
        s.delete_folder(fid)
        self.assertIsNone(s.items[it.id].folder_id)
        self.assertEqual(len(s.visible()), 1)

    def test_corrupt_vault_file_falls_back_to_backup(self) -> None:
        s = vault.create_local("Home", PW, FAST_ARGON)
        s.create(items.TYPE_NOTE, {"name": "N1", "notes": "x"})
        s.create(items.TYPE_NOTE, {"name": "N2", "notes": "y"})
        (s.info.dir / "vault.json").write_text("{ broken")
        s2 = vault.unlock(s.info, PW)
        self.assertEqual([i.name for i in s2.visible()], ["N1"])  # the .bak: one write behind

    def test_pin(self) -> None:
        s = vault.create_local("Home", PW, FAST_ARGON)
        s.create(items.TYPE_NOTE, {"name": "N", "notes": "x"})
        with self.assertRaises(VaultError):
            s.set_pin("12ab")
        s.set_pin("482915")
        s.lock()
        self.assertTrue(s.locked)
        self.assertEqual(s.items, {})
        with self.assertRaises(VaultError) as cm:
            s.unlock_pin("000000")
        self.assertEqual(cm.exception.reason, "wrong_pin")
        self.assertEqual(s.pin_tries_left, 4)
        s.unlock_pin("482915")
        self.assertEqual([i.name for i in s.visible()], ["N"])
        self.assertEqual(s.pin_tries_left, 5)

    def test_pin_wiped_after_five_wrong(self) -> None:
        s = vault.create_local("Home", PW, FAST_ARGON)
        s.set_pin("1234")
        s.lock()
        for _ in range(4):
            with self.assertRaises(VaultError):
                s.unlock_pin("9999")
        with self.assertRaises(VaultError) as cm:
            s.unlock_pin("9999")
        self.assertEqual(cm.exception.reason, "pin_wiped")
        self.assertFalse(s.has_pin)
        with self.assertRaises(VaultError):
            s.unlock_pin("1234")   # even the right PIN no longer works
        s.unlock_password(PW)
        self.assertFalse(s.locked)

    def test_wrong_owner_refused(self) -> None:
        s = vault.create_local("Home", PW, FAST_ARGON)
        body = items.new_item(items.TYPE_NOTE, {"name": "x"}, s.user_key(), "someone-else")
        with self.assertRaises(VaultError):
            s.backend.create_cipher(body)


VW, BW = find_vaultwarden(), find_bw()


@unittest.skipUnless(VW, "vaultwarden needed")
class ServerVaultTests(TempHome):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vw = Vaultwarden(VW).__enter__()
        cls.n = 0

    @classmethod
    def tearDownClass(cls) -> None:
        cls.vw.__exit__()

    def _register(self, kdf: Kdf = Kdf(0, 600_000)) -> str:
        from test_interop import Account
        type(self).n += 1
        email = f"vault{self.n}@example.com"
        Account(self.vw, email, kdf)
        return email

    def _login(self, email: str) -> vault.Session:
        att = vault.LoginAttempt(api.Server.custom(self.vw.url), email, PW, cafile=str(self.vw.cert))
        return att.submit()

    def test_login_sync_offline_unlock(self) -> None:
        email = self._register()
        s = self._login(email)
        s.create(items.TYPE_LOGIN, {"name": "Online", "login": {"password": "p"}})
        info = vault.list_accounts()[0]
        self.assertEqual(info.mode, "server")
        self.assertTrue(info.user_id)
        self.assertNotIn("Online", (info.dir / "cache.json").read_text())
        # Server gone: still opens from the encrypted cache.
        dead = vault.AccountInfo.from_json(info.to_json())
        dead.server = api.Server.custom("https://127.0.0.1:9")
        s2 = vault.unlock(dead, PW)
        self.assertEqual([i.name for i in s2.visible()], ["Online"])
        with self.assertRaises(ApiErrorOrVault):
            s2.sync()

    def test_token_refresh_after_restart(self) -> None:
        email = self._register()
        self._login(email)
        info = vault.list_accounts()[0]
        s = vault.unlock(info, PW, cafile=str(self.vw.cert))   # no access token yet
        s.sync()                                                # refreshes with the stored token
        s.create(items.TYPE_NOTE, {"name": "after restart", "notes": "x"})
        self.assertEqual([i.name for i in s.visible()], ["after restart"])

    def test_kdf_downgrade_refused(self) -> None:
        email = self._register()
        self._login(email)
        info = vault.list_accounts()[0]
        info.kdf = Kdf(0, 900_000)    # pretend we first saw a stronger KDF
        with self.assertRaises(VaultError) as cm:
            vault.LoginAttempt(api.Server.custom(self.vw.url), email, PW,
                               cafile=str(self.vw.cert), existing=info)
        self.assertEqual(cm.exception.reason, "kdf_downgrade")

    @unittest.skipUnless(BW, "Bitwarden CLI needed")
    def test_conflict_with_phone_keeps_both(self) -> None:
        email = self._register()
        s = self._login(email)
        bw = Bw(BW, self.vw.url, self.vw.cert)
        self.addCleanup(bw.close)
        bw.login(email, PW)
        made = bw.create_item({"type": 1, "name": "Shared", "login": {"password": "v1"}})
        s.sync()
        stale = s.items[made["id"]]
        cur = bw.json("get", "item", made["id"])
        cur["login"]["password"] = "phone"
        bw.run("edit", "item", made["id"], bw.run("encode", stdin=json.dumps(cur)))
        new, conflict = s.update(stale, {"login": {"password": "desktop"}})
        self.assertTrue(conflict)
        bw.run("sync")
        pws = sorted(i["login"]["password"] for i in bw.json("list", "items"))
        self.assertEqual(pws, ["desktop", "phone"])


ApiErrorOrVault = (api.ApiError, VaultError)


if __name__ == "__main__":
    unittest.main()
