"""GUI smoke tests, offscreen: every page and dialog builds in both languages,
and every English string has a Turkish one."""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mazevault.gui.i18n import STRINGS  # noqa: E402


class StringsTests(unittest.TestCase):
    def test_turkish_complete(self) -> None:
        self.assertEqual(sorted(set(STRINGS["en"]) - set(STRINGS["tr"])), [])

    def test_every_string_formats_through_t(self) -> None:
        # A placeholder named like t()'s own parameter once crashed the app.
        from mazevault.gui import i18n
        for lang in ("en", "tr"):
            i18n.set_language(lang)
            for key, text in STRINGS[lang].items():
                kw = {p: "x" for p in re.findall(r"{(\w+)}", text)}
                out = i18n.t(key, **kw)
                self.assertNotIn("{", out.replace("{{", ""), (lang, key))
        i18n.set_language("en")

    def test_placeholders_match(self) -> None:
        for key, en in STRINGS["en"].items():
            tr = STRINGS["tr"].get(key, "")
            self.assertEqual(set(re.findall(r"{(\w+)}", en)), set(re.findall(r"{(\w+)}", tr)), key)

    def test_every_used_key_exists(self) -> None:
        root = Path(__file__).resolve().parents[1] / "mazevault"
        used = set()
        for f in root.rglob("*.py"):
            used |= set(re.findall(r'\bt\("([a-z0-9_]+)"', f.read_text()))
        used |= set(re.findall(r'"(d_[a-z0-9_]+)"', (root / "gui/editor.py").read_text()))
        self.assertEqual(sorted(used - set(STRINGS["en"])), [])


def _dispose(w) -> None:
    """Delete a window now, not whenever the GC gets to it (after the
    QApplication, which crashes the interpreter at exit)."""
    import gc
    from PyQt6.QtCore import QCoreApplication, QEvent, QThreadPool
    QThreadPool.globalInstance().waitForDone(10_000)
    w._idle.stop()
    w._autosync.stop()
    w.close()
    w.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    gc.collect()


class WindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="maze-vault-gui-"))
        self._env = {k: os.environ.get(k) for k in ("XDG_DATA_HOME", "XDG_CONFIG_HOME")}
        os.environ["XDG_DATA_HOME"] = str(self.tmp / "data")
        os.environ["XDG_CONFIG_HOME"] = str(self.tmp / "config")

    def tearDown(self) -> None:
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_every_page_and_dialog(self) -> None:
        from mazevault.core import vault
        from mazevault.core.crypto import Kdf
        from mazevault.gui import editor, widgets
        from mazevault.gui.i18n import set_language
        from mazevault.gui.window import MainWindow
        vault.PIN_KDF.update(iterations=2, memory=16, parallelism=1)
        s = vault.create_local("T", "correct horse battery", Kdf(1, 2, 16, 1))
        s.create(1, {"name": "L", "login": {"username": "u", "password": "p", "totp": "JBSWY3DP",
                                             "uris": [{"uri": "https://x"}]}})
        s.create(3, {"name": "C", "card": {"number": "4111"}})
        s.create(4, {"name": "I", "identity": {"firstName": "A"}})
        s.create(2, {"name": "N", "notes": "x"})
        s.set_pin("1234")
        for lang in ("en", "tr"):
            set_language(lang)
            w = MainWindow()
            for show in (lambda: w.show_welcome(True), lambda: w.show_login(None),
                         w.show_local_create, lambda: w.show_lock(s.info)):
                show()
                w.grab()
            w._unlocked(s)
            for it in s.visible():
                w.vault_page.select(it.id)
                w.grab()
                editor.ItemEditor(w, s, it.type, it).grab()
            for typ in (1, 2, 3, 4):
                editor.ItemEditor(w, s, typ).grab()
            editor.GeneratorDialog(w, use_button=True).grab()
            editor.SettingsDialog(w, s).grab()
            editor.PinDialog(w, s).grab()
            widgets.ConfirmDialog(w, "a", "b", "c", danger=True).grab()
            w.lock()
            self.assertTrue(s.locked)
            _dispose(w)
        set_language("en")

    def test_clipboard_clears_only_its_own(self) -> None:
        from PyQt6.QtWidgets import QApplication
        from mazevault.gui.widgets import Clipboard
        Clipboard.copy("secret-1")
        self.assertEqual(QApplication.clipboard().text(), "secret-1")
        md = QApplication.clipboard().mimeData()
        self.assertEqual(bytes(md.data("x-kde-passwordManagerHint")), b"secret")
        Clipboard.clear_if_ours()
        self.assertEqual(QApplication.clipboard().text(), "")
        Clipboard.copy("secret-2")
        QApplication.clipboard().setText("user copied something else")
        Clipboard.clear_if_ours()
        self.assertEqual(QApplication.clipboard().text(), "user copied something else")


if __name__ == "__main__":
    unittest.main()
