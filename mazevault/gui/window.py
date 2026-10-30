"""Main window: chrome, page flow, locking and every vault action.

Frameless with its own 50px title bar like the other Maze apps. Sessions of
every account used since start stay in `self.sessions`, so a PIN set on one
keeps working after switching back to it; locking drops the keys and every
decrypted item from memory but keeps the PIN-wrapped key.
"""
from __future__ import annotations

import time

from PyQt6.QtCore import QEvent, QObject, QSize, QTimer, Qt
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QLabel, QMainWindow, QMenu,
                             QPushButton, QStackedWidget, QVBoxLayout, QWidget)

from mazevault import __version__
from mazevault.core import items as itm
from mazevault.core import settings, vault
from mazevault.core.items import Item
from mazevault.core.vault import AccountInfo, Session
from mazevault.gui import worker
from mazevault.gui.chrome import EdgeResizer, TitleBar, WindowButton, label
from mazevault.gui.editor import GeneratorDialog, ItemEditor, SettingsDialog
from mazevault.gui.glass import GlassBackground
from mazevault.gui.glyphs import glyph
from mazevault.gui.i18n import err, language, set_language, t
from mazevault.gui.icons import app_logo, logo_pixmap
from mazevault.gui.pages import LocalCreatePage, LockPage, LoginPage, WelcomePage
from mazevault.gui.vaultpage import VaultPage
from mazevault.gui.widgets import Clipboard, ConfirmDialog, TextDialog


class _Activity(QObject):
    """Notes the time of the last keyboard or mouse input, for auto-lock."""

    def __init__(self, win: "MainWindow"):
        super().__init__(win)
        self.win = win

    def eventFilter(self, obj, ev) -> bool:
        if ev.type() in (QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.Wheel):
            self.win.last_activity = time.monotonic()
        return False


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Maze Vault")
        self.setWindowIcon(app_logo())
        self.resize(1180, 780)
        self.setMinimumSize(980, 600)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setMouseTracking(True)
        self._resizer = EdgeResizer(self)
        app = QApplication.instance()
        app.installEventFilter(self._resizer)
        self._activity = _Activity(self)
        app.installEventFilter(self._activity)
        self.last_activity = time.monotonic()

        self.sessions: dict[str, Session] = {}
        self.session: Session | None = None
        self.account: AccountInfo | None = None
        self.vault_page: VaultPage | None = None
        self._syncing = False
        self._offline = False

        self._build_chrome()
        self._idle = QTimer(self, interval=10_000)
        self._idle.timeout.connect(self._check_idle)
        self._idle.start()
        self._autosync = QTimer(self, interval=5 * 60_000)
        self._autosync.timeout.connect(lambda: self.sync(quiet=True))
        self._watch_system()
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self.lock)
        QShortcut(QKeySequence("Ctrl+Q"), self, activated=self.close)
        QShortcut(QKeySequence("F5"), self, activated=self.sync)
        QShortcut(QKeySequence("Ctrl+G"), self, activated=self.generator)
        self.start()

    # ── chrome ─────────────────────────────────────────────────────────────
    def _build_chrome(self) -> None:
        root = GlassBackground()
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        header = TitleBar(self)
        header.setFixedHeight(50)
        h = QHBoxLayout(header)
        h.setContentsMargins(16, 0, 0, 0)
        h.setSpacing(8)
        logo = QLabel()
        logo.setPixmap(logo_pixmap(28))
        h.addWidget(logo)
        h.addWidget(label("MAZE VAULT", "wordmark"))
        h.addStretch(1)
        self._tools = []
        for icon, tip, fn in (("sync", "tip_sync", self.sync), ("dice", "tip_generator", self.generator),
                              ("lock", "tip_lock", self.lock)):
            b = QPushButton(objectName="win_btn")
            b.setIcon(glyph(icon, 16, "#9a9aa0"))
            b.setIconSize(QSize(16, 16))
            b.setToolTip(t(tip))
            b.clicked.connect(fn)
            h.addWidget(b)
            self._tools.append((icon, b))
        for code, text in (("en", "EN"), ("tr", "TR")):
            b = QPushButton(text, objectName="seg_on" if language() == code else "seg")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setToolTip(t("tip_language"))
            b.clicked.connect(lambda _=False, c=code: self.set_lang(c))
            h.addWidget(b)
        gear = QPushButton(objectName="win_btn")
        gear.setIcon(glyph("gear", 16, "#9a9aa0"))
        gear.setIconSize(QSize(16, 16))
        gear.setToolTip(t("tip_settings"))
        gear.clicked.connect(self.open_settings)
        h.addWidget(gear)
        sep = QFrame(objectName="vline")
        sep.setFixedSize(1, 22)
        h.addWidget(sep)
        self._max_btn = WindowButton("win_max", t("tip_maximize"))
        self._max_btn.clicked.connect(lambda: self.showNormal() if self.isMaximized() else self.showMaximized())
        mn = WindowButton("win_min", t("tip_minimize"))
        mn.clicked.connect(self.showMinimized)
        cl = WindowButton("win_close", t("tip_close"))
        cl.clicked.connect(self.close)
        for b in (mn, self._max_btn, cl):
            h.addWidget(b)
        v.addWidget(header)
        self.stack = QStackedWidget()
        v.addWidget(self.stack, 1)
        footer = QWidget(objectName="footer")
        footer.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        footer.setFixedHeight(30)
        fh = QHBoxLayout(footer)
        fh.setContentsMargins(22, 0, 22, 0)
        self._status = label("", "statusbar")
        fh.addWidget(self._status, 1)
        fh.addWidget(label(f"Maze Vault {__version__}", "statusbar"))
        v.addWidget(footer)
        self.setCentralWidget(root)
        self._flash_timer = QTimer(self, singleShot=True, interval=7000)
        self._flash_timer.timeout.connect(lambda: self._status.setText(""))
        self._update_tools()

    def _update_tools(self) -> None:
        unlocked = self.session is not None and not self.session.locked and self.vault_page is not None
        for icon, b in self._tools:
            if icon in ("sync", "lock"):
                b.setVisible(unlocked and (icon != "sync" or self.session.info.mode == "server"))

    def changeEvent(self, ev) -> None:
        if ev.type() == QEvent.Type.WindowStateChange:
            self._max_btn.set_kind("win_restore" if self.isMaximized() else "win_max")
        super().changeEvent(ev)

    def flash(self, text: str) -> None:
        self._status.setText(text)
        self._flash_timer.start()

    def _set_page(self, w: QWidget) -> None:
        old = self.stack.currentWidget()
        self.stack.addWidget(w)
        self.stack.setCurrentWidget(w)
        if old is not None and old is not w:
            self.stack.removeWidget(old)
            old.deleteLater()
        self._update_tools()

    def set_lang(self, code: str) -> None:
        if code == language():
            return
        set_language(code)
        settings.save(language=code)
        self.vault_page = None
        self._build_chrome()
        if self.session is not None and not self.session.locked:
            self._show_vault(self.session)
        else:
            self.start()

    def settings_changed(self) -> None:
        self.last_activity = time.monotonic()

    # ── flow ───────────────────────────────────────────────────────────────
    def start(self) -> None:
        accounts = vault.list_accounts()
        if not accounts:
            self.show_welcome(can_go_back=False)
            return
        last = settings.load()["last_account"]
        info = next((a for a in accounts if a.id == last), accounts[0])
        self.show_lock(info)

    def show_welcome(self, can_go_back: bool = True) -> None:
        self.vault_page = None
        p = WelcomePage(can_go_back)
        p.choose_server.connect(lambda: self.show_login(None))
        p.choose_local.connect(self.show_local_create)
        p.back.connect(self.start)
        self._set_page(p)

    def show_login(self, existing: AccountInfo | None) -> None:
        p = LoginPage(existing)
        p.done.connect(self._signed_in)
        p.back.connect(self.start if existing else lambda: self.show_welcome(bool(vault.list_accounts())))
        self._set_page(p)

    def show_local_create(self) -> None:
        p = LocalCreatePage()
        p.done.connect(self._signed_in)
        p.back.connect(lambda: self.show_welcome(bool(vault.list_accounts())))
        self._set_page(p)

    def show_lock(self, info: AccountInfo) -> None:
        self.vault_page = None
        self.account = info
        s = self.sessions.get(info.id)
        self.session = s
        p = LockPage(info, s, len(vault.list_accounts()) > 1)
        p.unlocked.connect(self._unlocked)
        p.add_account.connect(lambda: self.show_welcome(True))
        p.switch_account.connect(lambda: self._switch_menu(p))
        self._set_page(p)

    def _switch_menu(self, anchor: QWidget) -> None:
        m = QMenu(self)
        for a in vault.list_accounts():
            act = m.addAction(glyph("laptop" if a.mode == "local" else "server", 16),
                              a.name if a.mode == "local" else f"{a.email} · {a.server.web if a.server else ''}")
            act.triggered.connect(lambda _=False, x=a: self.show_lock(x))
        m.exec(anchor.mapToGlobal(anchor.rect().center()))

    def _signed_in(self, s: Session) -> None:
        self.sessions[s.info.id] = s
        self._unlocked(s, synced=True)

    def _unlocked(self, s: Session, synced: bool = False) -> None:
        self.sessions[s.info.id] = s
        self.session = s
        self.account = s.info
        settings.save(last_account=s.info.id)
        self.last_activity = time.monotonic()
        self._show_vault(s)
        if s.info.mode == "server":
            self._autosync.start()
            if not synced:
                self.sync(quiet=True)

    def _show_vault(self, s: Session) -> None:
        p = VaultPage(s, self.flash)
        p.request.connect(self._on_request)
        self.vault_page = p
        self._set_page(p)
        self._update_sync_label()

    def lock(self) -> None:
        s = self.session
        if s is None or s.locked:
            return
        if worker.busy():
            QTimer.singleShot(1000, self.lock)   # finish the running save first
            return
        s.lock()
        self._autosync.stop()
        Clipboard.clear_if_ours()
        self.show_lock(s.info)
        self.flash(t("locked_msg"))

    def _check_idle(self) -> None:
        mins = settings.load()["auto_lock_minutes"]
        if mins and self.session is not None and not self.session.locked and \
                time.monotonic() - self.last_activity > mins * 60:
            self.lock()

    def _watch_system(self) -> None:
        """Lock when the screen locks (org.freedesktop.ScreenSaver) and before
        sleep (logind PrepareForSleep). Missing services are ignored."""
        try:
            from PyQt6.QtDBus import QDBusConnection
        except ImportError:
            return
        self._dbus = _DBusWatcher(self)
        sess = QDBusConnection.sessionBus()
        if sess.isConnected():
            sess.connect("", "/ScreenSaver", "org.freedesktop.ScreenSaver", "ActiveChanged",
                         self._dbus.screensaver)
            sess.connect("", "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver",
                         "ActiveChanged", self._dbus.screensaver)
        sysbus = QDBusConnection.systemBus()
        if sysbus.isConnected():
            sysbus.connect("org.freedesktop.login1", "/org/freedesktop/login1",
                           "org.freedesktop.login1.Manager", "PrepareForSleep", self._dbus.sleep)

    # ── sync ───────────────────────────────────────────────────────────────
    def sync(self, quiet: bool = False) -> None:
        s = self.session
        if s is None or s.locked or s.info.mode != "server" or self._syncing:
            return
        self._syncing = True
        self._update_sync_label()

        def done(_r) -> None:
            self._syncing = False
            self._offline = False
            if self.vault_page is not None and self.session is s and not s.locked:
                self.vault_page.refresh()
            self._update_sync_label()
            if not quiet:
                self.flash(t("synced_msg"))

        def fail(e: BaseException) -> None:
            self._syncing = False
            reason = getattr(e, "reason", "")
            self._offline = reason in ("network", "tls", "server", "timeout")
            self._update_sync_label()
            if reason == "relogin":
                s.lock()
                self.show_login(s.info)
            if not quiet or not self._offline:
                self.flash(err(e))
        worker.run(s.sync, on_done=done, on_fail=fail, critical=False)

    def _update_sync_label(self) -> None:
        p, s = self.vault_page, self.session
        if p is None or s is None:
            return
        if s.info.mode == "local":
            text = t("local_vault")
        elif self._syncing:
            text = t("syncing")
        elif self._offline:
            text = t("offline")
        elif not s.info.last_sync:
            text = t("synced_never")
        else:
            ago = time.time() - s.info.last_sync
            when = t("just_now") if ago < 60 else t("min_ago", n=int(ago // 60)) if ago < 3600 \
                else t("h_ago", n=int(ago // 3600))
            text = t("synced_at", when=when)
        who = s.info.name if s.info.mode == "local" else s.info.email
        try:
            p.sidebar.footer.setText(f"{who}\n{text}")
        except RuntimeError:
            pass

    # ── actions ────────────────────────────────────────────────────────────
    def _op(self, fn, *args, then=None) -> None:
        """Run a vault change in the background, then refresh."""
        s = self.session

        def done(r) -> None:
            if self.vault_page is not None and not s.locked:
                self.vault_page.refresh()
                if then:
                    then(r)
            self._update_sync_label()

        def fail(e: BaseException) -> None:
            self.flash(err(e))
            if self.vault_page is not None and not s.locked:
                self.vault_page.refresh()
        self.flash(t("saving"))
        worker.run(fn, *args, on_done=done, on_fail=fail)

    def _on_request(self, action: str, payload) -> None:
        s = self.session
        if s is None or s.locked:
            return
        if action == "new":
            d = ItemEditor(self, s, payload)
            if d.exec() and d.result_value:
                r = d.result_value
                self._op(s.create, payload, r["plain"], r["folder"],
                         then=lambda it: (self.vault_page.select(it.id), self.flash("")))
        elif action == "edit":
            it: Item = payload
            d = ItemEditor(self, s, it.type, it)
            if d.exec() and d.result_value and d.result_value["changes"]:
                self._op(s.update, it, d.result_value["changes"], then=self._after_update)
        elif action == "favorite":
            it = payload
            self._op(s.update, it, {"favorite": not it.favorite}, then=self._after_update)
        elif action == "move":
            it, fid = payload
            self._op(s.update, it, {"folderId": fid}, then=self._after_update)
        elif action == "trash":
            it = payload
            if ConfirmDialog(self, t("trash_title", name=it.name), t("trash_body"), t("btn_delete"),
                             icon="trash").exec():
                self._op(s.trash, it, then=lambda _r: self.flash(""))
        elif action == "restore":
            self._op(s.restore, payload, then=lambda _r: self.flash(""))
        elif action == "purge":
            it = payload
            if ConfirmDialog(self, t("purge_title", name=it.name), t("purge_body"), t("purge_btn"),
                             danger=True, icon="warn").exec():
                self._op(s.purge, it, then=lambda _r: self.flash(""))
        elif action == "new_folder":
            d = TextDialog(self, t("fd_new"), t("f_name"))
            if d.exec() and d.value:
                self._op(s.create_folder, d.value, then=lambda _r: self.flash(""))
        elif action == "folder_menu":
            fid, pos = payload
            if not fid:
                return
            m = QMenu(self)
            a = m.addAction(glyph("edit", 16), t("fd_rename"))
            a.triggered.connect(lambda: self._rename_folder(fid))
            b = m.addAction(glyph("trash", 16), t("fd_delete"))
            b.triggered.connect(lambda: self._delete_folder(fid))
            m.exec(pos)

    def _after_update(self, result) -> None:
        it, conflict = result
        if conflict:
            self.flash(t("ed_conflict_saved"))
        else:
            self.flash("")
        if it is not None and self.vault_page is not None:
            self.vault_page.select(it.id)

    def _rename_folder(self, fid: str) -> None:
        s = self.session
        d = TextDialog(self, t("fd_rename"), t("f_name"), s.folders.get(fid, ""))
        if d.exec() and d.value:
            self._op(s.rename_folder, fid, d.value, then=lambda _r: self.flash(""))

    def _delete_folder(self, fid: str) -> None:
        s = self.session
        if ConfirmDialog(self, t("fd_delete"), t("fd_delete_body"), t("fd_delete"), icon="folder").exec():
            if self.vault_page is not None:
                self.vault_page.sidebar.current = "all"
            self._op(s.delete_folder, fid, then=lambda _r: self.flash(""))

    def generator(self) -> None:
        GeneratorDialog(self).exec()

    def open_settings(self) -> None:
        s = self.session if self.session is not None and not self.session.locked else None
        SettingsDialog(self, s).exec()

    def sign_out(self) -> None:
        s = self.session
        if s is None or s.info.mode != "server":
            return
        if not ConfirmDialog(self, t("st_signout_title", email=s.info.email), t("st_signout_body"),
                             t("st_signout"), icon="logout").exec():
            return
        s.lock()
        s.forget_pin()
        self.sessions.pop(s.info.id, None)
        try:
            vault.sign_out(s.info)
        except (OSError, vault.VaultError) as e:
            self.flash(err(e))
        self.session = None
        self.start()

    def closeEvent(self, ev) -> None:
        if worker.busy():
            ev.ignore()      # a save is running; it finishes first
            return
        for s in self.sessions.values():
            s.lock()
            s.forget_pin()
        Clipboard.clear_if_ours()
        ev.accept()


class _DBusWatcher(QObject):
    """Receives the D-Bus signals; slots need fixed signatures for QtDBus."""

    def __init__(self, win: MainWindow):
        super().__init__(win)
        self.win = win

    from PyQt6.QtCore import pyqtSlot

    @pyqtSlot(bool)
    def screensaver(self, active: bool) -> None:
        if active and settings.load()["lock_on_screen_lock"]:
            self.win.lock()

    @pyqtSlot(bool)
    def sleep(self, going: bool) -> None:
        if going and settings.load()["lock_on_sleep"]:
            self.win.lock()
