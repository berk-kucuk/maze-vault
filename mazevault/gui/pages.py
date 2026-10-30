"""The pages before the vault: welcome, sign in, create local vault, lock screen.

Every slow step (the KDF, signing in) runs in a worker; the page shows what it
is doing and its inputs are disabled meanwhile.
"""
from __future__ import annotations

from typing import Any, Callable

from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QStackedWidget, QVBoxLayout, QWidget)

from mazevault.core import api, vault
from mazevault.core.vault import AccountInfo, Session
from mazevault.gui import worker
from mazevault.gui.chrome import button, label
from mazevault.gui.glass import GlassFrame
from mazevault.gui.glyphs import glyph_pixmap
from mazevault.gui.i18n import err, t
from mazevault.gui.icons import logo_pixmap
from mazevault.gui.widgets import MIN_MASTER, PasswordEdit, PinPad, StrengthMeter


def _centered(inner: QWidget, width: int = 520) -> QWidget:
    page = QWidget()
    h = QHBoxLayout(page)
    h.setContentsMargins(24, 24, 24, 24)
    h.addStretch(1)
    col = QVBoxLayout()
    col.addStretch(1)
    inner.setMaximumWidth(width)
    inner.setMinimumWidth(min(width, 420))
    col.addWidget(inner)
    col.addStretch(2)
    h.addLayout(col, 100)
    h.addStretch(1)
    return page


class Form(GlassFrame):
    """A glass panel with fields, an error line, a status line and a busy state."""

    def __init__(self):
        super().__init__(radius=20, tint="#ffffff", strength=1.1)
        self.v = QVBoxLayout(self)
        self.v.setContentsMargins(30, 26, 30, 26)
        self.v.setSpacing(10)
        self.error = label("", "error", wrap=True)
        self.status = label("", "hint", wrap=True)
        self._busy = False

    def field(self, title: str, w: QWidget) -> None:
        self.v.addSpacing(2)
        self.v.addWidget(label(title, "field"))
        self.v.addWidget(w)

    def finish(self) -> None:
        self.v.addWidget(self.error)
        self.v.addWidget(self.status)
        self.error.hide()
        self.status.hide()

    def set_error(self, text: str | None) -> None:
        self.error.setText(text or "")
        self.error.setVisible(bool(text))

    def set_busy(self, text: str | None) -> None:
        self._busy = bool(text)
        self.status.setText(text or "")
        self.status.setVisible(bool(text))
        for w in self.findChildren(QWidget):
            if isinstance(w, (QPushButton, QLineEdit, QCheckBox, QComboBox)):
                w.setEnabled(not self._busy)
        if not self._busy:
            self.refresh()

    def refresh(self) -> None:
        """Re-apply enabled states."""

    def run(self, busy: str, fn: Callable[..., Any], *args, on_done: Callable[[Any], None],
            on_fail: Callable[[BaseException], None] | None = None) -> None:
        self.set_error(None)
        self.set_busy(busy)

        def done(r: Any) -> None:
            self.set_busy(None)
            on_done(r)

        def fail(e: BaseException) -> None:
            self.set_busy(None)
            (on_fail or (lambda x: self.set_error(err(x))))(e)
        worker.run(fn, *args, on_done=done, on_fail=fail)


# ── welcome ──────────────────────────────────────────────────────────────────
class ChoiceCard(GlassFrame):
    clicked = pyqtSignal()

    def __init__(self, icon: str, title: str, sub: str):
        super().__init__(radius=18, interactive=True, strength=1.2)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        h = QHBoxLayout(self)
        h.setContentsMargins(20, 18, 20, 18)
        h.setSpacing(16)
        ic = QLabel()
        ic.setPixmap(glyph_pixmap(icon, 30))
        h.addWidget(ic, 0, Qt.AlignmentFlag.AlignTop)
        v = QVBoxLayout()
        v.setSpacing(4)
        v.addWidget(label(title, "card_title"))
        v.addWidget(label(sub, "tagline", wrap=True))
        h.addLayout(v, 1)
        arrow = QLabel()
        arrow.setPixmap(glyph_pixmap("point", 18, "#9a9aa0"))
        h.addWidget(arrow, 0, Qt.AlignmentFlag.AlignVCenter)

    def mouseReleaseEvent(self, ev) -> None:
        if ev.button() == Qt.MouseButton.LeftButton and self.rect().contains(ev.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(ev)


class WelcomePage(QWidget):
    choose_server = pyqtSignal()
    choose_local = pyqtSignal()
    back = pyqtSignal()

    def __init__(self, can_go_back: bool):
        super().__init__()
        inner = QWidget()
        v = QVBoxLayout(inner)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(12)
        top = QHBoxLayout()
        mark = QLabel()
        mark.setPixmap(logo_pixmap(84))
        top.addWidget(mark)
        top.addStretch(1)
        if can_go_back:
            b = button(t("back"), "ghost", "restore")
            b.clicked.connect(self.back)
            top.addWidget(b, 0, Qt.AlignmentFlag.AlignTop)
        v.addLayout(top)
        v.addSpacing(6)
        v.addWidget(label(t("eyebrow"), "eyebrow"))
        v.addWidget(label(t("hero_title"), "hero_title", wrap=True))
        v.addWidget(label(t("hero_sub"), "hero_sub", wrap=True))
        v.addSpacing(14)
        v.addWidget(label(t("welcome_q"), "section"))
        s = ChoiceCard("server", t("opt_server"), t("opt_server_sub"))
        s.clicked.connect(self.choose_server)
        lc = ChoiceCard("laptop", t("opt_local"), t("opt_local_sub"))
        lc.clicked.connect(self.choose_local)
        v.addWidget(s)
        v.addWidget(lc)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(_centered(inner, 620))


# ── sign in ──────────────────────────────────────────────────────────────────
class LoginPage(QWidget):
    done = pyqtSignal(object)      # Session
    back = pyqtSignal()

    def __init__(self, existing: AccountInfo | None = None):
        super().__init__()
        self._existing = existing
        self._attempt: vault.LoginAttempt | None = None
        self._providers: dict[int, Any] = {}

        self.form = f = Form()
        head = QHBoxLayout()
        head.addWidget(label(t("login_title"), "dlg_title"), 1)
        b = button(t("back"), "ghost", "restore")
        b.clicked.connect(self.back)
        head.addWidget(b)
        f.v.addLayout(head)

        self.stack = QStackedWidget()
        # step 1: credentials
        p1 = QWidget()
        v1 = QVBoxLayout(p1)
        v1.setContentsMargins(0, 0, 0, 0)
        v1.setSpacing(8)
        self.kind = QComboBox()
        self.kind.addItem(t("srv_custom"), "custom")
        self.kind.addItem(t("srv_us"), "us")
        self.kind.addItem(t("srv_eu"), "eu")
        self.kind.currentIndexChanged.connect(self.refresh)
        v1.addWidget(label(t("f_server"), "field"))
        v1.addWidget(self.kind)
        self.url_title = label(t("f_url"), "field")
        self.url = QLineEdit()
        self.url.setPlaceholderText(t("ph_url"))
        v1.addWidget(self.url_title)
        v1.addWidget(self.url)
        self.email = QLineEdit()
        self.email.setPlaceholderText("you@example.com")
        v1.addWidget(label(t("f_email"), "field"))
        v1.addWidget(self.email)
        self.pw = PasswordEdit()
        v1.addWidget(label(t("f_master"), "field"))
        v1.addWidget(self.pw)
        self.stack.addWidget(p1)
        # step 2: two-step login
        p2 = QWidget()
        v2 = QVBoxLayout(p2)
        v2.setContentsMargins(0, 0, 0, 0)
        v2.setSpacing(8)
        v2.addWidget(label(t("tf_title"), "card_title"))
        v2.addWidget(label(t("tf_body"), "tagline", wrap=True))
        self.provider = QComboBox()
        self.provider.currentIndexChanged.connect(self.refresh)
        v2.addWidget(label(t("tf_provider"), "field"))
        v2.addWidget(self.provider)
        self.code = QLineEdit()
        self.code.setObjectName("keyfield")
        self.code.setMaxLength(64)
        row = QHBoxLayout()
        row.addWidget(self.code, 1)
        self.send = button(t("tf_send_email"), "secondary", "note")
        self.send.clicked.connect(self._send_email)
        row.addWidget(self.send)
        v2.addWidget(label(t("tf_code"), "field"))
        v2.addLayout(row)
        self.remember = QCheckBox(t("tf_remember"))
        v2.addWidget(self.remember)
        self.stack.addWidget(p2)
        # step 3: new device OTP
        p3 = QWidget()
        v3 = QVBoxLayout(p3)
        v3.setContentsMargins(0, 0, 0, 0)
        v3.setSpacing(8)
        v3.addWidget(label(t("nd_title"), "card_title"))
        v3.addWidget(label(t("nd_body"), "tagline", wrap=True))
        self.otp = QLineEdit()
        self.otp.setObjectName("keyfield")
        self.otp.setMaxLength(32)
        v3.addWidget(label(t("tf_code"), "field"))
        v3.addWidget(self.otp)
        self.stack.addWidget(p3)
        f.v.addWidget(self.stack)
        f.finish()

        btns = QHBoxLayout()
        btns.addStretch(1)
        self.ok = button(t("btn_login"), "get_lg", "unlock")
        self.ok.clicked.connect(self._submit)
        btns.addWidget(self.ok)
        f.v.addSpacing(6)
        f.v.addLayout(btns)
        f.refresh = self.refresh  # type: ignore[method-assign]
        for w in (self.url, self.email, self.pw, self.code, self.otp):
            w.textChanged.connect(self.refresh)
            w.returnPressed.connect(self._submit)
        if existing is not None:
            self.email.setText(existing.email)
            self.email.setEnabled(False)
            if existing.server:
                kind = existing.server.kind.removeprefix("bitwarden-")
                idx = self.kind.findData(kind if kind in ("us", "eu") else "custom")
                self.kind.setCurrentIndex(max(idx, 0))
                if existing.server.kind == "custom":
                    self.url.setText(existing.server.web)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(_centered(f, 520))
        self.refresh()
        QTimer.singleShot(0, lambda: (self.pw if existing else self.url).setFocus())

    def refresh(self) -> None:
        custom = self.kind.currentData() == "custom"
        self.url.setVisible(custom)
        self.url_title.setVisible(custom)
        step = self.stack.currentIndex()
        if step == 0:
            ok = bool(self.email.text().strip() and self.pw.text()
                      and (not custom or self.url.text().strip()))
        elif step == 1:
            ok = bool(self.code.text().strip())
            self.send.setVisible(self.provider.currentData() == api.TWO_FACTOR_EMAIL)
        else:
            ok = bool(self.otp.text().strip())
        self.ok.setText(t("btn_login") if step == 0 else t("btn_verify"))
        self.ok.setEnabled(ok and not self.form._busy)

    def _server(self) -> api.Server:
        k = self.kind.currentData()
        return api.Server.bitwarden(k) if k in ("us", "eu") else api.Server.custom(self.url.text())

    def _submit(self) -> None:
        if not self.ok.isEnabled():
            return
        step = self.stack.currentIndex()
        if step == 0:
            try:
                server = self._server()
            except api.ApiError as e:
                self.form.set_error(err(e))
                return
            email, pw = self.email.text().strip(), self.pw.text()

            def start() -> Session:
                self._attempt = vault.LoginAttempt(server, email, pw, existing=self._existing)
                return self._attempt.submit()
            self.form.run(t("logging_in"), start, on_done=self._finished, on_fail=self._failed)
        elif step == 1:
            tf = (int(self.provider.currentData()), self.code.text().strip().replace(" ", ""),
                  self.remember.isChecked())
            self.form.run(t("logging_in"), lambda: self._attempt.submit(two_factor=tf),
                          on_done=self._finished, on_fail=self._failed)
        else:
            otp = self.otp.text().strip()
            self.form.run(t("logging_in"), lambda: self._attempt.submit(new_device_otp=otp),
                          on_done=self._finished, on_fail=self._failed)

    def _finished(self, s: Session) -> None:
        self.pw.wipe()
        self.done.emit(s)

    def _failed(self, e: BaseException) -> None:
        if isinstance(e, api.TwoFactorRequired):
            names = {api.TWO_FACTOR_AUTHENTICATOR: t("tf_authenticator"),
                     api.TWO_FACTOR_EMAIL: t("tf_email"), api.TWO_FACTOR_YUBIKEY: t("tf_yubikey")}
            self.provider.clear()
            for p in sorted(e.providers):
                if p in api.SUPPORTED_TWO_FACTOR:
                    self.provider.addItem(names[p], p)
            if self.provider.count() == 0:
                self.form.set_error(t("tf_unsupported"))
                return
            self.stack.setCurrentIndex(1)
            self.code.setFocus()
            self.refresh()
            return
        if isinstance(e, api.NewDeviceOtpRequired):
            self.stack.setCurrentIndex(2)
            self.otp.setFocus()
            self.refresh()
            return
        self.form.set_error(err(e))
        if getattr(e, "reason", "") == "wrong_password":
            self.pw.selectAll()
            self.pw.setFocus()

    def _send_email(self) -> None:
        if self._attempt is None:
            return
        self.form.run(t("logging_in"), self._attempt.send_email_code,
                      on_done=lambda _r: self.form.status.setText(t("tf_sent")) or self.form.status.show())


# ── local vault ──────────────────────────────────────────────────────────────
class LocalCreatePage(QWidget):
    done = pyqtSignal(object)
    back = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.form = f = Form()
        head = QHBoxLayout()
        head.addWidget(label(t("local_title"), "dlg_title"), 1)
        b = button(t("back"), "ghost", "restore")
        b.clicked.connect(self.back)
        head.addWidget(b)
        f.v.addLayout(head)
        self.name = QLineEdit()
        self.name.setPlaceholderText(t("ph_local_name"))
        self.name.setMaxLength(64)
        f.field(t("f_name"), self.name)
        self.pw = PasswordEdit()
        f.field(t("f_master"), self.pw)
        self.meter = StrengthMeter()
        f.v.addWidget(self.meter)
        self.pw2 = PasswordEdit()
        f.field(t("f_confirm"), self.pw2)
        warn = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(glyph_pixmap("warn", 18, "#e6e6ea"))
        warn.addWidget(ic, 0, Qt.AlignmentFlag.AlignTop)
        warn.addWidget(label(t("local_warn"), "warnline", wrap=True), 1)
        f.v.addSpacing(4)
        f.v.addLayout(warn)
        f.finish()
        btns = QHBoxLayout()
        btns.addStretch(1)
        self.ok = button(t("btn_create"), "get_lg", "plus")
        self.ok.clicked.connect(self._create)
        btns.addWidget(self.ok)
        f.v.addLayout(btns)
        f.refresh = self.refresh  # type: ignore[method-assign]
        self.pw.textChanged.connect(self.meter.set_password)
        for w in (self.name, self.pw, self.pw2):
            w.textChanged.connect(self.refresh)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(_centered(f, 520))
        self.refresh()

    def refresh(self) -> None:
        self.ok.setEnabled(len(self.pw.text()) >= MIN_MASTER and bool(self.pw2.text())
                           and not self.form._busy)

    def _create(self) -> None:
        if self.pw.text() != self.pw2.text():
            self.form.set_error(t("pw_mismatch"))
            return
        name, pw = self.name.text().strip() or "Maze Vault", self.pw.text()
        self.form.run(t("creating"), vault.create_local, name, pw,
                      on_done=lambda s: (self.pw.wipe(), self.pw2.wipe(), self.done.emit(s)))


# ── lock screen ──────────────────────────────────────────────────────────────
class LockPage(QWidget):
    unlocked = pyqtSignal(object)      # Session
    add_account = pyqtSignal()
    switch_account = pyqtSignal()
    relogin = pyqtSignal(object)       # AccountInfo

    def __init__(self, info: AccountInfo, session: Session | None, many_accounts: bool):
        super().__init__()
        self.info = info
        self.session = session
        self.form = f = Form()
        top = QVBoxLayout()
        top.setSpacing(6)
        mark = QLabel()
        mark.setPixmap(logo_pixmap(76))
        mark.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        top.addWidget(mark)
        tl = label(t("lock_title"), "dlg_title")
        tl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        top.addWidget(tl)
        who = info.name if info.mode == "local" else info.email
        sub = t("local_vault") if info.mode == "local" else (info.server.web if info.server else "")
        w1 = label(who, "card_title")
        w1.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        w2 = label(sub, "path")
        w2.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        top.addWidget(w1)
        top.addWidget(w2)
        f.v.addLayout(top)
        f.v.addSpacing(8)

        self.stack = QStackedWidget()
        pwp = QWidget()
        pv = QVBoxLayout(pwp)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.setSpacing(8)
        pv.addWidget(label(t("f_master"), "field"))
        self.pw = PasswordEdit()
        self.pw.returnPressed.connect(self._unlock_pw)
        pv.addWidget(self.pw)
        self.ok = button(t("btn_unlock"), "get_lg", "unlock")
        self.ok.clicked.connect(self._unlock_pw)
        r = QHBoxLayout()
        r.addStretch(1)
        r.addWidget(self.ok)
        pv.addSpacing(4)
        pv.addLayout(r)
        self.stack.addWidget(pwp)
        pinp = QWidget()
        pinv = QVBoxLayout(pinp)
        pinv.setContentsMargins(0, 0, 0, 0)
        self.pad = PinPad()
        self.pad.submitted.connect(self._unlock_pin)
        pinv.addWidget(self.pad)
        self.tries = label("", "hint")
        self.tries.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        pinv.addWidget(self.tries)
        self.stack.addWidget(pinp)
        f.v.addWidget(self.stack)
        f.finish()

        links = QHBoxLayout()
        self.toggle = button("", "ghost", "pin")
        self.toggle.clicked.connect(self._toggle)
        links.addWidget(self.toggle)
        links.addStretch(1)
        if many_accounts:
            sw = button(t("switch_account"), "ghost", "list")
            sw.clicked.connect(self.switch_account)
            links.addWidget(sw)
        add = button(t("add_account"), "ghost", "plus")
        add.clicked.connect(self.add_account)
        links.addWidget(add)
        f.v.addLayout(links)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(_centered(f, 480))
        self._show(pin=bool(session and session.has_pin))

    def _show(self, pin: bool) -> None:
        self.stack.setCurrentIndex(1 if pin else 0)
        has_pin = bool(self.session and self.session.has_pin)
        self.toggle.setVisible(has_pin)
        self.toggle.setText(t("use_master") if pin else t("use_pin"))
        if pin and self.session:
            self.tries.setText(t("pin_tries", n=self.session.pin_tries_left))
        QTimer.singleShot(0, lambda: (self.pad if pin else self.pw).setFocus())

    def _toggle(self) -> None:
        self.form.set_error(None)
        self._show(pin=self.stack.currentIndex() == 0)

    def _unlock_pw(self) -> None:
        pw = self.pw.text()
        if not pw:
            return
        if self.session is not None:
            def go() -> Session:
                self.session.unlock_password(pw)
                return self.session
        else:
            def go() -> Session:
                return vault.unlock(self.info, pw)

        def fail(e: BaseException) -> None:
            self.form.set_error(err(e))
            self.pw.selectAll()
            self.pw.setFocus()
        self.form.run(t("unlocking"), go, on_done=self._ok, on_fail=fail)

    def _unlock_pin(self, pin: str) -> None:
        s = self.session
        if s is None:
            return

        def go() -> Session:
            s.unlock_pin(pin)
            return s

        def fail(e: BaseException) -> None:
            if getattr(e, "reason", "") == "pin_wiped":
                self.form.set_error(t("pin_wiped"))
                self._show(pin=False)
            else:
                self.form.set_error(err(e))
                self.tries.setText(t("pin_tries", n=s.pin_tries_left))
                self.pad.setFocus()
        self.form.run(t("unlocking"), go, on_done=self._ok, on_fail=fail)

    def _ok(self, s: Session) -> None:
        self.pw.wipe()
        self.unlocked.emit(s)
