"""Shared widgets: dialogs on the frameless black base, password fields, the
strength meter, the PIN pad, the TOTP ring and the clipboard guard."""
from __future__ import annotations

import math
from typing import Any, Callable

from PyQt6.QtCore import QMimeData, QRectF, QSize, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QPainter, QPen
from PyQt6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QGridLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, QRadioButton,
                             QSpinBox, QVBoxLayout, QWidget)

from mazevault.core import settings
from mazevault.gui import worker
from mazevault.gui.chrome import TitleBar, WindowButton, button, label
from mazevault.gui.glyphs import glyph, glyph_pixmap
from mazevault.gui.i18n import err, t

MIN_MASTER = 12


# ── clipboard ────────────────────────────────────────────────────────────────
class Clipboard:
    """Copies secrets with KDE's password-manager hint, so Klipper keeps no
    history of them, and clears them after the configured delay — unless the
    user has copied something else meanwhile."""

    _timer: QTimer | None = None
    _value: str = ""

    @classmethod
    def copy(cls, text: str, secret: bool = True) -> int:
        cb = QApplication.clipboard()
        if cb is None:
            return 0
        mime = QMimeData()
        mime.setText(text)
        if secret:
            mime.setData("x-kde-passwordManagerHint", b"secret")
        cb.setMimeData(mime)
        secs = settings.load()["clipboard_seconds"] if secret else 0
        cls._value = text if secs else ""
        if cls._timer is None:
            # Parented to the application: an orphan QTimer would outlive it
            # and crash the interpreter at exit.
            cls._timer = QTimer(QApplication.instance(), singleShot=True)
            cls._timer.timeout.connect(cls.clear_if_ours)
            cls._timer.destroyed.connect(cls._forget_timer)
        if secs:
            cls._timer.start(secs * 1000)
        return secs

    @classmethod
    def _forget_timer(cls, *_a) -> None:
        cls._timer = None

    @classmethod
    def clear_if_ours(cls) -> None:
        cb = QApplication.clipboard()
        if cb is not None and cls._value and cb.text() == cls._value:
            cb.clear()
        cls._value = ""


# ── inputs ───────────────────────────────────────────────────────────────────
class PasswordEdit(QLineEdit):
    def __init__(self, placeholder: str = "", mono: bool = False):
        super().__init__()
        self.setEchoMode(QLineEdit.EchoMode.Password)
        self.setPlaceholderText(placeholder)
        self.setMaxLength(1024)
        if mono:
            self.setObjectName("keyfield")
        self._toggle = QAction(glyph("eye", 16, "#9a9aa0"), t("show_pw"), self)
        self._toggle.triggered.connect(self.flip)
        self.addAction(self._toggle, QLineEdit.ActionPosition.TrailingPosition)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)

    def flip(self) -> None:
        hidden = self.echoMode() == QLineEdit.EchoMode.Password
        self.setEchoMode(QLineEdit.EchoMode.Normal if hidden else QLineEdit.EchoMode.Password)
        self._toggle.setIcon(glyph("eye_off" if hidden else "eye", 16, "#9a9aa0"))
        self._toggle.setText(t("hide_pw" if hidden else "show_pw"))

    def wipe(self) -> None:
        self.setText("")


def strength(pw: str, minimum: int = MIN_MASTER) -> int:
    if len(pw) < minimum:
        return 0
    from mazevault.core.generator import entropy_bits
    bits = min(entropy_bits(pw), len(set(pw)) * 2 * math.log2(95))
    return 1 if bits < 50 else 2 if bits < 65 else 3 if bits < 90 else 4


class StrengthMeter(QWidget):
    def __init__(self, minimum: int = MIN_MASTER):
        super().__init__()
        self._min = minimum
        self._score = -1
        self._label = ""
        self.setFixedHeight(22)

    def set_password(self, pw: str) -> None:
        self._score = -1 if not pw else strength(pw, self._min)
        self._label = "" if not pw else (t("strength_0", n=self._min) if self._score == 0
                                         else t(f"strength_{self._score}"))
        self.update()

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        seg_w, gap = 34, 5
        for i in range(4):
            on = self._score > i
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor("#f2f2f4") if on else QColor(255, 255, 255, 26))
            p.drawRoundedRect(QRectF(i * (seg_w + gap), 8, seg_w, 5), 2.5, 2.5)
        p.setPen(QColor("#f2f2f4") if self._score == 0 else QColor("#9a9aa0"))
        f = p.font()
        f.setPixelSize(11)
        f.setBold(self._score == 0)
        p.setFont(f)
        p.drawText(QRectF(4 * (seg_w + gap) + 6, 0, self.width(), 22),
                   Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, self._label)
        p.end()


# ── dialogs ──────────────────────────────────────────────────────────────────
class Dialog(QDialog):
    """Frameless black dialog: header with title and ✕, body, button row.
    While busy (a worker runs) it cannot be closed."""

    def __init__(self, parent: QWidget | None, title: str, width: int = 520):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setModal(True)
        self.setFixedWidth(width)
        self._busy = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(1, 1, 1, 1)
        outer.setSpacing(0)
        head = TitleBar(self, name="dlg_header")
        head.setFixedHeight(56)
        h = QHBoxLayout(head)
        h.setContentsMargins(24, 0, 0, 0)
        h.addWidget(label(title, "dlg_title"))
        h.addStretch(1)
        self._close = WindowButton("win_close", t("tip_close"))
        self._close.clicked.connect(self.reject)
        h.addWidget(self._close)
        outer.addWidget(head)
        body = QWidget()
        self.body = QVBoxLayout(body)
        self.body.setContentsMargins(24, 4, 24, 6)
        self.body.setSpacing(10)
        outer.addWidget(body)
        st = QWidget()
        sv = QVBoxLayout(st)
        sv.setContentsMargins(24, 0, 24, 0)
        self._error = label("", "error", wrap=True)
        self._error.hide()
        self._status = label("", "hint", wrap=True)
        self._status.hide()
        sv.addWidget(self._error)
        sv.addWidget(self._status)
        outer.addWidget(st)
        foot = QWidget()
        self.buttons = QHBoxLayout(foot)
        self.buttons.setContentsMargins(24, 14, 24, 22)
        self.buttons.setSpacing(10)
        self.buttons.addStretch(1)
        outer.addWidget(foot)

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), QColor("#0a0a0b"))
        p.setPen(QPen(QColor(255, 255, 255, 36), 1))
        p.drawRect(self.rect().adjusted(0, 0, -1, -1))
        p.end()

    def add_field(self, title: str, widget: QWidget, hint: str | None = None) -> None:
        self.body.addSpacing(2)
        self.body.addWidget(label(title, "field"))
        self.body.addWidget(widget)
        if hint:
            self.body.addWidget(label(hint, "hint", wrap=True))

    def add_text(self, text: str, name: str = "tagline") -> QLabel:
        lb = label(text, name, wrap=True)
        self.body.addWidget(lb)
        return lb

    def add_button(self, text: str, name: str = "secondary_lg", icon: str | None = None) -> QPushButton:
        b = button(text, name, icon)
        self.buttons.addWidget(b)
        return b

    def set_error(self, text: str | None) -> None:
        self._error.setText(text or "")
        self._error.setVisible(bool(text))
        self.adjustSize()

    def set_busy(self, text: str | None) -> None:
        self._busy = bool(text)
        self._status.setText(text or "")
        self._status.setVisible(bool(text))
        for w in self.findChildren(QWidget):
            if isinstance(w, (QPushButton, QLineEdit, QCheckBox, QComboBox, QRadioButton, QSpinBox)):
                w.setEnabled(not self._busy)
        if not self._busy:
            self._after_unbusy()
        self.adjustSize()

    def _after_unbusy(self) -> None:
        """Re-apply enabled/disabled rules after set_busy(None)."""

    def run(self, busy_text: str, fn: Callable[..., Any], *args, on_done: Callable[[Any], None],
            on_fail: Callable[[BaseException], None] | None = None, **kwargs) -> None:
        self.set_error(None)
        self.set_busy(busy_text)

        def done(r: Any) -> None:
            self.set_busy(None)
            on_done(r)

        def fail(e: BaseException) -> None:
            self.set_busy(None)
            (on_fail or (lambda x: self.set_error(err(x))))(e)
        worker.run(fn, *args, on_done=done, on_fail=fail, **kwargs)

    def reject(self) -> None:
        if not self._busy:
            super().reject()

    def showEvent(self, ev) -> None:
        super().showEvent(ev)
        self.adjustSize()


class ConfirmDialog(Dialog):
    def __init__(self, parent: QWidget | None, title: str, body: str, confirm_text: str,
                 danger: bool = False, icon: str | None = None):
        super().__init__(parent, title, 500)
        row = QHBoxLayout()
        if icon:
            ic = QLabel()
            ic.setPixmap(glyph_pixmap(icon, 26))
            row.addWidget(ic, 0, Qt.AlignmentFlag.AlignTop)
            row.addSpacing(6)
        row.addWidget(label(body, "tagline", wrap=True), 1)
        self.body.addLayout(row)
        cancel = self.add_button(t("btn_cancel"), "secondary_lg")
        cancel.clicked.connect(self.reject)
        self.ok = self.add_button(confirm_text, "danger_lg" if danger else "get_lg")
        self.ok.clicked.connect(self.accept)
        self.ok.setDefault(not danger)


class TextDialog(Dialog):
    def __init__(self, parent: QWidget | None, title: str, field_title: str, initial: str = ""):
        super().__init__(parent, title, 460)
        self.value: str | None = None
        self.edit = QLineEdit(initial)
        self.edit.setMaxLength(200)
        self.edit.selectAll()
        self.add_field(field_title, self.edit)
        cancel = self.add_button(t("btn_cancel"), "secondary_lg")
        cancel.clicked.connect(self.reject)
        ok = self.add_button(t("btn_save"), "get_lg", "check")
        ok.setDefault(True)
        ok.clicked.connect(self._go)

    def _go(self) -> None:
        v = " ".join(self.edit.text().split())
        if not v:
            self.set_error(t("ed_name_required"))
            return
        self.value = v
        self.accept()


# ── PIN pad ──────────────────────────────────────────────────────────────────
class PinPad(QWidget):
    submitted = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._pin = ""
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(18)
        self.dots = QLabel()
        self.dots.setObjectName("pin_dots")
        self.dots.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(self.dots)
        grid = QGridLayout()
        grid.setSpacing(12)
        keys = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "back", "0", "ok"]
        for i, k in enumerate(keys):
            b = QPushButton(objectName="pinkey")
            b.setFixedSize(68, 56)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            if k == "back":
                b.setIcon(glyph("backspace", 20))
                b.setIconSize(QSize(20, 20))
                b.clicked.connect(self.backspace)
            elif k == "ok":
                b.setIcon(glyph("check", 20, "#000000"))
                b.setIconSize(QSize(20, 20))
                b.setObjectName("pinkey_ok")
                b.clicked.connect(self.submit)
            else:
                b.setText(k)
                b.clicked.connect(lambda _=False, d=k: self.press(d))
            grid.addWidget(b, i // 3, i % 3)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addLayout(grid)
        row.addStretch(1)
        v.addLayout(row)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._render()

    def _render(self) -> None:
        self.dots.setText("  ".join("●" for _ in self._pin) if self._pin else "·  ·  ·  ·")

    def press(self, d: str) -> None:
        if len(self._pin) < 12:
            self._pin += d
            self._render()

    def backspace(self) -> None:
        self._pin = self._pin[:-1]
        self._render()

    def clear(self) -> None:
        self._pin = ""
        self._render()

    def submit(self) -> None:
        if self._pin:
            pin, self._pin = self._pin, ""
            self._render()
            self.submitted.emit(pin)

    def keyPressEvent(self, ev) -> None:
        txt = ev.text()
        if txt.isdigit():
            self.press(txt)
        elif ev.key() == Qt.Key.Key_Backspace:
            self.backspace()
        elif ev.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.submit()
        else:
            super().keyPressEvent(ev)


# ── TOTP ring ────────────────────────────────────────────────────────────────
class Ring(QWidget):
    """Seconds left of a TOTP period, as a closing ring with the number inside."""

    def __init__(self, size: int = 26):
        super().__init__()
        self.setFixedSize(size, size)
        self._left, self._period = 30, 30

    def set_time(self, left: int, period: int) -> None:
        self._left, self._period = left, period
        self.update()

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        p.setPen(QPen(QColor(255, 255, 255, 30), 2.2))
        p.drawEllipse(r)
        pen = QPen(QColor("#f2f2f4"), 2.2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        span = int(360 * 16 * self._left / max(self._period, 1))
        p.drawArc(r, 90 * 16, span)
        f = p.font()
        f.setPixelSize(9)
        f.setBold(True)
        p.setFont(f)
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, str(self._left))
        p.end()
