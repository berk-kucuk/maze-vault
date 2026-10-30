"""The unlocked vault: sidebar, searchable list, detail pane."""
from __future__ import annotations

from datetime import datetime
from typing import Callable

from PyQt6.QtCore import QModelIndex, QRect, QSize, QTimer, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QKeySequence, QPainter, QShortcut
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                             QListWidgetItem, QMenu, QPushButton, QScrollArea, QStyle,
                             QStyledItemDelegate, QStyleOptionViewItem, QVBoxLayout, QWidget)

from mazevault.core import items as itm
from mazevault.core import totp
from mazevault.core.items import Item
from mazevault.core.vault import Session
from mazevault.gui.chrome import button, label
from mazevault.gui.glass import GlassFrame
from mazevault.gui.glyphs import glyph, glyph_pixmap
from mazevault.gui.i18n import t
from mazevault.gui.pill import Pill
from mazevault.gui.widgets import Clipboard, Ring

TYPE_ICON = {itm.TYPE_LOGIN: "globe", itm.TYPE_NOTE: "note", itm.TYPE_CARD: "card",
             itm.TYPE_IDENTITY: "user", itm.TYPE_SSH_KEY: "key"}
NAV_TYPES = [("login", itm.TYPE_LOGIN, "nav_login"), ("card", itm.TYPE_CARD, "nav_card"),
             ("identity", itm.TYPE_IDENTITY, "nav_identity"), ("note", itm.TYPE_NOTE, "nav_note"),
             ("ssh", itm.TYPE_SSH_KEY, "nav_ssh")]


def subtitle(it: Item) -> str:
    s = it.section()
    if it.type == itm.TYPE_LOGIN:
        return s.get("username") or (s.get("uris") or [{}])[0].get("uri") or ""
    if it.type == itm.TYPE_CARD:
        num = s.get("number") or ""
        brand = s.get("brand") or ""
        return f"{brand} •••• {num[-4:]}".strip() if num else brand
    if it.type == itm.TYPE_IDENTITY:
        return " ".join(x for x in (s.get("firstName"), s.get("lastName")) if x) or s.get("email") or ""
    if it.type == itm.TYPE_SSH_KEY:
        return s.get("keyFingerprint") or ""
    return ""


def matches(it: Item, q: str) -> bool:
    if not q:
        return True
    q = q.lower()
    s = it.section()
    hay = [it.name, subtitle(it), it.data.get("notes") or ""]
    if it.type == itm.TYPE_LOGIN:
        hay += [u.get("uri") or "" for u in s.get("uris") or []]
    return any(q in (h or "").lower() for h in hay)


# ── sidebar ──────────────────────────────────────────────────────────────────
class Sidebar(QWidget):
    changed = pyqtSignal(str)          # filter key
    folder_menu = pyqtSignal(str, object)   # folder id, global pos

    def __init__(self):
        super().__init__(objectName="sidebar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedWidth(230)
        self.current = "all"
        self.v = QVBoxLayout(self)
        self.v.setContentsMargins(12, 14, 12, 12)
        self.v.setSpacing(2)
        self.footer = label("", "statusbar", wrap=True)

    def rebuild(self, session: Session) -> None:
        while self.v.count():
            w = self.v.takeAt(0).widget()
            if w is not None and w is not self.footer:
                w.deleteLater()
        live = session.visible()
        counts = {"all": len(live), "fav": sum(1 for i in live if i.favorite),
                  "trash": len(session.visible(trash=True))}
        for key, typ, _ in NAV_TYPES:
            counts[key] = sum(1 for i in live if i.type == typ)

        def nav(key: str, icon: str, text: str, n: int | None = None) -> None:
            b = QPushButton(text, objectName="nav_on" if key == self.current else "nav")
            b.setIcon(glyph(icon, 16, "#000000" if key == self.current else "#bdbdc2"))
            b.setIconSize(QSize(16, 16))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            if n is not None:
                b.setText(f"{text}   {n}" if n else text)
            b.clicked.connect(lambda _=False, k=key: self._pick(k))
            if key.startswith("folder:"):
                fid = key.split(":", 1)[1]
                b.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                b.customContextMenuRequested.connect(
                    lambda pos, f=fid, w=b: self.folder_menu.emit(f, w.mapToGlobal(pos)))
            self.v.addWidget(b)

        self.v.addWidget(label(t("nav_vault"), "section"))
        nav("all", "vault", t("nav_all"), counts["all"])
        nav("fav", "star", t("nav_fav"), counts["fav"])
        self.v.addSpacing(10)
        self.v.addWidget(label(t("nav_types"), "section"))
        for key, typ, text in NAV_TYPES:
            if key == "ssh" and not counts["ssh"]:
                continue
            nav(key, TYPE_ICON[typ], t(text), counts[key])
        self.v.addSpacing(10)
        head = QHBoxLayout()
        head.addWidget(label(t("nav_folders"), "section"), 1)
        self.add_folder = QPushButton(objectName="mini")
        self.add_folder.setIcon(glyph("plus", 14, "#9a9aa0"))
        self.add_folder.setFixedSize(24, 24)
        self.add_folder.setToolTip(t("fd_new"))
        self.add_folder.setCursor(Qt.CursorShape.PointingHandCursor)
        hw = QWidget()
        hw.setLayout(head)
        head.setContentsMargins(0, 0, 0, 0)
        head.addWidget(self.add_folder)
        self.v.addWidget(hw)
        for fid, name in sorted(session.folders.items(), key=lambda kv: kv[1].lower()):
            n = sum(1 for i in live if i.folder_id == fid)
            nav(f"folder:{fid}", "folder", name, n)
        nav("folder:", "folder", t("nav_nofolder"), sum(1 for i in live if not i.folder_id))
        self.v.addSpacing(10)
        nav("trash", "trash", t("nav_trash"), counts["trash"])
        self.v.addStretch(1)
        self.v.addWidget(self.footer)

    def _pick(self, key: str) -> None:
        self.current = key
        self.changed.emit(key)


# ── list ─────────────────────────────────────────────────────────────────────
class RowDelegate(QStyledItemDelegate):
    H = 56

    def sizeHint(self, option, index) -> QSize:
        return QSize(option.rect.width(), self.H)

    def paint(self, p: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        it: Item = index.data(Qt.ItemDataRole.UserRole)
        r = option.rect
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hover = bool(option.state & QStyle.StateFlag.State_MouseOver)
        if selected or hover:
            bg = QColor(255, 255, 255, 30 if selected else 14)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(bg)
            p.drawRoundedRect(r.adjusted(4, 2, -4, -2), 10, 10)
        icon = "warn" if it.damaged else TYPE_ICON.get(it.type, "note")
        p.drawPixmap(r.left() + 16, r.top() + (self.H - 20) // 2,
                     glyph_pixmap(icon, 20, "#f2f2f4" if selected else "#9a9aa0"))
        f = QFont(option.font)
        f.setPixelSize(13)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor("#f2f2f4"))
        text_r = QRect(r.left() + 50, r.top() + 9, r.width() - 84, 20)
        name = it.name or "—"
        p.drawText(text_r, Qt.AlignmentFlag.AlignVCenter,
                   p.fontMetrics().elidedText(name, Qt.TextElideMode.ElideRight, text_r.width()))
        f.setBold(False)
        f.setPixelSize(11)
        p.setFont(f)
        p.setPen(QColor("#8f8f95"))
        sub_r = QRect(r.left() + 50, r.top() + 29, r.width() - 84, 18)
        p.drawText(sub_r, Qt.AlignmentFlag.AlignVCenter,
                   p.fontMetrics().elidedText(subtitle(it), Qt.TextElideMode.ElideRight, sub_r.width()))
        if it.favorite:
            p.drawPixmap(r.right() - 30, r.top() + (self.H - 14) // 2, glyph_pixmap("star_on", 14, "#bdbdc2"))
        p.restore()


# ── detail ───────────────────────────────────────────────────────────────────
class FieldRow(QWidget):
    def __init__(self, title: str, value: str, *, secret: bool = False, mono: bool = False,
                 link: str | None = None, flash: Callable[[str], None]):
        super().__init__(objectName="fieldrow")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._value = value
        self._secret = secret
        self._shown = not secret
        self._flash = flash
        h = QHBoxLayout(self)
        h.setContentsMargins(14, 8, 8, 8)
        h.setSpacing(6)
        v = QVBoxLayout()
        v.setSpacing(2)
        v.addWidget(label(title, "field"))
        self.val = label("", "fieldval_mono" if (mono or secret) else "fieldval", wrap=not secret)
        self.val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse
                                         if not secret else Qt.TextInteractionFlag.NoTextInteraction)
        v.addWidget(self.val)
        h.addLayout(v, 1)
        if secret:
            self.eye = self._mini("eye", t("show_pw"), self._toggle)
            h.addWidget(self.eye)
        if link:
            h.addWidget(self._mini("external", t("btn_open"),
                                   lambda: QDesktopServices.openUrl(QUrl(link))))
        h.addWidget(self._mini("copy", t("btn_copy"), self._copy))
        self._render()

    def _mini(self, icon: str, tip: str, fn) -> QPushButton:
        b = QPushButton(objectName="mini")
        b.setIcon(glyph(icon, 15, "#bdbdc2"))
        b.setIconSize(QSize(15, 15))
        b.setFixedSize(32, 32)
        b.setToolTip(tip)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.clicked.connect(fn)
        return b

    def _render(self) -> None:
        self.val.setText(self._value if self._shown else "•" * min(max(len(self._value), 8), 24))

    def _toggle(self) -> None:
        self._shown = not self._shown
        self.eye.setIcon(glyph("eye_off" if self._shown else "eye", 15, "#bdbdc2"))
        self._render()

    def _copy(self) -> None:
        secs = Clipboard.copy(self._value, secret=self._secret)
        self._flash(t("copied_clear", n=secs) if secs else t("copied"))


class TotpRow(QWidget):
    def __init__(self, secret: str, flash: Callable[[str], None]):
        super().__init__(objectName="fieldrow")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._flash = flash
        try:
            self._t = totp.parse(secret)
        except totp.TotpError:
            self._t = None
        h = QHBoxLayout(self)
        h.setContentsMargins(14, 8, 8, 8)
        v = QVBoxLayout()
        v.setSpacing(2)
        v.addWidget(label(t("d_totp"), "field"))
        self.code = label("", "totp")
        v.addWidget(self.code)
        h.addLayout(v, 1)
        self.ring = Ring()
        h.addWidget(self.ring)
        b = QPushButton(objectName="mini")
        b.setIcon(glyph("copy", 15, "#bdbdc2"))
        b.setFixedSize(32, 32)
        b.setToolTip(t("btn_copy"))
        b.clicked.connect(self._copy)
        h.addWidget(b)
        self.tick()

    def tick(self) -> None:
        if self._t is None:
            self.code.setText(t("ed_totp_bad"))
            return
        c = self._t.code()
        self.code.setText(f"{c[:len(c) // 2]} {c[len(c) // 2:]}")
        self.ring.set_time(self._t.remaining(), self._t.period)

    def _copy(self) -> None:
        if self._t:
            secs = Clipboard.copy(self._t.code(), secret=True)
            self._flash(t("copied_clear", n=secs) if secs else t("copied"))


def _date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M")
    except (ValueError, AttributeError):
        return "—"


class DetailPane(QScrollArea):
    def __init__(self, page: "VaultPage"):
        super().__init__()
        self.page = page
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.viewport().setAutoFillBackground(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._totp: list[TotpRow] = []
        self._timer = QTimer(self, interval=1000)
        self._timer.timeout.connect(self._tick)
        self.show_item(None)

    def _tick(self) -> None:
        for r in list(self._totp):
            try:
                r.tick()
            except RuntimeError:
                self._totp.remove(r)

    def show_item(self, it: Item | None) -> None:
        self._totp = []
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(18, 18, 22, 22)
        if it is None:
            e = label(t("empty_detail"), "empty")
            e.setAlignment(Qt.AlignmentFlag.AlignCenter)
            outer.addStretch(1)
            outer.addWidget(e)
            outer.addStretch(2)
            self.setWidget(page)
            self._timer.stop()
            return
        box = GlassFrame(radius=18)
        v = QVBoxLayout(box)
        v.setContentsMargins(22, 20, 22, 20)
        v.setSpacing(10)
        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(glyph_pixmap(TYPE_ICON.get(it.type, "note"), 24))
        head.addWidget(ic)
        head.addSpacing(4)
        head.addWidget(label(it.name or "—", "detail_title", wrap=True), 1)
        flash = self.page.flash
        if it.deleted:
            rs = button(t("btn_restore"), "secondary", "restore")
            rs.clicked.connect(lambda: self.page.request.emit("restore", it))
            pg = button(t("btn_purge"), "ghost", "trash")
            pg.clicked.connect(lambda: self.page.request.emit("purge", it))
            head.addWidget(rs)
            head.addWidget(pg)
        else:
            star = QPushButton(objectName="mini")
            star.setIcon(glyph("star_on" if it.favorite else "star", 16, "#f2f2f4"))
            star.setFixedSize(34, 34)
            star.setToolTip(t("fav_remove" if it.favorite else "fav_add"))
            star.setEnabled(it.editable)
            star.clicked.connect(lambda: self.page.request.emit("favorite", it))
            head.addWidget(star)
            ed = button(t("btn_edit"), "secondary", "edit")
            ed.setEnabled(it.editable)
            ed.clicked.connect(lambda: self.page.request.emit("edit", it))
            head.addWidget(ed)
            more = QPushButton(objectName="mini")
            more.setIcon(glyph("more", 16))
            more.setFixedSize(34, 34)
            more.clicked.connect(lambda: self._more(it, more))
            head.addWidget(more)
        v.addLayout(head)
        if it.damaged:
            v.addWidget(self._banner("warn", t("damaged")))
        elif not it.editable:
            v.addWidget(self._banner("lock", t("readonly_org")))
        if it.id in self.page.session.conflicts:
            v.addWidget(self._banner("history", t("conflict")))

        s = it.section()

        def row(title: str, value: str | None, **kw) -> None:
            if value:
                v.addWidget(FieldRow(title, value, flash=flash, **kw))

        if it.type == itm.TYPE_LOGIN:
            row(t("d_username"), s.get("username"))
            row(t("d_password"), s.get("password"), secret=True)
            if s.get("totp"):
                tr = TotpRow(s["totp"], flash)
                self._totp.append(tr)
                v.addWidget(tr)
            for u in s.get("uris") or []:
                uri = u.get("uri") or ""
                link = uri if uri.startswith(("http://", "https://")) else None
                row(t("d_uri"), uri, link=link)
        elif it.type == itm.TYPE_CARD:
            row(t("d_cardholder"), s.get("cardholderName"))
            row(t("d_brand"), s.get("brand"))
            row(t("d_number"), s.get("number"), secret=True, mono=True)
            exp = "/".join(x for x in (s.get("expMonth"), s.get("expYear")) if x)
            row(t("d_expiry"), exp)
            row(t("d_code"), s.get("code"), secret=True)
        elif it.type == itm.TYPE_IDENTITY:
            name = " ".join(x for x in (s.get("title"), s.get("firstName"), s.get("middleName"),
                                         s.get("lastName")) if x)
            row(t("d_name"), name)
            row(t("d_username"), s.get("username"))
            row(t("d_company"), s.get("company"))
            row(t("d_email"), s.get("email"))
            row(t("d_phone"), s.get("phone"))
            addr = "\n".join(x for x in (s.get("address1"), s.get("address2"), s.get("address3"),
                                          " ".join(y for y in (s.get("postalCode"), s.get("city")) if y),
                                          s.get("state"), s.get("country")) if x)
            row(t("d_address"), addr)
            row(t("d_ssn"), s.get("ssn"), secret=True)
            row(t("d_passport"), s.get("passportNumber"), secret=True)
            row(t("d_license"), s.get("licenseNumber"), secret=True)
        elif it.type == itm.TYPE_SSH_KEY:
            row(t("d_fingerprint"), s.get("keyFingerprint"), mono=True)
            row(t("d_public"), s.get("publicKey"), mono=True)
            row(t("d_private"), s.get("privateKey"), secret=True)
        notes = it.data.get("notes")
        if notes:
            v.addWidget(FieldRow(t("d_notes"), notes, flash=flash))
        fields = [f for f in it.data.get("fields") or [] if f.get("name") or f.get("value")]
        if fields:
            v.addSpacing(4)
            v.addWidget(label(t("d_fields"), "section"))
            for f in fields:
                row(f.get("name") or "—", f.get("value") or "", secret=int(f.get("type") or 0) == 1)
        hist = [h for h in it.data.get("passwordHistory") or [] if h.get("password")]
        if hist:
            v.addSpacing(4)
            v.addWidget(label(f"{t('d_history')}  ·  {len(hist)}", "section"))
            for h in hist:
                row(_date(h.get("lastUsedDate") or ""), h.get("password"), secret=True)
        v.addSpacing(6)
        meta = label(f"{t('d_updated', date=_date(it.revision))}   ·   "
                     f"{t('d_created', date=_date(it.raw.get('creationDate') or ''))}", "meta")
        v.addWidget(meta)
        outer.addWidget(box)
        outer.addStretch(1)
        self.setWidget(page)
        if self._totp:
            self._timer.start()
        else:
            self._timer.stop()

    def _banner(self, icon: str, text: str) -> QWidget:
        w = QWidget(objectName="banner")
        w.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        h = QHBoxLayout(w)
        h.setContentsMargins(12, 10, 12, 10)
        ic = QLabel()
        ic.setPixmap(glyph_pixmap(icon, 18, "#e6e6ea"))
        h.addWidget(ic, 0, Qt.AlignmentFlag.AlignTop)
        h.addWidget(label(text, "warnline", wrap=True), 1)
        return w

    def _more(self, it: Item, anchor: QWidget) -> None:
        m = QMenu(self)
        if it.editable:
            fm = m.addMenu(glyph("folder", 16), t("ed_folder").capitalize())
            for fid, name in [(None, t("nav_nofolder"))] + sorted(
                    self.page.session.folders.items(), key=lambda kv: kv[1].lower()):
                a = fm.addAction(name)
                a.setCheckable(True)
                a.setChecked(it.folder_id == fid)
                a.triggered.connect(lambda _=False, f=fid: self.page.request.emit("move", (it, f)))
            m.addSeparator()
        a = m.addAction(glyph("trash", 16), t("btn_delete"))
        a.setEnabled(it.raw.get("edit", True) is not False)
        a.triggered.connect(lambda: self.page.request.emit("trash", it))
        m.exec(anchor.mapToGlobal(anchor.rect().bottomLeft()))


# ── page ─────────────────────────────────────────────────────────────────────
class VaultPage(QWidget):
    request = pyqtSignal(str, object)    # action, payload — handled by the window

    def __init__(self, session: Session, flash: Callable[[str], None]):
        super().__init__()
        self.session = session
        self.flash = flash
        self._selected: str | None = None
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.sidebar = Sidebar()
        self.sidebar.changed.connect(lambda _k: self.refresh_list())
        self.sidebar.folder_menu.connect(lambda f, pos: self.request.emit("folder_menu", (f, pos)))
        h.addWidget(self.sidebar)

        mid = QWidget(objectName="listpane")
        mid.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        mid.setFixedWidth(340)
        mv = QVBoxLayout(mid)
        mv.setContentsMargins(10, 12, 10, 10)
        mv.setSpacing(8)
        top = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(t("ph_search"))
        self.search.addAction(glyph("search", 16, "#8f8f95"), QLineEdit.ActionPosition.LeadingPosition)
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(lambda _s: self.refresh_list())
        top.addWidget(self.search, 1)
        self.new = button(t("btn_new"), "get", "plus")
        self.new.clicked.connect(self._new_menu)
        top.addWidget(self.new)
        mv.addLayout(top)
        self.list = QListWidget(objectName="itemlist")
        self.list.setItemDelegate(RowDelegate(self.list))
        self.list.setMouseTracking(True)
        self.list.setUniformItemSizes(True)
        self.list.setFrameShape(QFrame.Shape.NoFrame)
        self.list.currentItemChanged.connect(self._picked)
        self.list.itemDoubleClicked.connect(self._double)
        mv.addWidget(self.list, 1)
        self.empty = label("", "empty")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        mv.addWidget(self.empty)
        h.addWidget(mid)
        self.detail = DetailPane(self)
        h.addWidget(self.detail, 1)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=lambda: (self.search.setFocus(),
                                                                  self.search.selectAll()))
        QShortcut(QKeySequence("Ctrl+N"), self, activated=self._new_menu)
        self.refresh()

    def set_session(self, s: Session) -> None:
        self.session = s
        self.refresh()

    def refresh(self) -> None:
        self.sidebar.rebuild(self.session)
        self.sidebar.add_folder.clicked.connect(lambda: self.request.emit("new_folder", None))
        self.refresh_list()

    def _filtered(self) -> list[Item]:
        key = self.sidebar.current
        s = self.session
        if key == "trash":
            base = s.visible(trash=True)
        else:
            base = s.visible()
            if key == "fav":
                base = [i for i in base if i.favorite]
            elif key.startswith("folder:"):
                fid = key.split(":", 1)[1] or None
                base = [i for i in base if i.folder_id == fid]
            else:
                for k, typ, _ in NAV_TYPES:
                    if key == k:
                        base = [i for i in base if i.type == typ]
        q = self.search.text().strip()
        return [i for i in base if matches(i, q)]

    def refresh_list(self) -> None:
        keep = self._selected
        self.list.blockSignals(True)
        self.list.clear()
        found = None
        for it in self._filtered():
            li = QListWidgetItem()
            li.setData(Qt.ItemDataRole.UserRole, it)
            self.list.addItem(li)
            if it.id == keep:
                found = li
        self.list.blockSignals(False)
        n = self.list.count()
        self.empty.setText("" if n else (t("empty_search") if self.search.text() else t("empty_list")))
        self.empty.setVisible(not n)
        if found is not None:
            self.list.setCurrentItem(found)
            self.detail.show_item(found.data(Qt.ItemDataRole.UserRole))
        else:
            self._selected = None
            self.detail.show_item(None)

    def select(self, item_id: str | None) -> None:
        self._selected = item_id
        self.refresh_list()

    def _picked(self, cur: QListWidgetItem | None, _prev) -> None:
        it = cur.data(Qt.ItemDataRole.UserRole) if cur else None
        self._selected = it.id if it else None
        self.detail.show_item(it)

    def _double(self, li: QListWidgetItem) -> None:
        it: Item = li.data(Qt.ItemDataRole.UserRole)
        if it.type == itm.TYPE_LOGIN and it.section().get("password"):
            secs = Clipboard.copy(it.section()["password"])
            self.flash(t("copied_clear", n=secs) if secs else t("copied"))

    def _new_menu(self) -> None:
        m = QMenu(self)
        for typ, key in ((itm.TYPE_LOGIN, "new_login"), (itm.TYPE_CARD, "new_card"),
                         (itm.TYPE_IDENTITY, "new_identity"), (itm.TYPE_NOTE, "new_note")):
            a = m.addAction(glyph(TYPE_ICON[typ], 16), t(key))
            a.triggered.connect(lambda _=False, ty=typ: self.request.emit("new", ty))
        m.addSeparator()
        a = m.addAction(glyph("folder", 16), t("new_folder"))
        a.triggered.connect(lambda: self.request.emit("new_folder", None))
        m.exec(self.new.mapToGlobal(self.new.rect().bottomLeft()))
