"""Item editor, password generator, settings and PIN dialogs."""
from __future__ import annotations

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit,
                             QPlainTextEdit, QPushButton, QScrollArea, QSlider, QFrame,
                             QVBoxLayout, QWidget)

from mazevault import __version__
from mazevault.core import generator, items as itm, settings, totp
from mazevault.core.items import Item
from mazevault.core.vault import Session
from mazevault.gui.chrome import button, label
from mazevault.gui.glyphs import glyph
from mazevault.gui.i18n import language, t
from mazevault.gui.widgets import Clipboard, Dialog, PasswordEdit

TYPE_NAME = {itm.TYPE_LOGIN: "new_login", itm.TYPE_CARD: "new_card",
             itm.TYPE_IDENTITY: "new_identity", itm.TYPE_NOTE: "new_note"}
SECTION_LABELS = {
    "login": [("username", "d_username", False), ("password", "d_password", True),
              ("totp", "d_totp", False)],
    "card": [("cardholderName", "d_cardholder", False), ("brand", "d_brand", False),
             ("number", "d_number", True), ("expMonth", "d_exp_month", False), ("expYear", "d_exp_year", False),
             ("code", "d_code", True)],
    "identity": [("title", "d_title", False), ("firstName", "d_first", False),
                 ("middleName", "d_middle", False), ("lastName", "d_last", False),
                 ("username", "d_username", False), ("company", "d_company", False),
                 ("email", "d_email", False), ("phone", "d_phone", False),
                 ("address1", "d_addr1", False), ("address2", "d_addr2", False),
                 ("address3", "d_addr3", False), ("city", "d_city", False),
                 ("state", "d_state", False), ("postalCode", "d_postal", False),
                 ("country", "d_country", False), ("ssn", "d_ssn", True),
                 ("passportNumber", "d_passport", True), ("licenseNumber", "d_license", True)],
}


class ItemEditor(Dialog):
    """Create or edit. Returns (type, changes or plain, folder) via .result_value;
    the window does the (slow, networked) save in a worker."""

    def __init__(self, parent: QWidget | None, session: Session, item_type: int,
                 item: Item | None = None):
        title = t("ed_edit") if item else t("ed_new", type=t(TYPE_NAME.get(item_type, "new_note")).lower())
        super().__init__(parent, title, 600)
        self.session = session
        self.item = item
        self.type = item_type
        self.result_value: dict | None = None
        data = item.data if item else {}
        sec_name = itm.SECTION.get(item_type, "")
        sec = (data.get(sec_name) or {}) if item else {}

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setMaximumHeight(560)
        inner = QWidget()
        self.form = QVBoxLayout(inner)
        self.form.setContentsMargins(0, 0, 8, 0)
        self.form.setSpacing(8)
        scroll.setWidget(inner)
        self.body.addWidget(scroll)

        self.name = QLineEdit(data.get("name") or "")
        self._field(t("f_name"), self.name)
        self.inputs: dict[str, QLineEdit] = {}
        for key, lbl, secret in SECTION_LABELS.get(sec_name, []):
            w = PasswordEdit() if secret else QLineEdit()
            w.setText(sec.get(key) or "")
            title = t(lbl)
            if key == "password":
                row = QHBoxLayout()
                row.addWidget(w, 1)
                g = button(t("ed_generate"), "secondary", "dice")
                g.clicked.connect(lambda _=False, target=w: self._generate(target))
                row.addWidget(g)
                self.form.addWidget(label(title.upper(), "field"))
                self.form.addLayout(row)
            else:
                self._field(title.upper(), w)
            self.inputs[key] = w

        self.uris: list[QLineEdit] = []
        if item_type == itm.TYPE_LOGIN:
            self.form.addSpacing(4)
            self.form.addWidget(label(t("ed_uris"), "field"))
            self.uri_box = QVBoxLayout()
            self.form.addLayout(self.uri_box)
            for u in sec.get("uris") or [{}]:
                self._add_uri(u.get("uri") or "")
            add = button(t("ed_add_uri"), "ghost", "plus")
            add.clicked.connect(lambda: self._add_uri(""))
            self.form.addWidget(add, 0, Qt.AlignmentFlag.AlignLeft)

        self.form.addSpacing(4)
        self.form.addWidget(label(t("d_notes").upper(), "field"))
        self.notes = QPlainTextEdit(data.get("notes") or "")
        self.notes.setFixedHeight(90)
        self.form.addWidget(self.notes)

        self.form.addSpacing(4)
        self.form.addWidget(label(t("ed_fields"), "field"))
        self.field_box = QVBoxLayout()
        self.form.addLayout(self.field_box)
        self.fields: list[tuple[QLineEdit, QLineEdit, QCheckBox]] = []
        for f in data.get("fields") or []:
            self._add_field(f.get("name") or "", f.get("value") or "", int(f.get("type") or 0) == 1)
        addf = button(t("ed_add_field"), "ghost", "plus")
        addf.clicked.connect(lambda: self._add_field("", "", False))
        self.form.addWidget(addf, 0, Qt.AlignmentFlag.AlignLeft)

        row = QHBoxLayout()
        self.folder = QComboBox()
        self.folder.addItem(t("nav_nofolder"), None)
        for fid, n in sorted(session.folders.items(), key=lambda kv: kv[1].lower()):
            self.folder.addItem(n, fid)
        cur = item.folder_id if item else None
        self.folder.setCurrentIndex(max(self.folder.findData(cur), 0))
        self.fav = QCheckBox(t("ed_favorite"))
        self.fav.setChecked(bool(item and item.favorite))
        fw = QVBoxLayout()
        fw.addWidget(label(t("ed_folder"), "field"))
        fw.addWidget(self.folder)
        row.addLayout(fw, 1)
        row.addSpacing(10)
        row.addWidget(self.fav, 0, Qt.AlignmentFlag.AlignBottom)
        self.form.addLayout(row)

        cancel = self.add_button(t("btn_cancel"), "secondary_lg")
        cancel.clicked.connect(self.reject)
        ok = self.add_button(t("btn_save"), "get_lg", "check")
        ok.setDefault(True)
        ok.clicked.connect(self._save)

    def _field(self, title: str, w: QWidget) -> None:
        self.form.addWidget(label(title, "field"))
        self.form.addWidget(w)

    def _add_uri(self, value: str) -> None:
        e = QLineEdit(value)
        e.setPlaceholderText("https://")
        self.uri_box.addWidget(e)
        self.uris.append(e)

    def _add_field(self, name: str, value: str, hidden: bool) -> None:
        row = QHBoxLayout()
        n = QLineEdit(name)
        n.setPlaceholderText(t("ed_field_name"))
        val = QLineEdit(value)
        val.setPlaceholderText(t("ed_field_value"))
        h = QCheckBox(t("ed_hidden"))
        h.setChecked(hidden)
        row.addWidget(n, 2)
        row.addWidget(val, 3)
        row.addWidget(h)
        self.field_box.addLayout(row)
        self.fields.append((n, val, h))

    def _generate(self, target: QLineEdit) -> None:
        g = GeneratorDialog(self, use_button=True)
        if g.exec() and g.value:
            target.setText(g.value)

    def _save(self) -> None:
        name = self.name.text().strip()
        if not name:
            self.set_error(t("ed_name_required"))
            return
        sec_name = itm.SECTION.get(self.type, "")
        sec = {k: (w.text() if k == "password" else w.text().strip()) or None
               for k, w in self.inputs.items()}
        if sec.get("totp"):
            try:
                totp.parse(sec["totp"])
            except totp.TotpError:
                self.set_error(t("ed_totp_bad"))
                return
        if self.type == itm.TYPE_LOGIN:
            sec["uris"] = [{"uri": e.text().strip()} for e in self.uris if e.text().strip()]
        fields = [{"name": n.text().strip(), "value": v.text(), "type": 1 if h.isChecked() else 0}
                  for n, v, h in self.fields if n.text().strip() or v.text()]
        notes = self.notes.toPlainText() or None
        folder = self.folder.currentData()
        if self.item is None:
            plain = {"name": name, "notes": notes, "favorite": self.fav.isChecked(), "fields": fields}
            if sec_name and sec_name != "secureNote":
                plain[sec_name] = sec
            self.result_value = {"new": True, "plain": plain, "folder": folder}
        else:
            changes: dict = {}
            old = self.item.data
            if name != (old.get("name") or ""):
                changes["name"] = name
            if (notes or None) != (old.get("notes") or None):
                changes["notes"] = notes
            if self.fav.isChecked() != self.item.favorite:
                changes["favorite"] = self.fav.isChecked()
            if folder != self.item.folder_id:
                changes["folderId"] = folder
            old_sec = self.item.section()
            diff = {k: v for k, v in sec.items() if k != "uris" and (v or None) != (old_sec.get(k) or None)}
            if self.type == itm.TYPE_LOGIN:
                old_uris = [u.get("uri") for u in old_sec.get("uris") or [] if u.get("uri")]
                if [u["uri"] for u in sec["uris"]] != old_uris:
                    diff["uris"] = sec["uris"]
            if diff:
                changes[sec_name] = diff
            old_fields = [{"name": f.get("name") or "", "value": f.get("value") or "",
                           "type": int(f.get("type") or 0)} for f in old.get("fields") or []]
            if fields != old_fields:
                changes["fields"] = fields
            self.result_value = {"new": False, "changes": changes}
        self.accept()


class GeneratorDialog(Dialog):
    def __init__(self, parent: QWidget | None, use_button: bool = False):
        super().__init__(parent, t("gen_title"), 520)
        self.value: str | None = None
        self.out = QLineEdit()
        self.out.setObjectName("genout")
        self.out.setReadOnly(True)
        self.body.addWidget(self.out)
        self.bits = label("", "hint")
        self.body.addWidget(self.bits)
        row = QHBoxLayout()
        row.addWidget(label(t("gen_length"), "field"))
        self.len_lbl = label("", "stat")
        row.addStretch(1)
        row.addWidget(self.len_lbl)
        self.body.addLayout(row)
        self.length = QSlider(Qt.Orientation.Horizontal)
        self.length.setRange(8, 64)
        self.length.setValue(20)
        self.body.addWidget(self.length)
        opts = QHBoxLayout()
        self.opts = {}
        for key in ("gen_upper", "gen_lower", "gen_digits", "gen_symbols"):
            c = QCheckBox(t(key))
            c.setChecked(True)
            opts.addWidget(c)
            self.opts[key] = c
        opts.addStretch(1)
        self.body.addLayout(opts)
        self.amb = QCheckBox(t("gen_ambiguous"))
        self.body.addWidget(self.amb)
        for w in list(self.opts.values()) + [self.amb]:
            w.toggled.connect(self._regen)
        self.length.valueChanged.connect(self._regen)
        again = self.add_button(t("gen_again"), "secondary_lg", "dice")
        again.clicked.connect(self._regen)
        copy = self.add_button(t("btn_copy"), "secondary_lg", "copy")
        copy.clicked.connect(lambda: Clipboard.copy(self.out.text()))
        if use_button:
            use = self.add_button(t("gen_use"), "get_lg", "check")
            use.clicked.connect(self._use)
        else:
            done = self.add_button("OK", "get_lg")
            done.clicked.connect(self.accept)
        self._regen()

    def _regen(self) -> None:
        o = self.opts
        pw = generator.password(self.length.value(), lower=o["gen_lower"].isChecked(),
                                upper=o["gen_upper"].isChecked(), digits=o["gen_digits"].isChecked(),
                                symbols=o["gen_symbols"].isChecked(),
                                avoid_ambiguous=self.amb.isChecked())
        self.out.setText(pw)
        self.len_lbl.setText(str(self.length.value()))
        self.bits.setText(t("gen_bits", n=int(generator.entropy_bits(pw))))

    def _use(self) -> None:
        self.value = self.out.text()
        self.accept()


class PinDialog(Dialog):
    def __init__(self, parent: QWidget | None, session: Session):
        super().__init__(parent, t("pin_title"), 440)
        self.session = session
        self.add_text(t("pin_body"))
        self.a = PasswordEdit(mono=True)
        self.b = PasswordEdit(mono=True)
        for w in (self.a, self.b):
            w.setMaxLength(12)
        self.add_field(t("pin_new"), self.a)
        self.add_field(t("pin_again"), self.b)
        cancel = self.add_button(t("btn_cancel"), "secondary_lg")
        cancel.clicked.connect(self.reject)
        ok = self.add_button(t("btn_save"), "get_lg", "check")
        ok.clicked.connect(self._go)

    def _go(self) -> None:
        if self.a.text() != self.b.text():
            self.set_error(t("pin_mismatch"))
            return
        pin = self.a.text()
        self.run(t("saving"), self.session.set_pin, pin, on_done=lambda _r: self.accept())


class SettingsDialog(Dialog):
    def __init__(self, window, session: Session | None):
        super().__init__(window, t("st_title"), 560)
        self.window_ = window
        self.session = session
        s = settings.load()
        self.body.addWidget(label(t("st_language"), "field"))
        row = QHBoxLayout()
        for code, text in (("en", "English"), ("tr", "Türkçe")):
            b = QPushButton(text, objectName="seg_on" if language() == code else "seg")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _=False, c=code: (self.accept(), window.set_lang(c)))
            row.addWidget(b)
        row.addStretch(1)
        self.body.addLayout(row)

        self.body.addSpacing(6)
        self.body.addWidget(label(t("st_security"), "field"))
        self.autolock = self._combo([(0, t("st_never")), (1, t("st_minute")), (5, t("st_minutes", n=5)),
                                     (10, t("st_minutes", n=10)), (30, t("st_minutes", n=30)),
                                     (60, t("st_hour")), (240, t("st_hours", n=4))],
                                    s["auto_lock_minutes"], "auto_lock_minutes")
        self._row(t("st_autolock"), self.autolock)
        self.clip = self._combo([(0, t("st_never")), (10, t("st_seconds", n=10)), (30, t("st_seconds", n=30)),
                                 (60, t("st_seconds", n=60)), (120, t("st_seconds", n=120))],
                                s["clipboard_seconds"], "clipboard_seconds")
        self._row(t("st_clipboard"), self.clip)
        for key, text in (("lock_on_screen_lock", "st_screenlock"), ("lock_on_sleep", "st_sleep")):
            c = QCheckBox(t(text))
            c.setChecked(s[key])
            c.toggled.connect(lambda v, k=key: settings.save(**{k: bool(v)}))
            self.body.addWidget(c)

        if session is not None:
            self.body.addSpacing(6)
            self.body.addWidget(label(t("st_pin"), "field"))
            self.body.addWidget(label(t("st_pin_sub"), "hint", wrap=True))
            pr = QHBoxLayout()
            setb = button(t("st_pin_change") if session.has_pin else t("st_pin_set"), "secondary", "pin")
            setb.clicked.connect(self._set_pin)
            pr.addWidget(setb)
            if session.has_pin:
                rm = button(t("st_pin_remove"), "ghost", "trash")
                rm.clicked.connect(self._remove_pin)
                pr.addWidget(rm)
            pr.addStretch(1)
            self.body.addLayout(pr)
            self.body.addSpacing(6)
            self.body.addWidget(label(t("st_account"), "field"))
            info = session.info
            where = t("st_server", url=info.server.web) if info.server else \
                t("st_local", path=str(info.dir / "vault.json"))
            self.body.addWidget(label(f"{info.email if info.mode == 'server' else info.name}", "title"))
            self.body.addWidget(label(where, "path", wrap=True))
            if info.mode == "server":
                so = button(t("st_signout"), "ghost", "logout")
                so.clicked.connect(lambda: (self.accept(), window.sign_out()))
                self.body.addWidget(so, 0, Qt.AlignmentFlag.AlignLeft)
        self.body.addSpacing(8)
        self.body.addWidget(label(t("st_about", ver=__version__), "hint"))
        ok = self.add_button("OK", "get_lg", "check")
        ok.clicked.connect(self.accept)

    def _combo(self, options, current, key) -> QComboBox:
        c = QComboBox()
        for v, text in options:
            c.addItem(text, v)
        best = min(range(len(options)), key=lambda i: abs(options[i][0] - current))
        c.setCurrentIndex(best)
        c.currentIndexChanged.connect(lambda _i: (settings.save(**{key: int(c.currentData())}),
                                                  self.window_.settings_changed()))
        return c

    def _row(self, text: str, w: QWidget) -> None:
        r = QHBoxLayout()
        r.addWidget(label(text, "tagline"), 1)
        w.setMinimumWidth(170)
        r.addWidget(w)
        self.body.addLayout(r)

    def _set_pin(self) -> None:
        if PinDialog(self, self.session).exec():
            self.window_.flash(t("pin_set_ok"))
            self.accept()

    def _remove_pin(self) -> None:
        self.session.forget_pin()
        self.window_.flash(t("pin_removed"))
        self.accept()
