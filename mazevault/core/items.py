"""Vault items (Bitwarden "ciphers"): decrypting them for display, and writing
changes back without losing anything.

The rule that keeps other clients' data safe: an edit never rebuilds an item
from what Maze Vault understands. It starts from the item exactly as the
server sent it — every field, including ones this version has never heard of
(passkeys, new item types, future additions) — and replaces only the fields
the user changed, each freshly encrypted. Everything else goes back
byte-for-byte as it came.

An item any of whose fields fails to decrypt is marked `damaged` and is
read-only: writing it back could replace the unreadable field with nothing.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable

from mazevault.core import crypto
from mazevault.core.crypto import CryptoError, SymmetricKey

TYPE_LOGIN = 1
TYPE_NOTE = 2
TYPE_CARD = 3
TYPE_IDENTITY = 4
TYPE_SSH_KEY = 5

SECTION = {TYPE_LOGIN: "login", TYPE_NOTE: "secureNote", TYPE_CARD: "card",
           TYPE_IDENTITY: "identity", TYPE_SSH_KEY: "sshKey"}

# Encrypted string fields of each section (what a *new* item may set).
LOGIN_FIELDS = ("username", "password", "totp")
CARD_FIELDS = ("cardholderName", "brand", "number", "expMonth", "expYear", "code")
IDENTITY_FIELDS = ("title", "firstName", "middleName", "lastName", "address1", "address2",
                   "address3", "city", "state", "postalCode", "country", "company", "email",
                   "phone", "ssn", "username", "passportNumber", "licenseNumber")
SSH_FIELDS = ("privateKey", "publicKey", "keyFingerprint")
SECTION_FIELDS = {"login": LOGIN_FIELDS, "card": CARD_FIELDS, "identity": IDENTITY_FIELDS,
                  "sshKey": SSH_FIELDS, "secureNote": ()}

# Keys that are never encrypted, whatever they look like.
_PLAIN_KEYS = {"id", "organizationId", "folderId", "userId", "revisionDate", "creationDate",
               "deletedDate", "archivedDate", "object", "type", "collectionIds", "edit",
               "viewPassword", "favorite", "reprompt", "organizationUseTotp", "permissions",
               "match", "linkedId", "credentialId", "counter", "discoverable", "keyType",
               "keyAlgorithm", "keyCurve", "rpId", "userHandle", "attachments", "url",
               "fileName", "size", "sizeName", "passwordRevisionDate", "lastUsedDate"}


# ── key case ─────────────────────────────────────────────────────────────────
def camel(obj: Any) -> Any:
    """Bitwarden has answered in PascalCase and camelCase over the years, and
    Vaultwarden followed. Everything is handled in camelCase."""
    if isinstance(obj, dict):
        return {(k[:1].lower() + k[1:] if isinstance(k, str) else k): camel(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [camel(v) for v in obj]
    return obj


# ── decrypting ───────────────────────────────────────────────────────────────
@dataclass
class Item:
    raw: dict                     # as the server sent it (camelCase, still encrypted)
    data: dict                    # same shape, strings decrypted
    damaged: list[str] = field(default_factory=list)   # paths that failed

    @property
    def id(self) -> str:
        return self.raw.get("id", "")

    @property
    def type(self) -> int:
        return int(self.raw.get("type", 0))

    @property
    def name(self) -> str:
        return self.data.get("name") or ""

    @property
    def deleted(self) -> bool:
        return bool(self.raw.get("deletedDate"))

    @property
    def folder_id(self) -> str | None:
        return self.raw.get("folderId")

    @property
    def organization_id(self) -> str | None:
        return self.raw.get("organizationId")

    @property
    def favorite(self) -> bool:
        return bool(self.raw.get("favorite"))

    @property
    def revision(self) -> str:
        return self.raw.get("revisionDate", "")

    @property
    def editable(self) -> bool:
        return not self.damaged and self.raw.get("edit", True) is not False

    def section(self) -> dict:
        return self.data.get(SECTION.get(self.type, ""), None) or {}


def item_key(raw: dict, owner_key: SymmetricKey) -> SymmetricKey:
    """The key that encrypts this item's fields: its own key if it has one."""
    k = raw.get("key")
    if k:
        return SymmetricKey.from_bytes(crypto.decrypt(k, owner_key))
    return owner_key


def _walk_decrypt(obj: Any, key: SymmetricKey, path: str, damaged: list[str]) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "key" and path == "":
                out[k] = v  # the item key itself, not text
            elif k in _PLAIN_KEYS:
                out[k] = copy.deepcopy(v)
            else:
                out[k] = _walk_decrypt(v, key, f"{path}.{k}" if path else k, damaged)
        return out
    if isinstance(obj, list):
        return [_walk_decrypt(v, key, f"{path}[{i}]", damaged) for i, v in enumerate(obj)]
    if crypto.looks_encrypted(obj):
        try:
            return crypto.decrypt_text(obj, key)
        except CryptoError:
            damaged.append(path)
            return None
    return obj


def decrypt_item(raw: dict, keys: Callable[[str | None], SymmetricKey | None]) -> Item:
    """keys(org_id) → the user key (None) or that organisation's key."""
    raw = camel(raw)
    owner = keys(raw.get("organizationId"))
    damaged: list[str] = []
    if owner is None:
        return Item(raw, {"name": None}, ["<no key>"])
    try:
        k = item_key(raw, owner)
    except CryptoError:
        return Item(raw, {"name": None}, ["key"])
    data = _walk_decrypt(raw, k, "", damaged)
    _verify_uri_checksums(data, damaged)
    return Item(raw, data, damaged)


def _uri_checksum(uri: str) -> str:
    return base64.b64encode(hashlib.sha256(uri.encode()).digest()).decode()


def _verify_uri_checksums(data: dict, damaged: list[str]) -> None:
    """Bitwarden clients store a checksum of every login URI; a mismatch means
    the URI was swapped (by a server, for instance) and must not be trusted."""
    login = data.get("login") or {}
    for i, u in enumerate(login.get("uris") or []):
        if isinstance(u, dict) and u.get("uri") is not None and u.get("uriChecksum"):
            if u["uriChecksum"] != _uri_checksum(u["uri"]):
                damaged.append(f"login.uris[{i}].uriChecksum")


# ── writing ──────────────────────────────────────────────────────────────────
def _enc(value: str | None, key: SymmetricKey) -> str | None:
    if value is None or value == "":
        return None
    return crypto.encrypt_text(value, key)


def _uris(uris: list[dict], key: SymmetricKey) -> list[dict]:
    out = []
    for u in uris:
        uri = u.get("uri") or ""
        if not uri:
            continue
        out.append({"uri": _enc(uri, key), "uriChecksum": _enc(_uri_checksum(uri), key),
                    "match": u.get("match")})
    return out


def _fields(fields: list[dict], key: SymmetricKey) -> list[dict]:
    return [{"type": int(f.get("type", 0)), "name": _enc(f.get("name"), key),
             "value": _enc(f.get("value"), key), "linkedId": f.get("linkedId")}
            for f in fields]


def new_item(item_type: int, plain: dict, owner_key: SymmetricKey, encrypted_for: str,
             folder_id: str | None = None, own_key: bool = True) -> dict:
    """A request body for a brand-new item.

    encrypted_for: the id of the user whose key encrypted it. Servers check
    it, so an item can never be stored encrypted for the wrong account.
    own_key: give the item its own key (cipher.key), as current Bitwarden
    clients do, wrapped by the user or organisation key.
    """
    body: dict = {"type": item_type, "folderId": folder_id, "organizationId": None,
                  "encryptedFor": encrypted_for,
                  "favorite": bool(plain.get("favorite")), "reprompt": int(plain.get("reprompt", 0))}
    key = owner_key
    if own_key:
        ik = SymmetricKey.generate()
        body["key"] = str(crypto.encrypt(ik.to_bytes(), owner_key))
        key = ik
    body["name"] = _enc(plain.get("name") or "", key) or crypto.encrypt_text("", key)
    body["notes"] = _enc(plain.get("notes"), key)
    sec = SECTION[item_type]
    sp = plain.get(sec) or {}
    out = {f: _enc(sp.get(f), key) for f in SECTION_FIELDS[sec]}
    if item_type == TYPE_LOGIN:
        out["uris"] = _uris(sp.get("uris") or [], key)
    if item_type == TYPE_NOTE:
        out = {"type": 0}
    body[sec] = out
    body["fields"] = _fields(plain.get("fields") or [], key)
    return body


def apply_changes(item: Item, changes: dict, owner_key: SymmetricKey, encrypted_for: str) -> dict:
    """The update request: the item as received, with only `changes` replaced.

    changes: {"name": str, "notes": str|None, "favorite": bool, "folderId": str|None,
              "<section>": {field: str|None, "uris": [...]}, "fields": [...]}
    The previous password goes into passwordHistory, as every Bitwarden client
    does, so a changed password is never simply gone.
    """
    if not item.editable:
        raise CryptoError("item_damaged")
    body = copy.deepcopy(item.raw)
    key = item_key(item.raw, owner_key)
    for k in ("name", "notes"):
        if k in changes:
            body[k] = _enc(changes[k], key) if k == "notes" else \
                (_enc(changes[k], key) or crypto.encrypt_text("", key))
    for k in ("favorite", "folderId", "reprompt"):
        if k in changes:
            body[k] = changes[k]
    sec = SECTION.get(item.type)
    if sec and sec in changes and sec != "secureNote":
        target = body.setdefault(sec, {}) or {}
        body[sec] = target
        for f, v in changes[sec].items():
            if f == "uris":
                target["uris"] = _uris(v or [], key)
                # The pre-2018 single-URI field mirrors the first URI; a stale
                # copy would show the old address in old clients.
                if "uri" in target:
                    target["uri"] = target["uris"][0]["uri"] if target["uris"] else None
            elif f in SECTION_FIELDS[sec]:
                if sec == "login" and f == "password":
                    old = (item.section() or {}).get("password")
                    if old and old != v:
                        hist = body.get("passwordHistory") or []
                        hist.insert(0, {"password": crypto.encrypt_text(old, key),
                                        "lastUsedDate": _now()})
                        body["passwordHistory"] = hist[:5]
                target[f] = _enc(v, key)
    if "fields" in changes:
        body["fields"] = _fields(changes["fields"] or [], key)
    # The server refuses the update if the item changed since this revision
    # (another device edited it): the caller then keeps both versions.
    body["lastKnownRevisionDate"] = item.revision or None
    body["encryptedFor"] = encrypted_for
    for k in ("object", "edit", "viewPassword", "permissions", "collectionIds",
              "organizationUseTotp", "revisionDate", "creationDate", "deletedDate", "id"):
        body.pop(k, None)
    return body


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def folder_name(raw: dict, user_key: SymmetricKey) -> str | None:
    try:
        return crypto.decrypt_text(camel(raw)["name"], user_key)
    except (CryptoError, KeyError):
        return None
