"""Accounts, unlocking, syncing and editing — the heart of Maze Vault.

An account is either
  * "server": a Bitwarden-compatible server (the user's Vaultwarden, Bitwarden
    Cloud...). The server holds the vault; this machine keeps an encrypted
    cache of it so it opens offline and survives a server loss.
  * "local": no server. The vault lives in vault.json in exactly the same
    encrypted format, so it can later be pushed to a server unchanged.

On disk, per account (~/.local/share/maze-vault/accounts/<id>/), nothing is
ever plaintext:
    account.json   server, e-mail, pinned KDF, the password-wrapped user key,
                   the refresh token encrypted under the user key
    cache.json     the last sync, as the server sent it (encrypted items)
    history/       the previous N syncs, for recovery after a server-side loss
    vault.json     local accounts only: the vault itself

Data-safety rules:
  * Deleting moves an item to the trash; permanent deletion only from there.
  * Edits carry the revision they were based on. If another device changed the
    item meanwhile, the edit is saved as a separate copy — nothing is
    overwritten (see Session.update).
  * Items that do not decrypt completely are read-only (items.py).
  * The KDF is pinned at first login; a server that later offers weaker
    parameters is refused (a compromised server's downgrade attack).
  * Every file write is atomic with a .bak.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from mazevault.core import api, atomic, crypto, items, paths
from mazevault.core.api import ApiError, Server
from mazevault.core.crypto import CryptoError, Kdf, SymmetricKey
from mazevault.core.items import Item

FORMAT = 1
HISTORY_KEEP = 10
PIN_MAX_TRIES = 5
# PIN → key: deliberately slow, so the in-memory PIN blob is not a shortcut.
PIN_KDF = dict(iterations=3, memory=64, parallelism=4)


class VaultError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ── account records ──────────────────────────────────────────────────────────
@dataclass
class AccountInfo:
    id: str
    mode: str                       # "server" | "local"
    email: str                      # the KDF salt; for local vaults a generated one
    name: str
    kdf: Kdf
    protected_key: str              # user key wrapped by the master key
    private_key: str | None         # RSA private key wrapped by the user key
    user_id: str
    server: Server | None = None
    device_id: str = ""
    refresh_enc: str | None = None  # refresh token, encrypted under the user key
    created: float = 0.0
    last_sync: float = 0.0
    previous_keys: list[str] = field(default_factory=list)

    @property
    def dir(self) -> Path:
        return paths.accounts_dir() / self.id

    def to_json(self) -> dict:
        return {"format": FORMAT, "id": self.id, "mode": self.mode, "email": self.email,
                "name": self.name, "kdf": self.kdf.to_json(), "protectedKey": self.protected_key,
                "privateKey": self.private_key, "userId": self.user_id,
                "server": self.server.to_json() if self.server else None,
                "deviceId": self.device_id, "refreshEnc": self.refresh_enc,
                "created": self.created, "lastSync": self.last_sync,
                "previousKeys": self.previous_keys[-5:]}

    @classmethod
    def from_json(cls, d: dict) -> "AccountInfo":
        k = d["kdf"]
        return cls(id=d["id"], mode=d["mode"], email=d["email"], name=d.get("name") or d["email"],
                   kdf=Kdf(int(k["kdf"]), int(k["kdfIterations"]), k.get("kdfMemory"),
                           k.get("kdfParallelism")),
                   protected_key=d["protectedKey"], private_key=d.get("privateKey"),
                   user_id=d["userId"],
                   server=Server.from_json(d["server"]) if d.get("server") else None,
                   device_id=d.get("deviceId") or "", refresh_enc=d.get("refreshEnc"),
                   created=float(d.get("created") or 0), last_sync=float(d.get("lastSync") or 0),
                   previous_keys=list(d.get("previousKeys") or []))

    def save(self) -> None:
        atomic.ensure_private_dir(self.dir)
        atomic.write_json(self.dir / "account.json", self.to_json())


def list_accounts() -> list[AccountInfo]:
    out = []
    try:
        dirs = sorted(paths.accounts_dir().iterdir())
    except OSError:
        return out
    for d in dirs:
        data = atomic.read_json(d / "account.json")
        if isinstance(data, dict):
            try:
                out.append(AccountInfo.from_json(data))
            except (KeyError, TypeError, ValueError):
                continue
    out.sort(key=lambda a: a.created)
    return out


def _kdf_weaker(new: Kdf, pinned: Kdf) -> bool:
    if new.type != pinned.type:
        return False  # a deliberate KDF change; check_kdf still enforces minimums
    if new.type == crypto.KDF_PBKDF2:
        return new.iterations < pinned.iterations
    return (new.iterations < pinned.iterations or (new.memory or 0) < (pinned.memory or 0)
            or (new.parallelism or 0) < (pinned.parallelism or 0))


def sign_out(info: AccountInfo) -> Path:
    """Forget a server account on this computer. Its encrypted cache and
    history are not deleted but moved to an archive folder: if the server ever
    loses the vault, that copy may be the only one left."""
    if info.mode != "server":
        raise VaultError("local_signout")
    arch = atomic.ensure_private_dir(paths.data_dir() / "signed-out")
    dest = arch / f"{info.id}-{int(time.time())}"
    os.rename(info.dir, dest)
    atomic.fsync_dir(arch)
    return dest


# ── backends ─────────────────────────────────────────────────────────────────
class ServerBackend:
    def __init__(self, info: AccountInfo, client: api.Client):
        self.info = info
        self.client = client

    def call(self, session: "Session", fn: Callable, *args):
        """Run an API call; on an expired token refresh once and retry."""
        if not self.client.access_token:
            session.refresh_token()
        try:
            return fn(*args)
        except ApiError as e:
            if e.status != 401:
                raise
            session.refresh_token()
            return fn(*args)


class LocalBackend:
    """The "server" of a local vault: one JSON file, same encrypted format."""

    def __init__(self, info: AccountInfo):
        self.info = info
        self.path = info.dir / "vault.json"

    def load(self) -> dict:
        data = atomic.read_json(self.path)
        if not isinstance(data, dict):
            raise VaultError("local_missing", str(self.path))
        return data

    def save(self, data: dict) -> None:
        snapshot(self.info, self.load() if self.path.exists() else None)
        atomic.write_json(self.path, data)

    def sync(self) -> dict:
        data = self.load()
        return {"profile": {"id": self.info.user_id, "key": self.info.protected_key,
                            "privateKey": self.info.private_key, "organizations": []},
                "ciphers": data.get("ciphers", []), "folders": data.get("folders", []),
                "collections": [], "sends": []}

    def _check_owner(self, body: dict) -> None:
        if body.get("encryptedFor") not in (None, self.info.user_id):
            raise VaultError("wrong_owner")

    def create_cipher(self, body: dict) -> dict:
        self._check_owner(body)
        data = self.load()
        now = _now_iso()
        c = {k: v for k, v in copy.deepcopy(body).items()
             if k not in ("lastKnownRevisionDate", "encryptedFor")}
        c.update({"id": str(uuid.uuid4()), "revisionDate": now, "creationDate": now,
                  "deletedDate": None, "object": "cipherDetails", "edit": True})
        data.setdefault("ciphers", []).append(c)
        self.save(data)
        return c

    def update_cipher(self, cid: str, body: dict) -> dict:
        self._check_owner(body)
        data = self.load()
        for i, c in enumerate(data.get("ciphers", [])):
            if c["id"] == cid:
                if body.get("lastKnownRevisionDate") not in (None, c.get("revisionDate")):
                    raise ApiError("stale", "out of date", 400)
                new = {k: v for k, v in copy.deepcopy(body).items()
                       if k not in ("lastKnownRevisionDate", "encryptedFor")}
                new.update({"id": cid, "creationDate": c.get("creationDate"),
                            "revisionDate": _now_iso(), "deletedDate": c.get("deletedDate"),
                            "object": "cipherDetails", "edit": True})
                data["ciphers"][i] = new
                self.save(data)
                return new
        raise ApiError("not_found", cid, 404)

    def _set_deleted(self, cid: str, value: str | None) -> dict:
        data = self.load()
        for c in data.get("ciphers", []):
            if c["id"] == cid:
                c["deletedDate"] = value
                c["revisionDate"] = _now_iso()
                self.save(data)
                return c
        raise ApiError("not_found", cid, 404)

    def soft_delete_cipher(self, cid: str) -> None:
        self._set_deleted(cid, _now_iso())

    def restore_cipher(self, cid: str) -> dict:
        return self._set_deleted(cid, None)

    def delete_cipher(self, cid: str) -> None:
        data = self.load()
        keep = [c for c in data.get("ciphers", []) if not (c["id"] == cid and c.get("deletedDate"))]
        if len(keep) == len(data.get("ciphers", [])):
            raise VaultError("not_in_trash")
        data["ciphers"] = keep
        self.save(data)

    def create_folder(self, name_enc: str) -> dict:
        data = self.load()
        f = {"id": str(uuid.uuid4()), "name": name_enc, "revisionDate": _now_iso()}
        data.setdefault("folders", []).append(f)
        self.save(data)
        return f

    def update_folder(self, fid: str, name_enc: str) -> dict:
        data = self.load()
        for f in data.get("folders", []):
            if f["id"] == fid:
                f["name"] = name_enc
                f["revisionDate"] = _now_iso()
                self.save(data)
                return f
        raise ApiError("not_found", fid, 404)

    def delete_folder(self, fid: str) -> None:
        data = self.load()
        data["folders"] = [f for f in data.get("folders", []) if f["id"] != fid]
        for c in data.get("ciphers", []):
            if c.get("folderId") == fid:
                c["folderId"] = None   # items are never deleted with their folder
        self.save(data)


# ── history ──────────────────────────────────────────────────────────────────
def snapshot(info: AccountInfo, data: dict | None) -> None:
    """Keep the previous encrypted state; the newest HISTORY_KEEP survive."""
    if not data:
        return
    hdir = atomic.ensure_private_dir(info.dir / "history")
    blob = json.dumps(data, sort_keys=True).encode()
    digest = hashlib.sha256(blob).hexdigest()[:16]
    existing = sorted(hdir.glob("*.json"))
    if existing and existing[-1].name.endswith(f"-{digest}.json"):
        return
    atomic.write_bytes(hdir / f"{int(time.time() * 1000)}-{digest}.json", blob)
    for old in sorted(hdir.glob("*.json"))[:-HISTORY_KEEP]:
        try:
            old.unlink()
        except OSError:
            pass


def forget_in_history(info: AccountInfo, cid: str) -> int:
    """Remove one item from every history snapshot (audit V1).

    Snapshots keep the previous encrypted states so a bad sync or edit can be
    undone — which also kept an item deleted "forever" on disk for the next
    HISTORY_KEEP saves, and in the vault file's own .bak until the next save.
    Entries are matched by id; nothing is decrypted.
    Returns how many snapshots changed.
    """
    changed = 0
    # The previous state of the vault file itself is kept as *.json.bak by
    # atomic.write_json: right after a purge that copy still holds the item.
    backups = sorted(info.dir.glob("*.json.bak"))
    for path in history(info) + backups:
        try:
            data = json.loads(path.read_bytes())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        ciphers = data.get("ciphers")
        if not isinstance(ciphers, list):
            continue
        kept = [c for c in ciphers if not (isinstance(c, dict) and c.get("id") == cid)]
        if len(kept) != len(ciphers):
            data["ciphers"] = kept
            atomic.write_bytes(path, json.dumps(data, sort_keys=True).encode())
            changed += 1
    return changed


def history(info: AccountInfo) -> list[Path]:
    return sorted((info.dir / "history").glob("*.json"), reverse=True)


# ── creating accounts ────────────────────────────────────────────────────────
def _new_keys(password: str, salt_email: str, kdf: Kdf) -> tuple[bytes, SymmetricKey, str, str, str]:
    mk = crypto.master_key(password, salt_email, kdf)
    uk = SymmetricKey.generate()
    pub, der = crypto.generate_rsa()
    return mk, uk, crypto.wrap_user_key(uk, mk), pub, str(crypto.encrypt(der, uk))


def create_local(name: str, password: str, kdf: Kdf | None = None) -> "Session":
    kdf = kdf or Kdf(crypto.KDF_ARGON2ID, 3, 64, 4)
    crypto.check_kdf(kdf)
    aid = secrets.token_hex(8)
    salt_email = f"{aid}@local.maze-vault"
    _mk, uk, prot, _pub, priv = _new_keys(password, salt_email, kdf)
    info = AccountInfo(id=aid, mode="local", email=salt_email, name=name.strip() or "Maze Vault",
                       kdf=kdf, protected_key=prot, private_key=priv, user_id=str(uuid.uuid4()),
                       created=time.time())
    info.save()
    atomic.write_json(info.dir / "vault.json", {"format": FORMAT, "ciphers": [], "folders": []})
    s = Session(info, uk)
    s.load_cache()
    return s


class LoginAttempt:
    """A server login in progress. Holds the derived master key so the 2FA
    step does not repeat the (slow) KDF. Never stored."""

    def __init__(self, server: Server, email: str, password: str, cafile: str | None = None,
                 existing: AccountInfo | None = None):
        self.server = server
        self.email = email.strip().lower()
        self.password = password
        self.existing = existing
        self.client = api.Client(server, existing.device_id if existing else None, cafile=cafile)
        pre = self.client.prelogin(self.email)
        try:
            self.kdf = Kdf.from_prelogin(pre)
        except CryptoError:
            raise
        if existing and _kdf_weaker(self.kdf, existing.kdf):
            raise VaultError("kdf_downgrade", f"{self.kdf} < {existing.kdf}")
        salt = pre.get("salt") or self.email
        self.mk = crypto.master_key(password, salt, self.kdf)
        self.hash = crypto.master_password_hash(self.mk, password)

    def send_email_code(self) -> None:
        self.client.send_email_code(self.email, self.hash)

    def submit(self, two_factor: tuple[int, str, bool] | None = None,
               new_device_otp: str | None = None) -> "Session":
        """Raises api.TwoFactorRequired / NewDeviceOtpRequired / ApiError."""
        tok = self.client.login_password(self.email, self.hash, two_factor=two_factor,
                                         new_device_otp=new_device_otp)
        if not tok.key:
            raise VaultError("no_key", "the server sent no account key")
        uk = crypto.unwrap_user_key(tok.key, self.mk)
        info = self.existing or AccountInfo(
            id=secrets.token_hex(8), mode="server", email=self.email, name=self.email,
            kdf=self.kdf, protected_key=tok.key, private_key=tok.private_key, user_id="",
            server=self.server, device_id=self.client.device_id, created=time.time())
        if self.existing and info.protected_key != tok.key:
            info.previous_keys.append(info.protected_key)
        info.protected_key = tok.key
        info.private_key = tok.private_key or info.private_key
        info.kdf = self.kdf
        info.refresh_enc = crypto.encrypt_text(tok.refresh, uk) if tok.refresh else None
        s = Session(info, uk, self.client)
        s.sync()          # also sets user_id and saves the account
        self.mk = b""
        self.password = ""
        return s


def unlock(info: AccountInfo, password: str, cafile: str | None = None) -> "Session":
    """Offline unlock with the master password: the cached, password-wrapped
    user key is unwrapped locally. No network needed."""
    mk = crypto.master_key(password, info.email, info.kdf)
    try:
        uk = crypto.unwrap_user_key(info.protected_key, mk)
    except CryptoError:
        raise VaultError("wrong_password") from None
    client = api.Client(info.server, info.device_id, cafile=cafile) if info.mode == "server" else None
    s = Session(info, uk, client)
    s.load_cache()
    return s


# ── an unlocked vault ────────────────────────────────────────────────────────
class Session:
    def __init__(self, info: AccountInfo, user_key: SymmetricKey, client: api.Client | None = None):
        self.info = info
        self._user_key: SymmetricKey | None = user_key
        self._org_keys: dict[str, SymmetricKey] = {}
        self.backend = ServerBackend(info, client) if info.mode == "server" else LocalBackend(info)
        self.items: dict[str, Item] = {}
        self.folders: dict[str, str] = {}
        self._pin: tuple[bytes, str] | None = None   # (salt, user key wrapped by PIN key)
        self._pin_tries = 0
        self.conflicts: list[str] = []

    # keys
    @property
    def locked(self) -> bool:
        return self._user_key is None

    def user_key(self) -> SymmetricKey:
        if self._user_key is None:
            raise VaultError("locked")
        return self._user_key

    def _key_for(self, org_id: str | None) -> SymmetricKey | None:
        if org_id is None:
            return self.user_key()
        return self._org_keys.get(org_id)

    # cache / sync
    def _apply(self, data: dict) -> None:
        data = items.camel(data)
        uk = self.user_key()
        profile = data.get("profile") or {}
        self._org_keys = {}
        priv = profile.get("privateKey") or self.info.private_key
        if priv:
            try:
                der = crypto.decrypt(priv, uk)
                for org in profile.get("organizations") or []:
                    if org.get("key"):
                        try:
                            self._org_keys[org["id"]] = SymmetricKey.from_bytes(
                                crypto.rsa_decrypt(org["key"], der))
                        except CryptoError:
                            pass
            except CryptoError:
                pass
        self.items = {c["id"]: items.decrypt_item(c, self._key_for) for c in data.get("ciphers") or []}
        folders = {}
        for f in data.get("folders") or []:
            name = items.folder_name(f, uk)
            folders[f["id"]] = name if name is not None else "⚠"
        self.folders = folders
        if self._user_key is None:
            # Locked while this ran (a background sync): drop what it decrypted.
            self.items, self.folders, self._org_keys = {}, {}, {}
            raise VaultError("locked")

    def load_cache(self) -> None:
        if self.info.mode == "local":
            self._apply(self.backend.sync())
            return
        data = atomic.read_json(self.info.dir / "cache.json")
        if isinstance(data, dict):
            self._apply(data)

    def refresh_token(self) -> None:
        b = self.backend
        if not isinstance(b, ServerBackend):
            return
        if not self.info.refresh_enc:
            raise VaultError("relogin")
        try:
            refresh = crypto.decrypt_text(self.info.refresh_enc, self.user_key())
            tok = b.client.refresh(refresh)
        except CryptoError as e:              # a stored token that does not decrypt
            raise VaultError("relogin") from e
        except ApiError as e:
            if e.status in (400, 401):
                raise VaultError("relogin") from e
            raise
        if tok.refresh and tok.refresh != refresh:
            self.info.refresh_enc = crypto.encrypt_text(tok.refresh, self.user_key())
            self.info.save()

    def sync(self) -> None:
        if isinstance(self.backend, LocalBackend):
            self.load_cache()
            return
        data = items.camel(self.backend.call(self, self.backend.client.sync))
        profile = data.get("profile") or {}
        if profile.get("id"):
            self.info.user_id = profile["id"]
        if profile.get("key") and profile["key"] != self.info.protected_key:
            # The master password was changed on another device. The user key
            # usually stays; the old wrapper is kept for recovery.
            self.info.previous_keys.append(self.info.protected_key)
            self.info.protected_key = profile["key"]
        decrypted_before = self.items
        self._apply(data)
        if self.items and all(it.damaged for it in self.items.values()) and \
                not (decrypted_before and all(it.damaged for it in decrypted_before.values())):
            # Every item stopped decrypting: the account key was rotated
            # elsewhere. Keep the old cache; ask for a fresh login.
            self.load_cache()
            raise VaultError("relogin", "account key changed")
        previous = atomic.read_json(self.info.dir / "cache.json")
        snapshot(self.info, previous if isinstance(previous, dict) else None)
        atomic.ensure_private_dir(self.info.dir)
        atomic.write_json(self.info.dir / "cache.json", data)
        self.info.last_sync = time.time()
        self.info.save()

    def _call(self, name: str, *args):
        b = self.backend
        if isinstance(b, ServerBackend):
            return b.call(self, getattr(b.client, name), *args)
        return getattr(b, name)(*args)

    # items
    def visible(self, trash: bool = False) -> list[Item]:
        out = [it for it in self.items.values() if it.deleted == trash]
        out.sort(key=lambda i: (i.name or "").lower())
        return out

    def create(self, item_type: int, plain: dict, folder_id: str | None = None) -> Item:
        body = items.new_item(item_type, plain, self.user_key(), self.info.user_id, folder_id)
        raw = self._call("create_cipher", body)
        self.sync()
        return self.items.get(items.camel(raw or {}).get("id"), None) or Item(raw or {}, {})

    def update(self, item: Item, changes: dict) -> tuple[Item | None, bool]:
        """Returns (item, conflict). On conflict the edit was saved as a new
        item next to the other device's version; neither is lost."""
        owner = self._key_for(item.organization_id)
        if owner is None:
            raise VaultError("no_key")
        body = items.apply_changes(item, changes, owner, self.info.user_id)
        try:
            self._call("update_cipher", item.id, body)
        except ApiError as e:
            if not _is_stale(e):
                raise
            plain = _plain_after(item, changes)
            plain["name"] = f"{plain.get('name') or ''} (Maze Vault {datetime.now():%Y-%m-%d %H:%M})"
            copy_body = items.new_item(item.type, plain, self.user_key(), self.info.user_id,
                                       item.folder_id)
            raw = self._call("create_cipher", copy_body)
            self.sync()
            new_id = items.camel(raw or {}).get("id")
            if new_id:
                self.conflicts.append(new_id)
            return self.items.get(new_id), True
        self.sync()
        return self.items.get(item.id), False

    def trash(self, item: Item) -> None:
        self._call("soft_delete_cipher", item.id)
        self.sync()

    def restore(self, item: Item) -> None:
        self._call("restore_cipher", item.id)
        self.sync()

    def purge(self, item: Item) -> None:
        """Permanent deletion: only for an item already in the trash."""
        if not item.deleted:
            raise VaultError("not_in_trash")
        self._call("delete_cipher", item.id)
        self.sync()
        # Forever means forever on this disk too, not "until ten more saves".
        forget_in_history(self.info, item.id)

    def create_folder(self, name: str) -> None:
        self._call("create_folder", crypto.encrypt_text(name, self.user_key()))
        self.sync()

    def rename_folder(self, fid: str, name: str) -> None:
        self._call("update_folder", fid, crypto.encrypt_text(name, self.user_key()))
        self.sync()

    def delete_folder(self, fid: str) -> None:
        self._call("delete_folder", fid)
        self.sync()

    # lock / PIN
    def set_pin(self, pin: str) -> None:
        if not pin.isdigit() or not 4 <= len(pin) <= 12:
            raise VaultError("bad_pin")
        salt = os.urandom(16)
        k = _pin_key(pin, salt)
        self._pin = (salt, str(crypto.encrypt(self.user_key().to_bytes(), k)))
        self._pin_tries = 0

    @property
    def has_pin(self) -> bool:
        return self._pin is not None

    @property
    def pin_tries_left(self) -> int:
        return PIN_MAX_TRIES - self._pin_tries if self._pin else 0

    def lock(self) -> None:
        """Forget the user key and every decrypted item. The PIN blob (if any)
        stays in memory so the PIN can unlock again."""
        self._user_key = None
        self._org_keys = {}
        self.items = {}
        self.folders = {}

    def forget_pin(self) -> None:
        self._pin = None
        self._pin_tries = 0

    def unlock_pin(self, pin: str) -> None:
        if self._pin is None:
            raise VaultError("no_pin")
        salt, blob = self._pin
        try:
            raw = crypto.decrypt(blob, _pin_key(pin, salt))
        except CryptoError:
            self._pin_tries += 1
            if self._pin_tries >= PIN_MAX_TRIES:
                self.forget_pin()
                raise VaultError("pin_wiped") from None
            raise VaultError("wrong_pin") from None
        self._user_key = SymmetricKey.from_bytes(raw)
        self._pin_tries = 0
        self.load_cache()

    def unlock_password(self, password: str) -> None:
        s = unlock(self.info, password)
        self._user_key = s._user_key
        self._pin_tries = 0
        self.load_cache()


def _pin_key(pin: str, salt: bytes) -> SymmetricKey:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    raw = Argon2id(salt=salt, length=64, iterations=PIN_KDF["iterations"],
                   lanes=PIN_KDF["parallelism"], memory_cost=PIN_KDF["memory"] * 1024).derive(pin.encode())
    return SymmetricKey.from_bytes(raw)


def _is_stale(e: ApiError) -> bool:
    msg = (e.message or "").lower()
    return e.reason == "stale" or ("out of date" in msg) or ("resync" in msg)


def _plain_after(item: Item, changes: dict) -> dict:
    plain = copy.deepcopy(item.data)
    for k, v in changes.items():
        if isinstance(v, dict) and isinstance(plain.get(k), dict):
            plain[k].update(v)
        else:
            plain[k] = v
    return plain
