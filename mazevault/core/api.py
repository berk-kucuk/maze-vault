"""HTTP client for the Bitwarden server API (Vaultwarden, self-hosted Bitwarden,
Bitwarden Cloud).

Only ciphertext and the master password *hash* ever cross the wire — see
crypto.py. Plain HTTP is refused for every host except this machine itself,
so a typo in the server address can never send even that hash in the clear.

Written on urllib alone: no third-party HTTP stack to trust or update.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field

from mazevault import __version__

DEVICE_TYPE_LINUX_DESKTOP = 8
CLIENT_ID = "desktop"
MAX_RESPONSE = 256 * 1024 * 1024
TIMEOUT = 30

# 2FA providers (Bitwarden TwoFactorProviderType)
TWO_FACTOR_AUTHENTICATOR = 0
TWO_FACTOR_EMAIL = 1
TWO_FACTOR_DUO = 2
TWO_FACTOR_YUBIKEY = 3
TWO_FACTOR_REMEMBER = 5
TWO_FACTOR_WEBAUTHN = 7
SUPPORTED_TWO_FACTOR = (TWO_FACTOR_AUTHENTICATOR, TWO_FACTOR_EMAIL, TWO_FACTOR_YUBIKEY)


class ApiError(Exception):
    """reason: short key for the GUI; status: HTTP status (0 = no response)."""

    def __init__(self, reason: str, message: str = "", status: int = 0, data: dict | None = None):
        super().__init__(f"{reason} ({status}): {message}" if message else f"{reason} ({status})")
        self.reason = reason
        self.message = message
        self.status = status
        self.data = data or {}


class TwoFactorRequired(ApiError):
    def __init__(self, providers: dict, data: dict):
        super().__init__("two_factor", "two-step login required", 400, data)
        # {provider type: provider info}; keys arrive as strings.
        self.providers = {int(k): v for k, v in providers.items()}


class NewDeviceOtpRequired(ApiError):
    def __init__(self, data: dict):
        super().__init__("new_device_otp", "new device verification required", 400, data)


# ── servers ──────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Server:
    api: str
    identity: str
    web: str
    kind: str = "custom"      # "custom", "bitwarden-us", "bitwarden-eu"

    @classmethod
    def custom(cls, base: str) -> "Server":
        base = normalize_url(base)
        return cls(api=f"{base}/api", identity=f"{base}/identity", web=base)

    @classmethod
    def bitwarden(cls, region: str = "us") -> "Server":
        tld = "eu" if region == "eu" else "com"
        return cls(api=f"https://api.bitwarden.{tld}", identity=f"https://identity.bitwarden.{tld}",
                   web=f"https://vault.bitwarden.{tld}", kind=f"bitwarden-{region}")

    def to_json(self) -> dict:
        return {"api": self.api, "identity": self.identity, "web": self.web, "kind": self.kind}

    @classmethod
    def from_json(cls, d: dict) -> "Server":
        return cls(api=d["api"], identity=d["identity"], web=d["web"], kind=d.get("kind", "custom"))


def _is_loopback(host: str) -> bool:
    if host in ("localhost",) or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ApiError("bad_url", "empty")
    if "://" not in url:
        url = "https://" + url
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("https", "http") or not p.hostname:
        raise ApiError("bad_url", url)
    if p.scheme == "http" and not _is_loopback(p.hostname):
        raise ApiError("insecure_url", url)
    if p.username or p.password or p.query or p.fragment:
        raise ApiError("bad_url", url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path.rstrip("/"), "", ""))


# ── tokens ───────────────────────────────────────────────────────────────────
@dataclass
class Tokens:
    access: str
    refresh: str | None
    expires_in: int
    raw: dict = field(default_factory=dict)

    @property
    def key(self) -> str | None:
        return self.raw.get("Key") or self.raw.get("key")

    @property
    def private_key(self) -> str | None:
        return self.raw.get("PrivateKey") or self.raw.get("privateKey")

    def kdf_json(self) -> dict:
        r = self.raw
        return {"kdf": r.get("Kdf", r.get("kdf")), "kdfIterations": r.get("KdfIterations", r.get("kdfIterations")),
                "kdfMemory": r.get("KdfMemory", r.get("kdfMemory")),
                "kdfParallelism": r.get("KdfParallelism", r.get("kdfParallelism"))}


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def _ci(d: dict, *names: str, default=None):
    """Case-insensitive get: Bitwarden answers PascalCase, Vaultwarden camelCase."""
    low = {k.lower(): v for k, v in d.items()} if isinstance(d, dict) else {}
    for n in names:
        if n.lower() in low:
            return low[n.lower()]
    return default


# ── client ───────────────────────────────────────────────────────────────────
class Client:
    def __init__(self, server: Server, device_id: str | None = None, cafile: str | None = None):
        """cafile: an extra CA to trust, for servers behind a private CA."""
        self.server = server
        self.device_id = device_id or str(uuid.uuid4())
        self.access_token: str | None = None
        self._ctx = ssl.create_default_context()
        if cafile:
            self._ctx.load_verify_locations(cafile=cafile)

    # low level
    def _request(self, method: str, url: str, *, json_body=None, form: dict | None = None,
                 headers: dict | None = None, auth: bool = True) -> dict | list | None:
        h = {
            "Accept": "application/json",
            "User-Agent": f"MazeVault/{__version__} (Linux)",
            "Bitwarden-Client-Name": "maze-vault",
            "Bitwarden-Client-Version": __version__,
            "Device-Type": str(DEVICE_TYPE_LINUX_DESKTOP),
        }
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode()
            h["Content-Type"] = "application/json; charset=utf-8"
        elif form is not None:
            data = urllib.parse.urlencode(form).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
        if auth:
            if not self.access_token:
                raise ApiError("not_logged_in")
            h["Authorization"] = f"Bearer {self.access_token}"
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=self._ctx) as resp:
                body = resp.read(MAX_RESPONSE + 1)
                status = resp.status
        except urllib.error.HTTPError as e:
            try:
                body = e.read(1024 * 1024)
            finally:
                e.close()
            raise self._error(e.code, body) from None
        except ssl.SSLCertVerificationError as e:
            raise ApiError("tls", str(e.verify_message or e)) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, ssl.SSLError):
                raise ApiError("tls", str(reason)) from None
            raise ApiError("network", str(reason)) from None
        if len(body) > MAX_RESPONSE:
            raise ApiError("too_large")
        if status == 204 or not body.strip():
            return None
        try:
            return json.loads(body)
        except ValueError:
            raise ApiError("bad_response", body[:200].decode(errors="replace"), status) from None

    @staticmethod
    def _error(status: int, body: bytes) -> ApiError:
        try:
            data = json.loads(body) if body else {}
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        providers = _ci(data, "TwoFactorProviders2")
        if providers:
            return TwoFactorRequired(providers, data)
        desc = str(_ci(data, "error_description", default="") or "")
        model = _ci(data, "ErrorModel") or {}
        msg = str(_ci(model, "Message", default="") or _ci(data, "message", default="") or desc)
        low = (msg + " " + desc).lower()
        if "new device" in low and ("verif" in low or "otp" in low):
            return NewDeviceOtpRequired(data)
        if status in (400, 401) and ("username or password" in low or "invalid_grant" in low
                                     or desc == "invalid_username_or_password"):
            return ApiError("wrong_password", msg, status, data)
        if "captcha" in low:
            return ApiError("captcha", msg, status, data)
        if status == 401:
            return ApiError("unauthorized", msg, status, data)
        if status == 404:
            return ApiError("not_found", msg, status, data)
        if status == 429:
            return ApiError("rate_limited", msg, status, data)
        if status >= 500:
            return ApiError("server", msg, status, data)
        return ApiError("rejected", msg, status, data)

    def _api(self, method: str, path: str, body=None):
        return self._request(method, f"{self.server.api}/{path.lstrip('/')}", json_body=body)

    # identity
    def prelogin(self, email: str) -> dict:
        body = {"email": email}
        try:
            r = self._request("POST", f"{self.server.identity}/accounts/prelogin", json_body=body, auth=False)
        except ApiError as e:
            if e.status != 404:
                raise
            r = self._request("POST", f"{self.server.api}/accounts/prelogin", json_body=body, auth=False)
        return {k.lower(): v for k, v in (r or {}).items()}

    def _device(self) -> dict:
        return {"deviceType": str(DEVICE_TYPE_LINUX_DESKTOP), "deviceIdentifier": self.device_id,
                "deviceName": "Maze Vault"}

    def _token(self, form: dict, email: str | None = None) -> Tokens:
        headers = {"Auth-Email": _b64url(email)} if email else {}
        r = self._request("POST", f"{self.server.identity}/connect/token", form=form,
                          headers=headers, auth=False)
        if not isinstance(r, dict) or "access_token" not in r:
            raise ApiError("bad_response", "no access token")
        self.access_token = r["access_token"]
        return Tokens(r["access_token"], r.get("refresh_token"), int(r.get("expires_in", 3600)), r)

    def login_password(self, email: str, password_hash: str, *, two_factor: tuple[int, str, bool] | None = None,
                       new_device_otp: str | None = None) -> Tokens:
        form = {"grant_type": "password", "username": email, "password": password_hash,
                "scope": "api offline_access", "client_id": CLIENT_ID, **self._device()}
        if two_factor is not None:
            provider, token, remember = two_factor
            form.update({"twoFactorProvider": str(provider), "twoFactorToken": token,
                         "twoFactorRemember": "1" if remember else "0"})
        if new_device_otp:
            form["newDeviceOtp"] = new_device_otp
        return self._token(form, email)

    def login_api_key(self, client_id: str, client_secret: str) -> Tokens:
        form = {"grant_type": "client_credentials", "client_id": client_id,
                "client_secret": client_secret, "scope": "api", **self._device()}
        return self._token(form)

    def refresh(self, refresh_token: str) -> Tokens:
        form = {"grant_type": "refresh_token", "client_id": CLIENT_ID, "refresh_token": refresh_token}
        return self._token(form)

    def send_email_code(self, email: str, password_hash: str) -> None:
        self._request("POST", f"{self.server.api}/two-factor/send-email-login", auth=False,
                      json_body={"email": email, "masterPasswordHash": password_hash,
                                 "deviceIdentifier": self.device_id})

    def register(self, email: str, password_hash: str, protected_key: str, kdf: dict,
                 public_key: str, encrypted_private_key: str, name: str = "") -> None:
        """Create an account (a throwaway test server, or a user's own
        Vaultwarden with sign-ups open). Current servers use the two-step
        flow; the token comes back directly when e-mail verification is off."""
        ident = self.server.identity
        token = self._request("POST", f"{ident}/accounts/register/send-verification-email",
                              json_body={"email": email, "name": name or email.split("@")[0],
                                         "receiveMarketingEmails": False}, auth=False)
        if not isinstance(token, str) or not token:
            raise ApiError("verify_email", "the server sent a verification e-mail")
        self._request("POST", f"{ident}/accounts/register/finish", auth=False, json_body={
            "email": email, "emailVerificationToken": token,
            "masterPasswordHash": password_hash, "masterPasswordHint": None,
            "userSymmetricKey": protected_key,
            "userAsymmetricKeys": {"publicKey": public_key, "encryptedPrivateKey": encrypted_private_key},
            **kdf})

    # vault
    def sync(self) -> dict:
        r = self._api("GET", "sync?excludeDomains=true")
        if not isinstance(r, dict):
            raise ApiError("bad_response", "sync")
        return r

    def revision_date(self) -> int:
        r = self._api("GET", "accounts/revision-date")
        return int(r) if isinstance(r, (int, float)) else 0

    def create_cipher(self, cipher: dict) -> dict:
        return self._api("POST", "ciphers", cipher)

    def update_cipher(self, cipher_id: str, cipher: dict) -> dict:
        return self._api("PUT", f"ciphers/{cipher_id}", cipher)

    def soft_delete_cipher(self, cipher_id: str) -> None:
        self._api("PUT", f"ciphers/{cipher_id}/delete")

    def restore_cipher(self, cipher_id: str) -> dict:
        return self._api("PUT", f"ciphers/{cipher_id}/restore")

    def delete_cipher(self, cipher_id: str) -> None:
        """Permanent. Only ever called for an item already in the trash."""
        self._api("DELETE", f"ciphers/{cipher_id}")

    def create_folder(self, name_enc: str) -> dict:
        return self._api("POST", "folders", {"name": name_enc})

    def update_folder(self, folder_id: str, name_enc: str) -> dict:
        return self._api("PUT", f"folders/{folder_id}", {"name": name_enc})

    def delete_folder(self, folder_id: str) -> None:
        self._api("DELETE", f"folders/{folder_id}")

    def config(self) -> dict:
        try:
            r = self._request("GET", f"{self.server.api}/config", auth=False)
        except ApiError:
            return {}
        return r if isinstance(r, dict) else {}
