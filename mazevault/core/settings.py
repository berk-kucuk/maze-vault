"""Per-user preferences, in ~/.config/maze-vault/settings.json. No secrets here."""
from __future__ import annotations

from mazevault.core import atomic, paths

DEFAULTS = {
    "language": "en",            # "en" (default) or "tr"
    "auto_lock_minutes": 10,     # lock after this long without use; 0 = never
    "lock_on_screen_lock": True,
    "lock_on_sleep": True,
    "clipboard_seconds": 30,     # clear a copied secret after this long; 0 = never
    "last_account": "",
}
LANGUAGES = ("en", "tr")


def _path():
    return paths.config_dir() / "settings.json"


def load() -> dict:
    out = dict(DEFAULTS)
    data = atomic.read_json(_path())
    if isinstance(data, dict):
        for k, v in data.items():
            if k in DEFAULTS and type(v) is type(DEFAULTS[k]):
                out[k] = v
    if out["language"] not in LANGUAGES:
        out["language"] = "en"
    out["auto_lock_minutes"] = max(0, min(out["auto_lock_minutes"], 24 * 60))
    out["clipboard_seconds"] = max(0, min(out["clipboard_seconds"], 600))
    return out


def save(**values) -> None:
    try:
        atomic.ensure_private_dir(paths.config_dir())
        atomic.write_json(_path(), {**load(), **values})
    except OSError:
        pass
