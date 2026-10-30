"""Where Maze Vault keeps things.

    ~/.local/share/maze-vault/accounts/<id>/   one account (see vault.py)
    ~/.config/maze-vault/settings.json         preferences
"""
from __future__ import annotations

import os
from pathlib import Path


def _xdg(var: str, fallback: str) -> Path:
    value = os.environ.get(var, "")
    return Path(value) if value and os.path.isabs(value) else Path.home() / fallback


def data_dir() -> Path:
    return _xdg("XDG_DATA_HOME", ".local/share") / "maze-vault"


def accounts_dir() -> Path:
    return data_dir() / "accounts"


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / "maze-vault"
