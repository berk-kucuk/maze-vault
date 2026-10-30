"""Crash-safe small-file writes (same rules as Maze Capsule).

New content goes to a temp file in the same directory, is fsync'ed, renamed
over the old file, and the directory is fsync'ed: a power cut leaves the old
file or the new one, never a mix. JSON files keep a `.bak` of the previous
valid version and `read_json` falls back to it.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    fsync_dir(path.parent)


def _backup(path: Path) -> Path:
    return path.with_name(path.name + ".bak")


def write_json(path: Path, obj: Any) -> None:
    path = Path(path)
    data = (json.dumps(obj, indent=1, ensure_ascii=False) + "\n").encode()
    if path.exists():
        try:
            current = path.read_bytes()
            json.loads(current)
            write_bytes(_backup(path), current)
        except (OSError, ValueError):
            pass
    write_bytes(path, data)


def read_json(path: Path) -> Any | None:
    path = Path(path)
    for candidate in (path, _backup(path)):
        try:
            return json.loads(candidate.read_bytes())
        except (OSError, ValueError):
            continue
    return None


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        if path.stat().st_mode & 0o077:
            path.chmod(0o700)
    except OSError:
        pass
    return path
