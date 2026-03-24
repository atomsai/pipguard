"""Well-known filesystem paths used by pipguard."""

from __future__ import annotations

import site
import sys
from pathlib import Path


def site_packages_dirs() -> list[Path]:
    """Return all active site-packages directories."""
    dirs: list[Path] = []
    for d in site.getsitepackages():
        p = Path(d)
        if p.is_dir():
            dirs.append(p)
    user_sp = site.getusersitepackages()
    if isinstance(user_sp, str):
        p = Path(user_sp)
        if p.is_dir():
            dirs.append(p)
    return dirs


def pip_cache_dir() -> Path | None:
    """Return pip's HTTP cache directory if it exists."""
    candidates = [
        Path.home() / ".cache" / "pip",
        Path.home() / "Library" / "Caches" / "pip",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def uv_cache_dir() -> Path | None:
    """Return uv's cache directory if it exists."""
    candidates = [
        Path.home() / ".cache" / "uv",
        Path.home() / "Library" / "Caches" / "uv",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def history_files() -> list[Path]:
    """Return shell history files that exist."""
    candidates = [
        Path.home() / ".bash_history",
        Path.home() / ".zsh_history",
    ]
    return [c for c in candidates if c.is_file()]


def python_prefix() -> Path:
    """Return the active Python prefix (venv or system)."""
    return Path(sys.prefix)
