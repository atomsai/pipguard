"""General utility helpers."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def python_executable() -> str:
    """Return the path to the running Python interpreter."""
    return sys.executable


def is_python_file(path: Path) -> bool:
    """Return True if *path* looks like a Python source file."""
    return path.suffix == ".py" and path.is_file()


def is_pth_file(path: Path) -> bool:
    """Return True if *path* is a .pth file."""
    return path.suffix == ".pth" and path.is_file()


def walk_python_files(root: Path) -> list[Path]:
    """Recursively yield all .py files under *root*."""
    results: list[Path] = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            fp = Path(dirpath) / fname
            if is_python_file(fp):
                results.append(fp)
    return sorted(results)


def walk_pth_files(root: Path) -> list[Path]:
    """Recursively yield all .pth files under *root*."""
    results: list[Path] = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            fp = Path(dirpath) / fname
            if is_pth_file(fp):
                results.append(fp)
    return sorted(results)


def walk_all_files(root: Path) -> list[Path]:
    """Recursively yield all files under *root*."""
    results: list[Path] = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            results.append(Path(dirpath) / fname)
    return sorted(results)


def relative_display(path: Path, base: Path) -> str:
    """Return a short display path relative to *base* when possible."""
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)
