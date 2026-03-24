"""Archive detection and unpacking dispatcher."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pipguard.unpack.sdist import unpack_sdist
from pipguard.unpack.wheel import unpack_wheel


def detect_and_unpack(path: Path, dest: Path | None = None) -> Path:
    """Detect the archive type of *path* and unpack into *dest*.

    If *path* is already a directory, return it directly.
    Returns the path to the unpacked directory.
    """
    if path.is_dir():
        return path

    if dest is None:
        dest = Path(tempfile.mkdtemp(prefix="pipguard_unpack_"))

    name = path.name.lower()
    if name.endswith(".whl"):
        return unpack_wheel(path, dest)
    if name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".tar.bz2"):
        return unpack_sdist(path, dest)
    if name.endswith(".zip"):
        return unpack_wheel(path, dest)  # zip-based, same logic

    raise ValueError(f"Unsupported archive format: {path.name}")
