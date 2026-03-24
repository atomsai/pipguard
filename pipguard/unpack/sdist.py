"""Sdist unpacking (.tar.gz archives)."""

from __future__ import annotations

import tarfile
from pathlib import Path


def _is_safe_tar_member(dest: Path, member: tarfile.TarInfo) -> bool:
    if member.issym() or member.islnk():
        return False
    name = member.name
    if name.startswith("/"):
        return False
    candidate = (dest / name).resolve()
    return str(candidate).startswith(str(dest.resolve()))


def unpack_sdist(tar_path: Path, dest: Path) -> Path:
    """Unpack a .tar.gz / .tgz / .tar.bz2 archive into *dest*."""
    with tarfile.open(tar_path, "r:*") as tf:
        # Security: filter out absolute paths and path traversals
        members = []
        for m in tf.getmembers():
            if not _is_safe_tar_member(dest, m):
                continue
            members.append(m)
        tf.extractall(dest, members=members)
    return dest
