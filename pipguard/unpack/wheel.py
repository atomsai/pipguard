"""Wheel unpacking (.whl files are zip archives)."""

from __future__ import annotations

import zipfile
from pathlib import Path


def _is_safe_zip_path(dest: Path, member_name: str) -> bool:
    candidate = (dest / member_name).resolve()
    return str(candidate).startswith(str(dest.resolve()))


def unpack_wheel(whl_path: Path, dest: Path) -> Path:
    """Unpack a .whl (zip) archive into *dest* and return the extraction root."""
    with zipfile.ZipFile(whl_path, "r") as zf:
        for member in zf.infolist():
            name = member.filename
            if member.is_dir():
                continue
            if name.startswith("/") or not _is_safe_zip_path(dest, name):
                continue
            zf.extract(member, dest)
    return dest
