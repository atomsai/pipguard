"""Resolve package specs to downloadable artifacts."""

from __future__ import annotations

from pathlib import Path


def list_artifacts(download_dir: Path) -> list[Path]:
    """List downloaded artifact files (wheels, sdists) in a directory."""
    exts = {".whl", ".tar.gz", ".tgz", ".zip"}
    results: list[Path] = []
    for f in sorted(download_dir.iterdir()):
        if f.is_file():
            if any(f.name.endswith(ext) for ext in exts):
                results.append(f)
    return results
