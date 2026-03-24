"""Package metadata model."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Optional


@dataclasses.dataclass(slots=True)
class PackageInfo:
    """Metadata about a package artifact being scanned."""

    name: str
    version: Optional[str] = None
    path: Optional[Path] = None
    artifact_type: str = "unknown"  # wheel, sdist, directory

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "path": str(self.path) if self.path else None,
            "artifact_type": self.artifact_type,
        }
