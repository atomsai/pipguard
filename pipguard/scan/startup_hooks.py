"""Startup hook scanning (delegates to relevant detectors)."""

from __future__ import annotations

from pathlib import Path

from pipguard.detectors.pth_detector import detect_pth
from pipguard.detectors.startup_file_detector import detect_startup_file
from pipguard.models.finding import Finding


def scan_startup_hooks(root: Path) -> list[Finding]:
    """Scan a directory tree for startup hook abuse."""
    from pipguard.core.utils import walk_all_files

    findings: list[Finding] = []
    for path in walk_all_files(root):
        if path.suffix == ".pth":
            findings.extend(detect_pth(path))
        findings.extend(detect_startup_file(path))
    return findings
