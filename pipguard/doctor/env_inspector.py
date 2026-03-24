"""Inspect site-packages for suspicious artifacts."""

from __future__ import annotations

from pathlib import Path

from pipguard.core.utils import walk_pth_files, walk_python_files
from pipguard.detectors.env_dump_detector import detect_env_dump
from pipguard.detectors.exfil_detector import detect_exfil
from pipguard.detectors.import_time_detector import detect_import_time
from pipguard.detectors.pth_detector import detect_pth
from pipguard.detectors.secret_path_detector import detect_secret_paths
from pipguard.detectors.startup_file_detector import detect_startup_file
from pipguard.models.finding import Finding


def inspect_site_packages(sp_dir: Path) -> list[Finding]:
    """Scan a site-packages directory for suspicious files."""
    findings: list[Finding] = []

    for pth in walk_pth_files(sp_dir):
        findings.extend(detect_pth(pth))
        findings.extend(detect_startup_file(pth))

    # Scan installed package Python files while skipping metadata-heavy directories.
    for py in walk_python_files(sp_dir):
        parts = {p.lower() for p in py.parts}
        if "__pycache__" in parts:
            continue
        if any(part.endswith(".dist-info") or part.endswith(".egg-info") for part in parts):
            continue
        findings.extend(detect_startup_file(py))
        findings.extend(detect_import_time(py))
        findings.extend(detect_env_dump(py))
        findings.extend(detect_secret_paths(py))
        findings.extend(detect_exfil(py))

    return findings
