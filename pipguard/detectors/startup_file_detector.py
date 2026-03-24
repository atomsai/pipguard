"""Detect suspicious startup hook files (sitecustomize.py, usercustomize.py, *_init.pth)."""

from __future__ import annotations

from pathlib import Path

from pipguard.core.constants import SCORE_STARTUP_HOOK, SEVERITY_HIGH
from pipguard.models.finding import Finding

_SUSPICIOUS_NAMES = {"sitecustomize.py", "usercustomize.py"}


def _is_suspicious_pth_name(name: str) -> bool:
    return name.endswith("_init.pth")


def detect_startup_file(path: Path) -> list[Finding]:
    """Flag the mere presence of startup hook files."""
    findings: list[Finding] = []
    name = path.name.lower()

    if name in _SUSPICIOUS_NAMES or _is_suspicious_pth_name(name):
        findings.append(
            Finding(
                rule_id="STARTUP-HOOK",
                severity=SEVERITY_HIGH,
                file=str(path),
                message=f"Suspicious startup hook file: {name}",
                confidence=0.9,
                tags=("startup", "persistence"),
            )
        )
    return findings


SCORE_MAP = {"STARTUP-HOOK": SCORE_STARTUP_HOOK}
