"""Detect executable code in .pth files."""

from __future__ import annotations

import re
from pathlib import Path

from pipguard.core.constants import SCORE_EXECUTABLE_PTH, SEVERITY_CRITICAL, SEVERITY_HIGH
from pipguard.models.finding import Finding

_SUSPICIOUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*import\s+"),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bcompile\s*\("),
    re.compile(r"\bopen\s*\("),
    re.compile(r"\brequests\b"),
    re.compile(r"\bhttpx\b"),
    re.compile(r"\burllib\b"),
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\bsocket\b"),
    re.compile(r"\bbase64\b"),
    re.compile(r"\bos\.environ\b"),
]

_CODE_HEURISTIC = re.compile(r"[;=(]")


def detect_pth(path: Path) -> list[Finding]:
    """Scan a single .pth file for executable content."""
    findings: list[Finding] = []
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return findings

    suspicious_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for pat in _SUSPICIOUS_PATTERNS:
            if pat.search(stripped):
                suspicious_lines.append(stripped)
                break
        else:
            if _CODE_HEURISTIC.search(stripped):
                suspicious_lines.append(stripped)

    if suspicious_lines:
        evidence = "\n".join(suspicious_lines[:5])
        severity = SEVERITY_CRITICAL if len(suspicious_lines) >= 2 else SEVERITY_HIGH
        findings.append(
            Finding(
                rule_id="PTH-EXEC",
                severity=severity,
                file=str(path),
                message="Executable code detected in .pth file",
                evidence=evidence,
                confidence=0.95,
                tags=("pth", "executable", "startup"),
            )
        )
    return findings


SCORE_MAP = {"PTH-EXEC": SCORE_EXECUTABLE_PTH}
