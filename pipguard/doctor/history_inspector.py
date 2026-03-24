"""Inspect shell history for suspicious commands."""

from __future__ import annotations

import re

from pipguard.core.constants import SEVERITY_MEDIUM
from pipguard.core.paths import history_files
from pipguard.models.finding import Finding

_SUSPICIOUS_HISTORY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("pip install from unusual source", re.compile(r"pip install.*--index-url\s+http://")),
    ("curl piped to shell", re.compile(r"curl\s+.*\|\s*(bash|sh|python)")),
    ("wget piped to shell", re.compile(r"wget\s+.*\|\s*(bash|sh|python)")),
    ("base64 decode in shell", re.compile(r"base64\s+(-d|--decode)")),
    ("suspicious pip install", re.compile(r"pip install\s+--trusted-host")),
]


def inspect_history_files() -> list[Finding]:
    """Scan shell history files for suspicious commands."""
    findings: list[Finding] = []
    for hist_file in history_files():
        try:
            content = hist_file.read_text(errors="replace")
        except OSError:
            continue

        for label, pattern in _SUSPICIOUS_HISTORY_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                findings.append(
                    Finding(
                        rule_id="HISTORY-SUSPICIOUS",
                        severity=SEVERITY_MEDIUM,
                        file=str(hist_file),
                        message=f"Suspicious shell history: {label} ({len(matches)} occurrences)",
                        confidence=0.6,
                        tags=("history", "shell"),
                    )
                )

    return findings
