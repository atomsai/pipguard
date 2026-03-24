"""Simple text-based heuristic rules (fallback for non-parseable files)."""

from __future__ import annotations

import re
from pathlib import Path

from pipguard.core.constants import SEVERITY_MEDIUM
from pipguard.models.finding import Finding

_TEXT_SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("os.environ", re.compile(r"\bos\.environ\b")),
    ("exec(", re.compile(r"\bexec\s*\(")),
    ("eval(", re.compile(r"\beval\s*\(")),
    ("base64.b64decode", re.compile(r"\bbase64\.b64decode\b")),
    ("subprocess", re.compile(r"\bsubprocess\.(run|Popen|call)\b")),
    ("requests.post", re.compile(r"\brequests\.(post|put)\b")),
    ("socket.connect", re.compile(r"\bsocket\.connect\b")),
]


def scan_text_rules(path: Path) -> list[Finding]:
    """Apply text-based heuristic rules to a single file."""
    findings: list[Finding] = []
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return findings

    for label, pattern in _TEXT_SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            findings.append(
                Finding(
                    rule_id="TEXT-HEURISTIC",
                    severity=SEVERITY_MEDIUM,
                    file=str(path),
                    message=f"Text heuristic match: {label}",
                    confidence=0.6,
                    tags=("text-heuristic",),
                )
            )

    return findings
