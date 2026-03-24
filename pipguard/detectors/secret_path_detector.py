"""Detect reads of sensitive filesystem paths."""

from __future__ import annotations

import ast
from pathlib import Path

from pipguard.core.constants import SCORE_SECRET_PATH_READ, SENSITIVE_PATH_MARKERS, SEVERITY_HIGH
from pipguard.models.finding import Finding

_READ_FUNCTIONS = {"open", "read_text", "read_bytes", "expanduser", "glob", "rglob"}


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _extract_string_literals(node: ast.AST) -> list[str]:
    """Collect string literals from a node subtree."""
    strings: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            strings.append(child.value)
    return strings


def detect_secret_paths(path: Path) -> list[Finding]:
    """Detect references to sensitive filesystem paths."""
    findings: list[Finding] = []
    try:
        source = path.read_text(errors="replace")
    except OSError:
        return findings

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    literals: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _call_name(node)
            if call_name in _READ_FUNCTIONS:
                literals.extend(_extract_string_literals(node))

    matched_markers: list[str] = []
    for lit in literals:
        for marker in SENSITIVE_PATH_MARKERS:
            if marker in lit:
                matched_markers.append(marker)

    # Deduplicate markers
    matched_markers = sorted(set(matched_markers))

    if matched_markers:
        confidence = min(0.7 + len(matched_markers) * 0.05, 0.98)
        findings.append(
            Finding(
                rule_id="SECRET-PATH-READ",
                severity=SEVERITY_HIGH,
                file=str(path),
                message=f"References to sensitive paths: {', '.join(matched_markers[:5])}",
                evidence="; ".join(matched_markers[:5]),
                confidence=confidence,
                tags=("secret-path", "credential-read"),
            )
        )

    return findings


SCORE_MAP = {"SECRET-PATH-READ": SCORE_SECRET_PATH_READ}
