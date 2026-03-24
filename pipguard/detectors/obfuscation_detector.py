"""Detect obfuscation patterns (base64, marshal, exec, eval, etc.)."""

from __future__ import annotations

import ast
from pathlib import Path

from pipguard.core.constants import (
    OBFUSCATION_CALL_PATTERNS,
    SCORE_DYNAMIC_EXEC,
    SCORE_OBFUSCATION,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from pipguard.models.finding import Finding

_EXEC_EVAL = {"exec", "eval", "compile"}


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts: list[str] = [node.func.attr]
        obj = node.func.value
        while isinstance(obj, ast.Attribute):
            parts.append(obj.attr)
            obj = obj.value
        if isinstance(obj, ast.Name):
            parts.append(obj.id)
        return ".".join(reversed(parts))
    return None


def detect_obfuscation(path: Path) -> list[Finding]:
    """Detect obfuscation / dynamic execution patterns."""
    findings: list[Finding] = []
    try:
        source = path.read_text(errors="replace")
    except OSError:
        return findings

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    has_decode = False
    has_exec = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name and name in OBFUSCATION_CALL_PATTERNS:
                if name in _EXEC_EVAL:
                    has_exec = True
                    findings.append(
                        Finding(
                            rule_id="DYNAMIC-EXEC",
                            severity=SEVERITY_HIGH,
                            file=str(path),
                            message=f"Dynamic execution: {name}()",
                            evidence=f"line {node.lineno}" if hasattr(node, "lineno") else None,
                            confidence=0.85,
                            tags=("obfuscation", "dynamic-exec"),
                        )
                    )
                else:
                    has_decode = True
                    findings.append(
                        Finding(
                            rule_id="OBFUSCATION",
                            severity=SEVERITY_MEDIUM,
                            file=str(path),
                            message=f"Obfuscation pattern: {name}()",
                            evidence=f"line {node.lineno}" if hasattr(node, "lineno") else None,
                            confidence=0.75,
                            tags=("obfuscation",),
                        )
                    )

    # Upgrade: obfuscation + exec together => high
    if has_decode and has_exec:
        for i, f in enumerate(findings):
            if f.rule_id == "OBFUSCATION":
                findings[i] = Finding(
                    rule_id=f.rule_id,
                    severity=SEVERITY_HIGH,
                    file=f.file,
                    message=f.message + " (combined with dynamic exec)",
                    evidence=f.evidence,
                    confidence=min(f.confidence + 0.1, 0.98),
                    tags=f.tags,
                )

    return findings


SCORE_MAP = {"OBFUSCATION": SCORE_OBFUSCATION, "DYNAMIC-EXEC": SCORE_DYNAMIC_EXEC}
