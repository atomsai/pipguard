"""Detect suspicious subprocess invocations."""

from __future__ import annotations

import ast
from pathlib import Path

from pipguard.core.constants import (
    SCORE_SUSPICIOUS_SUBPROCESS,
    SEVERITY_HIGH,
    SUSPICIOUS_COMMANDS,
)
from pipguard.models.finding import Finding

_SUBPROCESS_CALLS = {"subprocess.run", "subprocess.Popen", "subprocess.call", "os.system"}


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


def _extract_string_args(node: ast.Call) -> list[str]:
    """Collect string arguments from a call."""
    strings: list[str] = []
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            strings.append(arg.value)
        elif isinstance(arg, ast.List):
            for elt in arg.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    strings.append(elt.value)
    return strings


def detect_subprocess(path: Path) -> list[Finding]:
    """Detect suspicious subprocess invocations."""
    findings: list[Finding] = []
    try:
        source = path.read_text(errors="replace")
    except OSError:
        return findings

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name and name in _SUBPROCESS_CALLS:
                args = _extract_string_args(node)
                cmd_text = " ".join(args)
                suspicious_cmd = None
                for pattern in SUSPICIOUS_COMMANDS:
                    if pattern in cmd_text:
                        suspicious_cmd = pattern
                        break

                if suspicious_cmd:
                    findings.append(
                        Finding(
                            rule_id="SUSPICIOUS-SUBPROCESS",
                            severity=SEVERITY_HIGH,
                            file=str(path),
                            message=f"Suspicious subprocess with '{suspicious_cmd}'",
                            evidence=f"line {node.lineno}: {cmd_text[:100]}",
                            confidence=0.85,
                            tags=("subprocess", "command-exec"),
                        )
                    )

    return findings


SCORE_MAP = {"SUSPICIOUS-SUBPROCESS": SCORE_SUSPICIOUS_SUBPROCESS}
