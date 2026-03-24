"""Detect suspicious import-time (top-level) side effects in Python files."""

from __future__ import annotations

import ast
from pathlib import Path

from pipguard.core.constants import SCORE_IMPORT_TIME_SIDE_EFFECT, SEVERITY_HIGH
from pipguard.models.finding import Finding

_SUSPICIOUS_TOP_LEVEL_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "urllib.request.urlopen",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "os.system",
    "exec",
    "eval",
}


def _call_name(node: ast.Call) -> str | None:
    """Extract the dotted name of a Call node's function."""
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


def _iter_top_level_calls(stmt: ast.stmt) -> list[ast.Call]:
    """Return call nodes directly executed by a module-level statement."""
    calls: list[ast.Call] = []
    for node in ast.walk(stmt):
        if isinstance(node, ast.Call):
            calls.append(node)
    return calls


def detect_import_time(path: Path) -> list[Finding]:
    """Detect top-level suspicious calls in a Python file."""
    findings: list[Finding] = []
    try:
        source = path.read_text(errors="replace")
    except OSError:
        return findings

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for call in _iter_top_level_calls(node):
            name = _call_name(call)
            if name and name in _SUSPICIOUS_TOP_LEVEL_CALLS:
                findings.append(
                    Finding(
                        rule_id="IMPORT-TIME-SIDE-EFFECT",
                        severity=SEVERITY_HIGH,
                        file=str(path),
                        message=f"Top-level suspicious call: {name}()",
                        evidence=f"line {call.lineno}",
                        confidence=0.85,
                        tags=("import-time", "side-effect"),
                    )
                )
    return findings


SCORE_MAP = {"IMPORT-TIME-SIDE-EFFECT": SCORE_IMPORT_TIME_SIDE_EFFECT}
