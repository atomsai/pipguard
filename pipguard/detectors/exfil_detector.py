"""Detect outbound network / exfiltration sinks."""

from __future__ import annotations

import ast
from pathlib import Path

from pipguard.core.constants import EXFIL_CALL_PATTERNS, SCORE_EXFIL_SINK, SEVERITY_MEDIUM
from pipguard.models.finding import Finding


def _call_name(node: ast.Call) -> str | None:
    """Extract the dotted name of a Call node."""
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


def _socket_module_aliases(tree: ast.AST) -> set[str]:
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                if name.name == "socket":
                    aliases.add(name.asname or "socket")
    return aliases


def detect_exfil(path: Path) -> list[Finding]:
    """Detect exfiltration sinks (network calls)."""
    findings: list[Finding] = []
    try:
        source = path.read_text(errors="replace")
    except OSError:
        return findings

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    socket_aliases = _socket_module_aliases(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            matched = bool(name and name in EXFIL_CALL_PATTERNS)

            # Catch common sink styles like `sock.connect(...)` and `sock.send(...)`
            # when the module imported socket somewhere in the file.
            if (
                not matched
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"connect", "send"}
                and socket_aliases
            ):
                matched = True
                name = f"*.{node.func.attr}"

            if matched and name:
                findings.append(
                    Finding(
                        rule_id="EXFIL-SINK",
                        severity=SEVERITY_MEDIUM,
                        file=str(path),
                        message=f"Outbound network call: {name}()",
                        evidence=f"line {node.lineno}" if hasattr(node, "lineno") else None,
                        confidence=0.8,
                        tags=("exfil", "network"),
                    )
                )

    return findings


SCORE_MAP = {"EXFIL-SINK": SCORE_EXFIL_SINK}
