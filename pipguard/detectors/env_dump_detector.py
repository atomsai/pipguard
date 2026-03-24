"""Detect environment variable enumeration patterns."""

from __future__ import annotations

import ast
from pathlib import Path

from pipguard.core.constants import SCORE_ENV_ENUMERATION, SEVERITY_MEDIUM
from pipguard.models.finding import Finding

_TEXT_PATTERNS = [
    "os.environ",
    "dict(os.environ)",
    "os.environ.items()",
    "json.dumps(dict(os.environ))",
]


def _is_env_access(node: ast.AST) -> bool:
    """Return True if node accesses os.environ in an enumeration-like way."""
    if isinstance(node, ast.Attribute):
        if (
            isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "os"
            and node.value.attr == "environ"
            and node.attr in ("items", "keys", "values", "copy")
        ):
            return True
        if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
            return True
    return False


def detect_env_dump(path: Path) -> list[Finding]:
    """Detect env enumeration in a Python file via AST + text heuristics."""
    findings: list[Finding] = []
    try:
        source = path.read_text(errors="replace")
    except OSError:
        return findings

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        # Text fallback when AST parsing fails.
        for pat in _TEXT_PATTERNS:
            if pat in source:
                findings.append(
                    Finding(
                        rule_id="ENV-ENUM",
                        severity=SEVERITY_MEDIUM,
                        file=str(path),
                        message=f"Environment enumeration pattern: {pat}",
                        evidence=pat,
                        confidence=0.75,
                        tags=("env", "enumeration"),
                    )
                )
                break
        return findings

    # AST-first detection for line-aware evidence.
    text_hit_line: int | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and _is_env_access(node):
            text_hit_line = getattr(node, "lineno", None)
            break

    for pat in _TEXT_PATTERNS:
        if pat in source:
            evidence = f"line {text_hit_line}" if text_hit_line is not None else pat
            findings.append(
                Finding(
                    rule_id="ENV-ENUM",
                    severity=SEVERITY_MEDIUM,
                    file=str(path),
                    message=f"Environment enumeration pattern: {pat}",
                    evidence=evidence,
                    confidence=0.8,
                    tags=("env", "enumeration"),
                )
            )
            break

    # AST pass for loops over os.environ
    for node in ast.walk(tree):
        if isinstance(node, ast.For) and _is_env_access(node.iter):
            findings.append(
                Finding(
                    rule_id="ENV-ENUM",
                    severity=SEVERITY_MEDIUM,
                    file=str(path),
                    message="Loop over os.environ detected",
                    evidence=f"line {node.lineno}",
                    confidence=0.85,
                    tags=("env", "enumeration"),
                )
            )

    # Deduplicate by keeping unique messages
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        key = f"{f.rule_id}:{f.message}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


SCORE_MAP = {"ENV-ENUM": SCORE_ENV_ENUMERATION}
