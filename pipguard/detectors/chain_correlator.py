"""Source-to-sink correlation: escalate severity when both source and sink appear together."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from pipguard.core.constants import (
    SCORE_SOURCE_TO_SINK,
    SCORE_SOURCE_TO_SINK_FUNCTION,
    SEVERITY_CRITICAL,
)
from pipguard.models.finding import Finding

_SOURCE_RULES = {"ENV-ENUM", "SECRET-PATH-READ"}
_SINK_RULES = {"EXFIL-SINK", "SUSPICIOUS-SUBPROCESS"}
_LINE_RE = re.compile(r"line\s+(\d+)")


def _line_from_evidence(evidence: str | None) -> int | None:
    if not evidence:
        return None
    match = _LINE_RE.search(evidence)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _function_ranges_for_file(filepath: str) -> list[tuple[str, int, int]]:
    p = Path(filepath)
    if not p.exists() or p.suffix != ".py":
        return []
    try:
        source = p.read_text(errors="replace")
        tree = ast.parse(source, filename=filepath)
    except (OSError, SyntaxError):
        return []

    ranges: list[tuple[str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.end_lineno is None:
                continue
            ranges.append((node.name, node.lineno, node.end_lineno))
    return ranges


def _function_for_line(line: int, fn_ranges: list[tuple[str, int, int]]) -> str | None:
    for name, start, end in fn_ranges:
        if start <= line <= end:
            return name
    return None


def correlate(findings: list[Finding]) -> list[Finding]:
    """Analyze findings and add correlation findings for source-to-sink chains.

    Correlation is performed at:
    1) same function (when line evidence is available), and
    2) same file (fallback / broader signal).
    """
    files_with_sources: dict[str, list[Finding]] = {}
    files_with_sinks: dict[str, list[Finding]] = {}

    for f in findings:
        if f.rule_id in _SOURCE_RULES:
            files_with_sources.setdefault(f.file, []).append(f)
        if f.rule_id in _SINK_RULES:
            files_with_sinks.setdefault(f.file, []).append(f)

    correlation_findings: list[Finding] = []
    for filepath in set(files_with_sources) & set(files_with_sinks):
        sources = files_with_sources[filepath]
        sinks = files_with_sinks[filepath]
        source_desc = ", ".join(sorted({f.rule_id for f in sources}))
        sink_desc = ", ".join(sorted({f.rule_id for f in sinks}))

        fn_ranges = _function_ranges_for_file(filepath)
        function_pairs: set[str] = set()
        if fn_ranges:
            source_fns = {
                _function_for_line(line, fn_ranges)
                for line in (_line_from_evidence(f.evidence) for f in sources)
                if line is not None
            }
            sink_fns = {
                _function_for_line(line, fn_ranges)
                for line in (_line_from_evidence(f.evidence) for f in sinks)
                if line is not None
            }
            function_pairs = {name for name in source_fns & sink_fns if name}

        if function_pairs:
            fn_text = ", ".join(sorted(function_pairs))
            message = (
                f"Function-level source-to-sink correlation in [{fn_text}]: "
                f"[{source_desc}] -> [{sink_desc}]"
            )
            confidence = 0.97
            rule_id = "SOURCE-TO-SINK-FUNCTION"
        else:
            message = f"Source-to-sink correlation: [{source_desc}] -> [{sink_desc}]"
            confidence = 0.92
            rule_id = "SOURCE-TO-SINK"

        correlation_findings.append(
            Finding(
                rule_id=rule_id,
                severity=SEVERITY_CRITICAL,
                file=filepath,
                message=message,
                confidence=confidence,
                tags=("correlation", "critical-chain"),
            )
        )

    return findings + correlation_findings


SCORE_MAP = {
    "SOURCE-TO-SINK": SCORE_SOURCE_TO_SINK,
    "SOURCE-TO-SINK-FUNCTION": SCORE_SOURCE_TO_SINK_FUNCTION,
}
