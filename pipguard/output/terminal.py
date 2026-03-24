"""Terminal output formatting for pipguard."""

from __future__ import annotations

import sys
from typing import TextIO

from pipguard.models.finding import Finding
from pipguard.models.report import Report
from pipguard.runtime.runner import RunResult

# ANSI color codes
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_SEVERITY_COLORS = {
    "critical": _RED,
    "high": _RED,
    "medium": _YELLOW,
    "low": _DIM,
}

_VERDICT_COLORS = {
    "blocked": _RED,
    "warned": _YELLOW,
    "allowed": _GREEN,
    "review-now": _RED,
    "no-major-findings": _GREEN,
    "high exposure": _RED,
    "medium exposure": _YELLOW,
    "low exposure": _GREEN,
    "minimal exposure": _GREEN,
}


def _color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


def print_scan_report(report: Report, stream: TextIO = sys.stdout) -> None:
    """Print a scan report to the terminal."""
    vc = _VERDICT_COLORS.get(report.verdict, "")
    header = _color(f"{report.verdict.upper()}", _BOLD + vc)
    stream.write(f"\n{header} [{report.verdict}]\n")
    stream.write(f"Target: {report.target}\n")
    stream.write(f"Score: {report.score}\n\n")

    if report.findings:
        stream.write("Why this was flagged:\n")
        for f in report.findings:
            sc = _SEVERITY_COLORS.get(f.severity, "")
            bullet = _color(f"  [{f.severity}]", sc)
            stream.write(f"{bullet} {f.message}\n")
            if f.evidence:
                stream.write(f"         {_color(f.evidence, _DIM)}\n")
        stream.write("\n")

    if report.next_steps:
        stream.write("Next steps:\n")
        for i, step in enumerate(report.next_steps, 1):
            stream.write(f"  {i}. {step}\n")
        stream.write("\n")


def print_doctor_report(report: Report, stream: TextIO = sys.stdout) -> None:
    """Print a doctor report."""
    vc = _VERDICT_COLORS.get(report.verdict, "")
    header = _color(f"RESULT", _BOLD + vc)
    stream.write(f"\n{header} [{report.verdict}]\n")

    if report.findings:
        stream.write("\nFindings:\n")
        for f in report.findings:
            sc = _SEVERITY_COLORS.get(f.severity, "")
            bullet = _color(f"  [{f.severity}]", sc)
            stream.write(f"{bullet} {f.message}\n")
            if f.evidence:
                stream.write(f"         {f.evidence}\n")
        stream.write("\n")

    if report.next_steps:
        stream.write("Next steps:\n")
        for i, step in enumerate(report.next_steps, 1):
            stream.write(f"  {i}. {step}\n")
        stream.write("\n")


def print_env_audit(report: Report, stream: TextIO = sys.stdout) -> None:
    """Print env-audit results."""
    summary = report.summary
    label = summary.get("exposure_label", report.verdict)
    vc = _VERDICT_COLORS.get(label, "")
    header = _color("RESULT", _BOLD + vc)
    stream.write(f"\n{header} [{label}]\n")

    cred_vars = summary.get("credential_env_vars", [])
    if cred_vars:
        stream.write("\nDetected likely credentials:\n")
        for var in cred_vars:
            stream.write(f"  • {var}\n")

    secret_files = summary.get("sensitive_local_files", [])
    if secret_files:
        stream.write("\nDetected sensitive local files:\n")
        for sf in secret_files:
            stream.write(f"  • {sf}\n")

    stream.write(f"\nExposure score: {summary.get('exposure_score', 0)}/100\n")

    if report.score >= 40:
        stream.write(
            "\nRisk:\n"
            "  Any compromised dependency running in this shell could likely access\n"
            "  these secrets.\n"
        )

    if report.next_steps:
        stream.write("\nNext steps:\n")
        for i, step in enumerate(report.next_steps, 1):
            stream.write(f"  {i}. {step}\n")
    stream.write("\n")


def print_run_result(result: RunResult, stream: TextIO = sys.stdout) -> None:
    """Print the run command results."""
    if result.dry_run:
        stream.write(f"\n{_color('DRY RUN', _BOLD + _CYAN)} — no process launched\n")
    else:
        stream.write(f"\n{_color('Launching with scrubbed environment...', _BOLD)}\n")

    if result.inherited:
        stream.write("\nInherited:\n")
        for var in result.inherited:
            stream.write(f"  • {var}\n")

    if result.blocked:
        stream.write(f"\n{_color('Blocked:', _BOLD + _RED)}\n")
        for var in result.blocked:
            stream.write(f"  • {var}\n")

    stream.write(f"\n{_color('Blast radius reduced.', _GREEN)}\n\n")
