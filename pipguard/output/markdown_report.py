"""Markdown report output."""

from __future__ import annotations

from pathlib import Path

from pipguard.models.report import Report


def report_to_markdown(report: Report) -> str:
    """Render a report as Markdown text."""
    lines: list[str] = []
    lines.append(f"# pipguard Report\n")
    lines.append(f"**Target:** {report.target}  ")
    lines.append(f"**Verdict:** {report.verdict}  ")
    lines.append(f"**Score:** {report.score}\n")

    if report.findings:
        lines.append("## Findings\n")
        for f in report.findings:
            lines.append(f"- **[{f.severity}]** {f.message}")
            if f.evidence:
                lines.append(f"  - Evidence: `{f.evidence}`")

    if report.next_steps:
        lines.append("\n## Next Steps\n")
        for i, step in enumerate(report.next_steps, 1):
            lines.append(f"{i}. {step}")

    return "\n".join(lines) + "\n"


def save_markdown_report(report: Report, path: str | Path) -> None:
    """Write a report to a Markdown file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(report_to_markdown(report))
