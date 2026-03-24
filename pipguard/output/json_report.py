"""JSON report output."""

from __future__ import annotations

import json
from pathlib import Path

from pipguard.models.report import Report


def save_json_report(report: Report, path: str | Path) -> None:
    """Write a report to a JSON file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(report.to_dict(), f, indent=2)


def report_to_json(report: Report) -> str:
    """Serialize a report to a JSON string."""
    return json.dumps(report.to_dict(), indent=2)
