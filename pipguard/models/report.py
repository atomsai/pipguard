"""Scan report data model."""

from __future__ import annotations

import dataclasses
from typing import Any

from pipguard.models.finding import Finding


@dataclasses.dataclass(slots=True)
class Report:
    """Aggregated report from a scan, doctor, or audit operation."""

    target: str
    verdict: str
    score: int = 0
    findings: list[Finding] = dataclasses.field(default_factory=list)
    summary: dict[str, Any] = dataclasses.field(default_factory=dict)
    next_steps: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "verdict": self.verdict,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "next_steps": self.next_steps,
        }
