"""Data model for a single security finding."""

from __future__ import annotations

import dataclasses
from typing import Optional


@dataclasses.dataclass(frozen=True, slots=True)
class Finding:
    """A single security finding produced by a detector."""

    rule_id: str
    severity: str  # low, medium, high, critical
    file: str
    message: str
    evidence: Optional[str] = None
    confidence: float = 0.8
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "message": self.message,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "tags": list(self.tags),
        }
