"""Verdict constants."""

from __future__ import annotations

import enum


class Verdict(str, enum.Enum):
    ALLOWED = "allowed"
    WARNED = "warned"
    BLOCKED = "blocked"
    REVIEW_NOW = "review-now"
    NO_MAJOR_FINDINGS = "no-major-findings"

    def __str__(self) -> str:
        return self.value
