"""Default policy enforcement."""

from __future__ import annotations

from pipguard.core.config import ScanConfig
from pipguard.models.report import Report


def should_block(report: Report, config: ScanConfig) -> bool:
    """Return True if the report should block installation per the active policy."""
    if config.policy == "warn":
        return False

    has_critical = any(f.severity == "critical" for f in report.findings)
    has_high = any(f.severity == "high" for f in report.findings)

    # PRD behavior: any high/critical blocks by default, independent of score.
    if has_critical and not config.allow_critical:
        return True
    if has_high and not (config.allow_high or config.allow_critical):
        return True

    # Explicit overrides can force allow.
    if config.allow_critical:
        return False
    if config.allow_high and not has_critical:
        return False

    # Fallback to verdict for medium/low aggregate risk.
    return report.verdict == "blocked"
