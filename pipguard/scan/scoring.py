"""Scan scoring — aggregate findings into a numeric score and verdict."""

from __future__ import annotations

from pipguard.core.constants import (
    SEVERITY_CRITICAL,
    THRESHOLD_BLOCKED,
    THRESHOLD_WARNED,
)
from pipguard.detectors import (
    chain_correlator,
    env_dump_detector,
    exfil_detector,
    ioc_detector,
    obfuscation_detector,
    pth_detector,
    secret_path_detector,
    startup_file_detector,
    subprocess_detector,
)
from pipguard.detectors.import_time_detector import SCORE_MAP as IMPORT_SCORE
from pipguard.models.finding import Finding
from pipguard.models.verdict import Verdict

_ALL_SCORE_MAPS: list[dict[str, int]] = [
    pth_detector.SCORE_MAP,
    startup_file_detector.SCORE_MAP,
    IMPORT_SCORE,
    env_dump_detector.SCORE_MAP,
    secret_path_detector.SCORE_MAP,
    exfil_detector.SCORE_MAP,
    obfuscation_detector.SCORE_MAP,
    subprocess_detector.SCORE_MAP,
    chain_correlator.SCORE_MAP,
    ioc_detector.SCORE_MAP,
]

RULE_SCORES: dict[str, int] = {}
for _sm in _ALL_SCORE_MAPS:
    RULE_SCORES.update(_sm)


def compute_score(findings: list[Finding]) -> int:
    """Compute an additive risk score from findings."""
    seen_rules: set[str] = set()
    score = 0
    for f in findings:
        key = f"{f.rule_id}:{f.file}"
        if key in seen_rules:
            continue
        seen_rules.add(key)
        score += RULE_SCORES.get(f.rule_id, 10)
    return score


def determine_verdict(score: int, findings: list[Finding]) -> Verdict:
    """Determine the verdict for a scan based on score and findings."""
    has_critical = any(f.severity == SEVERITY_CRITICAL for f in findings)
    if has_critical:
        return Verdict.BLOCKED
    if score >= THRESHOLD_BLOCKED:
        return Verdict.BLOCKED
    if score >= THRESHOLD_WARNED:
        return Verdict.WARNED
    return Verdict.ALLOWED
