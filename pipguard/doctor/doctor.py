"""Inspect the current Python environment for signs of compromise."""

from __future__ import annotations

from pipguard.core.config import ScanConfig
from pipguard.core.paths import site_packages_dirs
from pipguard.detectors.ioc_detector import detect_ioc_in_directory, get_pack
from pipguard.doctor.cache_inspector import inspect_pip_cache, inspect_uv_cache
from pipguard.doctor.env_inspector import inspect_site_packages
from pipguard.doctor.history_inspector import inspect_history_files
from pipguard.doctor.rotation_advice import build_next_steps
from pipguard.models.finding import Finding
from pipguard.models.report import Report
from pipguard.models.verdict import Verdict
from pipguard.scan.scoring import compute_score


def run_doctor(config: ScanConfig | None = None) -> Report:
    """Run a full doctor inspection of the current environment."""
    config = config or ScanConfig()
    findings: list[Finding] = []

    # 1. Inspect site-packages
    for sp_dir in site_packages_dirs():
        findings.extend(inspect_site_packages(sp_dir))

    # 2. Inspect shell history
    findings.extend(inspect_history_files())

    # 3. Inspect caches
    findings.extend(inspect_pip_cache())
    findings.extend(inspect_uv_cache())

    # 4. IOC pack
    if config.ioc_pack:
        pack = get_pack(config.ioc_pack)
        if pack:
            for sp_dir in site_packages_dirs():
                findings.extend(detect_ioc_in_directory(sp_dir, pack))

    score = compute_score(findings)
    has_critical = any(f.severity == "critical" for f in findings)
    has_high = any(f.severity == "high" for f in findings)

    if has_critical or has_high:
        verdict = Verdict.REVIEW_NOW
    elif findings:
        verdict = Verdict.WARNED
    else:
        verdict = Verdict.NO_MAJOR_FINDINGS

    next_steps = build_next_steps(findings)

    return Report(
        target="current environment",
        verdict=verdict.value,
        score=score,
        findings=findings,
        summary={"site_packages_scanned": len(site_packages_dirs())},
        next_steps=next_steps,
    )
