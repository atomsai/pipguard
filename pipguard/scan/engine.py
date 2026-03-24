"""Main scan engine — orchestrates detectors and produces a Report."""

from __future__ import annotations

from pathlib import Path

from pipguard.core.config import ScanConfig
from pipguard.core.utils import walk_all_files, walk_pth_files, walk_python_files
from pipguard.detectors.chain_correlator import correlate
from pipguard.detectors.env_dump_detector import detect_env_dump
from pipguard.detectors.exfil_detector import detect_exfil
from pipguard.detectors.import_time_detector import detect_import_time
from pipguard.detectors.ioc_detector import detect_ioc_in_directory, get_pack
from pipguard.detectors.obfuscation_detector import detect_obfuscation
from pipguard.detectors.pth_detector import detect_pth
from pipguard.detectors.secret_path_detector import detect_secret_paths
from pipguard.detectors.startup_file_detector import detect_startup_file
from pipguard.detectors.subprocess_detector import detect_subprocess
from pipguard.models.finding import Finding
from pipguard.models.report import Report
from pipguard.scan.scoring import compute_score, determine_verdict


def _severity_rank(level: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(level, 9)


def scan_directory(root: Path, config: ScanConfig | None = None) -> Report:
    """Scan an unpacked directory and return a Report."""
    config = config or ScanConfig()
    findings: list[Finding] = []

    # 1. Scan .pth files
    for pth in walk_pth_files(root):
        findings.extend(detect_pth(pth))
        findings.extend(detect_startup_file(pth))

    # 2. Scan Python source files
    for py in walk_python_files(root):
        findings.extend(detect_startup_file(py))
        findings.extend(detect_import_time(py))
        findings.extend(detect_env_dump(py))
        findings.extend(detect_secret_paths(py))
        findings.extend(detect_exfil(py))
        findings.extend(detect_obfuscation(py))
        findings.extend(detect_subprocess(py))

    # 3. IOC pack (if configured)
    if config.ioc_pack:
        pack = get_pack(config.ioc_pack)
        if pack:
            findings.extend(detect_ioc_in_directory(root, pack))

    # 4. Source-to-sink correlation
    findings = correlate(findings)

    # Deterministic ordering for stable JSON output across runs.
    findings.sort(key=lambda f: (_severity_rank(f.severity), f.file, f.rule_id, f.message))

    # 5. Score and verdict
    score = compute_score(findings)
    verdict = determine_verdict(score, findings)

    # Build summary
    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    next_steps: list[str] = []
    if verdict.value == "blocked":
        next_steps = [
            "Do NOT install this package.",
            "Review the findings above.",
            "Report the package to PyPI if it appears malicious.",
        ]
    elif verdict.value == "warned":
        next_steps = [
            "Review the flagged findings carefully before installing.",
            "Consider the package's reputation and maintenance status.",
        ]

    return Report(
        target=str(root),
        verdict=verdict.value,
        score=score,
        findings=findings,
        summary={"severity_counts": severity_counts, "file_count": len(walk_all_files(root))},
        next_steps=next_steps,
    )
