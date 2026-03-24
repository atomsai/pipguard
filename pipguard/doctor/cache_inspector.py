"""Inspect pip and uv caches for suspicious artifacts."""

from __future__ import annotations

import os
from pathlib import Path

from pipguard.core.constants import SEVERITY_MEDIUM
from pipguard.core.paths import pip_cache_dir, uv_cache_dir
from pipguard.models.finding import Finding

_SUSPICIOUS_FILENAMES = {
    "litellm_init.pth",
    "sysmon.py",
    "sitecustomize.py",
    "usercustomize.py",
}


def _scan_cache_dir(cache_dir: Path, cache_name: str) -> list[Finding]:
    """Walk a cache directory looking for suspicious file names."""
    findings: list[Finding] = []
    try:
        for dirpath, _dirs, files in os.walk(cache_dir):
            for fname in files:
                if fname in _SUSPICIOUS_FILENAMES:
                    findings.append(
                        Finding(
                            rule_id="CACHE-SUSPICIOUS",
                            severity=SEVERITY_MEDIUM,
                            file=str(Path(dirpath) / fname),
                            message=f"Suspicious file in {cache_name} cache: {fname}",
                            confidence=0.7,
                            tags=("cache", cache_name),
                        )
                    )
    except OSError:
        pass
    return findings


def inspect_pip_cache() -> list[Finding]:
    """Inspect pip's HTTP cache."""
    cache = pip_cache_dir()
    if cache is None:
        return []
    return _scan_cache_dir(cache, "pip")


def inspect_uv_cache() -> list[Finding]:
    """Inspect uv's cache."""
    cache = uv_cache_dir()
    if cache is None:
        return []
    return _scan_cache_dir(cache, "uv")
