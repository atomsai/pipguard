"""Credential exposure detection helpers used by env-audit and detectors."""

from __future__ import annotations

import os
from pathlib import Path

from pipguard.core.constants import (
    CREDENTIAL_ENV_EXACT,
    CREDENTIAL_ENV_PREFIXES,
    CREDENTIAL_ENV_SUFFIXES,
    SENSITIVE_LOCAL_PATHS,
    SENSITIVE_RUNTIME_ENV_EXACT,
)


def is_credential_env_var(name: str) -> bool:
    """Return True if *name* likely holds a credential."""
    upper = name.upper()
    if upper in CREDENTIAL_ENV_EXACT:
        return True
    if upper in SENSITIVE_RUNTIME_ENV_EXACT:
        return True
    for suffix in CREDENTIAL_ENV_SUFFIXES:
        if upper.endswith(suffix):
            return True
    return any(upper.startswith(prefix) for prefix in CREDENTIAL_ENV_PREFIXES)


def detect_credential_env_vars(env: dict[str, str] | None = None) -> list[str]:
    """Return a sorted list of env var names that look like credentials."""
    env = env if env is not None else dict(os.environ)
    return sorted(name for name in env if is_credential_env_var(name))


def detect_sensitive_local_files(home: Path | None = None) -> list[str]:
    """Return relative paths (from ~) of sensitive files/dirs that exist."""
    home = home or Path.home()
    found: list[str] = []
    for rel in SENSITIVE_LOCAL_PATHS:
        p = home / rel
        if p.exists():
            found.append(f"~/{rel}")
    # Also check .env in current working directory
    if (Path.cwd() / ".env").exists():
        found.append(".env (cwd)")
    return sorted(found)


def exposure_score(cred_vars: list[str], secret_files: list[str]) -> int:
    """Compute a 0-100 exposure score."""
    score = 0

    # Base additive score
    score += min(len(cred_vars) * 10, 55)
    score += min(len(secret_files) * 8, 30)

    # High-impact bumpers
    lowered_files = [f.lower() for f in secret_files]
    if any(".aws/" in f or "gcloud" in f or ".azure" in f for f in lowered_files):
        score += 15
    if any(".kube/config" in f for f in lowered_files):
        score += 15
    if any(".ssh" in f for f in lowered_files):
        score += 10

    if len(cred_vars) >= 4:
        score += 10

    return min(score, 100)


def exposure_label(score: int) -> str:
    """Return a human label for the exposure score."""
    if score >= 70:
        return "high exposure"
    if score >= 40:
        return "medium exposure"
    if score >= 15:
        return "low exposure"
    return "minimal exposure"
