"""Environment audit — detect credential exposure in the current shell."""

from __future__ import annotations

import os
from pathlib import Path

from pipguard.core.exposure import (
    detect_credential_env_vars,
    detect_sensitive_local_files,
    exposure_label,
    exposure_score,
)
from pipguard.models.report import Report


def run_env_audit(
    env: dict[str, str] | None = None,
    home: Path | None = None,
) -> Report:
    """Audit the current process environment and produce a risk report."""
    env = env if env is not None else dict(os.environ)
    home = home or Path.home()

    cred_vars = detect_credential_env_vars(env)
    secret_files = detect_sensitive_local_files(home)
    score = exposure_score(cred_vars, secret_files)
    label = exposure_label(score)

    next_steps: list[str] = []
    if score >= 40:
        next_steps.append("Use `pipguard run` with a minimal env allowlist.")
        next_steps.append("Avoid broad inherited shell environments for untrusted tools.")
    if any("aws" in f.lower() for f in secret_files):
        next_steps.append("Consider using AWS SSO or short-lived credentials.")
    if any("kube" in f.lower() for f in secret_files):
        next_steps.append("Restrict KUBECONFIG to the minimal required context.")
    if any("ssh" in f.lower() for f in secret_files):
        next_steps.append("Use SSH agent forwarding instead of raw key files where possible.")
    if not next_steps:
        next_steps.append("Environment exposure is low. Continue with normal precautions.")

    return Report(
        target="current environment",
        verdict=label,
        score=score,
        findings=[],
        summary={
            "credential_env_vars": cred_vars,
            "sensitive_local_files": secret_files,
            "exposure_score": score,
            "exposure_label": label,
        },
        next_steps=next_steps,
    )
