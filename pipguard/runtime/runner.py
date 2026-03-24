"""Scrubbed-environment process runner."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field

from pipguard.core.constants import SAFE_BASELINE_ENV
from pipguard.core.exposure import is_credential_env_var
from pipguard.runtime.profiles import get_profile


@dataclass
class RunResult:
    """Result of a `pipguard run` invocation."""

    inherited: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    child_env: dict[str, str] = field(default_factory=dict)
    exit_code: int = 0
    dry_run: bool = False


def build_child_env(
    *,
    allow_env: list[str] | None = None,
    allow_env_prefix: list[str] | None = None,
    profiles: list[str] | None = None,
    strict: bool = False,
) -> RunResult:
    """Build a scrubbed child environment from scratch.

    The architecture here is designed so a future `pipguard broker`
    module could inject short-lived credentials into the child env
    after building it.
    """
    allow_env = list(allow_env or [])
    allow_env_prefix = list(allow_env_prefix or [])

    # Merge profile allowlists
    for profile_name in profiles or []:
        profile = get_profile(profile_name)
        if profile:
            allow_env.extend(profile.get("allow_env", []))
            allow_env_prefix.extend(profile.get("allow_env_prefix", []))

    # Start with safe baseline
    baseline = list(SAFE_BASELINE_ENV)
    if strict:
        baseline = ["PATH", "HOME"]

    allowed_names = set(baseline + allow_env)
    allowed_prefixes = tuple(allow_env_prefix)

    parent_env = dict(os.environ)
    child_env: dict[str, str] = {}
    inherited: list[str] = []
    blocked: list[str] = []

    for key, value in sorted(parent_env.items()):
        if key in allowed_names or (allowed_prefixes and key.startswith(allowed_prefixes)):
            child_env[key] = value
            inherited.append(key)
        elif is_credential_env_var(key):
            blocked.append(key)
        # Non-credential, non-allowed vars are silently dropped

    return RunResult(
        inherited=inherited,
        blocked=blocked,
        child_env=child_env,
    )


def run_command(
    command: list[str],
    *,
    allow_env: list[str] | None = None,
    allow_env_prefix: list[str] | None = None,
    profiles: list[str] | None = None,
    strict: bool = False,
    dry_run: bool = False,
) -> RunResult:
    """Launch *command* with a scrubbed environment."""
    result = build_child_env(
        allow_env=allow_env,
        allow_env_prefix=allow_env_prefix,
        profiles=profiles,
        strict=strict,
    )
    result.dry_run = dry_run

    if dry_run:
        return result

    proc = subprocess.run(command, env=result.child_env)
    result.exit_code = proc.returncode
    return result
