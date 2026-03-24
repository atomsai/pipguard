"""Credential rotation advice based on findings."""

from __future__ import annotations

from pipguard.models.finding import Finding

_IMPACT_MAP: dict[str, str] = {
    "SECRET-PATH-READ": "credential files",
    "ENV-ENUM": "environment secrets",
    "EXFIL-SINK": "data exfiltration",
    "PTH-EXEC": "persistent startup hook",
    "IOC-FILENAME": "known IOC match",
    "IOC-STRING-MARKER": "known IOC string marker",
    "SOURCE-TO-SINK": "source-to-sink data flow",
}


def build_next_steps(findings: list[Finding]) -> list[str]:
    """Produce remediation steps based on the findings present."""
    if not findings:
        return ["No suspicious findings. Environment appears clean."]

    steps: list[str] = []
    has_critical = any(f.severity == "critical" for f in findings)
    has_exfil = any(f.rule_id == "EXFIL-SINK" for f in findings)
    has_secret = any(f.rule_id == "SECRET-PATH-READ" for f in findings)
    has_env = any(f.rule_id == "ENV-ENUM" for f in findings)

    steps.append("Remove the affected environment or virtual environment.")

    if has_secret or has_exfil or has_critical:
        steps.append("Rotate ALL potentially exposed credentials immediately.")
        steps.append("Review SSH keys, cloud credentials, and API tokens.")

    if has_env:
        steps.append("Rotate environment variable secrets (API keys, tokens).")

    steps.append("Review shell history and CI/CD secrets for exposure.")
    steps.append("Audit recent pip/uv install commands for unexpected packages.")

    if has_critical:
        steps.append("Consider this a confirmed incident — follow your IR playbook.")

    return steps
