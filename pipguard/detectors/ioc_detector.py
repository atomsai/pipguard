"""IOC (Indicator of Compromise) pack detection."""

from __future__ import annotations

import os
from pathlib import Path

from pipguard.core.constants import SCORE_IOC_MATCH, SEVERITY_CRITICAL
from pipguard.models.finding import Finding


IOC_PACKS: dict[str, dict] = {
    "litellm-march-2026": {
        "description": "IOCs related to the litellm supply chain incident (March 2026)",
        "suspicious_filenames": [
            "litellm_init.pth",
            "sysmon.py",
        ],
        "suspicious_directories": [
            "node-setup",
        ],
        "suspicious_service_names": [
            "sysmon.service",
        ],
        "suspicious_domains": [
            "gw.onionresolver.com",
        ],
        "suspicious_package_names": [
            "litellm",
        ],
        "suspicious_versions": {
            "litellm": ["4.97.1"],
        },
        "suspicious_string_markers": [
            "litellm_init.pth",
            "sysmon",
            "onionresolver",
            "node-setup",
        ],
    },
    "pyronut-march-2026": {
        "description": "IOCs related to the pyronut Telegram bot backdoor incident (March 2026)",
        "suspicious_filenames": [],
        "suspicious_directories": [],
        "suspicious_service_names": [],
        "suspicious_domains": [],
        "suspicious_package_names": [
            "pyronut",
        ],
        "suspicious_versions": {
            "pyronut": ["2.0.184", "2.0.185", "2.0.186"],
        },
        "suspicious_string_markers": [
            "import pyrogram.helpers.secret as secret",
            "secret.init_secret(self)",
            "pyrogram.helpers.secret",
            'pyrogram.filters.command("shell")',
            'pyrogram.filters.command("e")',
            "OWNERS = [1905813501, 8020909936]",
            '["/bin/bash", "-c", cmd]',
        ],
    },
}


def get_pack(name: str) -> dict | None:
    """Return an IOC pack by name, or None."""
    return IOC_PACKS.get(name)


def list_packs() -> list[str]:
    """Return available IOC pack names."""
    return sorted(IOC_PACKS.keys())


def detect_ioc_in_file(path: Path, pack: dict) -> list[Finding]:
    """Check a file against an IOC pack."""
    findings: list[Finding] = []

    fname = path.name
    for suspicious in pack.get("suspicious_filenames", []):
        if fname == suspicious:
            findings.append(
                Finding(
                    rule_id="IOC-FILENAME",
                    severity=SEVERITY_CRITICAL,
                    file=str(path),
                    message=f"IOC match: suspicious filename '{fname}'",
                    confidence=0.95,
                    tags=("ioc", "filename"),
                )
            )
    for service_name in pack.get("suspicious_service_names", []):
        if fname == service_name:
            findings.append(
                Finding(
                    rule_id="IOC-FILENAME",
                    severity=SEVERITY_CRITICAL,
                    file=str(path),
                    message=f"IOC match: suspicious service file '{fname}'",
                    confidence=0.95,
                    tags=("ioc", "service"),
                )
            )

    # Check if file content contains suspicious string markers
    try:
        content = path.read_text(errors="replace")
    except OSError:
        content = ""

    for marker in pack.get("suspicious_string_markers", []):
        if marker in content:
            findings.append(
                Finding(
                    rule_id="IOC-STRING-MARKER",
                    severity=SEVERITY_CRITICAL,
                    file=str(path),
                    message=f"IOC match: suspicious string marker '{marker}'",
                    evidence=marker,
                    confidence=0.9,
                    tags=("ioc", "string-marker"),
                )
            )

    for domain in pack.get("suspicious_domains", []):
        if domain in content:
            findings.append(
                Finding(
                    rule_id="IOC-STRING-MARKER",
                    severity=SEVERITY_CRITICAL,
                    file=str(path),
                    message=f"IOC match: suspicious domain '{domain}'",
                    evidence=domain,
                    confidence=0.95,
                    tags=("ioc", "domain"),
                )
            )

    return findings


def _metadata_name_version(meta_path: Path) -> tuple[str | None, str | None]:
    try:
        content = meta_path.read_text(errors="replace")
    except OSError:
        return None, None
    name: str | None = None
    version: str | None = None
    for line in content.splitlines():
        if line.startswith("Name: "):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version: "):
            version = line.split(":", 1)[1].strip()
        if name and version:
            break
    return name, version


def detect_ioc_in_dist_metadata(dist_info_dir: Path, pack: dict) -> list[Finding]:
    """Detect IOC package/version matches in *.dist-info METADATA."""
    findings: list[Finding] = []
    metadata_file = dist_info_dir / "METADATA"
    if not metadata_file.exists():
        return findings

    name, version = _metadata_name_version(metadata_file)
    if not name:
        return findings

    lowered_name = name.lower()
    suspicious_names = {n.lower() for n in pack.get("suspicious_package_names", [])}
    suspicious_versions = {
        k.lower(): {v for v in versions}
        for k, versions in pack.get("suspicious_versions", {}).items()
    }

    if lowered_name in suspicious_names:
        findings.append(
            Finding(
                rule_id="IOC-PACKAGE",
                severity=SEVERITY_CRITICAL,
                file=str(metadata_file),
                message=f"IOC match: suspicious package '{name}'",
                evidence=f"Name: {name}",
                confidence=0.96,
                tags=("ioc", "package"),
            )
        )

    if lowered_name in suspicious_versions and version in suspicious_versions[lowered_name]:
        findings.append(
            Finding(
                rule_id="IOC-PACKAGE",
                severity=SEVERITY_CRITICAL,
                file=str(metadata_file),
                message=f"IOC match: suspicious version '{name}=={version}'",
                evidence=f"Version: {version}",
                confidence=0.98,
                tags=("ioc", "package-version"),
            )
        )

    wheel_file = dist_info_dir / "WHEEL"
    if wheel_file.exists():
        try:
            wheel_content = wheel_file.read_text(errors="replace")
        except OSError:
            wheel_content = ""
        for marker in pack.get("suspicious_string_markers", []):
            if marker in wheel_content:
                findings.append(
                    Finding(
                        rule_id="IOC-WHEEL-META",
                        severity=SEVERITY_CRITICAL,
                        file=str(wheel_file),
                        message=f"IOC match in wheel metadata marker '{marker}'",
                        evidence=marker,
                        confidence=0.9,
                        tags=("ioc", "wheel-metadata"),
                    )
                )
        for domain in pack.get("suspicious_domains", []):
            if domain in wheel_content:
                findings.append(
                    Finding(
                        rule_id="IOC-WHEEL-META",
                        severity=SEVERITY_CRITICAL,
                        file=str(wheel_file),
                        message=f"IOC match in wheel metadata domain '{domain}'",
                        evidence=domain,
                        confidence=0.95,
                        tags=("ioc", "wheel-metadata"),
                    )
                )

    record_file = dist_info_dir / "RECORD"
    if record_file.exists():
        try:
            record_content = record_file.read_text(errors="replace")
        except OSError:
            record_content = ""

        lines = [line.split(",", 1)[0] for line in record_content.splitlines() if line]
        for record_path in lines:
            record_name = Path(record_path).name
            for suspicious in pack.get("suspicious_filenames", []):
                if record_name == suspicious:
                    findings.append(
                        Finding(
                            rule_id="IOC-RECORD",
                            severity=SEVERITY_CRITICAL,
                            file=str(record_file),
                            message=f"IOC match in RECORD path '{record_path}'",
                            evidence=record_path,
                            confidence=0.95,
                            tags=("ioc", "record"),
                        )
                    )
        for marker in pack.get("suspicious_string_markers", []):
            if marker in record_content:
                findings.append(
                    Finding(
                        rule_id="IOC-RECORD",
                        severity=SEVERITY_CRITICAL,
                        file=str(record_file),
                        message=f"IOC marker in RECORD metadata '{marker}'",
                        evidence=marker,
                        confidence=0.9,
                        tags=("ioc", "record"),
                    )
                )
        for domain in pack.get("suspicious_domains", []):
            if domain in record_content:
                findings.append(
                    Finding(
                        rule_id="IOC-RECORD",
                        severity=SEVERITY_CRITICAL,
                        file=str(record_file),
                        message=f"IOC domain in RECORD metadata '{domain}'",
                        evidence=domain,
                        confidence=0.95,
                        tags=("ioc", "record"),
                    )
                )
    return findings


def detect_ioc_in_directory(root: Path, pack: dict) -> list[Finding]:
    """Walk a directory for IOC matches."""
    findings: list[Finding] = []

    for dirpath, dirnames, filenames in os.walk(root):
        for dname in dirnames:
            for suspicious in pack.get("suspicious_directories", []):
                if dname == suspicious:
                    findings.append(
                        Finding(
                            rule_id="IOC-DIRECTORY",
                            severity=SEVERITY_CRITICAL,
                            file=str(Path(dirpath) / dname),
                            message=f"IOC match: suspicious directory '{dname}'",
                            confidence=0.9,
                            tags=("ioc", "directory"),
                        )
                    )
            if dname.endswith(".dist-info"):
                findings.extend(detect_ioc_in_dist_metadata(Path(dirpath) / dname, pack))

        for fname in filenames:
            fpath = Path(dirpath) / fname
            findings.extend(detect_ioc_in_file(fpath, pack))

    return findings


SCORE_MAP = {
    "IOC-FILENAME": SCORE_IOC_MATCH,
    "IOC-STRING-MARKER": SCORE_IOC_MATCH,
    "IOC-DIRECTORY": SCORE_IOC_MATCH,
    "IOC-PACKAGE": SCORE_IOC_MATCH,
    "IOC-RECORD": SCORE_IOC_MATCH,
    "IOC-WHEEL-META": SCORE_IOC_MATCH,
}
