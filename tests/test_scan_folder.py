"""Tests for scanning a folder end-to-end."""

from pathlib import Path

from pipguard.scan.engine import scan_directory


FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestScanFolder:
    def test_benign_package_allowed(self):
        report = scan_directory(FIXTURES / "benign" / "normal_package")
        assert report.verdict == "allowed"
        assert report.score == 0
        assert len(report.findings) == 0

    def test_malicious_pth_exfil_blocked(self):
        report = scan_directory(FIXTURES / "malicious" / "pth_env_exfil")
        assert report.verdict == "blocked"
        assert report.score > 0
        rule_ids = {f.rule_id for f in report.findings}
        assert "PTH-EXEC" in rule_ids
        assert "ENV-ENUM" in rule_ids or "SECRET-PATH-READ" in rule_ids

    def test_malicious_import_time_exfil_blocked(self):
        report = scan_directory(FIXTURES / "malicious" / "import_time_exfil")
        assert report.verdict == "blocked"
        assert report.score > 0
        rule_ids = {f.rule_id for f in report.findings}
        assert "IMPORT-TIME-SIDE-EFFECT" in rule_ids or "ENV-ENUM" in rule_ids

    def test_malicious_has_source_to_sink(self):
        report = scan_directory(FIXTURES / "malicious" / "pth_env_exfil")
        rule_ids = {f.rule_id for f in report.findings}
        assert "SOURCE-TO-SINK" in rule_ids

    def test_report_has_next_steps_when_blocked(self):
        report = scan_directory(FIXTURES / "malicious" / "pth_env_exfil")
        assert len(report.next_steps) > 0

    def test_report_to_dict(self):
        report = scan_directory(FIXTURES / "benign" / "normal_package")
        d = report.to_dict()
        assert d["verdict"] == "allowed"
        assert isinstance(d["findings"], list)
