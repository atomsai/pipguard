"""Tests for env_dump_detector."""

import tempfile
from pathlib import Path

from pipguard.detectors.env_dump_detector import detect_env_dump


def _write_py(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


class TestEnvDumpDetector:
    def test_no_env_access(self):
        path = _write_py("x = 1 + 2\n")
        findings = detect_env_dump(path)
        assert findings == []

    def test_os_environ_text(self):
        path = _write_py("import os\ndata = dict(os.environ)\n")
        findings = detect_env_dump(path)
        assert len(findings) >= 1
        assert findings[0].rule_id == "ENV-ENUM"

    def test_loop_over_environ(self):
        code = "import os\nfor k, v in os.environ.items():\n    print(k, v)\n"
        path = _write_py(code)
        findings = detect_env_dump(path)
        assert len(findings) >= 1

    def test_json_dumps_environ(self):
        code = "import os, json\njson.dumps(dict(os.environ))\n"
        path = _write_py(code)
        findings = detect_env_dump(path)
        assert len(findings) >= 1
