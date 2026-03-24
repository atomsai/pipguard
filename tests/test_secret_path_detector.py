"""Tests for secret_path_detector."""

import tempfile
from pathlib import Path

from pipguard.detectors.secret_path_detector import detect_secret_paths


def _write_py(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


class TestSecretPathDetector:
    def test_no_secret_paths(self):
        path = _write_py("x = 'hello world'\n")
        findings = detect_secret_paths(path)
        assert findings == []

    def test_ssh_key_path(self):
        path = _write_py("key = open('/home/user/.ssh/id_rsa').read()\n")
        findings = detect_secret_paths(path)
        assert len(findings) >= 1
        assert findings[0].rule_id == "SECRET-PATH-READ"

    def test_aws_credentials(self):
        path = _write_py("creds = open('/home/user/.aws/credentials').read()\n")
        findings = detect_secret_paths(path)
        assert len(findings) >= 1

    def test_multiple_paths_higher_confidence(self):
        code = (
            "a = open('~/.ssh/id_rsa').read()\n"
            "b = open('~/.aws/credentials').read()\n"
            "c = open('~/.kube/config').read()\n"
        )
        path = _write_py(code)
        findings = detect_secret_paths(path)
        assert len(findings) >= 1
        assert findings[0].confidence > 0.7

    def test_env_file(self):
        path = _write_py("data = open('.env').read()\n")
        findings = detect_secret_paths(path)
        assert len(findings) >= 1

    def test_kube_config(self):
        path = _write_py("kc = open('~/.kube/config').read()\n")
        findings = detect_secret_paths(path)
        assert len(findings) >= 1

    def test_string_literal_without_read_call_not_flagged(self):
        path = _write_py("PATH_HINT = '~/.ssh/id_rsa'\n")
        findings = detect_secret_paths(path)
        assert findings == []
