"""Tests for env-audit command."""

import tempfile
from pathlib import Path

from pipguard.core.exposure import (
    detect_credential_env_vars,
    detect_sensitive_local_files,
    exposure_label,
    exposure_score,
    is_credential_env_var,
)
from pipguard.runtime.env_audit import run_env_audit


class TestEnvAudit:
    def test_credential_detection(self):
        env = {
            "OPENAI_API_KEY": "sk-xxx",
            "AWS_ACCESS_KEY_ID": "AKIA...",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "HOME": "/home/user",
            "PATH": "/usr/bin",
            "NORMAL_VAR": "value",
        }
        creds = detect_credential_env_vars(env)
        assert "OPENAI_API_KEY" in creds
        assert "AWS_ACCESS_KEY_ID" in creds
        assert "AWS_SECRET_ACCESS_KEY" in creds
        assert "HOME" not in creds
        assert "PATH" not in creds
        assert "NORMAL_VAR" not in creds

    def test_is_credential_env_var(self):
        assert is_credential_env_var("OPENAI_API_KEY")
        assert is_credential_env_var("AWS_ACCESS_KEY_ID")
        assert is_credential_env_var("DATABASE_URL")
        assert is_credential_env_var("KUBECONFIG")
        assert is_credential_env_var("MY_SECRET")
        assert is_credential_env_var("GITHUB_TOKEN")
        assert not is_credential_env_var("HOME")
        assert not is_credential_env_var("PATH")

    def test_sensitive_files_detection(self, tmp_path: Path):
        (tmp_path / ".ssh").mkdir()
        (tmp_path / ".aws").mkdir()
        (tmp_path / ".aws" / "credentials").write_text("fake")
        files = detect_sensitive_local_files(tmp_path)
        assert any(".ssh" in f for f in files)
        assert any(".aws/credentials" in f for f in files)

    def test_exposure_score_high(self):
        creds = ["OPENAI_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
        files = ["~/.ssh", "~/.aws/credentials", "~/.kube/config"]
        score = exposure_score(creds, files)
        assert score >= 50

    def test_exposure_score_zero(self):
        score = exposure_score([], [])
        assert score == 0

    def test_exposure_labels(self):
        assert exposure_label(80) == "high exposure"
        assert exposure_label(50) == "medium exposure"
        assert exposure_label(20) == "low exposure"
        assert exposure_label(5) == "minimal exposure"

    def test_run_env_audit_integration(self, tmp_path: Path):
        env = {
            "OPENAI_API_KEY": "sk-xxx",
            "HOME": str(tmp_path),
            "PATH": "/usr/bin",
        }
        (tmp_path / ".ssh").mkdir()
        report = run_env_audit(env=env, home=tmp_path)
        assert report.summary["exposure_score"] > 0
        assert "OPENAI_API_KEY" in report.summary["credential_env_vars"]

    def test_env_audit_clean_env(self, tmp_path: Path):
        env = {"HOME": str(tmp_path), "PATH": "/usr/bin"}
        report = run_env_audit(env=env, home=tmp_path)
        assert report.summary["exposure_score"] == 0
