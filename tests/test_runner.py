"""Tests for run command."""

import os
from unittest import mock

from pipguard.runtime.runner import build_child_env, run_command


class TestRunner:
    def test_default_baseline_only(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/user",
                "LANG": "en_US.UTF-8",
                "TERM": "xterm",
                "OPENAI_API_KEY": "sk-xxx",
                "AWS_SECRET_ACCESS_KEY": "secret",
                "NORMAL_VAR": "val",
            },
            clear=True,
        ):
            result = build_child_env()
            assert "PATH" in result.inherited
            assert "HOME" in result.inherited
            assert "OPENAI_API_KEY" not in result.inherited
            assert "OPENAI_API_KEY" in result.blocked
            assert "AWS_SECRET_ACCESS_KEY" in result.blocked
            # NORMAL_VAR is neither in baseline nor credential, silently dropped
            assert "NORMAL_VAR" not in result.inherited
            assert "NORMAL_VAR" not in result.blocked

    def test_allow_env(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/user",
                "OPENAI_API_KEY": "sk-xxx",
                "CUSTOM_VAR": "abc",
            },
            clear=True,
        ):
            result = build_child_env(allow_env=["OPENAI_API_KEY", "CUSTOM_VAR"])
            assert "OPENAI_API_KEY" in result.inherited
            assert "CUSTOM_VAR" in result.inherited

    def test_allow_env_prefix(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/user",
                "MCP_HOST": "localhost",
                "MCP_PORT": "8080",
                "OPENAI_API_KEY": "sk-xxx",
            },
            clear=True,
        ):
            result = build_child_env(allow_env_prefix=["MCP_"])
            assert "MCP_HOST" in result.inherited
            assert "MCP_PORT" in result.inherited
            assert "OPENAI_API_KEY" in result.blocked

    def test_profile_ci(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/user",
                "CI": "true",
                "GITHUB_TOKEN": "ghp_xxx",
                "GITHUB_ACTIONS": "true",
                "OPENAI_API_KEY": "sk-xxx",
            },
            clear=True,
        ):
            result = build_child_env(profiles=["ci"])
            assert "CI" in result.inherited
            assert "GITHUB_TOKEN" in result.inherited
            assert "OPENAI_API_KEY" in result.blocked

    def test_strict_mode(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/user",
                "LANG": "en_US.UTF-8",
                "TERM": "xterm",
            },
            clear=True,
        ):
            result = build_child_env(strict=True)
            assert "PATH" in result.inherited
            assert "HOME" in result.inherited
            assert "LANG" not in result.inherited
            assert "TERM" not in result.inherited

    def test_dry_run(self):
        with mock.patch.dict(
            os.environ,
            {"PATH": "/usr/bin", "HOME": "/home/user"},
            clear=True,
        ):
            result = run_command(
                ["echo", "hello"],
                dry_run=True,
            )
            assert result.dry_run is True
            assert result.exit_code == 0

    def test_run_real_command(self):
        with mock.patch.dict(
            os.environ,
            {"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
            clear=True,
        ):
            result = run_command(["true"])
            assert result.exit_code == 0
            assert not result.dry_run

    def test_blocked_vars_are_credentials(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/user",
                "AWS_ACCESS_KEY_ID": "AKIA...",
                "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/cred.json",
                "DATABASE_URL": "postgres://...",
            },
            clear=True,
        ):
            result = build_child_env()
            assert "AWS_ACCESS_KEY_ID" in result.blocked
            assert "GOOGLE_APPLICATION_CREDENTIALS" in result.blocked
            assert "DATABASE_URL" in result.blocked
