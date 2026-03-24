"""Named environment profiles for `pipguard run`."""

from __future__ import annotations

PROFILES: dict[str, dict] = {
    "ci": {
        "description": "Minimal CI/CD environment",
        "allow_env": ["CI", "GITHUB_ACTIONS", "GITHUB_TOKEN", "GITHUB_SHA", "GITHUB_REF"],
        "allow_env_prefix": ["GITHUB_", "CI_", "RUNNER_"],
    },
    "cursor": {
        "description": "Cursor IDE agent environment",
        "allow_env": ["CURSOR_SESSION", "EDITOR", "VISUAL"],
        "allow_env_prefix": ["CURSOR_"],
    },
    "claude-code": {
        "description": "Claude Code agent environment",
        "allow_env": ["ANTHROPIC_API_KEY"],
        "allow_env_prefix": ["ANTHROPIC_", "CLAUDE_"],
    },
    "mcp-server": {
        "description": "MCP server environment",
        "allow_env": [],
        "allow_env_prefix": ["MCP_"],
    },
}


def get_profile(name: str) -> dict | None:
    """Return a named profile, or None."""
    return PROFILES.get(name)


def list_profiles() -> list[str]:
    """Return available profile names."""
    return sorted(PROFILES.keys())
