"""Shared constants for pipguard."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_ORDER = {SEVERITY_LOW: 0, SEVERITY_MEDIUM: 1, SEVERITY_HIGH: 2, SEVERITY_CRITICAL: 3}

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------
SCORE_EXECUTABLE_PTH = 90
SCORE_STARTUP_HOOK = 50
SCORE_IMPORT_TIME_SIDE_EFFECT = 50
SCORE_ENV_ENUMERATION = 35
SCORE_SECRET_PATH_READ = 60
SCORE_EXFIL_SINK = 50
SCORE_OBFUSCATION = 30
SCORE_DYNAMIC_EXEC = 40
SCORE_SUSPICIOUS_SUBPROCESS = 45
SCORE_SOURCE_TO_SINK = 80
SCORE_SOURCE_TO_SINK_FUNCTION = 95
SCORE_IOC_MATCH = 70

# ---------------------------------------------------------------------------
# Verdict thresholds
# ---------------------------------------------------------------------------
THRESHOLD_BLOCKED = 70
THRESHOLD_WARNED = 40

# ---------------------------------------------------------------------------
# Sensitive paths (substrings to match in string literals)
# ---------------------------------------------------------------------------
SENSITIVE_PATH_MARKERS: list[str] = [
    ".ssh",
    "id_rsa",
    "id_ed25519",
    ".aws/credentials",
    ".aws/config",
    ".config/gcloud",
    "application_default_credentials.json",
    ".azure",
    ".kube/config",
    ".docker/config.json",
    ".git-credentials",
    ".gitconfig",
    ".npmrc",
    ".pypirc",
    ".env",
    ".bash_history",
    ".zsh_history",
    ".netrc",
    ".gnupg",
    ".pem",
    ".key",
]

# ---------------------------------------------------------------------------
# Credential-bearing env var patterns
# ---------------------------------------------------------------------------
CREDENTIAL_ENV_SUFFIXES: list[str] = ["_KEY", "_TOKEN", "_SECRET"]
CREDENTIAL_ENV_PREFIXES: list[str] = [
    "AWS_",
    "GOOGLE_",
    "AZURE_",
    "OPENAI_",
    "ANTHROPIC_",
]
CREDENTIAL_ENV_EXACT: set[str] = {"DATABASE_URL", "KUBECONFIG"}

# ---------------------------------------------------------------------------
# Runtime-sensitive env vars that should be treated as high-risk
# even if they don't match generic credential naming patterns.
# ---------------------------------------------------------------------------
SENSITIVE_RUNTIME_ENV_EXACT: set[str] = {
    "SSH_AUTH_SOCK",
    "GIT_ASKPASS",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
}

# ---------------------------------------------------------------------------
# Exfil sink patterns (function calls)
# ---------------------------------------------------------------------------
EXFIL_CALL_PATTERNS: list[str] = [
    "requests.post",
    "requests.put",
    "requests.request",
    "httpx.post",
    "httpx.put",
    "httpx.request",
    "urllib.request.urlopen",
    "urllib.request.Request",
    "socket.connect",
    "socket.send",
]

# ---------------------------------------------------------------------------
# Obfuscation patterns
# ---------------------------------------------------------------------------
OBFUSCATION_CALL_PATTERNS: list[str] = [
    "base64.b64decode",
    "binascii.unhexlify",
    "marshal.loads",
    "zlib.decompress",
    "gzip.decompress",
    "compile",
    "exec",
    "eval",
]

# ---------------------------------------------------------------------------
# Suspicious subprocess commands
# ---------------------------------------------------------------------------
SUSPICIOUS_COMMANDS: list[str] = [
    "curl",
    "wget",
    "bash -c",
    "sh -c",
    "powershell",
    "Invoke-WebRequest",
    "scp",
    "nc ",
]

# ---------------------------------------------------------------------------
# Safe baseline env vars for `run`
# ---------------------------------------------------------------------------
SAFE_BASELINE_ENV: list[str] = ["PATH", "HOME", "LANG", "TERM"]

# ---------------------------------------------------------------------------
# Sensitive secret file / directory locations (relative to ~)
# ---------------------------------------------------------------------------
SENSITIVE_LOCAL_PATHS: list[str] = [
    ".ssh",
    ".aws/credentials",
    ".aws/config",
    ".config/gcloud",
    ".azure",
    ".kube/config",
    ".docker/config.json",
]
