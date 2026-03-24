# pipguard by AtomsAI

[![Tests](https://github.com/atomsai/pipguard/actions/workflows/tests.yml/badge.svg)](https://github.com/atomsai/pipguard/actions/workflows/tests.yml)

**Scan Python packages for supply-chain malware before install. Reduce blast radius when running untrusted tools.**

pipguard is a local-only, zero-dependency Python CLI that catches obvious supply-chain attacks — executable `.pth` files, import-time exfiltration, credential harvesting, obfuscated payloads — before they reach your environment.

Maintained & managed by [AtomsAI.com](https://atomsai.com) ([x.com/ai_atoms](https://x.com/ai_atoms)).

## Why

Recent supply-chain incidents (PyPI typosquatting, compromised maintainer accounts, malicious startup hooks) have shown that `pip install` is an implicit trust decision. pipguard adds a verification step between download and install, and provides tools to audit and contain blast radius in your development environment.

### LiteLLM `1.82.8` compromise case

The LiteLLM PyPI release `1.82.8` became a high-visibility example of why pre-install package scanning matters. The reported behavior was not just a dependency hygiene issue or a known CVE. It was a live supply-chain compromise pattern: startup-hook execution, credential discovery, and outbound data theft.

Community reports described the release as containing a malicious `litellm_init.pth` startup hook with base64-encoded instructions designed to collect credentials and exfiltrate them to a remote server.

> "LiteLLM HAS BEEN COMPROMISED, DO NOT UPDATE. We just discovered that LiteLLM pypi release 1.82.8. It has been compromised, it contains litellm_init.pth with base64 encoded instructions to send all the credentials it can find to remote server + self-replicate."  
> Source: Daniel Hnyk ([tweet](https://x.com/hnykda/status/2036414330267193815))

Why this matters:

- `.pth` files execute automatically during Python startup, which means damage can happen before a developer notices anything unusual.
- Credential theft targets the exact materials most AI and infra-heavy Python environments carry: API keys, cloud credentials, SSH material, shell history, and cluster configuration.
- A compromised package can affect both install-time trust and runtime blast radius, which is why `pipguard` includes both package scanning and environment containment commands.

Public discussion and incident context:

- Daniel Hnyk warning about the compromised LiteLLM `1.82.8` release: [x.com/hnykda/status/2036414330267193815](https://x.com/hnykda/status/2036414330267193815)
- Broader public discussion from Andrej Karpathy: [x.com/karpathy/status/2036487306585268612](https://x.com/karpathy/status/2036487306585268612)

`pipguard` is designed specifically for this class of attack: suspicious startup hooks, obfuscated payloads, environment enumeration, sensitive path reads, IOC matches, and source-to-sink exfiltration chains.

## What It Does

| Command | Purpose |
|---------|---------|
| `pipguard scan <path>` | Scan a wheel, sdist, or directory for malware patterns |
| `pipguard install <spec>` | Download → scan → install (blocks if malicious) |
| `pipguard doctor` | Inspect your current Python environment for compromise |
| `pipguard env-audit` | Show credential exposure in your current shell |
| `pipguard run -- <cmd>` | Launch a command with a scrubbed environment |

## Install

```bash
python3 -m pip install -e ".[dev]"
```

One-line runner options:

```bash
uvx --from git+https://github.com/atomsai/pipguard.git pipguard --help
```

```bash
pipx install git+https://github.com/atomsai/pipguard.git
pipguard --help
```

Or just clone and run directly:

```bash
git clone https://github.com/AtomsAI/pipguard.git
cd pipguard
python3 -m pipguard --help
```

> macOS note: many systems do not provide `python` by default. Prefer `python3` in commands.

## Quick Start

### Scan a package before installing

```bash
pipguard scan ./downloaded-package/
pipguard scan package-1.0-py3-none-any.whl
```

### Safe install (download → scan → install)

```bash
pipguard install requests
pipguard install "litellm==4.97.1" --policy block
pipguard install some-package --json-out report.json
```

### Check your environment after an incident

```bash
pipguard doctor
pipguard doctor --ioc litellm-march-2026
pipguard doctor --json-out doctor-report.json
```

### Audit credential exposure

```bash
pipguard env-audit
pipguard env-audit --json-out audit.json
```

### Run a tool with reduced blast radius

```bash
# Default: only PATH, HOME, LANG, TERM inherited
pipguard run -- python3 my_script.py

# Allow specific env vars
pipguard run --allow-env OPENAI_API_KEY -- python3 agent.py

# Use a named profile
pipguard run --profile claude-code -- claude

# See what would be inherited/blocked
pipguard run --dry-run -- node server.js

# Strict mode (only PATH and HOME)
pipguard run --strict --allow-env ANTHROPIC_API_KEY -- python3 agent.py
```

## Cheatsheet

```bash
# Pre-install scan (local artifact or folder)
pipguard scan ./dist/pkg-1.0.0-py3-none-any.whl

# Safe install wrapper (download -> scan -> local-only install)
pipguard install "requests>=2.31"

# Incident triage in current environment
pipguard doctor --ioc litellm-march-2026

# Exposure audit of current shell
pipguard env-audit

# Run tool with minimal env inheritance
pipguard run --allow-env OPENAI_API_KEY -- python3 app.py

# Dry-run to preview inherited vs blocked vars
pipguard run --profile mcp-server --dry-run -- my_mcp_server

# --- Remove pipguard ---
# If installed with pip:
python3 -m pip uninstall pipguard

# If installed with pipx:
pipx uninstall pipguard

# If used via uvx (ephemeral), no uninstall is required.
```

### Keep pipguard tamper-resistant

- Install `pipguard` outside project virtualenvs (prefer `pipx` or `uvx`) so dependency code in a project env cannot directly uninstall it.
- Run uninstall commands only from a trusted interactive shell, never from package-provided scripts.
- In CI or shared environments, pin a dedicated security-tool image/env where `pipguard` is preinstalled and treated as immutable during job execution.

## How It Works

1. `scan` unpacks the target (if archive), runs independent detectors, then correlates source-to-sink behavior.
2. Detectors emit typed findings (`rule_id`, severity, confidence, evidence) for auditable decisions.
3. Findings are scored with deterministic additive weights; critical chains force blocking.
4. `install` uses `pip download`, scans every downloaded artifact, then installs only from local files.
5. `doctor` inspects active `site-packages`, startup hooks, caches, and optional IOC packs.
6. `env-audit` and `run` reduce blast radius by identifying secrets and minimizing inherited env vars.

## Detection Rules

pipguard detects the following patterns:

| Rule | What It Detects | Severity |
|------|----------------|----------|
| PTH-EXEC | Executable code in `.pth` files | Critical/High |
| STARTUP-HOOK | `sitecustomize.py`, `usercustomize.py`, `*_init.pth` | High |
| IMPORT-TIME-SIDE-EFFECT | Top-level network/subprocess/exec calls | High |
| ENV-ENUM | `os.environ` enumeration | Medium |
| SECRET-PATH-READ | Reads of `~/.ssh`, `~/.aws`, `~/.kube`, etc. | High |
| EXFIL-SINK | Outbound HTTP, socket, subprocess with curl/wget | Medium |
| OBFUSCATION | base64/marshal/zlib decode patterns | Medium |
| DYNAMIC-EXEC | `exec()`, `eval()`, `compile()` | High |
| SUSPICIOUS-SUBPROCESS | Subprocess with curl, wget, bash -c, etc. | High |
| SOURCE-TO-SINK | Credential read + exfil in same file (correlation) | Critical |
| IOC-* | Known indicators of compromise from IOC packs | Critical |

### Scoring

Findings are scored additively. Verdict thresholds:

- **Score >= 70 or any critical finding** → `blocked`
- **Score 40–69** → `warned`
- **Score < 40** → `allowed`

## IOC Packs

pipguard ships with built-in IOC (Indicator of Compromise) packs for known incidents:

```bash
pipguard doctor --ioc litellm-march-2026
pipguard scan ./suspect-package --ioc litellm-march-2026
```

Available packs:
- `litellm-march-2026` — IOCs related to the litellm supply chain incident

## Environment Profiles for `run`

| Profile | Allows |
|---------|--------|
| `ci` | `CI`, `GITHUB_*`, `CI_*`, `RUNNER_*` |
| `cursor` | `CURSOR_*`, `EDITOR`, `VISUAL` |
| `claude-code` | `ANTHROPIC_*`, `CLAUDE_*` |
| `mcp-server` | `MCP_*` |

Combine profiles with explicit allowlists:

```bash
pipguard run --profile cursor --allow-env OPENAI_API_KEY -- cursor-agent
```

## Policy Controls

```bash
# Default: block on high/critical findings
pipguard install some-package

# Warn only (don't block)
pipguard install some-package --policy warn

# Allow high-severity findings
pipguard install some-package --allow-high

# Allow even critical findings (use with extreme caution)
pipguard install some-package --allow-critical
```

## JSON Reports

All commands support `--json-out` for machine-readable output:

```bash
pipguard scan ./package --json-out scan-report.json
pipguard doctor --json-out doctor-report.json
pipguard env-audit --json-out audit.json
pipguard run --dry-run --json-out run-report.json -- echo hello
```

## Release

- Current release: `v0.1.0`
- Release notes: see [`CHANGELOG.md`](CHANGELOG.md)

### Clean-install validation

The MVP has been validated via clean-install style runs using:
- `pipx install <repo-spec>` + CLI smoke tests
- `uvx --from <repo-spec> pipguard ...` + benign/malicious fixture scans

## Development

```bash
# Install dev dependencies
python3 -m pip install -e ".[dev]"

# Run tests
make test

# Run tests with coverage
make test-cov

# Lint
make lint

# Format
make format

# Run demo
make demo
```

## Troubleshooting

### `zsh: command not found: python`

Use `python3` instead of `python`:

```bash
python3 --version
python3 -m pip install -e ".[dev]"
python3 -m pipguard --help
```

### `zsh: command not found: pipguard`

You likely have not installed `pipguard` into your current environment, or your venv is not active.

```bash
# Option A: local venv
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m pipguard --help

# Option B: pipx global tool
pipx install git+https://github.com/atomsai/pipguard.git
pipguard --help
```

### `pipx` or `uvx` not found

Install one of them first:

```bash
python3 -m pip install pipx uv
python3 -m pipx ensurepath
```

Then restart your terminal and retry.

### `Error: Unsupported archive format`

`pipguard scan` supports wheels, sdists, and directories. Ensure your file is one of:
- `.whl`
- `.tar.gz`, `.tgz`, `.tar.bz2`
- unpacked folder

### `pipguard install` blocked my package

Use report output to inspect reasons. If you intentionally want non-blocking mode:

```bash
pipguard install <spec> --policy warn
```

Or explicit override (use with caution):

```bash
pipguard install <spec> --allow-high
pipguard install <spec> --allow-critical
```

### `doctor` shows many findings in a dev-heavy environment

This can happen in large environments with many tooling packages. Start with:

```bash
pipguard doctor --json-out doctor-report.json
```

Then review high/critical findings first and isolate suspicious startup hooks (`.pth`, `sitecustomize.py`, `usercustomize.py`).

### Need help?

Contact: **start@atomsai.com**

## Architecture

```
pipguard/
├── cli.py              # Argparse CLI entry point
├── models/             # Finding, Report, Verdict, PackageInfo
├── core/               # Config, constants, utils, hashing, paths, exposure
├── download/           # pip download/install wrappers
├── unpack/             # Archive extraction (wheel, sdist)
├── scan/               # Scan engine, scoring, AST analysis
├── detectors/          # Independent detector modules
├── doctor/             # Environment inspection
├── runtime/            # env-audit, scrubbed runner, profiles
├── output/             # Terminal, JSON, Markdown formatters
└── policies/           # Policy enforcement, allowlists
```

Each detector is independent and composable. The `chain_correlator` upgrades severity when source-to-sink patterns co-occur in the same file. The architecture supports adding Semgrep or GuardDog adapters later without changing the core scan engine.

## Limitations

- **Heuristic-based**: pipguard uses AST analysis and pattern matching, not full taint tracking. Sophisticated obfuscation may evade detection.
- **Python-only scanning**: Only Python files (`.py`) and `.pth` files are analyzed. Native extensions (`.so`, `.pyd`) are not inspected.
- **No network reputation**: pipguard is local-only and does not query package reputation services.
- **No signature verification**: Does not verify package signatures or provenance attestations.
- **Single-file correlation**: Source-to-sink correlation operates at file level, not cross-file.

## Product Principles

- **Local-only** — no telemetry, no network calls, no cloud dependencies.
- **Deterministic** — same input always produces same output.
- **Fast** — stdlib-only runtime, AST-based analysis, no heavy dependencies.
- **Auditable** — small codebase, clear detection rules, plain-English output.
- **Blast-radius focused** — not just detection, but containment via `run` and `env-audit`.

## Roadmap

- [ ] Semgrep adapter for custom rule integration
- [ ] GuardDog adapter for PyPI reputation checks
- [ ] `pipguard broker` — inject short-lived credentials into scrubbed environments
- [ ] Cross-file taint tracking
- [ ] Native extension inspection (`.so`/`.pyd` entropy analysis)
- [ ] SARIF output format
- [ ] GitHub Actions integration
- [ ] Pre-commit hook
- [ ] Package allowlist/denylist persistence
- [ ] Additional IOC packs

## Future Improvements In Progress

- Better function-level source-to-sink correlation (beyond file-level).
- Optional Semgrep / GuardDog adapter interfaces without changing default runtime path.
- More IOC packs for incident-driven response workflows.
- Policy files for team-wide CI enforcement.
- SARIF output for native code-scanning integration.

## Launch Assets

- Sample blocked output for screenshots/posts: [`assets/blocked-install-output.txt`](assets/blocked-install-output.txt)

## License

MIT — see [LICENSE](LICENSE).
