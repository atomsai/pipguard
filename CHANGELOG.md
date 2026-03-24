# Changelog

All notable changes to `pipguard` are documented in this file.

## v0.1.0 - 2026-03-25

Initial public MVP release.

### Added
- Core CLI commands: `scan`, `install`, `doctor`, `env-audit`, `run`.
- Modular detectors for startup hooks, env dumping, secret-path reads, exfiltration sinks, obfuscation, subprocess abuse, IOC matching, and source-to-sink correlation.
- IOC pack support with built-in `litellm-march-2026`.
- Install safety wrapper that downloads, scans artifacts, and installs from local artifacts only.
- Runtime blast-radius controls with scrubbed environment profiles and allowlist controls.
- JSON and terminal reporting output.
- Comprehensive tests and fixtures.
- Security guidance in `SECURITY.md`.

### Security Hardening
- Archive extraction protections against path traversal and unsafe link extraction.
- Grouped blocked-install summary with per-artifact reasons.
- Function-level source-to-sink correlation with dedicated scoring.
- IOC matching extended to `METADATA`, `WHEEL`, and `RECORD` in `.dist-info`.

### Validation
- Full unit test suite passing.
- Local smoke checks include:
  - `pipx` install + run validation
  - `uvx` run validation for benign and malicious fixture scans
