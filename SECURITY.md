## Security Notes

`pipguard` is a heuristic pre-install guard, not a sandbox or EDR.

### Threat Model

- Detect obvious malware patterns in Python package artifacts before install.
- Surface suspicious startup hooks and import-time behavior in active environments.
- Reduce secret exposure for child tools/processes with environment scrubbing.

### Hardening Defaults

- Local-only execution; no telemetry.
- Deterministic additive scoring with clear block rules.
- Archive extraction hardening against path traversal and unsafe links.
- Install path enforces local-only package installation after scanning.
- Runtime env is deny-by-default with explicit allowlist controls.

### Protecting pipguard from removal/tampering

- Prefer running via `uvx pipguard` or installing with `pipx` so it lives outside project dependency environments.
- Do not execute package-provided uninstall/cleanup scripts.
- In CI, keep `pipguard` in a base image/tooling layer that jobs cannot mutate.

### Known Limits

- Static heuristics cannot guarantee detection of all malware.
- Native binary payloads (`.so`, `.pyd`) are currently not deeply analyzed.
- Correlation is currently strongest at file-level (function-level expansion planned).
