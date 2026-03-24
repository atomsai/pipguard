#!/usr/bin/env bash
set -euo pipefail

echo "=== pipguard demo: blocking a malicious package ==="
echo ""

echo "--- Scanning malicious fixture (pth + env exfil) ---"
python -m pipguard scan fixtures/malicious/pth_env_exfil/ || true
echo ""

echo "--- Scanning malicious fixture (import-time exfil) ---"
python -m pipguard scan fixtures/malicious/import_time_exfil/ || true
echo ""

echo "--- Scanning benign fixture ---"
python -m pipguard scan fixtures/benign/normal_package/
echo ""

echo "--- Environment audit ---"
python -m pipguard env-audit
echo ""

echo "--- Dry-run with scrubbed env ---"
python -m pipguard run --dry-run -- echo "hello from scrubbed env"
echo ""

echo "=== Demo complete ==="
