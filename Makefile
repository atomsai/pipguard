.PHONY: test lint format demo install-dev clean

install-dev:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v --tb=short

test-cov:
	python -m pytest tests/ -v --tb=short --cov=pipguard --cov-report=term-missing

lint:
	ruff check pipguard/ tests/
	mypy pipguard/ --ignore-missing-imports

format:
	ruff format pipguard/ tests/
	ruff check --fix pipguard/ tests/

demo:
	@echo "=== Scanning malicious fixture ==="
	python -m pipguard scan fixtures/malicious/pth_env_exfil/
	@echo ""
	@echo "=== Scanning benign fixture ==="
	python -m pipguard scan fixtures/benign/normal_package/
	@echo ""
	@echo "=== Environment audit ==="
	python -m pipguard env-audit
	@echo ""
	@echo "=== Dry-run with scrubbed env ==="
	python -m pipguard run --dry-run -- echo hello

clean:
	rm -rf build/ dist/ *.egg-info .mypy_cache .ruff_cache .pytest_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
