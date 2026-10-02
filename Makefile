PYTHON ?= python

.PHONY: help test self-test acvp bench lint clean demo

help:
	@echo "QuantumPost"
	@echo ""
	@echo "  make test       run the unit test suite"
	@echo "  make self-test  run the built-in correctness tests"
	@echo "  make acvp       check against the NIST ACVP vectors (needs ACVP_DIR)"
	@echo "  make bench      rough operation timings"
	@echo "  make demo       end-to-end hybrid KEM demonstration"
	@echo "  make lint       byte-compile everything (and run ruff if installed)"
	@echo "  make clean      remove caches"

test:
	$(PYTHON) -m unittest discover -s tests -v

self-test:
	$(PYTHON) -m quantumpost self-test

acvp:
	$(PYTHON) tools/check_acvp.py

bench:
	$(PYTHON) -m quantumpost bench

demo:
	$(PYTHON) -m quantumpost hybrid-demo
	$(PYTHON) -m quantumpost list

lint:
	$(PYTHON) -m compileall -q quantumpost tests tools
	@command -v ruff >/dev/null 2>&1 && ruff check quantumpost tests tools \
		|| echo "ruff not installed; skipping lint (byte-compilation passed)"

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete