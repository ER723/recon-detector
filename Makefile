.PHONY: install test lint typecheck check lock

install:
	pip install --require-hashes -r requirements.txt -r requirements-dev.txt --break-system-packages

lock:
	pip install uv --break-system-packages -q
	{ echo "# Hash-pinned for OpenSSF Scorecard's Pinned-Dependencies check (a bare"; \
	  echo "# version pin like scapy==2.7.0 is not enough - it wants every package"; \
	  echo "# hash-verified, so a compromised/yanked-and-reuploaded artifact can't"; \
	  echo "# silently swap in). Generated from requirements.in - do not hand-edit."; \
	  echo "# Regenerate with: make lock"; \
	  uv pip compile requirements.in --generate-hashes --python-version 3.8 --no-header; } > requirements.txt
	{ echo "# Hash-pinned dev/CI tooling (pytest, ruff, mypy, etc.) - same reasoning"; \
	  echo "# as requirements.txt. Generated from requirements-dev.in - do not hand-edit."; \
	  echo "# Regenerate with: make lock"; \
	  uv pip compile requirements-dev.in --generate-hashes --python-version 3.11 --no-header; } > requirements-dev.txt

test:
	python3 -m pytest

lint:
	ruff check .

typecheck:
	mypy recon_detector.py

# Runs everything CI runs, in the same order, so you can check before pushing.
check: lint typecheck test
