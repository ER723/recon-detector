.PHONY: install test lint typecheck check

install:
	pip install -r requirements.txt --break-system-packages

test:
	python3 -m pytest

lint:
	ruff check .

typecheck:
	mypy recon_detector.py

# Runs everything CI runs, in the same order, so you can check before pushing.
check: lint typecheck test
