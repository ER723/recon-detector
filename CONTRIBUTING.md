# Contributing to recon-detector

Thanks for considering contributing. This project stays intentionally small
and dependency-light (see the README's "zero-cost, extremely lightweight"
goals) — please keep that in mind for anything you propose.

## Setup

```bash
git clone https://github.com/ER723/recon-detector.git
cd recon-detector
make install
```

`make install` installs the two runtime dependencies (`scapy`, `pyyaml`).
For development you'll also want the tooling used in CI:

```bash
pip install pytest pytest-cov ruff mypy types-PyYAML --break-system-packages
```

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and
import sorting, and [mypy](https://mypy-lang.org/) for type checking.
Config lives in `pyproject.toml`.

```bash
make lint       # ruff check .
make typecheck  # mypy recon_detector.py
```

Both run in CI on every push — a PR won't pass if either fails.

## Tests

```bash
make test   # runs pytest with coverage reporting
```

Tests live in `tests/test_detector.py` and exercise the detection logic
directly (no live packet capture needed, so they run fine in CI). If you're
adding a new detection type or changing thresholds, add a test that proves
it — this project's whole ethos (see the README's live-test-results
section) is verifying real behavior, not just describing intended behavior.

Run everything CI runs, in the same order, before pushing:

```bash
make check
```

## Making a change

1. Fork and branch from `main`.
2. Make your change, keeping it scoped — small, focused PRs are easier to
   review and easier to actually test live.
3. Run `make check` and fix anything it flags.
4. If you changed detection logic, config, or deployment steps, test it for
   real if you can (live traffic, an actual reboot, etc.) — not just a code
   review of the change. Note what you tested in the PR description.
5. Update the README if you changed user-facing behavior (a new alert type,
   a new config option, a new deploy step).
6. Open a PR using the provided template.

## Reporting bugs / requesting features

Use the issue templates — they ask for the specific details (environment,
config, logs) that make triage faster.

## Scope

Changes that add a paid dependency, a database, a second service, or
anything that meaningfully increases the resource footprint are likely to
need discussion first (open an issue before a PR) — they conflict with the
project's core goal of running comfortably on an 8GB VM at zero cost.
