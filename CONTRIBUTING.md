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

`make install` installs everything you need - runtime deps (`scapy`,
`pyyaml`) and dev/CI tooling (`pytest`, `ruff`, `mypy`, etc.) - all
hash-verified against `requirements.txt`/`requirements-dev.txt` (the same
files CI installs from, so what you run locally matches CI exactly). If
you add or bump a dependency, edit `requirements.in` or
`requirements-dev.in` and run `make lock` to regenerate the hash-pinned
files.

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

## Fuzzing

`fuzz/fuzz_config.py` fuzzes `load_config()`'s handling of arbitrary
YAML content - it already found two real crash bugs (an unhandled
`AttributeError` on non-mapping YAML, an unhandled `yaml.YAMLError` on
malformed syntax) before a single fuzz run, just from thinking through
what "arbitrary file content" could do to that function. Both are fixed
and covered by regression tests; the harness exists to keep checking for
the next one, and runs weekly + on any push touching
`recon_detector.py`/`fuzz/` (see `.github/workflows/fuzz.yml`).

Requires Python 3.12+ and Linux (see `requirements-fuzz.txt`'s header -
`atheris` doesn't ship wheels for 3.11 or macOS/Windows).

```bash
make fuzz FLAGS="-max_total_time=60"   # bounded run
make fuzz                               # runs until Ctrl+C
```

If you add a new function that parses external input (a new config
option, a new alert field derived from packet data), consider adding a
harness for it following the same pattern.

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

### Example: adding a test for a new alert type

If you add a new detection path, follow the existing test pattern in
`tests/test_detector.py` — construct a `Detector` with overridden config,
feed it synthetic timestamps, and assert on the alert it emits:

```python
def test_my_new_scan_type_triggers():
    d = make_detector({"my_new_scan": {"distinct_threshold": 3, "window_seconds": 10}})
    src = "10.0.0.9"
    alerts = []
    d._alert = lambda t, s, detail: alerts.append(t)

    now = 20_000.0
    for item in range(3):
        d._check_scan(d.my_new_activity, src, item, d.cfg["my_new_scan"], src,
                      "MY_NEW_SCAN", "SLOW_MY_NEW_SCAN", now, {"protocol": "TCP"})

    assert "MY_NEW_SCAN" in alerts
```

This mirrors how `_check_scan` is already exercised for vertical and
horizontal scans — reuse it rather than writing a new detection mechanism
from scratch unless the new alert type genuinely needs different logic.

### What happens after you open a PR

CI runs `make check`'s three steps automatically (lint, type check, tests
with coverage) — a PR with a red check won't be merged as-is. Beyond that,
review is informal: since this is currently a solo-maintained project,
expect a review comment or two asking what you tested and why, especially
for anything touching detection thresholds or the OSSEC/systemd deployment
config, where "it looks right" and "it works" have turned out to be
different things more than once in this project's own history (see the
README's live-test-results section for examples). Once CI is green and any
review comments are addressed, it gets merged.

## Reporting bugs / requesting features

Use the issue templates — they ask for the specific details (environment,
config, logs) that make triage faster.

## Scope

Changes that add a paid dependency, a database, a second service, or
anything that meaningfully increases the resource footprint are likely to
need discussion first (open an issue before a PR) — they conflict with the
project's core goal of running comfortably on an 8GB VM at zero cost.
