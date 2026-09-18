#!/usr/bin/env python3
"""
Atheris fuzz harness for recon-detector's config loading.

Targets load_config()'s handling of arbitrary YAML content. A malformed
or corrupted config.yaml - a typo pointing at the wrong file, a
corrupted deployment artifact, or a file an attacker with write access
tampered with - should fail cleanly, not crash the detector with an
unhandled exception. A defensive tool crashing on bad input is itself a
denial-of-service risk, so this is a real robustness property worth
verifying continuously, not a checkbox.

This harness already found two real bugs before a single fuzz run:
  - a non-mapping top-level YAML value (a string/list/number instead of
    key: value pairs) crashed with an unhandled AttributeError
  - genuinely malformed YAML syntax crashed with an unhandled
    yaml.YAMLError
Both are fixed in load_config() (see recon_detector.py) and covered by
tests/test_detector.py::test_load_config_rejects_non_mapping_yaml_cleanly.
This harness exists to keep checking for the next one.

Run locally:
    pip install atheris
    python3 fuzz/fuzz_config.py

Run for a fixed duration (used in CI):
    python3 fuzz/fuzz_config.py -max_total_time=60

Requires atheris, which only supports Linux and macOS (not Windows) and
CPython 3.8-3.12 - see https://github.com/google/atheris#supported-platforms.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import atheris

with atheris.instrument_imports():
    from recon_detector import load_config


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

    path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(text)
            path = f.name
        try:
            load_config(path)
        except SystemExit:
            pass  # load_config's own handled error path - expected, not a crash
    finally:
        if path:
            os.unlink(path)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
