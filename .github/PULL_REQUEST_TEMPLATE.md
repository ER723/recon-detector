## What does this change?

<!-- One or two sentences on what this PR does and why. -->

## How was this tested?

<!--
This project's whole ethos is "tested against real traffic/behavior, not
assumed." Please describe what you actually ran, not just what should work:
- Which command(s) did you run? (`make check`, live Nmap scans, a reboot test, etc.)
- If you touched detection logic: what real or simulated traffic did you
  test it against?
- If you touched OSSEC/systemd/deploy config: did you verify it live, not
  just review the config?
-->

## Checklist

- [ ] `make check` passes locally (lint + type check + tests)
- [ ] I tested this against real behavior, not just code review, where applicable
- [ ] I updated the README/docs if this changes user-facing behavior
- [ ] I did not add a paid dependency, database, or anything that breaks the "zero-cost, extremely lightweight" scope (see README)
