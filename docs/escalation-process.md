# recon-detector — Tier-1 Escalation Process

This document describes how a Tier-1 analyst should triage and escalate
alerts produced by recon-detector once they land in OSSEC. It's written
from the actual, live-tested pipeline (see [Live test results](../README.md#live-test-results)
in the README) — every example below uses real alert output captured
during that testing, not hypothetical data.

## 1. Where alerts come from

```
Nmap / real scan traffic
        |
        v
recon-detector (sniffs eth0, applies thresholds) --> recon_alerts.log (JSON, one alert per line)
        |
        v
OSSEC HIDS (decoder: recon-detector, rules 100100-100103)
        |
        v
/var/ossec/logs/alerts/alerts.log  (Rule ID + Level + full original JSON)
```

A Tier-1 analyst's starting point is always an entry in `alerts.log` —
either seen live via `tail -f`, or surfaced by whatever downstream
tooling consumes that log (SIEM forward, cron digest, etc.).

## 2. Alert type and severity reference

| `alert_type`            | OSSEC Rule ID | OSSEC Level | Meaning                                             |
|--------------------------|:---:|:---:|------------------------------------------------------|
| `TCP_VERTICAL_SCAN`      | 100103 | 10 (high)   | Many TCP ports hit on one host, fast                |
| `UDP_VERTICAL_SCAN`      | 100103 | 10 (high)   | Many UDP ports hit on one host, fast                 |
| `HORIZONTAL_SCAN`        | 100103 | 10 (high)   | Many distinct hosts touched, fast                    |
| `SLOW_TCP_VERTICAL_SCAN` | 100102 | 6 (medium)  | Same as above, deliberately spread out to evade      |
| `SLOW_UDP_VERTICAL_SCAN` | 100102 | 6 (medium)  | ...                                                   |
| `SLOW_HORIZONTAL_SCAN`   | 100102 | 6 (medium)  | ...                                                   |
| `PING_SWEEP`             | 100101 | 3 (low)     | Many hosts ICMP-pinged, fast                          |
| `ARP_SCAN`               | 100101 | 3 (low)     | Many hosts ARP-probed, fast (local subnet only)       |

Severity is set by recon-detector itself (see its README) and carried
straight through into the OSSEC rule that fires — a Tier-1 analyst does
not need to separately judge severity, only decide what to *do* about it
using the criteria in Section 4.

**Known gap:** OSSEC's rule description shows `$(srcip)` unresolved
rather than the actual source IP (see the README's OSSEC limitations
note). This does not affect triage: the real `source_ip` is always
present, in full, in the raw JSON printed directly under every alert —
read it from there, not from the description line.

## 3. Tier-1 triage procedure

For every new alert in `alerts.log`:

1. **Read the OSSEC level first.** It already encodes severity —
   `10` (high) always warrants closer attention than `3` (low) before
   you've read anything else.
2. **Extract the facts from the raw JSON line**, not the rule
   description: `source_ip`, `alert_type`, `count`, `window_seconds`,
   and the `sample` (ports) or `sample_hosts` field. `destination_ip`
   is also present for vertical-scan alerts.
3. **Check whether the source is expected.** Is `source_ip` a known,
   authorized scanner (a vulnerability scanner, a monitoring tool, your
   own testing box)? recon-detector has no built-in allowlist (a
   documented limitation) — this check is manual today.
   - Known → likely a false positive. Note it and move on; consider
     adding the source to your own tracking so repeat alerts from it
     aren't re-triaged from scratch each time.
   - Unknown / unexpected → continue triage.
4. **Check for a `SLOW_*` alert type specifically.** A slow-timed scan
   (`nmap -T0`/`-T1`-style) implies deliberate evasion effort by
   whoever generated it — that's a meaningful signal of intent, even
   though its OSSEC level (6, medium) is numerically lower than a fast
   scan's (10, high). Don't let the lower level alone cause you to
   deprioritize it.
5. **Check for related alerts from the same `source_ip`** in a nearby
   time window — recon-detector's own alert-type split (vertical vs.
   horizontal vs. sweep) means a single real attacker's recon often
   produces *multiple, different* alert types in sequence as they
   pivot from discovery to enumeration. Multiple distinct alert types
   from one source is a stronger signal than any single alert alone.
6. **Decide: close, monitor, or escalate**, using Section 4.

## 4. Escalation criteria — when Tier-1 hands off to Tier-2

Escalate if **any** of the following are true:

- Level **10 (high)** alert from a source that is not a known/allowed
  scanner.
- **Two or more distinct `alert_type` values** from the same
  `source_ip` within a short window (chained recon behavior — e.g. an
  `ARP_SCAN` followed by a `TCP_VERTICAL_SCAN` against a host it just
  discovered).
- Any `SLOW_*` alert from an unknown source — the evasion attempt
  itself is the escalation trigger, independent of its medium level.
- A `HORIZONTAL_SCAN` or `SLOW_HORIZONTAL_SCAN` targeting more than a
  handful of hosts (check the `sample` field's length against
  `count` — a `count` much larger than the printed `sample` means the
  real scope is larger than what's shown, since samples are capped).
- Any alert whose `source_ip` is **not** on the local subnet (an
  external or unexpected-origin source scanning at all is inherently
  more significant than internal traffic).

Otherwise (known source, single low/medium alert, no repeat pattern):
**log and close**, or **monitor** if borderline — no escalation needed.

## 5. What to hand to Tier-2

Package the following, copied directly from the raw JSON — don't
paraphrase or summarize the evidence itself:

- The full raw alert JSON line(s), for every alert type involved
- The OSSEC Rule ID and Level for each
- Timestamps (both recon-detector's `timestamp` field and the OSSEC
  alert's own timestamp, if they differ)
- Your own triage notes from Section 3: was the source known? was
  there a related alert? does this look like a chained pattern?
- A one-line recommendation (e.g., "unknown source, high severity,
  recommend block + deeper log review" or "unknown source, slow-scan
  pattern against 3 hosts, recommend monitoring + threat-intel lookup
  on source IP")

## 6. Known false-positive sources

- Your own testing traffic (this project's own live-test sessions
  produce real alerts, as documented in the README — expected, not a
  detection failure)
- Legitimate internal vulnerability scanners or monitoring tools that
  happen to touch many ports/hosts as part of normal operation
- A host's own outbound background traffic landing in the same window
  as a real scan it's also running, for `HORIZONTAL_SCAN` specifically
  (documented in the README's live-test notes — the sample list can
  include unrelated destinations, not just scan targets)

recon-detector has no built-in threat-intel or reputation lookups (a
documented limitation) — "is this IP known-bad" is not something the
tool tells you; that step is manual or belongs to whatever Tier-2
process/tooling handles it next.

## 7. Worked example (real data, from live testing)

Two real alerts from the same live-test session, same source
(`192.168.1.4`), same target (`192.168.1.27`), roughly four minutes
apart:

```json
{"timestamp": "2026-09-12T13:58:24Z", "alert_type": "TCP_VERTICAL_SCAN", "source_ip": "192.168.1.4", "severity": "high", "destination_ip": "192.168.1.27", "protocol": "TCP", "last_flags": "S", "count": 15, "window_seconds": 10, "sample": [19, 21, 22, 23, 24, 25, 31, 40, 53, 65, 7, 8, 80, 91, 94]}
```
```json
{"timestamp": "2026-09-12T14:02:28Z", "alert_type": "SLOW_TCP_VERTICAL_SCAN", "source_ip": "192.168.1.4", "severity": "medium", "destination_ip": "192.168.1.27", "protocol": "TCP", "last_flags": "S", "count": 72, "window_seconds": 300, "sample": [1, 11, 12, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 3, 30], "note": "stealthy/slow-timed scan pattern"}
```

**Triage walkthrough:**
- First alert: Rule 100103, level 10 (high). Source `192.168.1.4`
  hit 15 distinct ports on `192.168.1.27` in 10 seconds.
- In this specific session the source was known (the test machine
  itself) — in a real environment, an unrecognized source here would
  already meet the Section 4 "high severity, unknown source"
  escalation criterion on its own.
- Second alert, ~4 minutes later, same source/target pair: a
  **different** alert type (`SLOW_TCP_VERTICAL_SCAN`), level 6
  (medium), 72 ports touched over the 5-minute window.
- Per Section 3, step 5: this is the same `source_ip` producing
  **two distinct alert types** against the same target in a short
  span — the fast scan followed by continued, deliberately-paced
  probing after the fast scan was already loud enough to alert once.
  That combination — not the medium level of the second alert alone —
  is what would drive escalation for an unrecognized source: it reads
  as one actor doing an initial fast sweep, then continuing more
  carefully once they'd already been noisy.
- **Escalation package** would include both raw JSON lines above, both
  rule IDs/levels, the ~4-minute gap between them noted explicitly (it's
  evidence of sustained intent, not a one-off), and the recommendation:
  "same source, two alert types against one host, second attempt
  deliberately slow-timed — recommend full review of all traffic from
  192.168.1.4 in this window, not just what recon-detector flagged."

## 8. Limitations affecting escalation confidence

Carried forward from the project README — read in full before relying
on this process operationally:

- Heuristic, threshold-based detection: very slow/spread-out scans or
  quiet traffic can fall below thresholds entirely and never alert.
- No built-in allowlist: legitimate scanners must be recognized
  manually (Section 3, step 3) until one is added.
- No threat-intel/reputation lookups: "known-bad IP" is not something
  recon-detector or this process determines automatically.
- `HORIZONTAL_SCAN` samples can include unrelated background traffic
  when generated from the same host that's also scanning.
- This process assumes single-analyst Tier-1 review; it does not
  define SLA/timing targets, on-call rotation, or ticketing-system
  integration — those are organization-specific and out of scope here.
