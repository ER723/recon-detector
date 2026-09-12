# recon-detector

A free, lightweight network reconnaissance detector. Watches live traffic and
raises an alert when it sees the noisy behaviors attackers generate while
mapping a network before an attack:

- **Vertical scans** — one source hitting many ports on a **single**
  destination (classic single-target enumeration, e.g. `nmap -p1-1000 <ip>`).
  Tracked separately for TCP and UDP.
- **Horizontal scans** — one source touching many **distinct** destination
  hosts over TCP or UDP (classic network sweep, e.g. `nmap -p80 10.0.0.0/24`).
- **Ping sweeps** — one source ICMP-pinging many distinct hosts (a horizontal
  pattern specific to ICMP).
- **ARP scans** — one source sending many ARP "who-has" requests on the LAN.

Every TCP/UDP/horizontal check runs on **two sliding windows** per tracked
target:
- a **fast** window, tuned for default-speed scans (`nmap -T3`/`-T4`/`-T5`)
- a **slow** window with a higher count but a much longer time span, tuned
  for stealthy scans (`nmap -T0`/`-T1`) deliberately spread out to duck a
  fast threshold

It's a single Python file with one real dependency (`scapy`), in-memory
sliding-window counters (no database, no message queue), and structured
JSON alert logging — designed to run comfortably on a low-resource VM
(tested target: 8GB RAM, single core, Kali Linux) and to keep running for
weeks without attention: idle tracking state is pruned automatically, and a
periodic heartbeat log line proves the process is still alive.

## Why this exists

Reconnaissance (scanning, enumeration) is almost always the first stage of
an attack (MITRE ATT&CK [TA0043 — Reconnaissance](https://attack.mitre.org/tactics/TA0043/)).
Catching it early gives you a chance to respond before the attacker moves on
to exploitation. Commercial/heavy tools (Zeek, Suricata, Snort with full
rule sets) do this and much more, but they're overkill for a home lab or a
small network where you just want a clear signal: "someone is scanning me."

## Requirements

- Python 3.8+
- `scapy` (already installed on Kali Linux by default)
- Root/sudo (raw packet capture requires it)

## Install

```bash
git clone https://github.com/ER723/recon-detector.git
cd recon-detector
pip3 install -r requirements.txt
```

## Usage

```bash
# Run with defaults, sniff on the interface scapy picks automatically
sudo python3 recon_detector.py

# Specify an interface (recommended)
sudo python3 recon_detector.py --iface eth0

# Use a custom config with different thresholds
sudo python3 recon_detector.py --iface eth0 --config config.yaml

# Suppress console output, just write to the log file
sudo python3 recon_detector.py --iface eth0 --quiet
```

### Alert format

Alerts are appended to `recon_alerts.log` (path configurable) as one JSON
object per line, with a consistent schema regardless of alert type:

```json
{"timestamp": "2026-09-12T04:24:18Z", "alert_type": "TCP_VERTICAL_SCAN", "source_ip": "192.168.1.50", "severity": "high", "destination_ip": "192.168.1.10", "protocol": "TCP", "last_flags": "S", "count": 15, "window_seconds": 10, "sample": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]}
```

```json
{"timestamp": "2026-09-12T04:31:02Z", "alert_type": "HORIZONTAL_SCAN", "source_ip": "192.168.1.50", "severity": "high", "protocol": "TCP", "count": 12, "window_seconds": 10, "sample": ["192.168.1.10", "192.168.1.11", "..."]}
```

Every alert has `timestamp`, `alert_type`, `source_ip`, and `severity`
(`high`/`medium`/`low`); the remaining fields vary by type but always
include `count`, `window_seconds`, and a `sample` of the ports or hosts
involved. `alert_type` is one of:

| alert_type                | Meaning                                              |
|----------------------------|-------------------------------------------------------|
| `TCP_VERTICAL_SCAN`        | fast scan: many TCP ports on one destination         |
| `SLOW_TCP_VERTICAL_SCAN`   | same, spread out over the long window                |
| `UDP_VERTICAL_SCAN`        | fast scan: many UDP ports on one destination         |
| `SLOW_UDP_VERTICAL_SCAN`   | same, spread out over the long window                |
| `HORIZONTAL_SCAN`          | fast scan: many distinct destination hosts           |
| `SLOW_HORIZONTAL_SCAN`     | same, spread out over the long window                |
| `PING_SWEEP`               | many hosts ICMP-pinged quickly                       |
| `ARP_SCAN`                 | many hosts ARP-probed quickly (local subnet only)    |

Non-alert lines (startup banner, `[HEARTBEAT]`, `[cleanup]`) are plain text,
not JSON — a decoder should treat lines that don't parse as JSON as
informational, not as alerts.

### Tuning thresholds

Edit `config.yaml` (see comments in the file). Lower thresholds / shorter
windows catch scans faster but are more likely to flag legitimate bursty
traffic (backup agents, network monitoring tools, etc). Start with the
defaults, watch the log for a day, and tune from there.

Each of `tcp_vertical_scan`, `udp_vertical_scan`, and `horizontal_scan` has
two independent triggers:
- a **fast** one (`window_seconds` / `distinct_threshold`)
- a **slow** one (`long_window_seconds` / `long_window_threshold`)

### Testing it against yourself

From another machine on the same network:

```bash
# Vertical scan: many ports, one target
nmap -sS -p 1-100 <ip-of-the-machine-running-recon-detector>

# UDP vertical scan
nmap -sU -p 1-50 <ip-of-the-machine-running-recon-detector>

# Horizontal scan: one port, many targets on the subnet
nmap -sS -p 80 <subnet>.0/24

# Slow vertical scan (takes a few minutes to trip the long-window threshold)
nmap -sS -T1 -p 1-50 <ip-of-the-machine-running-recon-detector>
```

You should see the matching alert type appear within the configured window.

## Feeding this into OSSEC / Wazuh

Alerts are single-line JSON, so OSSEC/Wazuh can decode them natively with a
JSON log decoder pointed at `recon_alerts.log`, without writing a custom
regex — map `alert_type` to a rule name and `severity` to a rule level, e.g.
`high` → level 10+, `medium` → level 5-7, `low` → level 1-4.

This works with the lightweight OSSEC/Wazuh **agent** you're likely already
running. The full Wazuh manager+indexer+dashboard stack is heavier
(typically wants several GB of RAM on its own) — if you want that, run it on
separate hardware from the box doing the sniffing, so it doesn't compete
with recon-detector and Kali for the same 8GB.

## Running as a persistent service

`deploy/` has everything needed to run this unattended and production-style,
using only tools already on a Debian/Kali box (no new services, no cost):

```bash
sudo mkdir -p /opt/recon-detector
sudo cp -r ./* /opt/recon-detector/
sudo cp deploy/recon-detector.service /etc/systemd/system/
sudo cp deploy/recon-detector.logrotate /etc/logrotate.d/recon-detector
# edit the --iface value in the .service file to match your interface first
sudo systemctl daemon-reload
sudo systemctl enable --now recon-detector
sudo systemctl status recon-detector
sudo journalctl -u recon-detector -f
```

- **`recon-detector.service`** — starts on boot, restarts automatically on
  crash (`Restart=on-failure`).
- **`recon-detector.logrotate`** — rotates `recon_alerts.log` weekly, keeps
  8 weeks compressed, so the log can't grow unbounded.

## Running tests

```bash
python3 -m pytest tests/
# or, without pytest:
python3 tests/test_detector.py
```

## Limitations (read before relying on this)

- Heuristic, threshold-based detection — very slow scans (spread beyond the
  configured long window) or very quiet traffic can still fall below both
  thresholds, and legitimately bursty traffic can still false-positive.
- Single-process, in-memory state — restarting the script clears all
  tracked activity (this is intentional, keeps it lightweight). Idle
  per-source state is auto-pruned after `stale_after_seconds` so long-running
  memory use stays flat regardless.
- Detects reconnaissance only, not exploitation or later attack stages.
- No built-in threat-intel/reputation lookups — it flags *behavior*, not
  known-bad IPs.
- Not a replacement for Zeek/Suricata/Snort in a production environment —
  built for home-lab / small-network use where those are too heavy.

## License

MIT — see [LICENSE](LICENSE).
