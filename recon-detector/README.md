# recon-detector

A free, lightweight network reconnaissance detector. Watches live traffic and
raises an alert when it sees the noisy behaviors attackers generate while
mapping a network before an attack:

- **TCP port scans** — one source touching many distinct destination ports,
  both fast (default nmap timing) and **slow/stealthy** (`nmap -T0`/`-T1`
  style scans spread out to evade fast-window thresholds)
- **UDP port scans** — same idea, over UDP, tracked separately from TCP
- **Ping sweeps** — one source ICMP-pinging many distinct hosts quickly
- **ARP scans** — one source sending many ARP "who-has" requests quickly

It's a single Python file with one real dependency (`scapy`), in-memory
sliding-window counters (no database, no message queue), and plain-text
alert logging — designed to run comfortably on a low-resource VM (tested
target: 8GB RAM, single core, Kali Linux) and to keep running for weeks
without attention: idle tracking state is pruned automatically, and a
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

Alerts are appended to `recon_alerts.log` (path configurable) in a format
like:

```
2026-09-11 14:02:31 [ALERT] TCP_PORT_SCAN from 192.168.1.50 - 22 distinct dst ports in 10s (last flags=S)
2026-09-11 14:03:05 [ALERT] PING_SWEEP from 192.168.1.50 - 12 distinct hosts pinged in 10s
2026-09-11 14:10:40 [ALERT] SLOW_TCP_PORT_SCAN from 192.168.1.51 - 34 distinct dst ports over 300s (stealthy/slow-timed scan pattern) (last flags=S)
2026-09-11 14:15:00 [HEARTBEAT] recon-detector alive, tracking 3 active source entr(y/ies)
```

### Tuning thresholds

Edit `config.yaml` (see comments in the file). Lower thresholds / shorter
windows catch scans faster but are more likely to flag legitimate bursty
traffic (backup agents, network monitoring tools, etc). Start with the
defaults, watch the log for a day, and tune from there.

Each of `port_scan` and `udp_scan` has two independent triggers:
- a **fast** one (`window_seconds` / `distinct_port_threshold`) for
  default-speed scans
- a **slow** one (`long_window_seconds` / `long_window_threshold`) for scans
  deliberately spread out to stay under the fast threshold

### Testing it against yourself

From another machine on the same network:

```bash
# Fast TCP scan
nmap -sS -p 1-100 <ip-of-the-machine-running-recon-detector>

# UDP scan
nmap -sU -p 1-50 <ip-of-the-machine-running-recon-detector>

# Slow scan (takes a few minutes to trip the long-window threshold)
nmap -sS -T1 -p 1-50 <ip-of-the-machine-running-recon-detector>
```

You should see the matching alert appear within the configured window.

## Feeding this into OSSEC / Wazuh

Since alerts are plain-text log lines, you can point OSSEC/Wazuh's log
collector at `recon_alerts.log` as a custom log source and write a decoder/
rule that matches on `TCP_PORT_SCAN`, `UDP_PORT_SCAN`, `SLOW_TCP_PORT_SCAN`,
`SLOW_UDP_PORT_SCAN`, `PING_SWEEP`, or `ARP_SCAN` to turn these into
first-class alerts in your SOC pipeline, alongside your existing OSSEC setup.

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

- Heuristic, threshold-based detection — very slow scans (one port every
  many minutes, spread beyond the configured long window) or very quiet
  traffic can still fall below both thresholds, and legitimately bursty
  traffic can still false-positive.
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
