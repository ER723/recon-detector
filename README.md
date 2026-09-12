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

### Live test results

This was run for real: detector on a Kali VM (`--iface eth0`), scans launched
from a separate machine on the same LAN plus from the Kali VM itself for the
horizontal case. Every alert type fired as designed, using the real
thresholds in `config.yaml` (no tuning down for the demo). Timestamps/IPs are
from the actual run.

**ARP scan** — another device on the LAN (not the machine running the scans)
tripped this on its own, which is a good sign: the detector caught real
background ARP activity, not just the deliberate test traffic.
```json
{"timestamp": "2026-09-12T13:53:46Z", "alert_type": "ARP_SCAN", "source_ip": "192.168.1.4", "severity": "low", "protocol": "ARP", "count": 10, "window_seconds": 10, "sample_hosts": ["192.168.1.11", "192.168.1.14", "192.168.1.2", "192.168.1.23", "192.168.1.24", "192.168.1.29", "192.168.1.3", "192.168.1.34", "192.168.1.5", "192.168.1.8"]}
```

**TCP vertical scan** (`nmap -sS -p 1-100 <target>`):
```json
{"timestamp": "2026-09-12T13:58:24Z", "alert_type": "TCP_VERTICAL_SCAN", "source_ip": "192.168.1.4", "severity": "high", "destination_ip": "192.168.1.27", "protocol": "TCP", "last_flags": "S", "count": 15, "window_seconds": 10, "sample": [19, 21, 22, 23, 24, 25, 31, 40, 53, 65, 7, 8, 80, 91, 94]}
```

**UDP vertical scan** (`nmap -sU -p 1-50 <target>`):
```json
{"timestamp": "2026-09-12T13:58:34Z", "alert_type": "UDP_VERTICAL_SCAN", "source_ip": "192.168.1.4", "severity": "high", "destination_ip": "192.168.1.27", "protocol": "UDP", "count": 15, "window_seconds": 10, "sample": [1, 12, 13, 18, 20, 24, 25, 30, 31, 34, 35, 37, 41, 45, 50]}
```

**Slow vertical scan** (`nmap -sS -T1 -p 1-50 <target>`) — `-T1` deliberately
spaces probes ~15s apart to duck fast-window thresholds. The long window
caught it anyway, and kept re-alerting with a growing count as the scan
continued to trickle in:
```json
{"timestamp": "2026-09-12T13:58:24Z", "alert_type": "SLOW_TCP_VERTICAL_SCAN", "source_ip": "192.168.1.4", "severity": "medium", "destination_ip": "192.168.1.27", "protocol": "TCP", "last_flags": "S", "count": 30, "window_seconds": 300, "sample": [11, 12, 16, 17, 19, 21, 22, 23, 24, 25, 31, 35, 39, 40, 43, 5, 53, 56, 57, 62], "note": "stealthy/slow-timed scan pattern"}
{"timestamp": "2026-09-12T14:02:28Z", "alert_type": "SLOW_TCP_VERTICAL_SCAN", "source_ip": "192.168.1.4", "severity": "medium", "destination_ip": "192.168.1.27", "protocol": "TCP", "last_flags": "S", "count": 72, "window_seconds": 300, "sample": [1, 11, 12, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 3, 30], "note": "stealthy/slow-timed scan pattern"}
```

**Horizontal scan** (run from the Kali box itself — see note below —
`nmap -sS -p 80 192.168.1.0/24`):
```json
{"timestamp": "2026-09-12T14:09:55Z", "alert_type": "HORIZONTAL_SCAN", "source_ip": "192.168.1.27", "severity": "high", "protocol": "TCP", "count": 10, "window_seconds": 10, "sample": ["109.228.38.48", "192.168.1.1", "192.168.1.14", "192.168.1.19", "192.168.1.2", "192.168.1.20", "192.168.1.3", "192.168.1.4", "192.168.1.5", "87.106.54.7"]}
```

**Ping sweep** (`nmap -sn -PE --send-ip 192.168.1.0/24` — plain `-sn` prefers
ARP over ICMP on a local subnet, so `--send-ip` is needed to force real ICMP
echo requests and actually exercise this path):
```json
{"timestamp": "2026-09-12T14:21:56Z", "alert_type": "PING_SWEEP", "source_ip": "192.168.1.27", "severity": "medium", "protocol": "ICMP", "count": 10, "window_seconds": 10, "sample_hosts": ["192.168.1.1", "192.168.1.14", "192.168.1.16", "192.168.1.19", "192.168.1.2", "192.168.1.20", "192.168.1.255", "192.168.1.3", "192.168.1.4", "192.168.1.5"]}
```

**Notes from this run:**
- The scanning machine had to run `sudo nmap -sS`/`-sU` — SYN and UDP scans
  need raw sockets and root on the *scanning* machine, not just on the
  detector.
- A horizontal scan needs to be run *from* the machine running the
  detector, not *at* it from elsewhere. Horizontal detection looks for one
  source touching many destinations; a remote machine scanning a whole
  subnet sends most of that traffic to other hosts, which never crosses the
  detector's own network interface to be sniffed.
- The `HORIZONTAL_SCAN` sample above includes two public IPs alongside the
  LAN targets (`109.228.38.48`, `87.106.54.7`). Those weren't scan targets —
  they were the Kali VM's own background traffic (apt/telemetry/etc.)
  landing in the same 10-second window as the scan, from the same source.
  Harmless here (the LAN targets alone were enough to trip the threshold),
  but worth knowing: horizontal detection on a host that also generates its
  own outbound traffic can mix legitimate connections into the sample.

## Feeding this into OSSEC / Wazuh

This has been built and confirmed working end to end against a real, local
OSSEC HIDS 4.3.0 install (`local` install type — no manager/agent split, no
indexer, no dashboard: a single self-contained log-analysis engine on the
same box as the detector). Real `nmap`-triggered alerts were verified
landing in `/var/ossec/logs/alerts/alerts.log`, correctly classified by
severity.

The working decoder and rules are in `deploy/ossec/` — copy them onto your
OSSEC install:

```bash
sudo cp deploy/ossec/local_decoder.xml /var/ossec/etc/local_decoder.xml
sudo tee -a /var/ossec/rules/local_rules.xml < deploy/ossec/local_rules.xml
```

Then add a `<localfile>` block to `/var/ossec/etc/ossec.conf` (inside
`<ossec_config>`, anywhere before the closing tag) pointing at your
`recon_alerts.log`, and restart:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/home/YOUR_USER/recon-detector/recon_alerts.log</location>
</localfile>
```

```bash
sudo /var/ossec/bin/ossec-control restart
```

Confirmed rule/level mapping (tested live, not just in theory):

| recon-detector `severity` | OSSEC rule ID | OSSEC level |
|---|---|---|
| `high`                    | 100103        | 10          |
| `medium`                  | 100102        | 6           |
| `low`                     | 100101        | 3           |

**Known limitation:** the rule descriptions reference `$(srcip)`-style
field interpolation in earlier iterations of this setup, but extracting
`source_ip` into a named OSSEC field couldn't be made to work on this
build after several attempts — the cause wasn't pinned down. This is
cosmetic only: every alert in `alerts.log` still contains the complete,
original JSON line — including the real `source_ip` — directly beneath
the rule description. The shipped `deploy/ossec/` files reflect this by
not referencing `$(srcip)` at all, to avoid shipping a dangling
placeholder.

If you'd rather run the full Wazuh stack (manager+indexer+dashboard)
instead of standalone OSSEC, be aware it's meaningfully heavier — the
indexer alone typically wants several GB of RAM. Run it on separate
hardware from the box doing the sniffing if you go that route, so it
doesn't compete with recon-detector and Kali for the same 8GB.

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

**OSSEC also needs its own boot persistence** — its installer sets up
classic SysV init (`/etc/init.d/ossec` + `rc*.d` symlinks), which looked
correctly registered but did not actually start OSSEC after a real reboot
test on this system. `deploy/ossec/ossec.service` fixes that with a proper
systemd unit instead, confirmed working via an actual reboot (not just
`enable`d on paper):

```bash
sudo /var/ossec/bin/ossec-control stop   # if already running manually
sudo cp deploy/ossec/ossec.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ossec
sudo systemctl status ossec       # expect: active (exited) - correct for oneshot
sudo /var/ossec/bin/ossec-control status   # expect: 4 daemons running
```

Both `recon-detector` and `ossec` were confirmed running with zero manual
intervention after a cold `sudo reboot` on the Kali test VM.

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
- Horizontal-scan detection can mix a host's own legitimate outbound
  traffic into an alert's sample if run on the same machine that's also
  scanning — observed directly in live testing above.

## License

MIT — see [LICENSE](LICENSE).
