#!/usr/bin/env python3
"""
recon-detector: a lightweight, dependency-light network reconnaissance detector.

Detects, in real time, the noisy pre-attack behaviors an attacker generates
while mapping a network:

  - VERTICAL scans   (one source hitting many ports on ONE destination host)
      tracked separately for TCP and UDP
  - HORIZONTAL scans (one source touching many DISTINCT destination hosts,
      over TCP or UDP)
  - ICMP ping sweeps (one source pinging many distinct hosts - a horizontal
      pattern specific to ICMP)
  - ARP scans        (one source ARP-probing many distinct hosts on the LAN)

Vertical and horizontal TCP/UDP detection each use TWO sliding windows per
tracked key:
  - a short window, tuned to catch fast/default-speed scans (e.g. nmap -T4)
  - a long window with a higher count but looser rate, tuned to catch
    slow/stealthy scans (e.g. nmap -T0/-T1) that spread probes out to
    stay under a short-window threshold

Alerts are written as single-line JSON, one object per line, with a
consistent schema (source, destination, protocol, ports/hosts, count,
timestamp, severity) so they can be parsed directly by OSSEC/Wazuh's
JSON log decoder or any other log pipeline, without custom regex.

Design goals (deliberately kept simple so it runs happily on a VM with
8GB RAM and a single CPU core, with no external services and no cost):
  - Single Python file, one third-party dependency (scapy).
  - In-memory sliding-window counters, no database, no message queue.
  - A fixed-cadence loop (driven by scapy's own `timeout`, no extra threads)
    periodically prunes idle source trackers so memory stays bounded on a
    box that runs for weeks, and emits a heartbeat log line so "no alerts"
    can be told apart from "the detector silently died."

Usage:
    sudo python3 recon_detector.py --iface eth0
    sudo python3 recon_detector.py --iface eth0 --config config.yaml

Run `python3 recon_detector.py -h` for all options.
"""

import argparse
import json
import logging
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

try:
    from scapy.all import ARP, ICMP, IP, TCP, UDP, sniff
except ImportError:
    sys.exit(
        "scapy is required. Install it with:\n"
        "    pip3 install scapy\n"
        "(On Kali it is usually already installed.)"
    )

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


# --------------------------------------------------------------------------
# Defaults (overridable via --config or CLI flags)
# --------------------------------------------------------------------------

DEFAULTS = {
    "tcp_vertical_scan": {          # one source -> many ports on ONE dest, TCP
        "window_seconds": 10,
        "distinct_threshold": 15,
        "long_window_seconds": 300,
        "long_window_threshold": 30,
    },
    "udp_vertical_scan": {          # one source -> many ports on ONE dest, UDP
        "window_seconds": 10,
        "distinct_threshold": 15,
        "long_window_seconds": 300,
        "long_window_threshold": 30,
    },
    "horizontal_scan": {            # one source -> many DISTINCT dest hosts (TCP/UDP)
        "window_seconds": 10,
        "distinct_threshold": 10,
        "long_window_seconds": 300,
        "long_window_threshold": 20,
    },
    "ping_sweep": {                 # one source -> many distinct hosts, ICMP
        "window_seconds": 10,
        "distinct_threshold": 10,
    },
    "arp_scan": {                   # one source -> many distinct hosts, ARP
        "window_seconds": 10,
        "distinct_threshold": 10,
    },
    "alert_cooldown_seconds": 60,      # don't re-alert on the same src+type for this long
    "log_file": "recon_alerts.log",
    "stale_after_seconds": 600,        # drop a tracker after this long idle
    "heartbeat_interval_seconds": 300, # log a heartbeat + run cleanup this often
    "sample_size": 20,                 # max sample items included in an alert's detail
}

# Rough severity rating per alert type, included in every JSON alert so a
# SIEM (or a human) can triage without needing to know the alert-type names.
SEVERITY = {
    "TCP_VERTICAL_SCAN": "high",
    "UDP_VERTICAL_SCAN": "high",
    "SLOW_TCP_VERTICAL_SCAN": "medium",
    "SLOW_UDP_VERTICAL_SCAN": "medium",
    "HORIZONTAL_SCAN": "high",
    "SLOW_HORIZONTAL_SCAN": "medium",
    "PING_SWEEP": "medium",
    "ARP_SCAN": "low",
}


def load_config(path):
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS.items()}
    if path:
        if not HAVE_YAML:
            sys.exit("pyyaml not installed; run: pip3 install pyyaml")
        with open(path) as f:
            try:
                user_cfg = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                sys.exit(f"Invalid config file '{path}': not valid YAML.\n{e}")
        if not isinstance(user_cfg, dict):
            sys.exit(
                f"Invalid config file '{path}': top-level content must be a "
                f"YAML mapping (key: value pairs), got {type(user_cfg).__name__}."
            )
        for section, values in user_cfg.items():
            if isinstance(values, dict) and section in cfg:
                cfg[section].update(values)
            else:
                cfg[section] = values
    return cfg


# --------------------------------------------------------------------------
# Sliding-window tracker: for a given key, remembers (timestamp, item)
# pairs and reports how many *distinct* items occurred in the last N seconds.
# A single tracker can answer both a short-window and a long-window query,
# as long as it's trimmed to the longer of the two on write.
# --------------------------------------------------------------------------

@dataclass
class SourceActivity:
    events: deque = field(default_factory=deque)  # (timestamp, item)

    def add(self, item, now, max_window):
        self.events.append((now, item))
        self._trim(now, max_window)

    def _trim(self, now, max_window):
        while self.events and now - self.events[0][0] > max_window:
            self.events.popleft()

    def distinct_count(self, now, window):
        return len({item for ts, item in self.events if now - ts <= window})

    def distinct_items(self, now, window, limit):
        items = sorted({item for ts, item in self.events if now - ts <= window}, key=str)
        return items[:limit]

    def last_seen(self):
        return self.events[-1][0] if self.events else 0.0

    def is_stale(self, now, stale_after):
        return not self.events or (now - self.last_seen() > stale_after)


class Detector:
    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.log = logger

        # Vertical: keyed by (src, dst) -> distinct ports touched on that dst
        self.tcp_vertical = defaultdict(SourceActivity)
        self.udp_vertical = defaultdict(SourceActivity)
        # Horizontal: keyed by src -> distinct destination hosts touched (TCP/UDP)
        self.horizontal_activity = defaultdict(SourceActivity)
        # ICMP / ARP: keyed by src -> distinct hosts pinged / arp'd
        self.icmp_activity = defaultdict(SourceActivity)
        self.arp_activity = defaultdict(SourceActivity)

        self.last_alert = {}  # (src, alert_type) -> timestamp

    # -- alerting -----------------------------------------------------

    def _should_alert(self, src, alert_type, now):
        key = (src, alert_type)
        last = self.last_alert.get(key, 0)
        if now - last >= self.cfg["alert_cooldown_seconds"]:
            self.last_alert[key] = now
            return True
        return False

    def _alert(self, alert_type, src, detail):
        """detail is a dict of alert-specific fields (destination, protocol,
        ports/hosts, count, ...). Emits one JSON object per line."""
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time())),
            "alert_type": alert_type,
            "source_ip": src,
            "severity": SEVERITY.get(alert_type, "medium"),
        }
        payload.update(detail)
        self.log.warning(json.dumps(payload))

    # -- generic sliding-window scan check (shared by all TCP/UDP checks) ---

    def _check_scan(self, activity_dict, track_key, item, cfg, src,
                     alert_type_fast, alert_type_slow, now, extra_detail):
        max_window = max(cfg["window_seconds"], cfg["long_window_seconds"])
        act = activity_dict[track_key]
        act.add(item, now, max_window)
        limit = self.cfg["sample_size"]

        fast_count = act.distinct_count(now, cfg["window_seconds"])
        if fast_count >= cfg["distinct_threshold"] and self._should_alert(src, alert_type_fast, now):
            detail = dict(extra_detail)
            detail.update({
                "count": fast_count,
                "window_seconds": cfg["window_seconds"],
                "sample": act.distinct_items(now, cfg["window_seconds"], limit),
            })
            self._alert(alert_type_fast, src, detail)
            return

        # Only check the slow-scan window if the fast one didn't just fire,
        # so a fast scan isn't double-reported as slow too.
        long_count = act.distinct_count(now, cfg["long_window_seconds"])
        if long_count >= cfg["long_window_threshold"] and self._should_alert(src, alert_type_slow, now):
            detail = dict(extra_detail)
            detail.update({
                "count": long_count,
                "window_seconds": cfg["long_window_seconds"],
                "sample": act.distinct_items(now, cfg["long_window_seconds"], limit),
                "note": "stealthy/slow-timed scan pattern",
            })
            self._alert(alert_type_slow, src, detail)

    # -- packet handling ------------------------------------------------

    def handle_packet(self, pkt):
        now = time.time()

        if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # who-has (ARP request/scan)
            src = pkt[ARP].psrc
            target = pkt[ARP].pdst
            cfg = self.cfg["arp_scan"]
            act = self.arp_activity[src]
            act.add(target, now, cfg["window_seconds"])
            count = act.distinct_count(now, cfg["window_seconds"])
            if count >= cfg["distinct_threshold"] and self._should_alert(src, "ARP_SCAN", now):
                self._alert("ARP_SCAN", src, {
                    "protocol": "ARP",
                    "count": count,
                    "window_seconds": cfg["window_seconds"],
                    "sample_hosts": act.distinct_items(now, cfg["window_seconds"], self.cfg["sample_size"]),
                })
            return

        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        dst = pkt[IP].dst

        if pkt.haslayer(TCP):
            flags = pkt.sprintf("%TCP.flags%")
            self._check_scan(
                self.tcp_vertical, (src, dst), pkt[TCP].dport, self.cfg["tcp_vertical_scan"], src,
                "TCP_VERTICAL_SCAN", "SLOW_TCP_VERTICAL_SCAN", now,
                {"destination_ip": dst, "protocol": "TCP", "last_flags": flags},
            )
            self._check_scan(
                self.horizontal_activity, src, dst, self.cfg["horizontal_scan"], src,
                "HORIZONTAL_SCAN", "SLOW_HORIZONTAL_SCAN", now,
                {"protocol": "TCP"},
            )

        elif pkt.haslayer(UDP):
            self._check_scan(
                self.udp_vertical, (src, dst), pkt[UDP].dport, self.cfg["udp_vertical_scan"], src,
                "UDP_VERTICAL_SCAN", "SLOW_UDP_VERTICAL_SCAN", now,
                {"destination_ip": dst, "protocol": "UDP"},
            )
            self._check_scan(
                self.horizontal_activity, src, dst, self.cfg["horizontal_scan"], src,
                "HORIZONTAL_SCAN", "SLOW_HORIZONTAL_SCAN", now,
                {"protocol": "UDP"},
            )

        elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # echo-request
            cfg = self.cfg["ping_sweep"]
            act = self.icmp_activity[src]
            act.add(dst, now, cfg["window_seconds"])
            count = act.distinct_count(now, cfg["window_seconds"])
            if count >= cfg["distinct_threshold"] and self._should_alert(src, "PING_SWEEP", now):
                self._alert("PING_SWEEP", src, {
                    "protocol": "ICMP",
                    "count": count,
                    "window_seconds": cfg["window_seconds"],
                    "sample_hosts": act.distinct_items(now, cfg["window_seconds"], self.cfg["sample_size"]),
                })

    # -- production-readiness maintenance -------------------------------

    def cleanup(self):
        """Drop trackers for sources that have gone quiet, so memory stays
        bounded on a box that runs for weeks rather than a demo session."""
        now = time.time()
        stale_after = self.cfg["stale_after_seconds"]
        pruned = 0
        for d in (self.tcp_vertical, self.udp_vertical, self.horizontal_activity,
                  self.icmp_activity, self.arp_activity):
            stale_keys = [k for k, v in d.items() if v.is_stale(now, stale_after)]
            for k in stale_keys:
                del d[k]
                pruned += 1

        # Also forget old cooldown timestamps so this dict can't grow forever
        # on a network with many transient source IPs.
        cutoff = self.cfg["alert_cooldown_seconds"] * 4
        stale_alerts = [k for k, t in self.last_alert.items() if now - t > cutoff]
        for k in stale_alerts:
            del self.last_alert[k]

        if pruned or stale_alerts:
            self.log.info(f"[cleanup] pruned {pruned} idle tracker(s), "
                           f"{len(stale_alerts)} old cooldown entr(y/ies)")

    def heartbeat(self):
        """Prove liveness even when nothing has alerted, so a monitoring
        system (or a human) can tell 'quiet network' apart from 'crashed
        process' just by tailing the log."""
        active = (len(self.tcp_vertical) + len(self.udp_vertical) + len(self.horizontal_activity)
                  + len(self.icmp_activity) + len(self.arp_activity))
        self.log.info(f"[HEARTBEAT] recon-detector alive, tracking {active} active tracker entr(y/ies)")


def build_logger(log_file, quiet):
    logger = logging.getLogger("recon-detector")
    logger.setLevel(logging.INFO)
    # Alert lines are JSON on their own; keep the file free of a prefix so
    # each line is parseable as-is by a JSON log decoder. Non-alert lines
    # (startup banner, heartbeat, cleanup) are plain text with a timestamp.
    fmt = logging.Formatter("%(message)s")

    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    if not quiet:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)

    return logger


def main():
    parser = argparse.ArgumentParser(description="Lightweight network recon detector")
    parser.add_argument("--iface", help="Interface to sniff on (default: scapy's default)")
    parser.add_argument("--config", help="Path to YAML config file (optional)")
    parser.add_argument("--log-file", help="Override alert log file path")
    parser.add_argument("--quiet", action="store_true", help="Don't print alerts to stdout")
    parser.add_argument("--bpf", default="tcp or udp or icmp or arp",
                         help="BPF filter passed to scapy sniff (default: 'tcp or udp or icmp or arp')")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.log_file:
        cfg["log_file"] = args.log_file

    logger = build_logger(cfg["log_file"], args.quiet)
    detector = Detector(cfg, logger)

    def _scan_summary(key):
        s = cfg[key]
        return (f"{key}>={s['distinct_threshold']}/{s['window_seconds']}s "
                f"or >={s['long_window_threshold']}/{s['long_window_seconds']}s")

    parts = [
        _scan_summary("tcp_vertical_scan"),
        _scan_summary("udp_vertical_scan"),
        _scan_summary("horizontal_scan"),
        f"ping_sweep>={cfg['ping_sweep']['distinct_threshold']}/{cfg['ping_sweep']['window_seconds']}s",
        f"arp_scan>={cfg['arp_scan']['distinct_threshold']}/{cfg['arp_scan']['window_seconds']}s",
        f"heartbeat/cleanup every {cfg['heartbeat_interval_seconds']}s",
        f"stale trackers dropped after {cfg['stale_after_seconds']}s idle",
    ]
    logger.info(
        f"{time.strftime('%Y-%m-%d %H:%M:%S')} recon-detector starting on "
        f"iface={args.iface or 'default'} ({', '.join(parts)})"
    )

    # Sniff in fixed-length slices (via scapy's own `timeout`) instead of one
    # unbounded blocking call. This costs nothing extra (no threads, no new
    # dependency) but gives us a reliable clock tick to run heartbeat/cleanup
    # on, even during quiet periods with little or no matching traffic.
    tick = cfg["heartbeat_interval_seconds"]
    try:
        while True:
            sniff(iface=args.iface, filter=args.bpf, prn=detector.handle_packet,
                  store=False, timeout=tick)
            detector.heartbeat()
            detector.cleanup()
    except PermissionError:
        sys.exit("Permission denied: run with sudo (raw sockets require root).")
    except KeyboardInterrupt:
        logger.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} recon-detector stopped.")


if __name__ == "__main__":
    main()
