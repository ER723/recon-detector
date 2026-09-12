#!/usr/bin/env python3
"""
recon-detector: a lightweight, dependency-light network reconnaissance detector.

Detects, in real time, the noisy pre-attack behaviors an attacker generates
while mapping a network:

  - TCP port scans      (many distinct ports on one host from one source)
  - UDP port scans      (same, over UDP)
  - ICMP ping sweeps    (many distinct hosts pinged by one source, fast)
  - ARP scans           (many ARP "who-has" requests from one source, fast)

Both TCP and UDP scan detection use TWO sliding windows per source:
  - a short window, tuned to catch fast/default-speed scans (e.g. nmap -T4)
  - a long window with a higher count but looser rate, tuned to catch
    slow/stealthy scans (e.g. nmap -T0/-T1) that spread probes out to
    stay under a short-window threshold

Design goals (deliberately kept simple so it runs happily on a VM with
8GB RAM and a single CPU core, with no external services and no cost):
  - Single Python file, one third-party dependency (scapy).
  - In-memory sliding-window counters, no database, no message queue.
  - A fixed-cadence loop (driven by scapy's own `timeout`, no extra threads)
    periodically prunes idle source trackers so memory stays bounded on a
    box that runs for weeks, and emits a heartbeat log line so "no alerts"
    can be told apart from "the detector silently died."
  - Alerts are appended to a plain-text log (and optionally printed live),
    so they can be tailed by OSSEC / Wazuh as a custom log source.

Usage:
    sudo python3 recon_detector.py --iface eth0
    sudo python3 recon_detector.py --iface eth0 --config config.yaml

Run `python3 recon_detector.py -h` for all options.
"""

import argparse
import sys
import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
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
    "port_scan": {
        "window_seconds": 10,            # fast-scan window
        "distinct_port_threshold": 15,   # unique dst ports from one src -> alert
        "long_window_seconds": 300,      # slow-scan window (5 min)
        "long_window_threshold": 30,     # unique dst ports over the long window -> alert
    },
    "udp_scan": {
        "window_seconds": 10,
        "distinct_port_threshold": 15,
        "long_window_seconds": 300,
        "long_window_threshold": 30,
    },
    "ping_sweep": {
        "window_seconds": 10,
        "distinct_host_threshold": 10,  # unique dst IPs pinged by one src -> alert
    },
    "arp_scan": {
        "window_seconds": 10,
        "distinct_host_threshold": 10,  # unique ARP targets from one src -> alert
    },
    "alert_cooldown_seconds": 60,      # don't re-alert on the same src+type for this long
    "log_file": "recon_alerts.log",
    "stale_after_seconds": 600,        # drop a source's tracker after this long idle
    "heartbeat_interval_seconds": 300, # log a heartbeat + run cleanup this often
}


def load_config(path):
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS.items()}
    if path:
        if not HAVE_YAML:
            sys.exit("pyyaml not installed; run: pip3 install pyyaml")
        with open(path) as f:
            user_cfg = yaml.safe_load(f) or {}
        for section, values in user_cfg.items():
            if isinstance(values, dict) and section in cfg:
                cfg[section].update(values)
            else:
                cfg[section] = values
    return cfg


# --------------------------------------------------------------------------
# Sliding-window tracker: for a given source, remembers (timestamp, item)
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

    def last_seen(self):
        return self.events[-1][0] if self.events else 0.0

    def is_stale(self, now, stale_after):
        return not self.events or (now - self.last_seen() > stale_after)


class Detector:
    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.log = logger
        self.port_activity = defaultdict(SourceActivity)   # src_ip -> (dst,port) touched (TCP)
        self.udp_activity = defaultdict(SourceActivity)    # src_ip -> (dst,port) touched (UDP)
        self.icmp_activity = defaultdict(SourceActivity)   # src_ip -> hosts pinged
        self.arp_activity = defaultdict(SourceActivity)    # src_ip -> hosts arp'd
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
        msg = f"[ALERT] {alert_type} from {src} - {detail}"
        self.log.warning(msg)

    # -- scan-family helper (shared by TCP and UDP port scans) --------

    def _check_port_scan(self, activity_dict, cfg_key, alert_prefix, src, dst, dport, now, extra=""):
        cfg = self.cfg[cfg_key]
        max_window = max(cfg["window_seconds"], cfg["long_window_seconds"])
        act = activity_dict[src]
        act.add((dst, dport), now, max_window)

        fast_count = act.distinct_count(now, cfg["window_seconds"])
        if fast_count >= cfg["distinct_port_threshold"] and self._should_alert(src, f"{alert_prefix}_SCAN", now):
            self._alert(f"{alert_prefix}_SCAN", src,
                        f"{fast_count} distinct dst ports in {cfg['window_seconds']}s{extra}")
            return

        # Only check the slow-scan window if the fast one didn't just fire,
        # so a fast scan isn't double-reported as slow too.
        long_count = act.distinct_count(now, cfg["long_window_seconds"])
        if long_count >= cfg["long_window_threshold"] and self._should_alert(src, f"SLOW_{alert_prefix}_SCAN", now):
            self._alert(f"SLOW_{alert_prefix}_SCAN", src,
                        f"{long_count} distinct dst ports over {cfg['long_window_seconds']}s "
                        f"(stealthy/slow-timed scan pattern){extra}")

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
            if count >= cfg["distinct_host_threshold"] and self._should_alert(src, "ARP_SCAN", now):
                self._alert("ARP_SCAN", src,
                             f"{count} distinct hosts probed in {cfg['window_seconds']}s")
            return

        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        dst = pkt[IP].dst

        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            self._check_port_scan(self.port_activity, "port_scan", "TCP_PORT",
                                   src, dst, pkt[TCP].dport, now, extra=f" (last flags={flags})")

        elif pkt.haslayer(UDP):
            self._check_port_scan(self.udp_activity, "udp_scan", "UDP_PORT",
                                   src, dst, pkt[UDP].dport, now)

        elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # echo-request
            cfg = self.cfg["ping_sweep"]
            act = self.icmp_activity[src]
            act.add(dst, now, cfg["window_seconds"])
            count = act.distinct_count(now, cfg["window_seconds"])
            if count >= cfg["distinct_host_threshold"] and self._should_alert(src, "PING_SWEEP", now):
                self._alert("PING_SWEEP", src,
                             f"{count} distinct hosts pinged in {cfg['window_seconds']}s")

    # -- production-readiness maintenance -------------------------------

    def cleanup(self):
        """Drop trackers for sources that have gone quiet, so memory stays
        bounded on a box that runs for weeks rather than a demo session."""
        now = time.time()
        stale_after = self.cfg["stale_after_seconds"]
        pruned = 0
        for d in (self.port_activity, self.udp_activity, self.icmp_activity, self.arp_activity):
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
            self.log.info(f"[cleanup] pruned {pruned} idle source tracker(s), "
                           f"{len(stale_alerts)} old cooldown entr(y/ies)")

    def heartbeat(self):
        """Prove liveness even when nothing has alerted, so a monitoring
        system (or a human) can tell 'quiet network' apart from 'crashed
        process' just by tailing the log."""
        active = (len(self.port_activity) + len(self.udp_activity)
                  + len(self.icmp_activity) + len(self.arp_activity))
        self.log.info(f"[HEARTBEAT] recon-detector alive, tracking {active} active source entr(y/ies)")


def build_logger(log_file, quiet):
    logger = logging.getLogger("recon-detector")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

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

    logger.info(
        f"recon-detector starting on iface={args.iface or 'default'} "
        f"(tcp_scan>={cfg['port_scan']['distinct_port_threshold']}/{cfg['port_scan']['window_seconds']}s "
        f"or >={cfg['port_scan']['long_window_threshold']}/{cfg['port_scan']['long_window_seconds']}s, "
        f"udp_scan>={cfg['udp_scan']['distinct_port_threshold']}/{cfg['udp_scan']['window_seconds']}s "
        f"or >={cfg['udp_scan']['long_window_threshold']}/{cfg['udp_scan']['long_window_seconds']}s, "
        f"ping_sweep>={cfg['ping_sweep']['distinct_host_threshold']}/{cfg['ping_sweep']['window_seconds']}s, "
        f"arp_scan>={cfg['arp_scan']['distinct_host_threshold']}/{cfg['arp_scan']['window_seconds']}s, "
        f"heartbeat/cleanup every {cfg['heartbeat_interval_seconds']}s, "
        f"stale trackers dropped after {cfg['stale_after_seconds']}s idle)"
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
        logger.info("recon-detector stopped.")


if __name__ == "__main__":
    main()
