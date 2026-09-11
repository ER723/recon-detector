#!/usr/bin/env python3
"""
recon-detector: a lightweight, dependency-light network reconnaissance detector.

Detects, in real time, the noisy pre-attack behaviors an attacker generates
while mapping a network:

  - TCP port scans   (many distinct ports on one host from one source, fast)
  - ICMP ping sweeps (many distinct hosts pinged by one source, fast)
  - ARP scans        (many ARP "who-has" requests from one source, fast)

Design goals (deliberately kept simple so it runs happily on a VM with
8GB RAM and a single CPU core):
  - Single Python file, one third-party dependency (scapy).
  - In-memory sliding-window counters, no database, no message queue.
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
    from scapy.all import sniff, IP, TCP, ICMP, ARP
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
        "window_seconds": 10,   # sliding window to count activity in
        "distinct_port_threshold": 15,  # unique dst ports from one src -> alert
    },
    "ping_sweep": {
        "window_seconds": 10,
        "distinct_host_threshold": 10,  # unique dst IPs pinged by one src -> alert
    },
    "arp_scan": {
        "window_seconds": 10,
        "distinct_host_threshold": 10,  # unique ARP targets from one src -> alert
    },
    "alert_cooldown_seconds": 60,  # don't re-alert on the same src+type for this long
    "log_file": "recon_alerts.log",
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
# --------------------------------------------------------------------------

@dataclass
class SourceActivity:
    events: deque = field(default_factory=deque)  # (timestamp, item)

    def add(self, item, now, window):
        self.events.append((now, item))
        self._trim(now, window)

    def _trim(self, now, window):
        while self.events and now - self.events[0][0] > window:
            self.events.popleft()

    def distinct_count(self, now, window):
        self._trim(now, window)
        return len({item for _, item in self.events})


class Detector:
    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.log = logger
        self.port_activity = defaultdict(SourceActivity)   # src_ip -> ports touched
        self.icmp_activity = defaultdict(SourceActivity)   # src_ip -> hosts pinged
        self.arp_activity = defaultdict(SourceActivity)    # src_ip -> hosts arp'd
        self.last_alert = {}  # (src, alert_type) -> timestamp

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

        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            # SYN (scan probe) or SYN+ACK-less connect attempts both count;
            # we key on any packet toward a new dst port.
            cfg = self.cfg["port_scan"]
            act = self.port_activity[src]
            act.add((pkt[IP].dst, dport), now, cfg["window_seconds"])
            count = act.distinct_count(now, cfg["window_seconds"])
            if count >= cfg["distinct_port_threshold"] and self._should_alert(src, "PORT_SCAN", now):
                self._alert("PORT_SCAN", src,
                             f"{count} distinct dst ports in {cfg['window_seconds']}s "
                             f"(last flags={flags})")

        elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # echo-request
            cfg = self.cfg["ping_sweep"]
            act = self.icmp_activity[src]
            act.add(pkt[IP].dst, now, cfg["window_seconds"])
            count = act.distinct_count(now, cfg["window_seconds"])
            if count >= cfg["distinct_host_threshold"] and self._should_alert(src, "PING_SWEEP", now):
                self._alert("PING_SWEEP", src,
                             f"{count} distinct hosts pinged in {cfg['window_seconds']}s")


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
    parser.add_argument("--bpf", default="tcp or icmp or arp",
                         help="BPF filter passed to scapy sniff (default: 'tcp or icmp or arp')")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.log_file:
        cfg["log_file"] = args.log_file

    logger = build_logger(cfg["log_file"], args.quiet)
    detector = Detector(cfg, logger)

    logger.info(f"recon-detector starting on iface={args.iface or 'default'} "
                f"(port_scan>={cfg['port_scan']['distinct_port_threshold']}/"
                f"{cfg['port_scan']['window_seconds']}s, "
                f"ping_sweep>={cfg['ping_sweep']['distinct_host_threshold']}/"
                f"{cfg['ping_sweep']['window_seconds']}s, "
                f"arp_scan>={cfg['arp_scan']['distinct_host_threshold']}/"
                f"{cfg['arp_scan']['window_seconds']}s)")

    try:
        sniff(iface=args.iface, filter=args.bpf, prn=detector.handle_packet, store=False)
    except PermissionError:
        sys.exit("Permission denied: run with sudo (raw sockets require root).")
    except KeyboardInterrupt:
        logger.info("recon-detector stopped.")


if __name__ == "__main__":
    main()
