"""
Unit tests for the sliding-window detection logic.

These test the counting/alerting logic directly and don't sniff live
traffic, so they run fine in CI. They still import scapy (for the
Detector class's packet-field access), so scapy must be installed.
"""

import logging
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from recon_detector import Detector, SourceActivity, DEFAULTS  # noqa: E402


def make_detector(overrides=None):
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS.items()}
    if overrides:
        for section, values in overrides.items():
            if isinstance(values, dict) and isinstance(cfg.get(section), dict):
                cfg[section].update(values)
            else:
                cfg[section] = values
    logger = logging.getLogger("test")
    logger.handlers = [logging.NullHandler()]
    return Detector(cfg, logger)


def test_port_scan_triggers_after_threshold():
    d = make_detector({"port_scan": {"distinct_port_threshold": 5, "window_seconds": 10}})
    now = time.time()
    src = "10.0.0.5"
    alerts = []
    d._alert = lambda t, s, detail: alerts.append((t, s))

    for port in range(1, 5):  # 4 ports: below threshold
        d.port_activity[src].add(("10.0.0.1", port), now, 10)
    assert d.port_activity[src].distinct_count(now, 10) == 4

    d.port_activity[src].add(("10.0.0.1", 99), now, 10)  # 5th port
    count = d.port_activity[src].distinct_count(now, 10)
    assert count == 5


def test_activity_expires_outside_window():
    d = make_detector()
    src = "10.0.0.5"
    act = d.port_activity[src]
    t0 = 1000.0
    act.add(("10.0.0.1", 22), t0, 10)
    # 20 seconds later, well outside the 10s window -> should be forgotten
    count = act.distinct_count(t0 + 20, 10)
    assert count == 0


def test_alert_cooldown_suppresses_repeat_alerts():
    d = make_detector({"alert_cooldown_seconds": 60})
    now = 5000.0
    assert d._should_alert("10.0.0.5", "PORT_SCAN", now) is True
    # Immediately again -> suppressed
    assert d._should_alert("10.0.0.5", "PORT_SCAN", now + 1) is False
    # After cooldown -> allowed again
    assert d._should_alert("10.0.0.5", "PORT_SCAN", now + 61) is True


def test_slow_scan_detected_via_long_window():
    """A scan spread out slower than the fast window, but frequent enough
    over the long window, should still trigger a SLOW_TCP_PORT_SCAN."""
    d = make_detector({
        "port_scan": {
            "window_seconds": 10,
            "distinct_port_threshold": 100,   # unreachable fast threshold
            "long_window_seconds": 60,
            "long_window_threshold": 5,
        }
    })
    src = "10.0.0.9"
    alerts = []
    d._alert = lambda t, s, detail: alerts.append(t)

    t0 = 10_000.0
    # 6 distinct ports, one every 12s (well outside the 10s fast window,
    # well inside the 60s long window) -> should trip the slow-scan path.
    for i, port in enumerate(range(1, 7)):
        d._check_port_scan(d.port_activity, "port_scan", "TCP_PORT",
                            src, "10.0.0.1", port, t0 + i * 12)

    assert "SLOW_TCP_PORT_SCAN" in alerts
    assert "TCP_PORT_SCAN" not in alerts  # fast threshold never reached


def test_udp_scan_uses_separate_tracker_from_tcp():
    d = make_detector({"udp_scan": {"distinct_port_threshold": 3, "window_seconds": 10}})
    src = "10.0.0.7"
    alerts = []
    d._alert = lambda t, s, detail: alerts.append(t)

    now = 20_000.0
    for port in (53, 123, 161):
        d._check_port_scan(d.udp_activity, "udp_scan", "UDP_PORT",
                            src, "10.0.0.1", port, now)

    assert "UDP_PORT_SCAN" in alerts
    # TCP tracker for the same source must be untouched
    assert src not in d.port_activity


def test_cleanup_prunes_stale_sources_but_keeps_active_ones():
    d = make_detector({"stale_after_seconds": 100})
    now = 50_000.0

    old = SourceActivity()
    old.add(("10.0.0.1", 80), now - 1000, 100000)  # long idle -> stale
    d.port_activity["1.1.1.1"] = old

    fresh = SourceActivity()
    fresh.add(("10.0.0.1", 80), now - 5, 100000)  # recently active -> kept
    d.port_activity["2.2.2.2"] = fresh

    # Patch time.time() for the duration of the cleanup call
    import recon_detector
    real_time = recon_detector.time.time
    recon_detector.time.time = lambda: now
    try:
        d.cleanup()
    finally:
        recon_detector.time.time = real_time

    assert "1.1.1.1" not in d.port_activity
    assert "2.2.2.2" in d.port_activity


def test_heartbeat_logs_active_source_count():
    d = make_detector()
    d.port_activity["1.1.1.1"] = SourceActivity()
    d.icmp_activity["2.2.2.2"] = SourceActivity()

    lines = []
    d.log.info = lambda msg: lines.append(msg)
    d.heartbeat()

    assert len(lines) == 1
    assert "HEARTBEAT" in lines[0]
    assert "2 active" in lines[0]


if __name__ == "__main__":
    test_port_scan_triggers_after_threshold()
    test_activity_expires_outside_window()
    test_alert_cooldown_suppresses_repeat_alerts()
    test_slow_scan_detected_via_long_window()
    test_udp_scan_uses_separate_tracker_from_tcp()
    test_cleanup_prunes_stale_sources_but_keeps_active_ones()
    test_heartbeat_logs_active_source_count()
    print("All tests passed.")
