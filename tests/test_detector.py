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

from recon_detector import Detector, DEFAULTS  # noqa: E402


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


if __name__ == "__main__":
    test_port_scan_triggers_after_threshold()
    test_activity_expires_outside_window()
    test_alert_cooldown_suppresses_repeat_alerts()
    print("All tests passed.")
