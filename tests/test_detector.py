"""
Unit tests for the sliding-window detection logic.

These test the counting/alerting logic directly and don't sniff live
traffic, so they run fine in CI. They still import scapy (for the
Detector class's packet-field access), so scapy must be installed.
"""

import json
import logging
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from recon_detector import DEFAULTS, Detector, SourceActivity, load_config


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


def test_vertical_scan_triggers_on_many_ports_one_dest():
    """Many ports hit on a SINGLE destination -> vertical scan."""
    d = make_detector({"tcp_vertical_scan": {"distinct_threshold": 5, "window_seconds": 10}})
    now = time.time()
    src, dst = "10.0.0.5", "10.0.0.1"
    alerts = []
    d._alert = lambda t, s, detail: alerts.append((t, detail))

    for port in range(1, 6):  # 5 distinct ports on the same dst
        d._check_scan(d.tcp_vertical, (src, dst), port, d.cfg["tcp_vertical_scan"], src,
                      "TCP_VERTICAL_SCAN", "SLOW_TCP_VERTICAL_SCAN", now,
                      {"destination_ip": dst, "protocol": "TCP"})

    assert any(t == "TCP_VERTICAL_SCAN" for t, _ in alerts)
    _alert_type, detail = alerts[0]
    assert detail["destination_ip"] == dst
    assert detail["count"] == 5


def test_horizontal_scan_triggers_on_many_dests_not_vertical():
    """One port hit on MANY distinct destinations -> horizontal, not vertical."""
    d = make_detector({"horizontal_scan": {"distinct_threshold": 4, "window_seconds": 10},
                        "tcp_vertical_scan": {"distinct_threshold": 100}})  # unreachable
    now = time.time()
    src = "10.0.0.5"
    alerts = []
    d._alert = lambda t, s, detail: alerts.append(t)

    for i in range(4):
        dst = f"10.0.0.{i+1}"
        d._check_scan(d.tcp_vertical, (src, dst), 80, d.cfg["tcp_vertical_scan"], src,
                      "TCP_VERTICAL_SCAN", "SLOW_TCP_VERTICAL_SCAN", now, {"destination_ip": dst})
        d._check_scan(d.horizontal_activity, src, dst, d.cfg["horizontal_scan"], src,
                      "HORIZONTAL_SCAN", "SLOW_HORIZONTAL_SCAN", now, {"protocol": "TCP"})

    assert "HORIZONTAL_SCAN" in alerts
    assert "TCP_VERTICAL_SCAN" not in alerts  # each dst only hit once -> not vertical


def test_activity_expires_outside_window():
    act = SourceActivity()
    t0 = 1000.0
    act.add(("10.0.0.1", 22), t0, 10)
    # 20 seconds later, well outside the 10s window -> should be forgotten
    count = act.distinct_count(t0 + 20, 10)
    assert count == 0


def test_alert_cooldown_suppresses_repeat_alerts():
    d = make_detector({"alert_cooldown_seconds": 60})
    now = 5000.0
    assert d._should_alert("10.0.0.5", "TCP_VERTICAL_SCAN", now) is True
    assert d._should_alert("10.0.0.5", "TCP_VERTICAL_SCAN", now + 1) is False
    assert d._should_alert("10.0.0.5", "TCP_VERTICAL_SCAN", now + 61) is True


def test_slow_vertical_scan_detected_via_long_window():
    d = make_detector({
        "tcp_vertical_scan": {
            "window_seconds": 10,
            "distinct_threshold": 100,   # unreachable fast threshold
            "long_window_seconds": 60,
            "long_window_threshold": 5,
        }
    })
    src, dst = "10.0.0.9", "10.0.0.1"
    alerts = []
    d._alert = lambda t, s, detail: alerts.append(t)

    t0 = 10_000.0
    for i, port in enumerate(range(1, 7)):  # one port every 12s -> outside fast, inside long
        d._check_scan(d.tcp_vertical, (src, dst), port, d.cfg["tcp_vertical_scan"], src,
                      "TCP_VERTICAL_SCAN", "SLOW_TCP_VERTICAL_SCAN", t0 + i * 12,
                      {"destination_ip": dst})

    assert "SLOW_TCP_VERTICAL_SCAN" in alerts
    assert "TCP_VERTICAL_SCAN" not in alerts


def test_alert_emits_valid_json_with_expected_fields():
    d = make_detector()
    lines = []
    d.log.warning = lambda msg: lines.append(msg)

    d._alert("TCP_VERTICAL_SCAN", "10.0.0.5", {
        "destination_ip": "10.0.0.1", "protocol": "TCP", "count": 20,
        "window_seconds": 10, "sample": [80, 443],
    })

    assert len(lines) == 1
    payload = json.loads(lines[0])  # must parse as valid JSON
    for field in ("timestamp", "alert_type", "source_ip", "severity",
                  "destination_ip", "protocol", "count", "window_seconds"):
        assert field in payload
    assert payload["alert_type"] == "TCP_VERTICAL_SCAN"
    assert payload["severity"] == "high"


def test_cleanup_prunes_stale_sources_but_keeps_active_ones():
    d = make_detector({"stale_after_seconds": 100})
    now = 50_000.0

    old = SourceActivity()
    old.add(("10.0.0.1", 80), now - 1000, 100000)
    d.tcp_vertical[("1.1.1.1", "10.0.0.1")] = old

    fresh = SourceActivity()
    fresh.add(("10.0.0.1", 80), now - 5, 100000)
    d.tcp_vertical[("2.2.2.2", "10.0.0.1")] = fresh

    import recon_detector
    real_time = recon_detector.time.time
    recon_detector.time.time = lambda: now
    try:
        d.cleanup()
    finally:
        recon_detector.time.time = real_time

    assert ("1.1.1.1", "10.0.0.1") not in d.tcp_vertical
    assert ("2.2.2.2", "10.0.0.1") in d.tcp_vertical


def test_heartbeat_logs_active_tracker_count():
    d = make_detector()
    d.tcp_vertical[("1.1.1.1", "10.0.0.1")] = SourceActivity()
    d.icmp_activity["2.2.2.2"] = SourceActivity()

    lines = []
    d.log.info = lambda msg: lines.append(msg)
    d.heartbeat()

    assert len(lines) == 1
    assert "HEARTBEAT" in lines[0]
    assert "2 active" in lines[0]


def test_load_config_rejects_non_mapping_yaml_cleanly():
    """A config file whose top-level content isn't a mapping (a plain
    string, list, or number - e.g. a corrupted file or a typo pointing
    at the wrong file), or that isn't valid YAML at all, must fail with
    a clear, handled error, not an unhandled exception. Found via
    fuzzing prep, not by inspection - see fuzz/fuzz_config.py."""
    import tempfile

    bad_inputs = (
        "just a string",
        "- a\n- list\n",
        "42",
        "key: [unclosed bracket\n  nested: :bad:\n",  # malformed YAML syntax
    )
    for content in bad_inputs:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            with pytest.raises(SystemExit):
                load_config(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    test_vertical_scan_triggers_on_many_ports_one_dest()
    test_horizontal_scan_triggers_on_many_dests_not_vertical()
    test_activity_expires_outside_window()
    test_alert_cooldown_suppresses_repeat_alerts()
    test_slow_vertical_scan_detected_via_long_window()
    test_alert_emits_valid_json_with_expected_fields()
    test_cleanup_prunes_stale_sources_but_keeps_active_ones()
    test_heartbeat_logs_active_tracker_count()
    test_load_config_rejects_non_mapping_yaml_cleanly()
    print("All tests passed.")
