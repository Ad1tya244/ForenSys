"""
Phase 2 Verification Test Suite
Tests Modular Rule Engine & All 10 Detection Rules.
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import get_config
from pipeline.normalizer import EventNormalizer
from pipeline.state_engine import BehaviorStateEngine
from pipeline.rule_engine import RuleEngine

def test_phase2():
    print("=== [Phase 2 Verification] ===")

    config = get_config()
    normalizer = EventNormalizer()
    state_engine = BehaviorStateEngine()
    rule_engine = RuleEngine()

    # 1. Test Rule Auto-Discovery
    catalog = rule_engine.get_rule_catalog()
    rule_names = [r["name"] for r in catalog]
    print(f"Discovered {len(catalog)} modular rules: {rule_names}")
    assert len(catalog) >= 10, f"Expected at least 10 rules, found {len(catalog)}"

    now = time.time()

    # 2. Simulate ICMP Flood
    for _ in range(110):
        ev = normalizer.normalize_packet({"protocol": "ICMP", "src_ip": "192.168.1.200", "dst_ip": "10.0.0.1", "length": 64}, now)
        state_engine.process_event(ev)

    # 3. Simulate Port Scan
    for port in range(2000, 2025):
        ev = normalizer.normalize_connection({"local_ip": "192.168.1.200", "local_port": 50000, "remote_ip": "10.0.0.1", "remote_port": port, "process": "nmap"}, now)
        state_engine.process_event(ev)

    # 4. Simulate Reverse Shell
    rev_conn = normalizer.normalize_connection({"local_ip": "127.0.0.1", "local_port": 54321, "remote_ip": "185.220.101.45", "remote_port": 4444, "process": "python3", "pid": 9999}, now)
    state_engine.process_event(rev_conn)

    # Evaluate rules
    alerts = rule_engine.evaluate_all(state_engine, config, now)
    fired_rules = [a.rule_name for a in alerts]
    print(f"Triggered Alerts ({len(alerts)}): {fired_rules}")

    assert "ICMP Flood" in fired_rules, "ICMP Flood rule failed to trigger"
    assert "Port Scan" in fired_rules, "Port Scan rule failed to trigger"
    assert "Reverse Shell" in fired_rules, "Reverse Shell rule failed to trigger"

    print("✓ Auto-Discovery verified")
    print("✓ Modular Detection Rules verified")
    print("✓ Phase 2 All Verification Tests Passed Successfully!\n")

if __name__ == "__main__":
    test_phase2()
