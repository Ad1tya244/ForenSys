"""
Phase 3 Verification Test Suite
Tests Incident Correlation Engine, Cumulative Scoring, and MITRE Kill Chain Mapping.
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import get_config
from pipeline.normalizer import EventNormalizer
from pipeline.state_engine import BehaviorStateEngine
from pipeline.rule_engine import RuleEngine
from pipeline.correlation_engine import IncidentCorrelationEngine

def test_phase3():
    print("=== [Phase 3 Verification] ===")

    config = get_config()
    normalizer = EventNormalizer()
    state_engine = BehaviorStateEngine()
    rule_engine = RuleEngine()
    correlation_engine = IncidentCorrelationEngine()

    now = time.time()

    # 1. Simulate ICMP Flood from 192.168.1.105 (Score: 20)
    for _ in range(110):
        state_engine.process_event(normalizer.normalize_packet({"protocol": "ICMP", "src_ip": "192.168.1.105", "dst_ip": "10.0.0.1", "length": 64}, now))

    # 2. Simulate Port Scan from 192.168.1.105 (Score: 30)
    for p in range(3000, 3025):
        state_engine.process_event(normalizer.normalize_connection({"local_ip": "192.168.1.105", "local_port": 50000, "remote_ip": "10.0.0.1", "remote_port": p, "process": "nmap"}, now))

    # 3. Simulate Reverse Shell from python to 185.220.101.45:4444 (Score: 80)
    state_engine.process_event(normalizer.normalize_connection({"local_ip": "192.168.1.105", "local_port": 54321, "remote_ip": "185.220.101.45", "remote_port": 4444, "process": "python", "pid": 7777}, now))

    # Run detection rules
    alerts = rule_engine.evaluate_all(state_engine, config, now)
    print(f"Generated {len(alerts)} alerts for entity 192.168.1.105")

    # Correlate alerts into single incident
    incidents = correlation_engine.correlate(alerts, now)
    print(f"Correlated into {len(incidents)} Incident(s)")

    assert len(incidents) >= 1, "Expected at least 1 correlated incident"
    inc = incidents[0]
    
    print(f"Incident ID: {inc.id}")
    print(f"Title: {inc.title}")
    print(f"Risk Score: {inc.risk_score} (Severity: {inc.severity})")
    print(f"MITRE Stages: {inc.mitre_stages}")
    print(f"Timeline entries: {len(inc.timeline)}")

    assert inc.risk_score >= 130, f"Expected cumulative risk score >= 130, got {inc.risk_score}"
    assert inc.severity == "critical", f"Expected severity 'critical', got {inc.severity}"
    assert len(inc.mitre_stages) >= 2, "Expected multiple MITRE stages"

    print("✓ Alert Correlation into Single Incident verified")
    print("✓ Cumulative Risk Scoring & Severity Mapping verified")
    print("✓ MITRE ATT&CK Kill Chain Synthesis verified")
    print("✓ Phase 3 All Verification Tests Passed Successfully!\n")

if __name__ == "__main__":
    test_phase3()
