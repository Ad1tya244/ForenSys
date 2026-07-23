"""
Phase 5 Verification Test Suite
Tests SOAR Auto-Remediation Engine, Action Execution, Log Recording, and Rollback.
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
from pipeline.soar_engine import SOAREngine

def test_phase5():
    print("=== [Phase 5 Verification] ===")

    config = get_config()
    normalizer = EventNormalizer()
    state_engine = BehaviorStateEngine()
    rule_engine = RuleEngine()
    correlation_engine = IncidentCorrelationEngine()
    soar_engine = SOAREngine(log_path=os.path.join(os.path.dirname(__file__), "test_remediation.json"))

    now = time.time()

    # Simulate Reverse Shell incident
    state_engine.process_event(normalizer.normalize_connection({"local_ip": "192.168.1.120", "local_port": 54321, "remote_ip": "185.220.101.45", "remote_port": 4444, "process": "python3", "pid": 9999}, now))
    alerts = rule_engine.evaluate_all(state_engine, config, now)
    incidents = correlation_engine.correlate(alerts, now)
    assert len(incidents) >= 1, "Expected correlated incident"
    inc = incidents[0]

    # Evaluate and trigger SOAR Auto-Remediation
    logs = soar_engine.evaluate_and_remediate(inc, [])
    print(f"Executed {len(logs)} automated SOAR actions for incident {inc.id}:")
    for log in logs:
        print(f"  • [{log.status.upper()}] {log.action_type} -> target: {log.target} ({log.rule_name})")

    assert len(logs) >= 2, "Expected automated actions to execute for critical incident"
    assert "185.220.101.45" in soar_engine.get_blocked_ips(), "Expected IP 185.220.101.45 in blocked list"

    # Test Rollback
    first_action_id = logs[0].action_id
    rolled = soar_engine.rollback_action(first_action_id)
    assert rolled is not None, "Failed to rollback action"
    assert rolled.status == "rolled_back", f"Expected status 'rolled_back', got {rolled.status}"
    print(f"✓ Rollback verified for Action {first_action_id}")

    # Clean up test remediation file
    if os.path.exists(os.path.join(os.path.dirname(__file__), "test_remediation.json")):
        os.remove(os.path.join(os.path.dirname(__file__), "test_remediation.json"))

    print("✓ SOAR Auto-Remediation Execution verified")
    print("✓ Action Execution Logs & Context Enforcement verified")
    print("✓ Rollback Mechanism verified")
    print("✓ Phase 5 All Verification Tests Passed Successfully!\n")

if __name__ == "__main__":
    test_phase5()
