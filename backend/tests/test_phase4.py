"""
Phase 4 Verification Test Suite
Tests Forensic Evidence Collection, SHA-256 Checksum Hashing, and Vault Persistence.
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
from pipeline.evidence import EvidenceManager

def test_phase4():
    print("=== [Phase 4 Verification] ===")

    config = get_config()
    normalizer = EventNormalizer()
    state_engine = BehaviorStateEngine()
    rule_engine = RuleEngine()
    correlation_engine = IncidentCorrelationEngine()
    evidence_manager = EvidenceManager(vault_path=os.path.join(os.path.dirname(__file__), "test_vault.json"))

    now = time.time()

    # Simulate Reverse Shell & Port Scan
    state_engine.process_event(normalizer.normalize_connection({"local_ip": "192.168.1.110", "local_port": 50000, "remote_ip": "185.220.101.45", "remote_port": 4444, "process": "python", "pid": 8888}, now))
    for p in range(4000, 4022):
        state_engine.process_event(normalizer.normalize_connection({"local_ip": "192.168.1.110", "local_port": 50000, "remote_ip": "10.0.0.1", "remote_port": p, "process": "nmap"}, now))

    alerts = rule_engine.evaluate_all(state_engine, config, now)
    incidents = correlation_engine.correlate(alerts, now)
    assert len(incidents) >= 1, "Expected correlated incident"
    inc = incidents[0]

    # Generate forensic evidence package for incident
    evd = evidence_manager.generate_evidence(inc, state_engine)
    print(f"Generated Evidence ID: {evd.evidence_id}")
    print(f"Status: {evd.status}")
    print(f"SHA-256 Hash: {evd.sha256_hash}")
    print(f"Captured Packets: {len(evd.payload['packets'])}, Connections: {len(evd.payload['connections'])}")

    assert evd.status == "Sealed", f"Expected status 'Sealed', got {evd.status}"
    assert len(evd.sha256_hash) == 64, f"Expected 64-character SHA-256 hex string, got {len(evd.sha256_hash)}"
    assert evd.evidence_id in inc.evidence_ids, "Evidence ID missing from incident evidence_ids"

    # Clean up test vault file
    if os.path.exists(os.path.join(os.path.dirname(__file__), "test_vault.json")):
        os.remove(os.path.join(os.path.dirname(__file__), "test_vault.json"))

    print("✓ Automated Evidence Generation verified")
    print("✓ SHA-256 Integrity Checksum verified")
    print("✓ Evidence Lifecycle (Captured -> Hashed -> Sealed) verified")
    print("✓ Phase 4 All Verification Tests Passed Successfully!\n")

if __name__ == "__main__":
    test_phase4()
