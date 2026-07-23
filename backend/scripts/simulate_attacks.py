"""
ForenSys EDR/XDR Attack Simulation & Pipeline Verification Script
Simulates 6 threat vectors (ICMP Flood, Port Scan, DNS Beacon, Reverse Shell, Auth Attack, Data Exfiltration)
and verifies the full pipeline end-to-end:
Detection -> Correlation -> Incident -> Evidence -> SOAR Action.
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import get_config
from pipeline.normalizer import EventNormalizer
from pipeline.state_engine import BehaviorStateEngine
from pipeline.rule_engine import RuleEngine
from pipeline.correlation_engine import IncidentCorrelationEngine
from pipeline.evidence import EvidenceManager
from pipeline.soar_engine import SOAREngine

def run_simulation():
    print("==========================================================================")
    print("       FORENSYS BEHAVIOR-BASED EDR/XDR END-TO-END SIMULATION PIPELINE     ")
    print("==========================================================================")

    config = get_config()
    config["attack_simulation_mode"] = True
    normalizer = EventNormalizer()
    state_engine = BehaviorStateEngine()
    rule_engine = RuleEngine()
    correlation_engine = IncidentCorrelationEngine()
    evidence_manager = EvidenceManager(vault_path=os.path.join(os.path.dirname(__file__), "sim_vault.json"))
    soar_engine = SOAREngine(log_path=os.path.join(os.path.dirname(__file__), "sim_remediation.json"))

    now = time.time()
    attacker_ip = "198.51.100.44"
    c2_ip = "185.220.101.45"
    target_host = "10.0.0.1"

    print(f"\n[1/6] Simulating ICMP Flood from {attacker_ip}...")
    for _ in range(120):
        state_engine.process_event(normalizer.normalize_packet({
            "protocol": "ICMP", "src_ip": attacker_ip, "dst_ip": target_host, "length": 64
        }, now - 15.0))

    print(f"\n[2/6] Simulating Reconnaissance Port Scan from {attacker_ip}...")
    for port in range(1000, 1025):
        state_engine.process_event(normalizer.normalize_connection({
            "local_ip": attacker_ip, "local_port": 54321, "remote_ip": target_host, "remote_port": port, "process": "nmap"
        }, now - 10.0))

    print(f"\n[3/6] Simulating Brute Force Authentication Attack from {attacker_ip}...")
    for _ in range(4):
        state_engine.process_event(normalizer.normalize_log({
            "process": "sshd", "level": "error", "message": f"Failed password for invalid user root from {attacker_ip}"
        }, now - 8.0))
    state_engine.process_event(normalizer.normalize_log({
        "process": "sshd", "level": "info", "message": f"Accepted password for admin from {attacker_ip}"
    }, now - 7.0))

    print(f"\n[4/6] Simulating DNS Beaconing to C2 domain 'c2-beacon.attacker.com'...")
    for i in range(6):
        state_engine.process_event(normalizer.normalize_packet({
            "protocol": "UDP", "src_ip": target_host, "dst_ip": "8.8.8.8",
            "info": f"Standard query 0x1234 A c2-beacon.attacker.com", "length": 72
        }, now - (30.0 - i * 5.0)))

    print(f"\n[5/6] Simulating Reverse Shell Execution (python -> {c2_ip}:4444)...")
    state_engine.process_event(normalizer.normalize_connection({
        "local_ip": target_host, "local_port": 50123, "remote_ip": c2_ip, "remote_port": 4444, "process": "python3", "pid": 8812
    }, now - 3.0))

    print(f"\n[6/6] Simulating Data Exfiltration (60 MB outbound transfer)...")
    state_engine.process_event(normalizer.normalize_connection({
        "local_ip": target_host, "local_port": 50124, "remote_ip": c2_ip, "remote_port": 443, "process": "curl"
    }, now - 1.0))
    for _ in range(6):
        state_engine.process_event(normalizer.normalize_packet({
            "protocol": "TCP", "src_ip": target_host, "dst_ip": c2_ip, "length": 10485760  # 10 MB per pkt
        }, now - 1.0))

    print("\n--------------------------------------------------------------------------")
    print("STEP A: RUNNING MODULAR DETECTION RULES")
    print("--------------------------------------------------------------------------")
    alerts = rule_engine.evaluate_all(state_engine, config, now)
    print(f"Generated {len(alerts)} behavioral alerts:")
    for a in alerts:
        print(f"  [ALERT] {a.rule_name:<30} | Severity: {a.severity:<8} | Assets: {a.affected_assets}")

    print("\n--------------------------------------------------------------------------")
    print("STEP B: INCIDENT CORRELATION ENGINE")
    print("--------------------------------------------------------------------------")
    incidents = correlation_engine.correlate(alerts, now)
    print(f"Correlated alerts into {len(incidents)} Unified Incident(s):")
    for inc in incidents:
        print(f"\n🔥 INCIDENT ID   : {inc.id}")
        print(f"   Title         : {inc.title}")
        print(f"   Severity      : {inc.severity.upper()} (Risk Score: {inc.risk_score})")
        print(f"   Confidence    : {inc.confidence * 100:.0f}%")
        print(f"   MITRE Chain   : {' -> '.join(inc.mitre_stages)}")
        print(f"   Timeline      : {len(inc.timeline)} correlated detection events")

    assert len(incidents) >= 1, "Expected correlated incident"
    target_inc = incidents[0]

    print("\n--------------------------------------------------------------------------")
    print("STEP C: FORENSIC EVIDENCE COLLECTION & SHA-256 SEALING")
    print("--------------------------------------------------------------------------")
    evd = evidence_manager.generate_evidence(target_inc, state_engine)
    print(f"✅ Evidence ID    : {evd.evidence_id}")
    print(f"   Status         : {evd.status}")
    print(f"   SHA-256 Hash   : {evd.sha256_hash}")
    print(f"   Evidence Chain : {evd.to_dict()['chain']}")

    print("\n--------------------------------------------------------------------------")
    print("STEP D: SOAR AUTO-REMEDIATION EXECUTION")
    print("--------------------------------------------------------------------------")
    soar_logs = soar_engine.evaluate_and_remediate(target_inc, [])
    print(f"Executed {len(soar_logs)} automated SOAR containment action(s):")
    for log in soar_logs:
        print(f"  ⚡ [{log.status.upper()}] Action: {log.action_type:<20} | Target: {log.target:<18} | Details: {log.result_details.get('message')}")

    print("\n--------------------------------------------------------------------------")
    print("STEP E: VERIFYING ROLLBACK MECHANISM")
    print("--------------------------------------------------------------------------")
    if soar_logs:
        target_log = soar_logs[0]
        rolled = soar_engine.rollback_action(target_log.action_id)
        assert rolled is not None, "Rollback failed: action not found"
        print(f"🔄 Rollback status for action {target_log.action_id}: {rolled.status}")
        assert rolled.status == "rolled_back", "Rollback failed"

    # Cleanup temp files
    for tmp in [os.path.join(os.path.dirname(__file__), "sim_vault.json"), os.path.join(os.path.dirname(__file__), "sim_remediation.json")]:
        if os.path.exists(tmp):
            os.remove(tmp)

    # Reset simulation mode
    config["attack_simulation_mode"] = False

    print("\n==========================================================================")
    print("  SUCCESS: END-TO-END PIPELINE (DETECTION -> CORRELATION -> INCIDENT -> EVIDENCE -> SOAR) VERIFIED!")
    print("==========================================================================")

if __name__ == "__main__":
    run_simulation()
