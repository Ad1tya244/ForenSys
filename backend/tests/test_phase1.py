"""
Phase 1 Verification Test Suite
Tests Event Normalizer, Behavior State Engine, and Config Engine.
"""

import sys
import os
import time

# Add backend directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import get_config, update_config
from pipeline.normalizer import EventNormalizer, NormalizedEvent
from pipeline.state_engine import BehaviorStateEngine

def test_phase1():
    print("=== [Phase 1 Verification] ===")

    # 1. Config Test
    cfg = get_config()
    assert "icmp_threshold" in cfg, "Config missing icmp_threshold"
    assert cfg["icmp_threshold"] == 100, f"Expected icmp_threshold 100, got {cfg['icmp_threshold']}"
    print("✓ Configuration Engine verified")

    # 2. Normalizer Test
    normalizer = EventNormalizer()
    now = time.time()
    
    pkt = {"protocol": "ICMP", "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "length": 64}
    norm_pkt = normalizer.normalize_packet(pkt, now)
    assert norm_pkt.event_type == "PACKET"
    assert norm_pkt.protocol == "ICMP"
    assert norm_pkt.src_ip == "192.168.1.100"

    conn = {"local_ip": "127.0.0.1", "local_port": 54321, "remote_ip": "1.2.3.4", "remote_port": 4444, "process": "nc", "pid": 1234}
    norm_conn = normalizer.normalize_connection(conn, now)
    assert norm_conn.event_type == "CONNECTION"
    assert norm_conn.process_name == "nc"

    log = {"process": "sshd", "level": "error", "message": "Failed password for root from 192.168.1.50"}
    norm_log = normalizer.normalize_log(log, now)
    assert norm_log.auth_failure == True
    print("✓ Event Normalizer verified")

    # 3. State Engine Test
    engine = BehaviorStateEngine()

    # Simulate 120 ICMP packets over the last 8 seconds
    for i in range(120):
        t = now - (i * 0.05)  # spreads over last 6 seconds
        ev = normalizer.normalize_packet({"protocol": "ICMP", "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "length": 64}, t)
        engine.process_event(ev)

    # Simulate Port Scan: 25 unique ports in last 12 seconds
    for port in range(1000, 1025):
        t = now - 2.0
        ev = normalizer.normalize_connection({"local_ip": "192.168.1.100", "local_port": 50000, "remote_ip": "10.0.0.1", "remote_port": port, "process": "nmap"}, t)
        engine.process_event(ev)

    # Verify windows
    snaps = engine.get_all_window_snapshots(now)
    assert "5s" in snaps and "10s" in snaps and "30s" in snaps and "1m" in snaps and "5m" in snaps
    
    snap_10s = snaps["10s"]
    assert snap_10s.icmp_packets_by_src.get("192.168.1.100") == 120, f"Expected 120 ICMP packets in 10s window, got {snap_10s.icmp_packets_by_src.get('192.168.1.100')}"
    assert len(snap_10s.unique_dst_ports_by_src.get("192.168.1.100", set())) == 25, "Expected 25 unique ports in 10s window"

    print("✓ Behavior State Engine verified over 5s, 10s, 30s, 1m, 5m windows")
    print("✓ Phase 1 All Verification Tests Passed Successfully!\n")

if __name__ == "__main__":
    test_phase1()
