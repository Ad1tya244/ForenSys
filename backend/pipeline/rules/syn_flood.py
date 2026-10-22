"""
Rule 3: SYN Flood Detection
Detects a flood of bare TCP SYNs from one source concentrated on a few destination ports.
(Probes spread over many ports are a port scan, handled by the Port Scan rule, so one nmap run is not reported twice.)
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

class SYNFloodRule(BaseRule):
    name = "SYN Flood"
    description = "Detects excessive TCP SYN connection requests from a source IP within a rolling 10s window."
    datasource = "network"
    time_window = "10s"
    severity = "high"
    mitre_tactics = ["Impact"]
    confidence = 0.88
    recommended_remediation = "Add source IP to the perimeter blocklist (packet sniffer ignores it until manually unblocked)"
    max_target_ports = 5

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        threshold = config.get("syn_threshold", 50)
        window_sec = config.get("syn_window_sec", 10.0)
        max_ports = config.get("syn_flood_max_ports", self.max_target_ports)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        from pipeline.self_protection import get_primary_host_ip
        host_ip = get_primary_host_ip()

        for src_ip, count in snapshot.syn_packets_by_src.items():
            ports = snapshot.syn_ports_by_src.get(src_ip, set())
            if count < threshold or len(ports) > max_ports:
                continue
            src_ip_v4 = ensure_ipv4(src_ip)
            first_seen = snapshot.first_seen_by_src.get(src_ip, current_time)
            mttd_sec = round(max(0.0, current_time - first_seen), 3)
            episode = self.episode_id(f"syn-{src_ip_v4}", current_time)
            alerts.append(DetectionAlert(
                alert_id=f"syn-flood-{src_ip_v4}-{episode}",
                rule_name=self.name,
                severity=self.severity,
                title=f"TCP SYN Flood from {src_ip_v4}",
                description=(
                    f"Source IP {src_ip_v4} sent {count} TCP SYN packets to port(s) {sorted(ports)} on {host_ip} "
                    f"within {window_sec:g}s without completing handshakes (MTTD: {mttd_sec}s)."
                ),
                datasource=self.datasource,
                timestamp=current_time,
                affected_assets=[src_ip_v4, host_ip],
                mitre_tactics=self.mitre_tactics,
                confidence=self.confidence,
                remediation=self.recommended_remediation,
                metadata={
                    "src_ip": src_ip_v4, "src_ip_raw": src_ip, "attacker_ip": src_ip_v4,
                    "dst_ip": host_ip, "target_ip": host_ip, "block_ip": src_ip_v4,
                    "syn_count": count, "target_ports": sorted(ports), "threshold": threshold,
                    "window_sec": window_sec, "first_seen": first_seen, "mttd_sec": mttd_sec,
                    "detected_at": current_time, "attack_type": "syn_flood",
                }
            ))

        return alerts
