"""
Rule 2: Port Scan Detection
Detects a remote source IP probing 20+ unique destination ports within the window (nmap -sS / -sT style scans).
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

class PortScanRule(BaseRule):
    name = "Port Scan"
    description = "Detects source IP connecting to 20+ unique destination ports within a 15-second window."
    datasource = "network"
    time_window = "15s"
    severity = "high"
    mitre_tactics = ["Reconnaissance", "Discovery"]
    confidence = 0.90
    recommended_remediation = "Add scanning source IP to the perimeter blocklist (packet sniffer ignores it until manually unblocked)"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        threshold = config.get("portscan_threshold", 20)
        window_sec = config.get("portscan_window_sec", 15.0)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        from pipeline.self_protection import get_primary_host_ip
        host_ip = get_primary_host_ip()

        for src_ip, ports in snapshot.unique_dst_ports_by_src.items():
            if len(ports) < threshold:
                continue
            src_ip_v4 = ensure_ipv4(src_ip)
            sample_ports = sorted(ports)[:10]
            first_seen = snapshot.first_seen_by_src.get(src_ip, current_time)
            mttd_sec = round(max(0.0, current_time - first_seen), 3)
            episode = self.episode_id(f"scan-{src_ip_v4}", current_time)
            alerts.append(DetectionAlert(
                alert_id=f"portscan-{src_ip_v4}-{episode}",
                rule_name=self.name,
                severity=self.severity,
                title=f"Port Scan Detected from {src_ip_v4}",
                description=(
                    f"Source IP {src_ip_v4} probed {len(ports)} unique destination ports on {host_ip} within "
                    f"{window_sec:g}s (ports: {sample_ports}..., MTTD: {mttd_sec}s)."
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
                    "unique_ports": len(ports), "sample_ports": sample_ports, "threshold": threshold,
                    "window_sec": window_sec, "first_seen": first_seen, "mttd_sec": mttd_sec,
                    "detected_at": current_time, "attack_type": "port_scan",
                }
            ))

        return alerts
