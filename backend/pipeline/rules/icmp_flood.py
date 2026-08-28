"""
Rule 1: ICMP Flood Detection
Detects repeated ICMP Echo Requests from the same source IP exceeding threshold.
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

class ICMPFloodRule(BaseRule):
    name = "ICMP Flood"
    description = "Detects repeated ICMP Echo Requests from the same source IP over a rolling 10s window."
    datasource = "network"
    time_window = "10s"
    severity = "high"
    mitre_tactics = ["Impact"]
    confidence = 0.90
    recommended_remediation = "Temporarily block source IP at firewall"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        threshold = config.get("icmp_threshold", 20)
        window_sec = config.get("icmp_window_sec", 10.0)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        for src_ip, count in snapshot.icmp_packets_by_src.items():
            if src_ip in ("127.0.0.1", "localhost", "::1"):
                continue
            if count >= threshold:
                first_seen = snapshot.first_seen_by_src.get(src_ip, current_time - 1.2)
                mttd_sec = max(0.1, round(current_time - first_seen, 2))

                from pipeline.self_protection import get_primary_host_ip
                host_ip = get_primary_host_ip()

                src_ip_v4 = ensure_ipv4(src_ip)
                alerts.append(DetectionAlert(
                    alert_id=f"icmp-flood-{src_ip_v4}-{int(current_time // 10)}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"ICMP Flood Detected from {src_ip_v4}",
                    description=f"Attacker IP {src_ip_v4} generated {count} ICMP Echo Requests targeting {host_ip} within {window_sec}s (threshold: {threshold}, MTTD: {mttd_sec}s).",
                    datasource=self.datasource,
                    timestamp=current_time,
                    affected_assets=[src_ip_v4, host_ip],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={"src_ip": src_ip_v4, "attacker_ip": src_ip_v4, "dst_ip": host_ip, "target_ip": host_ip, "count": count, "window_sec": window_sec, "mttd_sec": mttd_sec}
                ))

        return alerts
