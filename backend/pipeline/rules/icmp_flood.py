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
    severity = "medium"
    mitre_tactics = ["Impact"]
    confidence = 0.90
    recommended_remediation = "Temporarily block source IP at firewall"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        threshold = config.get("icmp_threshold", 100)
        window_sec = config.get("icmp_window_sec", 10.0)

        from pipeline.self_protection import asset_trust_manager

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        for src_ip, count in snapshot.icmp_packets_by_src.items():
            if src_ip in asset_trust_manager.local_ips or src_ip.startswith("127."):
                continue
            if count >= threshold:
                alerts.append(DetectionAlert(
                    alert_id=f"icmp-flood-{src_ip}-{int(current_time // 10)}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"ICMP Flood Detected from {src_ip}",
                    description=f"Source IP {src_ip} generated {count} ICMP Echo Requests within {window_sec}s (threshold: {threshold}).",
                    datasource=self.datasource,
                    timestamp=current_time,
                    affected_assets=[src_ip, "localhost"],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={"src_ip": src_ip, "count": count, "window_sec": window_sec}
                ))
        return alerts
