"""
Rule 3: SYN Flood Detection
Detects excessive TCP SYN packets without completed handshakes over a 10s window.
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
    recommended_remediation = "Enable TCP SYN cookies and throttle source IP"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        threshold = config.get("syn_threshold", 50)
        window_sec = config.get("syn_window_sec", 10.0)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        for src_ip, count in snapshot.syn_packets_by_src.items():
            if count >= threshold:
                src_ip_v4 = ensure_ipv4(src_ip)
                alerts.append(DetectionAlert(
                    alert_id=f"syn-flood-{src_ip_v4}-{int(current_time // 10)}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"TCP SYN Flood from {src_ip_v4}",
                    description=f"Source IP {src_ip_v4} sent {count} TCP SYN packets within {window_sec}s without completing handshakes.",
                    datasource=self.datasource,
                    timestamp=current_time,
                    affected_assets=[src_ip_v4, "localhost"],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={"src_ip": src_ip_v4, "syn_count": count}
                ))

        return alerts
