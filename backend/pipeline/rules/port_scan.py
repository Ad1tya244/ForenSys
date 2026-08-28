"""
Rule 2: Port Scan Detection
Detects same source IP attempting 20+ unique destination ports within 15 seconds.
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
    severity = "medium"
    mitre_tactics = ["Reconnaissance", "Discovery"]
    confidence = 0.85
    recommended_remediation = "Temporary firewall block on scanning source IP"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        threshold = config.get("portscan_threshold", 20)
        window_sec = config.get("portscan_window_sec", 15.0)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        for src_ip, ports in snapshot.unique_dst_ports_by_src.items():
            if len(ports) >= threshold:
                src_ip_v4 = ensure_ipv4(src_ip)
                sample_ports = sorted(list(ports))[:10]
                alerts.append(DetectionAlert(
                    alert_id=f"portscan-{src_ip_v4}-{int(current_time // 15)}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"Port Scan Detected from {src_ip_v4}",
                    description=f"Source IP {src_ip_v4} attempted connections to {len(ports)} unique destination ports within {window_sec}s (Ports: {sample_ports}...).",
                    datasource=self.datasource,
                    timestamp=current_time,
                    affected_assets=[src_ip_v4, "localhost"],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={"src_ip": src_ip_v4, "unique_ports": len(ports), "sample_ports": sample_ports}
                ))

        return alerts
