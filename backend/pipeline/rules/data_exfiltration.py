"""
Rule 6: Data Exfiltration Detection
Detects large outbound network byte transfers to an external IP exceeding configurable threshold.
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine
from analyzers.ip_intel import is_private_ip

class DataExfiltrationRule(BaseRule):
    name = "Data Exfiltration"
    description = "Detects unusually high outbound transfer volume to an external destination IP within a 30s window."
    datasource = "network"
    time_window = "30s"
    severity = "high"
    mitre_tactics = ["Exfiltration"]
    confidence = 0.82
    recommended_remediation = "Isolate host connection and block external destination IP"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        limit_bytes = config.get("data_exfiltration_bytes", 52428800)  # 50 MB default
        window_sec = config.get("data_exfiltration_window_sec", 30.0)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        for dst_ip, total_bytes in snapshot.outbound_bytes_by_dst.items():
            if dst_ip and not is_private_ip(dst_ip) and total_bytes >= limit_bytes:
                mb = total_bytes / (1024 * 1024)
                alerts.append(DetectionAlert(
                    alert_id=f"exfil-{dst_ip}-{int(current_time // 30)}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"Potential Data Exfiltration to {dst_ip}",
                    description=f"Outbound network transfer of {mb:.2f} MB to external IP {dst_ip} in {window_sec}s exceeded threshold ({limit_bytes / (1024*1024):.1f} MB).",
                    datasource=self.datasource,
                    timestamp=current_time,
                    affected_assets=["localhost", dst_ip],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={"dst_ip": dst_ip, "transferred_bytes": total_bytes, "transferred_mb": round(mb, 2)}
                ))
        return alerts
