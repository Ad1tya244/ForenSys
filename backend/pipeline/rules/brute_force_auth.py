"""
Rule 5: Brute Force Authentication Detection
Detects repeated login failures followed by a successful authentication within a rolling window.
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

class BruteForceAuthRule(BaseRule):
    name = "Brute Force Authentication"
    description = "Detects multiple authentication failures followed by successful authentication from the same source IP/user within 60s."
    datasource = "log"
    time_window = "60s"
    severity = "high"
    mitre_tactics = ["Credential Access"]
    confidence = 0.90
    recommended_remediation = "Force credential reset and temporarily block source IP"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        limit = config.get("auth_failure_limit", 3)
        window_sec = config.get("auth_window_sec", 60.0)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        for key, fails in snapshot.auth_failures_by_src.items():
            if fails >= limit and snapshot.auth_successes_by_src.get(key, 0) > 0:
                key_v4 = ensure_ipv4(str(key))
                alerts.append(DetectionAlert(
                    alert_id=f"brute-force-{key_v4}-{int(current_time // 60)}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"Successful Brute Force Authentication ({key_v4})",
                    description=(
                        f"Source/Entity '{key_v4}' generated {fails} failed authentication attempts "
                        f"followed by successful login within {window_sec}s."
                    ),
                    datasource=self.datasource,
                    timestamp=current_time,
                    affected_assets=[str(key_v4), "auth_service"],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={"entity": str(key_v4), "failed_attempts": fails, "successful_login": True}
                ))

        return alerts
