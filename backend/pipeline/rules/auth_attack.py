"""
Rule 10: Authentication Attack Correlation Detection
Correlates multi-service authentication failures (SSH, sudo, loginwindow, SecurityAgent) into a unified attack detection.
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

class AuthAttackRule(BaseRule):
    name = "Authentication Attack Correlation"
    description = "Correlates authentication failures across multiple host authentication services (sshd, sudo, loginwindow) into a single incident."
    datasource = "log"
    time_window = "60s"
    severity = "medium"
    mitre_tactics = ["Credential Access"]
    confidence = 0.85
    recommended_remediation = "Enforce temporary login lockout and inspect host authentication log streams"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        window_sec = 60.0
        limit = config.get("auth_failure_limit", 3)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        total_auth_failures = sum(snapshot.auth_failures_by_src.values())

        if total_auth_failures >= limit:
            from analyzers.ip_intel import ensure_ipv4
            affected_sources = [ensure_ipv4(str(k)) for k in snapshot.auth_failures_by_src.keys()]
            alerts.append(DetectionAlert(
                alert_id=f"auth-attack-correlated-{int(current_time // 60)}",
                rule_name=self.name,
                severity=self.severity,
                title=f"Host Authentication Attack Surge ({total_auth_failures} failures)",
                description=f"Correlated {total_auth_failures} failed authentication attempts across system authentication services (sshd, sudo, loginwindow) within {window_sec}s.",
                datasource=self.datasource,
                timestamp=current_time,
                affected_assets=affected_sources + ["PAM/Auth"],
                mitre_tactics=self.mitre_tactics,
                confidence=self.confidence,
                remediation=self.recommended_remediation,
                metadata={"total_failures": total_auth_failures, "sources": affected_sources}
            ))

        return alerts
