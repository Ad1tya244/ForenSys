"""
Rule 4: Brute Force Authentication
Detects repeated authentication failures followed by a successful login from the same source within the window.
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine, is_local_ip

class BruteForceAuthRule(BaseRule):
    name = "Brute Force Authentication"
    description = "Detects multiple authentication failures followed by successful authentication from the same source IP/user within 60s."
    datasource = "log"
    time_window = "60s"
    severity = "critical"
    mitre_tactics = ["Credential Access"]
    confidence = 0.90
    recommended_remediation = "Add source IP to the perimeter blocklist and force a credential reset"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        limit = config.get("auth_failure_limit", 3)
        window_sec = config.get("auth_window_sec", 60.0)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        from pipeline.self_protection import get_primary_host_ip
        host_ip = get_primary_host_ip()

        for key, fails in snapshot.auth_failures_by_src.items():
            if fails < limit or snapshot.auth_successes_by_src.get(key, 0) <= 0:
                continue
            key_v4 = ensure_ipv4(str(key))
            is_ip = bool(key) and (key[0].isdigit() or ":" in key) and not is_local_ip(key)
            fail_events = snapshot.auth_fail_events.get(key, [])
            first_seen = min((e.timestamp for e in fail_events), default=current_time)
            episode = self.episode_id(f"brute-{key_v4}", current_time)
            meta = {
                "entity": key_v4, "failed_attempts": fails, "successful_login": True,
                "services": sorted({e.process_name for e in fail_events}),
                "target_ip": host_ip, "dst_ip": host_ip, "first_seen": first_seen,
                "mttd_sec": round(max(0.0, current_time - first_seen), 3), "detected_at": current_time,
                "attack_type": "brute_force",
            }
            if is_ip:
                meta.update({"src_ip": key_v4, "src_ip_raw": key, "attacker_ip": key_v4, "block_ip": key_v4})
            alerts.append(DetectionAlert(
                alert_id=f"brute-force-{key_v4}-{episode}",
                rule_name=self.name,
                severity=self.severity,
                title=f"Successful Brute Force Authentication ({key_v4})",
                description=(
                    f"Source/Entity '{key_v4}' generated {fails} failed authentication attempts "
                    f"followed by a successful login within {window_sec:g}s."
                ),
                datasource=self.datasource,
                timestamp=current_time,
                affected_assets=[str(key_v4), host_ip],
                mitre_tactics=self.mitre_tactics,
                confidence=self.confidence,
                remediation=self.recommended_remediation,
                metadata=meta,
            ))

        return alerts
