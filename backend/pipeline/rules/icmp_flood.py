"""
Rule 1: ICMP Flood / Ping Sweep Detection
Detects repeated ICMP Echo Requests from the same remote source IP exceeding threshold.
"""

import time
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
    recommended_remediation = "Add source IP to the perimeter blocklist (packet sniffer ignores it until manually unblocked)"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        threshold = config.get("icmp_threshold", 50)
        window_sec = config.get("icmp_window_sec", 10.0)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        from pipeline.self_protection import get_primary_host_ip
        host_ip = get_primary_host_ip()

        for src_ip, count in snapshot.icmp_packets_by_src.items():
            if count < threshold:
                continue
            src_ip_v4 = ensure_ipv4(src_ip)
            first_seen = snapshot.first_seen_by_src.get(src_ip, current_time)
            last_seen = snapshot.last_seen_by_src.get(src_ip, current_time)
            mttd_sec = round(max(0.0, current_time - first_seen), 3)
            targets = sorted(snapshot.icmp_dsts_by_src.get(src_ip, set()))
            kind = "ICMP Ping Sweep" if len(targets) >= 5 else "ICMP Flood"
            episode = self.episode_id(f"icmp-{src_ip_v4}", current_time)
            alerts.append(DetectionAlert(
                alert_id=f"icmp-flood-{src_ip_v4}-{episode}",
                rule_name=self.name,
                severity=self.severity,
                title=f"{kind} Detected from {src_ip_v4}",
                description=(
                    f"Attacker IP {src_ip_v4} generated {count} ICMP Echo Requests targeting {host_ip} within "
                    f"{window_sec:g}s (threshold: {threshold}, MTTD: {mttd_sec}s)."
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
                    "count": count, "window_sec": window_sec, "threshold": threshold,
                    "unique_targets": targets[:20], "first_seen": first_seen, "last_seen": last_seen,
                    "mttd_sec": mttd_sec, "detected_at": current_time, "attack_type": "icmp_flood",
                }
            ))

        return alerts
