"""
Rule 6: DNS Beaconing
Detects periodic DNS requests from a single process/host to the same external domain.
"""

import math
import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

IGNORED_DOMAIN_SUFFIXES = (".local", ".arpa", ".lan", ".internal", ".home", ".localdomain")

class DNSBeaconingRule(BaseRule):
    name = "DNS Beaconing"
    description = "Detects periodic DNS requests from a single process to the same external domain over a rolling window."
    datasource = "network"
    time_window = "60s"
    severity = "high"
    mitre_tactics = ["Command and Control"]
    confidence = 0.85
    recommended_remediation = "Sinkhole the C2 domain (packet sniffer ignores DNS traffic for it until manually unblocked)"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        window_sec = config.get("dns_beacon_window_sec", 60.0)
        min_queries = config.get("dns_beacon_min_queries", 5)
        max_variance = config.get("dns_beacon_max_variance", 0.20)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        for (entity, domain), timestamps in snapshot.dns_query_timestamps.items():
            if len(timestamps) < min_queries or domain.endswith(IGNORED_DOMAIN_SUFFIXES):
                continue

            ts_sorted = sorted(timestamps)
            intervals = [ts_sorted[i] - ts_sorted[i - 1] for i in range(1, len(ts_sorted))]
            if not intervals or any(i <= 0 for i in intervals):
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 0.1:  # ignore sub-100ms rapid spikes (bursts)
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            cov = math.sqrt(variance) / mean_interval

            # Low variance indicates regular, automated periodic beaconing
            if cov <= max_variance:
                episode = self.episode_id(f"dns-{entity}-{domain}", current_time)
                alerts.append(DetectionAlert(
                    alert_id=f"dns-beacon-{entity}-{domain}-{episode}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"DNS Beaconing to {domain} by {entity}",
                    description=(
                        f"'{entity}' issued {len(timestamps)} DNS queries for domain '{domain}' "
                        f"at regular intervals (avg {mean_interval:.1f}s, variance coefficient {cov:.2f})."
                    ),
                    datasource=self.datasource,
                    timestamp=current_time,
                    affected_assets=[entity, domain],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={
                        "process": entity, "domain": domain, "block_domain": domain, "query_count": len(timestamps),
                        "interval_sec": round(mean_interval, 2), "cov": round(cov, 2),
                        "first_seen": ts_sorted[0], "last_seen": ts_sorted[-1],
                        "mttd_sec": max(0.1, round(current_time - ts_sorted[0], 2)),
                        "detected_at": current_time, "attack_type": "dns_beacon",
                    }
                ))
        return alerts
