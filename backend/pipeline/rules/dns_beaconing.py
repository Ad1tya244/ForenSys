"""
Rule 4: DNS Beaconing Detection
Detects repeated DNS requests from the same process to the same domain at regular intervals.
"""

import time
import math
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

class DNSBeaconingRule(BaseRule):
    name = "DNS Beaconing"
    description = "Detects periodic DNS requests from a single process to the same external domain over a rolling window."
    datasource = "network"
    time_window = "60s"
    severity = "high"
    mitre_tactics = ["Command and Control"]
    confidence = 0.85
    recommended_remediation = "Isolate host process and block C2 domain at DNS filter"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        window_sec = config.get("dns_beacon_window_sec", 60.0)
        min_queries = config.get("dns_beacon_min_queries", 5)
        max_variance = config.get("dns_beacon_max_variance", 0.20)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        for (proc_name, domain), timestamps in snapshot.dns_query_timestamps.items():
            if len(timestamps) < min_queries:
                continue
            
            # Sort timestamps and compute intervals between consecutive queries
            ts_sorted = sorted(timestamps)
            intervals = [ts_sorted[i] - ts_sorted[i-1] for i in range(1, len(ts_sorted))]
            if not intervals or any(i <= 0 for i in intervals):
                continue
            
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 0.1:  # ignore sub-100ms rapid spikes (bursts)
                continue

            # Calculate coefficient of variation (std_dev / mean)
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            cov = std_dev / mean_interval

            # Low variance indicates regular, automated periodic beaconing
            if cov <= max_variance:
                alerts.append(DetectionAlert(
                    alert_id=f"dns-beacon-{proc_name}-{domain}-{int(current_time // 60)}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"DNS Beaconing to {domain} by {proc_name}",
                    description=(
                        f"Process '{proc_name}' issued {len(timestamps)} DNS queries for domain '{domain}' "
                        f"at regular intervals (avg {mean_interval:.1f}s, variance coefficient {cov:.2f})."
                    ),
                    datasource=self.datasource,
                    timestamp=current_time,
                    affected_assets=[proc_name, domain],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={"process": proc_name, "domain": domain, "query_count": len(timestamps), "interval_sec": round(mean_interval, 2), "cov": round(cov, 2)}
                ))
        return alerts
