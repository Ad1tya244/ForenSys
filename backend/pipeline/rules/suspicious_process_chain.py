"""
Rule 9: Suspicious Process Chain Detection
Detects anomalous parent-child process execution patterns (e.g. Office/Browser spawning terminal/shell interpreters).
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

class SuspiciousProcessChainRule(BaseRule):
    name = "Suspicious Process Chain"
    description = "Detects anomalous parent-child execution chains such as productivity software spawning terminal or command shells."
    datasource = "process"
    time_window = "30s"
    severity = "high"
    mitre_tactics = ["Execution", "Defense Evasion"]
    confidence = 0.88
    recommended_remediation = "Flag the child process tree as contained and review the document/binary source"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        suspicious_chains = config.get("suspicious_parent_chains", [
            {"parent": "Microsoft Word", "child": "Terminal"},
            {"parent": "Word", "child": "bash"},
            {"parent": "Excel", "child": "bash"},
            {"parent": "Safari", "child": "bash"},
            {"parent": "Chrome", "child": "sh"},
            {"parent": "python", "child": "nc"}
        ])

        reported = set()
        for ev in state_engine.recent_events(30.0, current_time):
            if ev.event_type != "PROCESS" or ev.parent_process == "unknown":
                continue
            parent, child = ev.parent_process, ev.process_name
            for chain in suspicious_chains:
                p_match = chain["parent"].lower() in parent.lower()
                c_match = chain["child"].lower() == child.lower()
                if p_match and c_match:
                    if (parent, child, ev.pid) in reported:
                        break
                    reported.add((parent, child, ev.pid))
                    episode = self.episode_id(f"procchain-{parent}-{child}-{ev.pid}", current_time)
                    alerts.append(DetectionAlert(
                        alert_id=f"procchain-{parent}-{child}-{ev.pid}-{episode}",
                        rule_name=self.name,
                        severity=self.severity,
                        title=f"Suspicious Process Chain: {parent} -> {child}",
                        description=f"Anomalous process creation detected: Parent '{parent}' spawned child process '{child}'.",
                        datasource=self.datasource,
                        timestamp=current_time,
                        affected_assets=[parent, child],
                        mitre_tactics=self.mitre_tactics,
                        confidence=self.confidence,
                        remediation=self.recommended_remediation,
                        metadata={
                            "parent_process": parent, "child_process": child, "process": child, "pid": ev.pid,
                            "ppid": ev.ppid, "quarantine_process": child, "first_seen": ev.timestamp,
                            "detected_at": current_time, "mttd_sec": max(0.1, round(current_time - ev.timestamp, 2)),
                            "attack_type": "process_chain",
                        }
                    ))
        return alerts
