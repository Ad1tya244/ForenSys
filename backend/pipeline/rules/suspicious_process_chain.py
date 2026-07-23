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
    recommended_remediation = "Terminate child process execution tree and quarantine document/binary source"

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

        snapshot = state_engine.get_window_snapshot(30.0, current_time)
        for parent, child in snapshot.process_chains:
            for chain in suspicious_chains:
                p_match = chain["parent"].lower() in parent.lower()
                c_match = chain["child"].lower() in child.lower()
                if p_match and c_match:
                    alerts.append(DetectionAlert(
                        alert_id=f"procchain-{parent}-{child}-{int(current_time // 30)}",
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
                        metadata={"parent_process": parent, "child_process": child}
                    ))
        return alerts
