"""
Rule 7: Suspicious Listening Port Detection
Detects new listening sockets opened by previously unseen or suspicious non-whitelisted processes.
Explicitly ignores legitimate system processes like kernel_task, launchd, WindowServer, systemd, loginwindow, etc.
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

class SuspiciousListeningPortRule(BaseRule):
    name = "Suspicious Listening Port"
    description = "Detects new listening sockets opened by non-whitelisted or suspicious processes."
    datasource = "network"
    time_window = "30s"
    severity = "medium"
    mitre_tactics = ["Persistence", "Command and Control"]
    confidence = 0.80
    recommended_remediation = "Audit listening process binary and check process execution path"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        whitelist = set(config.get("whitelisted_processes", []))
        window_sec = 30.0

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        for (proc_name, port) in snapshot.active_listeners:
            proc_lower = proc_name.lower()
            
            # 1. Ignore whitelisted system daemons & local processes
            if any(w.lower() in proc_lower for w in whitelist) or any(b in proc_lower for b in (
                "duetexpertd", "windowserver", "kernel_task", "launchd", "coreaudiod",
                "mds", "node", "python", "language_server", "antigravity", "loginwindow",
                "securityagent", "finder", "dock", "systemuiserver", "controlcenter"
            )):
                continue
            
            # 2. Alert if socket is unusual or suspicious process
            suspicious_keywords = ["nc", "netcat", "nmap", "python", "perl", "ruby", "bash", "sh", "zsh", "miner", "hack", "backdoor"]
            is_suspicious_name = any(k in proc_lower for k in suspicious_keywords)

            # Check if this is a newly observed listener not in long-term established history
            if is_suspicious_name or (proc_name, port) not in state_engine.seen_listeners_history:
                alerts.append(DetectionAlert(
                    alert_id=f"listen-{proc_name}-{port}-{int(current_time // 30)}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"Suspicious Listening Socket: {proc_name} on port {port}",
                    description=f"Process '{proc_name}' bound a new listening socket on port {port}. Process is not in system whitelist.",
                    datasource=self.datasource,
                    timestamp=current_time,
                    affected_assets=[proc_name, f"port_{port}"],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={"process": proc_name, "port": port}
                ))
        return alerts
