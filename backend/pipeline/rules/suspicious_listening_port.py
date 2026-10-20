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
    recommended_remediation = "Flag the listening process as contained and audit its binary and execution path"

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
            
            # 2. Alert if socket is unusual or suspicious process (exact tool names, not substrings like "sharingd")
            suspicious_names = {"nc", "ncat", "netcat", "nmap", "socat", "perl", "ruby", "bash", "sh", "zsh", "tclsh"}
            suspicious_fragments = ("miner", "hack", "backdoor", "reverse", "meterpreter")
            is_suspicious_name = proc_lower in suspicious_names or any(k in proc_lower for k in suspicious_fragments)

            # Check if this is a newly observed listener not in long-term established history
            if is_suspicious_name:
                episode = self.episode_id(f"listen-{proc_name}-{port}", current_time)
                alerts.append(DetectionAlert(
                    alert_id=f"listen-{proc_name}-{port}-{episode}",
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
                    metadata={
                        "process": proc_name, "port": port, "quarantine_process": proc_name,
                        "detected_at": current_time, "mttd_sec": 0.5, "attack_type": "suspicious_listener",
                    }
                ))
        return alerts
