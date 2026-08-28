"""
Rule 8: Reverse Shell Detection
Detects interactive shells (bash, zsh, python, perl, ruby) establishing outbound socket connections to uncommon external ports.
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine
from analyzers.ip_intel import is_private_ip

class ReverseShellRule(BaseRule):
    name = "Reverse Shell"
    description = "Detects interactive shell/scripting interpreters (bash, zsh, python, perl, ruby) connecting outbound to non-standard remote ports."
    datasource = "process_network"
    time_window = "10s"
    severity = "critical"
    mitre_tactics = ["Execution", "Command and Control"]
    confidence = 0.95
    recommended_remediation = "Immediately terminate shell process PID and isolate network endpoint"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        shells = set(config.get("shell_executables", ["bash", "zsh", "sh", "python", "python3", "perl", "ruby"]))
        uncommon_ports = set(config.get("uncommon_external_ports", [4444, 1337, 31337, 5555, 6666, 6667, 9001, 9050, 12345, 27374, 54321, 65535, 7777, 2222]))

        snapshot = state_engine.get_window_snapshot(10.0, current_time)
        for ev in state_engine.events:
            if ev.timestamp < current_time - 10.0:
                continue
            if ev.event_type == "CONNECTION" and ev.dst_port > 0:
                proc = ev.process_name.lower()
                rip = ev.dst_ip
                rport = ev.dst_port

                is_shell = any(s == proc or proc.endswith("/" + s) for s in shells)
                is_uncommon = rport in uncommon_ports or (not is_private_ip(rip) and rport not in (80, 443, 53, 123))

                if is_shell and is_uncommon:
                    from analyzers.ip_intel import ensure_ipv4
                    rip_v4 = ensure_ipv4(rip)
                    src_ip_v4 = ensure_ipv4(ev.src_ip)
                    alerts.append(DetectionAlert(
                        alert_id=f"revshell-{proc}-{rip_v4}-{rport}-{int(current_time // 10)}",
                        rule_name=self.name,
                        severity=self.severity,
                        title=f"Reverse Shell Execution: {ev.process_name} -> {rip_v4}:{rport}",
                        description=(
                            f"Shell interpreter '{ev.process_name}' (PID {ev.pid}) established an outbound "
                            f"connection to remote address {rip_v4}:{rport}. Strong indication of an active reverse shell."
                        ),
                        datasource=self.datasource,
                        timestamp=current_time,
                        affected_assets=[ev.process_name, rip_v4, f"pid_{ev.pid}"],
                        mitre_tactics=self.mitre_tactics,
                        confidence=self.confidence,
                        remediation=self.recommended_remediation,
                        metadata={"src_ip": src_ip_v4, "process": ev.process_name, "pid": ev.pid, "remote_ip": rip_v4, "remote_port": rport}
                    ))

        return alerts
