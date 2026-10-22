"""
Rule 5: Authentication Attack Correlation
Correlates failed logins across host authentication services (sshd, sudo, loginwindow), attributed per source.
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine, is_local_ip

# Remote-login services that are brute-forced by hammering new connections (hydra, medusa, ncrack, ...)
AUTH_SERVICE_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 445: "smb", 3389: "rdp", 5900: "vnc"}


class AuthAttackRule(BaseRule):
    name = "Authentication Attack Correlation"
    description = "Correlates authentication failures across multiple host authentication services (sshd, sudo, loginwindow) into a single incident."
    datasource = "log"
    time_window = "60s"
    severity = "high"
    mitre_tactics = ["Credential Access"]
    confidence = 0.85
    recommended_remediation = "Add attacking source IP to the perimeter blocklist and inspect host authentication logs"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        window_sec = 60.0
        limit = config.get("auth_failure_limit", 3)

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        from pipeline.self_protection import get_primary_host_ip
        host_ip = get_primary_host_ip()

        for key, fails in snapshot.auth_failures_by_src.items():
            key = str(key)
            # Only failures tied to a REMOTE source address are an attack we can name and contain. Failures with no
            # attacker address (sudo/loginwindow typos, historical log lines, ...) are deliberately ignored here:
            # a nameless "host surge" alert duplicated the real detection and was a false-positive source.
            is_remote_ip = bool(key) and (key[0].isdigit() or ":" in key) and not is_local_ip(key)
            if not is_remote_ip:
                continue
            if fails < limit:
                continue
            key_v4 = ensure_ipv4(key)
            fail_events = snapshot.auth_fail_events.get(key, [])
            first_seen = min((e.timestamp for e in fail_events), default=current_time)
            episode = self.episode_id(f"auth-{key_v4}", current_time)
            alerts.append(DetectionAlert(
                alert_id=f"auth-attack-{key_v4}-{episode}",
                rule_name=self.name,
                severity=self.severity,
                title=f"Authentication Attack from {key_v4} ({fails} failures)",
                description=(
                    f"Source {key_v4} caused {fails} failed authentication attempts against host authentication "
                    f"services within {window_sec:g}s."
                ),
                datasource=self.datasource,
                timestamp=current_time,
                affected_assets=[key_v4, host_ip],
                mitre_tactics=self.mitre_tactics,
                confidence=self.confidence,
                remediation=self.recommended_remediation,
                metadata={
                    "src_ip": key_v4, "src_ip_raw": key, "attacker_ip": key_v4, "block_ip": key_v4,
                    "dst_ip": host_ip, "target_ip": host_ip, "total_failures": fails,
                    "services": sorted({e.process_name for e in fail_events}),
                    "first_seen": first_seen, "mttd_sec": round(max(0.0, current_time - first_seen), 3),
                    "detected_at": current_time, "attack_type": "auth_attack",
                }
            ))

        # Network view of the same attack: a flood of new connections to one login service from one remote IP.
        # Works even when the service logs nothing (e.g. Remote Login disabled, FTP/RDP/VNC targets).
        net_threshold = config.get("auth_service_syn_threshold", 15)
        for src, port_counts in snapshot.syn_by_src_port.items():
            for port, count in port_counts.items():
                if port not in AUTH_SERVICE_PORTS or count < net_threshold:
                    continue
                src_v4 = ensure_ipv4(src)
                service = AUTH_SERVICE_PORTS[port]
                first_seen = snapshot.first_seen_by_src.get(src, current_time)
                episode = self.episode_id(f"authnet-{src_v4}-{port}", current_time)
                alerts.append(DetectionAlert(
                    alert_id=f"auth-attack-net-{src_v4}-{port}-{episode}",
                    rule_name=self.name,
                    severity=self.severity,
                    title=f"{service.upper()} Brute Force Attempt from {src_v4} ({count} connections)",
                    description=(
                        f"Source {src_v4} opened {count} connections to {service.upper()} (port {port}) on {host_ip} "
                        f"within {window_sec:g}s - consistent with automated password guessing."
                    ),
                    datasource="network",
                    timestamp=current_time,
                    affected_assets=[src_v4, host_ip],
                    mitre_tactics=self.mitre_tactics,
                    confidence=self.confidence,
                    remediation=self.recommended_remediation,
                    metadata={
                        "src_ip": src_v4, "src_ip_raw": src, "attacker_ip": src_v4, "block_ip": src_v4,
                        "dst_ip": host_ip, "target_ip": host_ip, "services": [service], "service_port": port,
                        "connection_attempts": count, "threshold": net_threshold, "window_sec": window_sec,
                        "first_seen": first_seen, "mttd_sec": round(max(0.0, current_time - first_seen), 3),
                        "detected_at": current_time, "attack_type": "auth_attack",
                    }
                ))

        return alerts
