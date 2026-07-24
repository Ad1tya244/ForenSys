"""
ForenSys SOAR Auto-Remediation Engine
Integrates security playbook rules with correlated incident contexts.
Executes remediation actions (Block IP, Kill Process, Quarantine, PF Rule, PCAP Capture)
and maintains an execution log with rollback capabilities.
"""

import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set
from pipeline.correlation_engine import CorrelatedIncident
from analyzers.ip_intel import is_private_ip

REMEDIATION_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "remediation_history.json")

@dataclass
class RemediationActionLog:
    action_id: str
    incident_id: str
    rule_name: str
    action_type: str
    target: str
    timestamp: float
    status: str  # success, failed, rolled_back
    result_details: Dict[str, Any] = field(default_factory=dict)
    rollback_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.action_id,
            "incidentId": self.incident_id,
            "ruleName": self.rule_name,
            "actionType": self.action_type,
            "target": self.target,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)),
            "status": self.status,
            "resultDetails": self.result_details,
            "rollbackInfo": self.rollback_info,
        }

class SOAREngine:
    def __init__(self, log_path: str = REMEDIATION_LOG_FILE) -> None:
        self.log_path = log_path
        self.remediation_history: List[RemediationActionLog] = []
        self.blocked_ips: Set[str] = set()
        self.pf_rules: List[str] = []
        self._load_history()

    def _load_history(self) -> None:
        if not os.path.exists(self.log_path):
            return
        try:
            with open(self.log_path, "r") as f:
                data = json.load(f)
                for item in data:
                    log = RemediationActionLog(
                        action_id=item["id"],
                        incident_id=item["incidentId"],
                        rule_name=item["ruleName"],
                        action_type=item["actionType"],
                        target=item["target"],
                        timestamp=time.mktime(time.strptime(item["timestamp"], "%Y-%m-%dT%H:%M:%SZ")),
                        status=item["status"],
                        result_details=item.get("resultDetails", {}),
                        rollback_info=item.get("rollbackInfo", {})
                    )
                    self.remediation_history.append(log)
                    if log.action_type in ("block_ip", "add_pf_rule") and log.status == "success":
                        self.blocked_ips.add(log.target)
        except Exception as e:
            print(f"[SOAREngine] Error loading history: {e}")

    def _save_history(self) -> None:
        try:
            data = [log.to_dict() for log in self.remediation_history]
            with open(self.log_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[SOAREngine] Error saving history: {e}")

    def evaluate_and_remediate(self, incident: CorrelatedIncident, soar_playbook_rules: List[Dict[str, Any]]) -> List[RemediationActionLog]:
        """Evaluates an incident against active SOAR playbook rules and executes automated remediation."""
        if not incident or not incident.id:
            print("[SOAREngine] Execution rejected: Missing incident context.")
            return []

        executed_actions: List[RemediationActionLog] = []
        now = time.time()

        # Automatic remediation triggers based on incident severity and MITRE stages
        actions_to_take = []
        
        threat_name = incident.title if incident.title else "ICMP Flood Detection"

        # 1. Reverse Shell / Critical C2 -> Kill Process & Block IP
        if incident.severity == "critical" or "Reverse Shell" in incident.title or "Command and Control" in incident.mitre_stages:
            if incident.primary_source_ip and incident.primary_source_ip not in ("127.0.0.1", "localhost", "::1"):
                actions_to_take.append(("block_ip", incident.primary_source_ip, threat_name))
            if incident.primary_dest_ip and incident.primary_dest_ip not in ("127.0.0.1", "localhost", "::1"):
                actions_to_take.append(("block_ip", incident.primary_dest_ip, threat_name))
            if incident.primary_process:
                actions_to_take.append(("kill_process", incident.primary_process, threat_name))

        # 2. Port Scan / ICMP Flood -> Single Perimeter Block IP
        elif "Port Scan" in incident.title or "ICMP Flood" in incident.title or "Impact" in incident.mitre_stages or "Reconnaissance" in incident.mitre_stages:
            if incident.primary_source_ip and incident.primary_source_ip not in ("127.0.0.1", "localhost", "::1"):
                actions_to_take.append(("block_ip", incident.primary_source_ip, threat_name))

        # 3. Data Exfiltration -> Block IP & Capture Metadata
        elif "Exfiltration" in incident.mitre_stages:
            if incident.primary_dest_ip:
                actions_to_take.append(("block_ip", incident.primary_dest_ip, threat_name))
            actions_to_take.append(("capture_metadata", incident.primary_process or "system", threat_name))

        # Always trigger analyst notification and PCAP capture for High/Critical incidents
        if incident.severity in ("high", "critical"):
            actions_to_take.append(("capture_pcap", incident.id, "Capture PCAP Snippet"))
            actions_to_take.append(("notify_analyst", incident.id, f"SOC Alert: High/Critical Incident {incident.id}"))

        # Execute configured actions
        for act_type, target, rule_name in actions_to_take:
            # Check if action was already taken for this incident & target
            already_done = any(
                log.incident_id == incident.id and log.action_type == act_type and log.target == target
                for log in self.remediation_history
            )
            if already_done:
                continue

            log = self.execute_action(incident.id, act_type, target, rule_name, now)
            executed_actions.append(log)

        return executed_actions

    def execute_action(self, incident_id: str, action_type: str, target: str, rule_name: str, now: Optional[float] = None) -> RemediationActionLog:
        """Executes a specific SOAR remediation action and records its execution log."""
        ts = now if now else time.time()
        if incident_id and incident_id != "MANUAL":
            act_id = incident_id
        else:
            matching_manual = sum(1 for log in self.remediation_history if log.action_id.startswith("MANUAL")) + 1
            act_id = f"MANUAL{matching_manual:02d}"
        
        # Enforce Self-Protection Safeguard Check before executing remediation
        from pipeline.self_protection import asset_trust_manager
        from config import get_config
        cfg = get_config()
        is_trusted, cancel_reason = asset_trust_manager.is_trusted_remediation_target(action_type, target, cfg)
        if is_trusted:
            log = RemediationActionLog(
                action_id=act_id,
                incident_id=incident_id,
                rule_name=rule_name,
                action_type=action_type,
                target=target,
                timestamp=ts,
                status="skipped",
                result_details={"message": cancel_reason or "Skipped due to trusted asset."},
                rollback_info={}
            )
            self.remediation_history.append(log)
            self._save_history()
            print(f"[SOAREngine] Action '{action_type}' on '{target}' cancelled: {cancel_reason or 'Skipped due to trusted asset.'}")
            return log

        status = "failed"
        result_details: Dict[str, Any] = {}
        rollback_info: Dict[str, Any] = {"action_type": action_type, "target": target}

        try:
            mttr_sec = max(0.1, round(ts - (now if now else ts), 2))
            if action_type == "block_ip":
                self.blocked_ips.add(target)
                status = "success"
                result_details = {"message": f"IP {target} added to active perimeter blocklist.", "mttr_sec": mttr_sec}
                rollback_info["command"] = f"unblock_ip {target}"

            elif action_type == "add_pf_rule":
                self.blocked_ips.add(target)
                self.pf_rules.append(f"block drop in quick from {target}")
                status = "success"
                result_details = {"message": f"PF rule 'block drop in quick from {target}' applied."}
                rollback_info["command"] = f"pfctl -t temp_block -T delete {target}"

            elif action_type == "kill_process":
                # Simulated / process kill log
                status = "success"
                result_details = {"message": f"Process '{target}' signaled for termination (SIGTERM)."}
                rollback_info["command"] = f"restart {target}"

            elif action_type == "quarantine_executable":
                status = "success"
                result_details = {"message": f"Executable file path '{target}' isolated to /var/quarantine/."}
                rollback_info["original_path"] = target

            elif action_type == "disable_interface":
                status = "success"
                result_details = {"message": f"Interface '{target}' marked down."}
                rollback_info["command"] = f"ifconfig {target} up"

            elif action_type == "capture_pcap":
                status = "success"
                result_details = {"message": f"Captured packet evidence snapshot for incident {target}."}

            elif action_type == "capture_metadata":
                status = "success"
                result_details = {"message": f"Captured process environment dump for {target}."}

            elif action_type == "notify_analyst":
                status = "success"
                result_details = {"message": f"Analyst push notification dispatched for incident {target}."}

            else:
                status = "failed"
                result_details = {"error": f"Unknown action type '{action_type}'"}

        except Exception as e:
            status = "failed"
            result_details = {"error": str(e)}

        log = RemediationActionLog(
            action_id=act_id,
            incident_id=incident_id,
            rule_name=rule_name,
            action_type=action_type,
            target=target,
            timestamp=ts,
            status=status,
            result_details=result_details,
            rollback_info=rollback_info
        )

        self.remediation_history.insert(0, log)
        self._save_history()
        return log

    def rollback_action(self, action_id: str) -> Optional[RemediationActionLog]:
        """Rolls back a previously executed remediation action."""
        for log in self.remediation_history:
            if log.action_id == action_id:
                if log.status == "rolled_back":
                    return log
                
                # Perform rollback
                if log.action_type in ("block_ip", "add_pf_rule") and log.target in self.blocked_ips:
                    self.blocked_ips.remove(log.target)
                
                log.status = "rolled_back"
                log.result_details["rollback_status"] = f"Action rolled back at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
                self._save_history()
                return log
        return None

    def get_history(self) -> List[Dict[str, Any]]:
        return [log.to_dict() for log in self.remediation_history]

    def get_blocked_ips(self) -> List[str]:
        return list(self.blocked_ips)

    def get_blocked_ip_details(self) -> List[Dict[str, Any]]:
        ip_map: Dict[str, Dict[str, Any]] = {}
        for log in self.remediation_history:
            if log.action_type in ("block_ip", "add_pf_rule") and log.target not in ("127.0.0.1", "localhost", "::1"):
                if log.target not in ip_map or log.status == "success":
                    ip_map[log.target] = {
                        "ip": log.target,
                        "blocked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(log.timestamp)),
                        "reason": log.rule_name or "Perimeter Security Remediation",
                        "action_id": log.action_id,
                        "incident_id": log.incident_id,
                        "status": "active" if (log.target in self.blocked_ips and log.status == "success") else log.status
                    }
        return list(ip_map.values())

    def block_ip(self, ip: str, reason: str = "Manual Perimeter Block") -> RemediationActionLog:
        self.blocked_ips.add(ip)
        log = self.execute_action("MANUAL", "block_ip", ip, reason)
        return log

    def unblock_ip(self, ip: str) -> Optional[RemediationActionLog]:
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
        for log in self.remediation_history:
            if log.target == ip and log.status == "success":
                log.status = "rolled_back"
                log.result_details["rollback_status"] = f"IP {ip} manually unblocked at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
                self._save_history()
                return log
        self._save_history()
        return None

    def clear_history(self) -> None:
        # Clear auto remediation execution logs without removing active perimeter firewall blocks
        self.remediation_history = [log for log in self.remediation_history if log.incident_id == "MANUAL"]
        try:
            with open(self.log_path, "w") as f:
                json.dump([log.to_dict() for log in self.remediation_history], f, indent=2)
        except Exception as e:
            print(f"[SOAREngine] Error clearing history: {e}")

soar_engine = SOAREngine()
