"""
ForenSys SOAR Auto-Remediation Engine

IMPORTANT: remediation here is purely *logical*. ForenSys never touches the OS firewall, running processes or files.
  - block_ip           -> IP is added to the perimeter blocklist; the packet sniffer ignores all telemetry to/from it
                          until an analyst manually unblocks it.
  - sinkhole_domain    -> domain is added to the DNS sinkhole list; the sniffer ignores DNS traffic for it.
  - quarantine_process -> process is flagged as contained in the ForenSys registry (the process itself is untouched).
  - capture_forensics / capture_pcap / notify_analyst -> evidence + audit trail entries.
Every executed action is recorded in the remediation history with a one-click rollback.
"""

import calendar
import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple
from pipeline.correlation_engine import CorrelatedIncident

REMEDIATION_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "remediation_history.json")
# The perimeter registry (what's currently blocked/quarantined) is persisted separately from the audit log below.
# Clearing the log is a view/housekeeping action; it must never silently release an active containment - an
# analyst clearing old noise from the history should not be the same click as "unblock every attacker."
PERIMETER_REGISTRY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "perimeter_registry.json")

# Action types that add an entry to one of the logical containment registries
BLOCK_ACTIONS = ("block_ip", "add_pf_rule")           # add_pf_rule: legacy history entries
DOMAIN_ACTIONS = ("sinkhole_domain",)
PROCESS_ACTIONS = ("quarantine_process", "kill_process")  # kill_process: legacy history entries
ISO = "%Y-%m-%dT%H:%M:%SZ"


def _iso(ts: float) -> str:
    return time.strftime(ISO, time.gmtime(ts))


@dataclass
class RemediationActionLog:
    action_id: str
    incident_id: str
    rule_name: str
    action_type: str
    target: str
    timestamp: float
    status: str  # success, failed, skipped, rolled_back
    result_details: Dict[str, Any] = field(default_factory=dict)
    rollback_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.action_id,
            "incidentId": self.incident_id,
            "ruleName": self.rule_name,
            "actionType": self.action_type,
            "target": self.target,
            "timestamp": _iso(self.timestamp),
            "status": self.status,
            "resultDetails": self.result_details,
            "rollbackInfo": self.rollback_info,
        }


def _v4(ip: str) -> str:
    from analyzers.ip_intel import ensure_ipv4
    return ensure_ipv4(ip)


class SOAREngine:
    def __init__(self, log_path: str = REMEDIATION_LOG_FILE, registry_path: str = PERIMETER_REGISTRY_FILE) -> None:
        self.log_path = log_path
        self.registry_path = registry_path
        self.remediation_history: List[RemediationActionLog] = []  # newest first; audit log only
        self.blocked_ips: Set[str] = set()
        self.blocked_domains: Set[str] = set()
        self.quarantined_processes: Set[str] = set()
        # Per-target metadata for the registries above (reason/when/which action put it there), keyed the same way.
        self._ip_meta: Dict[str, Dict[str, Any]] = {}
        self._domain_meta: Dict[str, Dict[str, Any]] = {}
        self._process_meta: Dict[str, Dict[str, Any]] = {}
        self._load_history()
        self._load_registry()

    # ── Persistence: audit log ──────────────────────────────────────────────────

    def _load_history(self) -> None:
        if not os.path.exists(self.log_path):
            return
        try:
            with open(self.log_path, "r") as f:
                data = json.load(f)
            for item in data:
                self.remediation_history.append(RemediationActionLog(
                    action_id=item["id"],
                    incident_id=item["incidentId"],
                    rule_name=item["ruleName"],
                    action_type=item["actionType"],
                    target=item["target"],
                    timestamp=calendar.timegm(time.strptime(item["timestamp"], ISO)),
                    status=item["status"],
                    result_details=item.get("resultDetails", {}),
                    rollback_info=item.get("rollbackInfo", {}),
                ))
        except Exception as e:
            print(f"[SOAREngine] Error loading history: {e}")

    def _save_history(self) -> None:
        try:
            data = [log.to_dict() for log in self.remediation_history]
            with open(self.log_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[SOAREngine] Error saving history: {e}")

    # ── Persistence: perimeter registry (what's currently contained) ───────────

    def _load_registry(self) -> None:
        if not os.path.exists(self.registry_path):
            # One-time migration from the old model (registry derived from the history log): reconstruct it
            # from whatever's on file so an existing install doesn't silently drop its active blocks on upgrade.
            if self.remediation_history:
                self._migrate_registry_from_history()
            return
        try:
            with open(self.registry_path, "r") as f:
                data = json.load(f)
            self._ip_meta = data.get("blocked_ips", {})
            self._domain_meta = data.get("blocked_domains", {})
            self._process_meta = data.get("quarantined_processes", {})
            self.blocked_ips = set(self._ip_meta)
            self.blocked_domains = set(self._domain_meta)
            self.quarantined_processes = set(self._process_meta)
        except Exception as e:
            print(f"[SOAREngine] Error loading perimeter registry: {e}")

    def _save_registry(self) -> None:
        try:
            with open(self.registry_path, "w") as f:
                json.dump({
                    "blocked_ips": self._ip_meta,
                    "blocked_domains": self._domain_meta,
                    "quarantined_processes": self._process_meta,
                }, f, indent=2)
        except Exception as e:
            print(f"[SOAREngine] Error saving perimeter registry: {e}")

    def _migrate_registry_from_history(self) -> None:
        """Runs once, only when no registry file exists yet: replays the audit log oldest-first so the most
        recent status of every target wins, to seed the new independent registry from pre-upgrade history."""
        for log in reversed(self.remediation_history):  # history is newest-first
            target_set, meta = self._registry_for(log.action_type)
            if target_set is None:
                continue
            key = log.target.lower() if log.action_type in DOMAIN_ACTIONS else log.target
            if log.status == "success":
                target_set.add(key)
                meta[key] = {"status": "active", "blocked_at": _iso(log.timestamp), "released_at": None,
                            "reason": log.rule_name, "action_id": log.action_id, "incident_id": log.incident_id}
            elif log.status == "rolled_back" and key in meta:
                target_set.discard(key)
                meta[key]["status"] = "released"
                meta[key]["released_at"] = _iso(log.timestamp)
        self._save_registry()
        print(f"[SOAREngine] Migrated perimeter registry from history: "
              f"{len(self.blocked_ips)} IP(s), {len(self.blocked_domains)} domain(s), "
              f"{len(self.quarantined_processes)} process(es).")

    def _registry_for(self, action_type: str) -> Tuple[Optional[Set[str]], Optional[Dict[str, Dict[str, Any]]]]:
        if action_type in BLOCK_ACTIONS:
            return self.blocked_ips, self._ip_meta
        if action_type in DOMAIN_ACTIONS:
            return self.blocked_domains, self._domain_meta
        if action_type in PROCESS_ACTIONS:
            return self.quarantined_processes, self._process_meta
        return None, None

    def _contain(self, action_type: str, target: str, act_id: str, incident_id: str, rule_name: str, ts: float) -> None:
        """Adds target to its perimeter registry, persisted independently of the audit log. Re-blocking a
        previously-released target simply reactivates its row (fresh reason/timestamp) rather than duplicating it."""
        target_set, meta = self._registry_for(action_type)
        if target_set is None:
            return
        key = target.lower() if action_type in DOMAIN_ACTIONS else target
        target_set.add(key)
        meta[key] = {
            "status": "active", "blocked_at": _iso(ts), "released_at": None,
            "reason": rule_name or "Perimeter Security Remediation",
            "action_id": act_id, "incident_id": incident_id,
        }
        self._save_registry()

    def _release(self, action_type: str, target: str) -> None:
        """Manual unblock / rollback: stops containment (removed from the active set the sniffer checks) but
        keeps the row in the registry, marked 'released', so it stays visible and can be re-blocked with one
        click instead of vanishing from the Playbooks list."""
        target_set, meta = self._registry_for(action_type)
        if target_set is None:
            return
        key = target.lower() if action_type in DOMAIN_ACTIONS else target
        target_set.discard(key)
        if key in meta:
            meta[key]["status"] = "released"
            meta[key]["released_at"] = _iso(time.time())
        self._save_registry()

    # ── Blocklist queries used by the packet sniffer ──────────────────────────

    def is_blocked(self, ip: str) -> bool:
        if not ip or not self.blocked_ips:
            return False
        return ip in self.blocked_ips or _v4(ip) in self.blocked_ips

    def is_domain_blocked(self, text: str) -> bool:
        low = (text or "").lower()
        return any(d in low for d in self.blocked_domains)

    # ── Planning ──────────────────────────────────────────────────────────────

    def plan_actions(self, incident: CorrelatedIncident) -> List[Tuple[str, str, str]]:
        """Maps an incident to the logical containment actions it warrants: (action_type, target, reason)."""
        from pipeline.self_protection import asset_trust_manager
        reason = incident.title
        plan: List[Tuple[str, str, str]] = []

        for ip in incident.block_ips:
            if ip and ip not in plan:
                plan.append(("block_ip", ip, reason))
        for domain in incident.block_domains:
            plan.append(("sinkhole_domain", domain, reason))
        for proc in incident.quarantine_processes:
            plan.append(("quarantine_process", proc, reason))

        if incident.severity in ("high", "critical"):
            plan.append(("notify_analyst", incident.id, f"SOC Alert: {incident.severity.upper()} incident {incident.id}"))
        return plan

    # ── Execution ─────────────────────────────────────────────────────────────

    def _next_action_id(self, incident_id: str) -> str:
        if incident_id and incident_id != "MANUAL":
            n = sum(1 for log in self.remediation_history if log.incident_id == incident_id) + 1
            return f"{incident_id}-A{n}"
        n = sum(1 for log in self.remediation_history if log.action_id.startswith("MANUAL")) + 1
        return f"MANUAL{n:02d}"

    def remediate(self, incident: CorrelatedIncident, now: Optional[float] = None) -> List[RemediationActionLog]:
        """Executes the containment plan for an incident (idempotent per incident/action/target)."""
        if not incident or not incident.id:
            print("[SOAREngine] Execution rejected: Missing incident context.")
            return []
        now = now if now else time.time()
        executed: List[RemediationActionLog] = []
        for act_type, target, reason in self.plan_actions(incident):
            already_done = any(
                log.incident_id == incident.id and log.action_type == act_type and log.target == target
                and log.status in ("success", "skipped")
                for log in self.remediation_history
            )
            if already_done:
                continue
            context = {
                "detected_at": _iso(incident.created_at),
                "mttr_sec": round(max(0.0, now - incident.created_at), 3),
                "severity": incident.severity,
                "attack_type": incident.attack_types[0] if incident.attack_types else "",
            }
            executed.append(self.execute_action(incident.id, act_type, target, reason, now, context))
        return executed

    def evaluate_and_remediate(self, incident: CorrelatedIncident, soar_playbook_rules: Optional[List[Dict[str, Any]]] = None) -> List[RemediationActionLog]:
        """Backwards-compatible entry point (playbook rules no longer gate containment)."""
        return self.remediate(incident)

    def execute_action(self, incident_id: str, action_type: str, target: str, rule_name: str,
                       now: Optional[float] = None, context: Optional[Dict[str, Any]] = None) -> RemediationActionLog:
        """Executes one logical SOAR action and records it in the history."""
        ts = now if now else time.time()
        act_id = self._next_action_id(incident_id)
        ctx = dict(context or {})

        # Self-protection safeguard: never contain ForenSys's own assets
        from pipeline.self_protection import asset_trust_manager
        from config import get_config
        is_trusted, cancel_reason = asset_trust_manager.is_trusted_remediation_target(action_type, target, get_config())
        if is_trusted:
            log = RemediationActionLog(
                action_id=act_id, incident_id=incident_id, rule_name=rule_name, action_type=action_type,
                target=target, timestamp=ts, status="skipped",
                result_details={"message": cancel_reason or "Skipped due to trusted asset.", **ctx},
            )
            self.remediation_history.insert(0, log)
            self._save_history()
            print(f"[SOAREngine] Action '{action_type}' on '{target}' cancelled: {cancel_reason}")
            return log

        status = "success"
        details: Dict[str, Any] = dict(ctx)
        rollback_info: Dict[str, Any] = {"action_type": action_type, "target": target}

        if action_type in BLOCK_ACTIONS:
            self._contain(action_type, target, act_id, incident_id, rule_name, ts)
            details["message"] = (f"IP {target} added to the perimeter blocklist - packet sniffer now ignores all "
                                  f"telemetry to/from it until manually unblocked (no OS firewall change).")
            rollback_info["command"] = f"unblock_ip {target}"
        elif action_type in DOMAIN_ACTIONS:
            self._contain(action_type, target, act_id, incident_id, rule_name, ts)
            details["message"] = (f"Domain {target} sinkholed - packet sniffer ignores DNS traffic for it "
                                  f"until manually released (no DNS/OS change).")
            rollback_info["command"] = f"release_domain {target}"
        elif action_type in PROCESS_ACTIONS:
            self._contain(action_type, target, act_id, incident_id, rule_name, ts)
            details["message"] = (f"Process '{target}' flagged as contained in the ForenSys registry "
                                  f"(simulated - the process itself is not signalled or modified).")
            details["simulated"] = True
            rollback_info["command"] = f"release_process {target}"
        elif action_type == "capture_forensics":
            details.setdefault("message", f"Forensic evidence for incident {target} captured and sealed.")
        elif action_type == "capture_pcap":
            details.setdefault("message", f"Packet capture for incident {target} saved.")
        elif action_type == "notify_analyst":
            details["message"] = f"Analyst notification dispatched for incident {target}."
        else:
            status = "failed"
            details["error"] = f"Unknown action type '{action_type}'"

        log = RemediationActionLog(
            action_id=act_id, incident_id=incident_id, rule_name=rule_name, action_type=action_type,
            target=target, timestamp=ts, status=status, result_details=details, rollback_info=rollback_info,
        )
        self.remediation_history.insert(0, log)
        self._save_history()
        return log

    def record(self, incident_id: str, action_type: str, target: str, rule_name: str,
               details: Dict[str, Any], now: Optional[float] = None) -> RemediationActionLog:
        """Appends an informational history entry (evidence capture etc.) without side effects."""
        return self.execute_action(incident_id, action_type, target, rule_name, now, details)

    # ── Rollback / manual control ─────────────────────────────────────────────

    def rollback_action(self, action_id: str) -> Optional[RemediationActionLog]:
        """Rolls back one previously executed remediation action (by its unique id)."""
        for log in self.remediation_history:
            if log.action_id != action_id:
                continue
            if log.status == "rolled_back":
                return log
            self._release(log.action_type, log.target)
            log.status = "rolled_back"
            log.result_details["rollback_status"] = f"Action rolled back at {_iso(time.time())}"
            self._save_history()
            return log
        return None

    def get_history(self) -> List[Dict[str, Any]]:
        return [log.to_dict() for log in self.remediation_history]

    def get_blocked_ips(self) -> List[str]:
        return sorted(self.blocked_ips)

    def get_blocked_ip_details(self) -> List[Dict[str, Any]]:
        """Reads straight from the perimeter registry: every IP ForenSys has ever blocked, active or not, so a
        manually-unblocked IP stays visible on the Playbooks page (status 'released') and can be re-blocked
        with one click instead of disappearing. Active ones are listed first, each group newest first."""
        rows = [
            {
                "ip": ip,
                "blocked_at": meta.get("blocked_at"),
                "released_at": meta.get("released_at"),
                "reason": meta.get("reason", "Perimeter Security Remediation"),
                "action_id": meta.get("action_id"),
                "incident_id": meta.get("incident_id"),
                "status": meta.get("status", "active"),  # legacy rows predating this field were always active
            }
            for ip, meta in self._ip_meta.items()
        ]
        rows.sort(key=lambda r: r.get("released_at") or r.get("blocked_at") or "", reverse=True)  # newest first...
        rows.sort(key=lambda r: r["status"] != "active")  # ...within each group; stable sort keeps active on top
        return rows

    def block_ip(self, ip: str, reason: str = "Manual Perimeter Block") -> RemediationActionLog:
        return self.execute_action("MANUAL", "block_ip", ip, reason)

    def unblock_ip(self, ip: str) -> Optional[RemediationActionLog]:
        """Manual unblock: removes the IP from the blocklist and marks its block action(s) as rolled back."""
        self._release("block_ip", ip)
        touched: Optional[RemediationActionLog] = None
        for log in self.remediation_history:
            if log.action_type in BLOCK_ACTIONS and log.target == ip and log.status == "success":
                log.status = "rolled_back"
                log.result_details["rollback_status"] = f"IP {ip} manually unblocked at {_iso(time.time())}"
                touched = touched or log
        self._save_history()
        return touched

    def clear_log(self) -> None:
        """Clears the remediation AUDIT LOG only. Active containment (blocked IPs/domains, quarantined
        processes) is left exactly as it was - clearing old history rows must never silently let an
        attacker's traffic back through. Use reset_all() to release containment too."""
        self.remediation_history.clear()
        try:
            with open(self.log_path, "w") as f:
                json.dump([], f, indent=2)
        except Exception as e:
            print(f"[SOAREngine] Error clearing history: {e}")

    def reset_all(self) -> None:
        """Full reset for starting a fresh demo: clears the audit log AND releases every active containment."""
        self.clear_log()
        self.blocked_ips.clear()
        self.blocked_domains.clear()
        self.quarantined_processes.clear()
        self._ip_meta.clear()
        self._domain_meta.clear()
        self._process_meta.clear()
        self._save_registry()

    # Backward-compatible alias (old call sites / tests): full reset, matching the previous behavior.
    clear_history = reset_all

soar_engine = SOAREngine()
