"""
ForenSys Incident Correlation Engine
Correlates related detection alerts into unified, multi-stage Security Incidents.
Calculates cumulative risk scores, maps MITRE ATT&CK kill chain stages, and determines incident severities.
"""

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional
from pipeline.rules.base import DetectionAlert

RULE_SCORES: Dict[str, int] = {
    "ICMP Flood": 20,
    "Port Scan": 30,
    "SYN Flood": 30,
    "Authentication Attack Correlation": 40,
    "Brute Force Authentication": 40,
    "Suspicious Listening Port": 35,
    "Suspicious Process Chain": 45,
    "DNS Beaconing": 50,
    "Data Exfiltration": 60,
    "Reverse Shell": 80,
}

RULE_PREFIXES: Dict[str, str] = {
    "ICMP Flood": "ICMP",
    "Port Scan": "SCAN",
    "SYN Flood": "SYN",
    "Brute Force Authentication": "AUTH",
    "Authentication Attack Correlation": "AUTH",
    "DNS Beaconing": "DNS",
    "Reverse Shell": "SHELL",
    "Data Exfiltration": "EXFIL",
    "Suspicious Listening Port": "LISTEN",
    "Suspicious Process Chain": "PROC",
}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _dedupe(values: List[str]) -> List[str]:
    seen: List[str] = []
    for v in values:
        if v and v not in seen:
            seen.append(v)
    return seen


@dataclass
class CorrelatedIncident:
    id: str
    title: str
    severity: str  # low, medium, high, critical
    status: str    # open, investigating, contained, resolved
    risk_score: int
    confidence: float
    created_at: float
    updated_at: float
    timeline: List[Dict[str, Any]]
    related_detections: List[Dict[str, Any]]
    mitre_stages: List[str]
    affected_assets: List[str]
    primary_source_ip: str = ""
    primary_dest_ip: str = ""
    primary_process: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    # Logical containment targets gathered from the member alerts (see SOAREngine.plan_actions)
    block_ips: List[str] = field(default_factory=list)
    block_domains: List[str] = field(default_factory=list)
    quarantine_processes: List[str] = field(default_factory=list)
    attack_types: List[str] = field(default_factory=list)
    entity_keys: Set[str] = field(default_factory=set)
    handled_alerts: Set[str] = field(default_factory=set)  # alert ids already run through the response workflow
    contained_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "riskScore": self.risk_score,
            "confidence": round(self.confidence, 2),
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.created_at)),
            "lastUpdated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.updated_at)),
            "timeline": self.timeline,
            "relatedAlerts": [d.get("id") for d in self.related_detections],
            "relatedDetections": self.related_detections,
            "mitreStages": self.mitre_stages,
            "affectedAssets": self.affected_assets,
            "primarySourceIp": self.primary_source_ip,
            "primaryDestIp": self.primary_dest_ip,
            "primaryProcess": self.primary_process,
            "evidenceCount": len(self.evidence_ids),
            "evidenceIds": self.evidence_ids,
            "blockIps": self.block_ips,
            "blockDomains": self.block_domains,
            "quarantineProcesses": self.quarantine_processes,
            "attackTypes": self.attack_types,
            "containedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.contained_at)) if self.contained_at else None,
        }

class IncidentCorrelationEngine:
    def __init__(self, correlation_window_sec: float = 900.0) -> None:
        self.correlation_window_sec = correlation_window_sec
        self.incidents: List[CorrelatedIncident] = []
        self._counters: Dict[str, int] = {}
        self._alert_incident: Dict[str, str] = {}  # alert id -> incident id (an alert is only ever reported once)

    def seed_counters(self, incident_ids: List[str]) -> None:
        """Continue numbering after ids already used in persisted history/evidence (ids must stay unique across restarts)."""
        for iid in incident_ids:
            m = re.match(r"^([A-Za-z]+)(\d+)", iid or "")
            if m:
                self._counters[m.group(1)] = max(self._counters.get(m.group(1), 0), int(m.group(2)))

    def reset(self) -> None:
        self.incidents.clear()
        self._alert_incident.clear()

    @staticmethod
    def _entity_keys(alert: DetectionAlert) -> Set[str]:
        """All entities an alert is about (remote IPs, process), so alerts sharing any entity land in one incident."""
        from analyzers.ip_intel import ensure_ipv4
        from pipeline.state_engine import is_local_ip
        md = alert.metadata
        keys: Set[str] = set()
        for field_name in ("block_ip", "src_ip", "remote_ip"):
            val = md.get(field_name)
            if val and not is_local_ip(val):
                keys.add(f"ip_{ensure_ipv4(val)}")
        if not keys and md.get("process"):
            keys.add(f"proc_{md['process']}")
        if not keys and alert.affected_assets:
            keys.add(f"asset_{ensure_ipv4(alert.affected_assets[0])}")
        return keys or {"global"}

    def correlate(self, alerts: List[DetectionAlert], now: Optional[float] = None) -> List[CorrelatedIncident]:
        """Groups new detection alerts into unified CorrelatedIncidents."""
        current_time = now if now else time.time()
        if not alerts:
            return self.incidents

        # 1. Cluster not-yet-reported alerts that share an entity
        clusters: List[Dict[str, Any]] = []   # {"keys": set, "alerts": [..]}
        for alert in alerts:
            if alert.alert_id in self._alert_incident:
                continue
            keys = self._entity_keys(alert)
            hits = [c for c in clusters if c["keys"] & keys]
            if hits:
                target = hits[0]
                for other in hits[1:]:
                    target["keys"] |= other["keys"]
                    target["alerts"] += other["alerts"]
                    clusters.remove(other)
                target["keys"] |= keys
                target["alerts"].append(alert)
            else:
                clusters.append({"keys": set(keys), "alerts": [alert]})

        # 2. Merge each cluster into an open incident sharing an entity, or open a new one
        for cluster in clusters:
            keys, cluster_alerts = cluster["keys"], cluster["alerts"]
            existing_inc = None
            for inc in self.incidents:
                if (inc.status in ("open", "investigating")
                        and (current_time - inc.updated_at) <= self.correlation_window_sec
                        and inc.entity_keys & keys):
                    existing_inc = inc
                    break

            if existing_inc:
                self._update_incident(existing_inc, cluster_alerts, current_time)
                target_inc = existing_inc
            else:
                target_inc = self._create_incident(cluster_alerts, current_time)
                self.incidents.insert(0, target_inc)
            target_inc.entity_keys |= keys
            for a in cluster_alerts:
                self._alert_incident[a.alert_id] = target_inc.id

        # Prune old incidents (> 1 day old)
        self.incidents = [inc for inc in self.incidents if (current_time - inc.updated_at) < 86400.0]
        if len(self._alert_incident) > 5000:
            live = {a.get("id") for inc in self.incidents for a in inc.related_detections}
            self._alert_incident = {k: v for k, v in self._alert_incident.items() if k in live}
        return self.incidents

    def _next_id(self, prefix: str) -> str:
        used = [int("".join(ch for ch in inc.id[len(prefix):] if ch.isdigit()) or 0)
                for inc in self.incidents if inc.id.startswith(prefix)]
        self._counters[prefix] = max(self._counters.get(prefix, 0), max(used, default=0)) + 1
        return f"{prefix}{self._counters[prefix]:02d}"

    @staticmethod
    def _absorb_targets(inc: CorrelatedIncident, a: DetectionAlert) -> None:
        md = a.metadata
        inc.block_ips = _dedupe(inc.block_ips + [md.get("block_ip", "")])
        inc.block_domains = _dedupe(inc.block_domains + [md.get("block_domain", "")])
        inc.quarantine_processes = _dedupe(inc.quarantine_processes + [md.get("quarantine_process", "")])
        inc.attack_types = _dedupe(inc.attack_types + [md.get("attack_type", "")])

    def _create_incident(self, alerts: List[DetectionAlert], now: float) -> CorrelatedIncident:
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
        prefix = RULE_PREFIXES.get(sorted_alerts[0].rule_name, "SEC")
        inc_id = self._next_id(prefix)

        confidences = [a.confidence for a in sorted_alerts]
        mitre_set: Set[str] = set()
        assets_set: List[str] = []
        timeline: List[Dict[str, Any]] = []
        related_dets: List[Dict[str, Any]] = []
        proc_name = ""
        dst_ip = ""

        inc = CorrelatedIncident(
            id=inc_id, title="", severity="low", status="open", risk_score=0,
            confidence=sum(confidences) / len(confidences) if confidences else 0.80,
            created_at=now, updated_at=now, timeline=timeline, related_detections=related_dets,
            mitre_stages=[], affected_assets=[],
        )
        for a in sorted_alerts:
            inc.risk_score += RULE_SCORES.get(a.rule_name, 30)
            mitre_set.update(a.mitre_tactics)
            for asset in a.affected_assets:
                if asset not in assets_set:
                    assets_set.append(asset)
            self._absorb_targets(inc, a)
            if not dst_ip:
                dst_ip = a.metadata.get("target_ip") or a.metadata.get("dst_ip") or ""
            if not proc_name and a.metadata.get("process"):
                proc_name = a.metadata["process"]
            timeline.append(self._timeline_entry(a))
            related_dets.append(a.to_dict())

        mitre_order = ["Reconnaissance", "Discovery", "Initial Access", "Credential Access", "Execution", "Persistence",
                       "Command and Control", "Exfiltration", "Impact"]
        inc.mitre_stages = [m for m in mitre_order if m in mitre_set] or list(mitre_set)
        inc.affected_assets = assets_set
        inc.primary_source_ip = inc.block_ips[0] if inc.block_ips else ""
        inc.primary_dest_ip = dst_ip
        inc.primary_process = proc_name
        inc.severity = self._calculate_severity(inc.risk_score, sorted_alerts)
        inc.title = self._title(inc, sorted_alerts)
        return inc

    def _update_incident(self, inc: CorrelatedIncident, new_alerts: List[DetectionAlert], now: float) -> None:
        inc.updated_at = now
        for a in sorted(new_alerts, key=lambda x: x.timestamp):
            if any(d.get("id") == a.alert_id for d in inc.related_detections):
                continue
            inc.risk_score += RULE_SCORES.get(a.rule_name, 30)
            for m in a.mitre_tactics:
                if m not in inc.mitre_stages:
                    inc.mitre_stages.append(m)
            for asset in a.affected_assets:
                if asset not in inc.affected_assets:
                    inc.affected_assets.append(asset)
            self._absorb_targets(inc, a)
            if not inc.primary_source_ip and inc.block_ips:
                inc.primary_source_ip = inc.block_ips[0]
            inc.timeline.append(self._timeline_entry(a))
            inc.related_detections.append(a.to_dict())

        all_alerts_sev = [d.get("severity", "low") for d in inc.related_detections]
        inc.severity = self._calculate_severity(inc.risk_score, severities=all_alerts_sev)
        rules = [t["rule"] for t in inc.timeline]
        if len(set(rules)) > 1:
            inc.title = self._multi_title(inc, rules)

    @staticmethod
    def _timeline_entry(a: DetectionAlert) -> Dict[str, Any]:
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(a.timestamp)),
            "rule": a.rule_name,
            "title": a.title,
            "description": a.description,
            "severity": a.severity,
        }

    @staticmethod
    def _multi_title(inc: CorrelatedIncident, rules: List[str]) -> str:
        uniq = _dedupe(rules)
        where = f" from {inc.block_ips[0]}" if inc.block_ips else ""
        return f"Multi-Stage Attack: {' + '.join(uniq[:3])}{where}"

    def _title(self, inc: CorrelatedIncident, alerts: List[DetectionAlert]) -> str:
        rules = [a.rule_name for a in alerts]
        if len(set(rules)) > 1:
            return self._multi_title(inc, rules)
        return alerts[0].title

    def _calculate_severity(self, risk_score: int, alerts: Optional[List[DetectionAlert]] = None,
                            severities: Optional[List[str]] = None) -> str:
        sevs = severities if severities is not None else [a.severity for a in (alerts or [])]
        base = max(sevs, key=lambda x: SEVERITY_ORDER.get(x, 0), default="low")
        by_score = "critical" if risk_score >= 81 else "high" if risk_score >= 61 else "medium" if risk_score >= 31 else "low"
        return max(base, by_score, key=lambda x: SEVERITY_ORDER.get(x, 0))
