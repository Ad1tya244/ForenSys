"""
ForenSys Incident Correlation Engine
Correlates related detection alerts into unified, multi-stage Security Incidents.
Calculates cumulative risk scores, maps MITRE ATT&CK kill chain stages, and determines incident severities.
"""

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
        }

class IncidentCorrelationEngine:
    def __init__(self, correlation_window_sec: float = 900.0) -> None:
        self.correlation_window_sec = correlation_window_sec
        self.incidents: List[CorrelatedIncident] = []

    def correlate(self, alerts: List[DetectionAlert], now: Optional[float] = None) -> List[CorrelatedIncident]:
        """Groups new detection alerts into unified CorrelatedIncidents."""
        current_time = now if now else time.time()
        if not alerts:
            return self.incidents

        # 1. Group alerts by matching entity keys (src_ip, dst_ip, or process)
        clusters: Dict[str, List[DetectionAlert]] = {}
        for alert in alerts:
            # Extract key entity identifier
            entity_key = "global"
            if alert.metadata.get("src_ip"):
                entity_key = f"ip_{alert.metadata['src_ip']}"
            elif alert.metadata.get("remote_ip"):
                entity_key = f"ip_{alert.metadata['remote_ip']}"
            elif alert.metadata.get("process"):
                entity_key = f"proc_{alert.metadata['process']}"
            elif alert.affected_assets:
                entity_key = f"asset_{alert.affected_assets[0]}"
            
            if entity_key not in clusters:
                clusters[entity_key] = []
            clusters[entity_key].append(alert)

        # 2. Process clusters into incidents
        for key, cluster_alerts in clusters.items():
            # Check if an existing open incident exists for this entity within correlation window
            existing_inc = None
            for inc in self.incidents:
                if inc.status in ("open", "investigating") and (current_time - inc.updated_at) <= self.correlation_window_sec:
                    if key.startswith("ip_") and (inc.primary_source_ip in key or inc.primary_dest_ip in key):
                        existing_inc = inc
                        break
                    elif key.startswith("proc_") and inc.primary_process in key:
                        existing_inc = inc
                        break

            if existing_inc:
                self._update_incident(existing_inc, cluster_alerts, current_time)
            else:
                new_inc = self._create_incident(cluster_alerts, current_time)
                self.incidents.insert(0, new_inc)

        # Prune old incidents (> 1 day old)
        self.incidents = [inc for inc in self.incidents if (current_time - inc.updated_at) < 86400.0]
        return self.incidents

    def _create_incident(self, alerts: List[DetectionAlert], now: float) -> CorrelatedIncident:
        inc_id = f"INC-{int(now * 1000) % 1000000:06d}"
        
        # Calculate risk score & collect assets
        risk_score = 0
        confidences = []
        mitre_set: Set[str] = set()
        assets_set: Set[str] = set()
        timeline: List[Dict[str, Any]] = []
        related_dets: List[Dict[str, Any]] = []

        src_ip = ""
        dst_ip = ""
        proc_name = ""

        # Sort alerts chronologically
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)

        for a in sorted_alerts:
            score = RULE_SCORES.get(a.rule_name, 30)
            risk_score += score
            confidences.append(a.confidence)
            for m in a.mitre_tactics:
                mitre_set.add(m)
            for asset in a.affected_assets:
                assets_set.add(asset)
            
            from pipeline.self_protection import asset_trust_manager

            candidate_src = a.metadata.get("src_ip") or a.metadata.get("remote_ip") or ""
            candidate_dst = a.metadata.get("dst_ip") or ""
            
            if candidate_src and candidate_src not in asset_trust_manager.local_ips and not candidate_src.startswith("127."):
                if not src_ip:
                    src_ip = candidate_src
            elif candidate_dst and candidate_dst not in asset_trust_manager.local_ips and not candidate_dst.startswith("127."):
                if not src_ip:
                    src_ip = candidate_dst

            if not dst_ip and candidate_dst:
                dst_ip = candidate_dst
            if not proc_name and a.metadata.get("process"):
                proc_name = a.metadata["process"]

            timeline.append({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(a.timestamp)),
                "rule": a.rule_name,
                "title": a.title,
                "description": a.description,
                "severity": a.severity,
            })
            related_dets.append(a.to_dict())

        # Determine severity score mapping: 0-30 Low, 31-60 Medium, 61-80 High, 81+ Critical
        severity = self._calculate_severity(risk_score)
        
        # Map MITRE stages chronologically
        mitre_order = ["Reconnaissance", "Discovery", "Initial Access", "Credential Access", "Execution", "Persistence", "Command and Control", "Exfiltration", "Impact"]
        mitre_stages = [m for m in mitre_order if m in mitre_set]
        if not mitre_stages and mitre_set:
            mitre_stages = list(mitre_set)

        # Synthesize Title
        if len(mitre_stages) >= 2:
            title = f"{' → '.join(mitre_stages[:3])} Intrusion Sequence"
        elif len(sorted_alerts) == 1:
            title = f"Behavioral Incident: {sorted_alerts[0].title}"
        else:
            title = f"Multi-Stage Threat Pattern ({', '.join(a.rule_name for a in sorted_alerts[:2])})"

        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.80

        return CorrelatedIncident(
            id=inc_id,
            title=title,
            severity=severity,
            status="open",
            risk_score=risk_score,
            confidence=avg_confidence,
            created_at=now,
            updated_at=now,
            timeline=timeline,
            related_detections=related_dets,
            mitre_stages=mitre_stages,
            affected_assets=list(assets_set),
            primary_source_ip=src_ip,
            primary_dest_ip=dst_ip,
            primary_process=proc_name
        )

    def _update_incident(self, inc: CorrelatedIncident, new_alerts: List[DetectionAlert], now: float) -> None:
        inc.updated_at = now
        for a in new_alerts:
            # Check if alert already included
            if any(d.get("id") == a.alert_id for d in inc.related_detections):
                continue
            
            score = RULE_SCORES.get(a.rule_name, 30)
            inc.risk_score += score
            for m in a.mitre_tactics:
                if m not in inc.mitre_stages:
                    inc.mitre_stages.append(m)
            for asset in a.affected_assets:
                if asset not in inc.affected_assets:
                    inc.affected_assets.append(asset)
            
            inc.timeline.append({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(a.timestamp)),
                "rule": a.rule_name,
                "title": a.title,
                "description": a.description,
                "severity": a.severity,
            })
            inc.related_detections.append(a.to_dict())

        inc.severity = self._calculate_severity(inc.risk_score)
        
        # Update multi-stage title
        if len(inc.mitre_stages) >= 2:
            inc.title = f"{' → '.join(inc.mitre_stages[:3])} Intrusion Sequence"

    def _calculate_severity(self, risk_score: int) -> str:
        if risk_score >= 81:
            return "critical"
        elif risk_score >= 61:
            return "high"
        elif risk_score >= 31:
            return "medium"
        return "low"
