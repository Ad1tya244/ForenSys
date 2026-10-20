"""
ForenSys Incident Response Orchestrator

Runs the standard workflow for every incident, in this order:

    attack detected -> incident raised -> auto-remediation (logical containment) -> forensic evidence sealed -> history

Containment is purely logical (blocklist / sinkhole / process flag, see SOAREngine) - no firewall or process is touched.
The evidence snapshot is taken *before* containment, because blocking an IP makes the sniffer ignore (and the state
engine purge) its traffic; the package is sealed right after, including the list of containment actions taken.
"""

import time
from typing import List, Optional
from pipeline.correlation_engine import CorrelatedIncident
from pipeline.evidence import EvidenceManager
from pipeline.soar_engine import SOAREngine, RemediationActionLog, BLOCK_ACTIONS, DOMAIN_ACTIONS, PROCESS_ACTIONS
from pipeline.state_engine import BehaviorStateEngine

CONTAINMENT_ACTIONS = BLOCK_ACTIONS + DOMAIN_ACTIONS + PROCESS_ACTIONS


class ResponseOrchestrator:
    def __init__(self, soar: SOAREngine, evidence: EvidenceManager, state_engine: BehaviorStateEngine) -> None:
        self.soar = soar
        self.evidence = evidence
        self.state_engine = state_engine

    def handle(self, incident: CorrelatedIncident, now: Optional[float] = None) -> List[RemediationActionLog]:
        """Responds to any not-yet-handled detections of an open incident. Returns the history entries created."""
        if incident.status not in ("open", "investigating"):
            return []
        pending = [d.get("id") for d in incident.related_detections if d.get("id") not in incident.handled_alerts]
        if not pending:
            return []
        now = now if now else time.time()

        # 1. Snapshot the attack telemetry while it is still in the state engine
        payload = self.evidence.collect(incident, self.state_engine, now)

        # 2. Auto-remediation (logical containment)
        actions = self.soar.remediate(incident, now)
        incident.handled_alerts.update(pending)
        contained = any(a.status == "success" and a.action_type in CONTAINMENT_ACTIONS for a in actions)
        for a in actions:
            if a.status == "success" and a.action_type in BLOCK_ACTIONS:
                self.state_engine.purge_ip(a.target)

        # 3. Seal the evidence (now including what was done about the attack)
        summary = [{"id": a.action_id, "action": a.action_type, "target": a.target, "status": a.status,
                    "time": a.to_dict()["timestamp"], "message": a.result_details.get("message")} for a in actions]
        pkg = self.evidence.seal(incident, payload, summary, now)

        # 4. Log the forensic capture in the remediation history
        details = pkg.payload.get("attack_details", {})
        ports = (details.get("port_scan") or {}).get("ports_probed")
        logged: List[RemediationActionLog] = [self.soar.record(
            incident.id, "capture_forensics", pkg.evidence_id, incident.title,
            {
                "message": (f"Forensic evidence {pkg.evidence_id} sealed (SHA-256 {pkg.sha256_hash[:16]}...): "
                            f"{pkg.payload.get('packet_total', 0)} packets, {len(pkg.payload.get('logs', []))} logs, "
                            f"{len(pkg.payload.get('connections', []))} connections captured."),
                "evidence_id": pkg.evidence_id, "sha256": pkg.sha256_hash,
                "attacker_ip": pkg.payload.get("attacker_ip"),
                "packets": pkg.payload.get("packet_total", 0), "logs": len(pkg.payload.get("logs", [])),
                "ports_probed": ports, "detected_at": pkg.payload["timing"]["detected_at"],
                "mttr_sec": round(max(0.0, now - incident.created_at), 3),
            },
            now)]
        for art in pkg.payload.get("artifacts", []):
            if art["name"].endswith(".pcap"):
                logged.append(self.soar.record(
                    incident.id, "capture_pcap", art["path"], incident.title,
                    {"message": f"Packet capture saved: {art['path']} ({art['packets']} packets, SHA-256 {art['sha256'][:16]}...)",
                     "sha256": art["sha256"], "bytes": art["bytes"], "evidence_id": pkg.evidence_id}, now))

        if contained:
            incident.status = "contained"
            incident.contained_at = now
        else:
            incident.status = "investigating"
        incident.updated_at = now
        return actions + logged
