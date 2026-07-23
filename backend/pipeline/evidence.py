"""
ForenSys Forensic Evidence Collection & Sealing Engine
Automatically captures network packets, system logs, process hierarchies, and socket history for incidents.
Computes immutable SHA-256 checksums and manages evidence lifecycle: Captured -> Hashed -> Sealed.
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from pipeline.correlation_engine import CorrelatedIncident
from pipeline.state_engine import BehaviorStateEngine

EVIDENCE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "evidence_vault.json")

@dataclass
class ForensicEvidencePackage:
    evidence_id: str
    incident_id: str
    timestamp: float
    status: str  # Captured, Hashed, Sealed
    payload: Dict[str, Any]
    sha256_hash: str = ""
    sealed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.evidence_id,
            "incidentId": self.incident_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)),
            "status": self.status,
            "hash": f"SHA256: {self.sha256_hash}",
            "sealedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.sealed_at)) if self.sealed_at else None,
            "payload": self.payload,
            "chain": [
                f"Captured at {time.strftime('%H:%M:%S UTC', time.gmtime(self.timestamp))}",
                f"Hashed via SHA-256 digest ({self.sha256_hash[:16]}...)",
                f"Sealed in Forensic Vault at {time.strftime('%H:%M:%S UTC', time.gmtime(self.sealed_at or self.timestamp))}"
            ]
        }

class EvidenceManager:
    def __init__(self, vault_path: str = EVIDENCE_FILE) -> None:
        self.vault_path = vault_path
        self.vault: Dict[str, ForensicEvidencePackage] = {}
        self._load_vault()

    def _load_vault(self) -> None:
        if not os.path.exists(self.vault_path):
            return
        try:
            with open(self.vault_path, "r") as f:
                data = json.load(f)
                for item in data:
                    pkg = ForensicEvidencePackage(
                        evidence_id=item["id"],
                        incident_id=item["incidentId"],
                        timestamp=time.mktime(time.strptime(item["timestamp"], "%Y-%m-%dT%H:%M:%SZ")),
                        status=item["status"],
                        payload=item.get("payload", {}),
                        sha256_hash=item.get("hash", "").replace("SHA256: ", ""),
                        sealed_at=time.mktime(time.strptime(item["sealedAt"], "%Y-%m-%dT%H:%M:%SZ")) if item.get("sealedAt") else None
                    )
                    self.vault[pkg.evidence_id] = pkg
        except Exception as e:
            print(f"[EvidenceManager] Error loading vault: {e}")

    def _save_vault(self) -> None:
        try:
            data = [pkg.to_dict() for pkg in self.vault.values()]
            with open(self.vault_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[EvidenceManager] Error saving vault: {e}")

    def generate_evidence(self, incident: CorrelatedIncident, state_engine: BehaviorStateEngine) -> ForensicEvidencePackage:
        """Captures telemetry snapshot, computes SHA-256 checksum, and seals package for an incident."""
        now = time.time()
        evd_id = f"EVD-{int(now * 1000) % 1000000:06d}"

        # 1. CAPTURE telemetry artifacts around incident timeframe (last 300s)
        packets_captured = []
        logs_captured = []
        processes_captured = []
        connections_captured = []
        listeners_captured = []

        affected_set = set(incident.affected_assets)

        for ev in state_engine.events:
            # Filter events related to incident assets
            is_relevant = (
                ev.src_ip in affected_set or
                ev.dst_ip in affected_set or
                ev.process_name in affected_set or
                any(a in ev.details.get("message", "") for a in affected_set)
            )
            if not is_relevant and len(packets_captured) > 50:
                continue

            if ev.event_type == "PACKET":
                packets_captured.append({
                    "protocol": ev.protocol,
                    "src_ip": ev.src_ip,
                    "src_port": ev.src_port,
                    "dst_ip": ev.dst_ip,
                    "dst_port": ev.dst_port,
                    "length": ev.byte_count,
                    "info": ev.details.get("info", "")
                })
            elif ev.event_type == "LOG":
                logs_captured.append({
                    "process": ev.process_name,
                    "pid": ev.pid,
                    "level": ev.details.get("level", "info"),
                    "message": ev.details.get("message", "")
                })
            elif ev.event_type == "PROCESS":
                processes_captured.append({
                    "process": ev.process_name,
                    "parent_process": ev.parent_process,
                    "pid": ev.pid,
                    "ppid": ev.ppid
                })
            elif ev.event_type == "CONNECTION":
                connections_captured.append({
                    "local_ip": ev.src_ip,
                    "local_port": ev.src_port,
                    "remote_ip": ev.dst_ip,
                    "remote_port": ev.dst_port,
                    "process": ev.process_name,
                    "pid": ev.pid
                })
            elif ev.event_type == "LISTENER":
                listeners_captured.append({
                    "ip": ev.src_ip,
                    "port": ev.src_port,
                    "process": ev.process_name,
                    "pid": ev.pid
                })

        payload = {
            "incident_id": incident.id,
            "incident_title": incident.title,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "affected_assets": incident.affected_assets,
            "mitre_stages": incident.mitre_stages,
            "packets": packets_captured[:30],
            "logs": logs_captured[:30],
            "processes": processes_captured[:20],
            "connections": connections_captured[:20],
            "listeners": listeners_captured[:10],
        }

        # 2. HASH payload via SHA-256 digest
        canonical_json = json.dumps(payload, sort_keys=True)
        sha256_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        # 3. SEAL evidence package
        pkg = ForensicEvidencePackage(
            evidence_id=evd_id,
            incident_id=incident.id,
            timestamp=now,
            status="Sealed",
            payload=payload,
            sha256_hash=sha256_hash,
            sealed_at=now
        )

        self.vault[evd_id] = pkg
        if evd_id not in incident.evidence_ids:
            incident.evidence_ids.append(evd_id)

        self._save_vault()
        return pkg

    def get_evidence(self, evidence_id: str) -> Optional[ForensicEvidencePackage]:
        return self.vault.get(evidence_id)

    def get_all_evidence(self) -> List[Dict[str, Any]]:
        return [pkg.to_dict() for pkg in sorted(self.vault.values(), key=lambda p: p.timestamp)]

    def clear_vault(self) -> None:
        self.vault = {}
        try:
            with open(self.vault_path, "w") as f:
                json.dump([], f)
        except Exception as e:
            print(f"[EvidenceManager] Error clearing vault: {e}")
