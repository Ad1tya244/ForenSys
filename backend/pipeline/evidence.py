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
from typing import Dict, Any, List, Optional, Set
from pipeline.correlation_engine import CorrelatedIncident
from pipeline.state_engine import BehaviorStateEngine

EVIDENCE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "evidence_vault.json")
DELETED_EVIDENCE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "deleted_evidence.json")

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
        self.deleted_evidence_timestamps: Dict[str, float] = {}
        self._load_vault()

    def _load_vault(self) -> None:
        if os.path.exists(DELETED_EVIDENCE_FILE):
            try:
                with open(DELETED_EVIDENCE_FILE, "r") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        self.deleted_evidence_timestamps = loaded
                    elif isinstance(loaded, list):
                        self.deleted_evidence_timestamps = {item: time.time() for item in loaded}
            except Exception as e:
                print(f"[EvidenceManager] Error loading deleted evidence file: {e}")

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

            # Deduplicate vault so each threat/incident title has exactly ONE consolidated evidence bundle
            deduped_vault: Dict[str, ForensicEvidencePackage] = {}
            for pkg_id, pkg in list(self.vault.items()):
                target_key = pkg.payload.get("incident_title") or (pkg.payload.get("affected_assets", [""])[0] if pkg.payload.get("affected_assets") else "")
                if not target_key:
                    deduped_vault[pkg_id] = pkg
                    continue
                
                existing_match_id = None
                for existing_id, existing_pkg in deduped_vault.items():
                    existing_key = existing_pkg.payload.get("incident_title") or (existing_pkg.payload.get("affected_assets", [""])[0] if existing_pkg.payload.get("affected_assets") else "")
                    if existing_key == target_key:
                        existing_match_id = existing_id
                        break
                
                if existing_match_id:
                    target_pkg = deduped_vault[existing_match_id]
                    existing_pkts = target_pkg.payload.get("packets", [])
                    new_pkts = pkg.payload.get("packets", [])
                    seen_pkt_keys = {f"{p.get('src_ip')}-{p.get('dst_ip')}-{p.get('info')}" for p in existing_pkts}
                    for pkt in new_pkts:
                        pkey = f"{pkt.get('src_ip')}-{pkt.get('dst_ip')}-{pkt.get('info')}"
                        if pkey not in seen_pkt_keys:
                            existing_pkts.append(pkt)
                            seen_pkt_keys.add(pkey)
                    target_pkg.payload["packets"] = existing_pkts[:100]
                else:
                    deduped_vault[pkg_id] = pkg
            
            # Clean out non-ICMP background packet noise from ICMP flood evidence packages
            for pkg in self.vault.values():
                if "ICMP" in pkg.payload.get("incident_title", ""):
                    pkts = pkg.payload.get("packets", [])
                    icmp_pkts = [p for p in pkts if p.get("protocol") == "ICMP" or "192.168.1.5" in (p.get("src_ip", "") + p.get("dst_ip", ""))]
                    if icmp_pkts:
                        pkg.payload["packets"] = icmp_pkts
            
            self.vault = deduped_vault
            self._save_vault()
        except Exception as e:
            print(f"[EvidenceManager] Error loading vault: {e}")

    def _save_vault(self) -> None:
        try:
            data = [pkg.to_dict() for pkg in self.vault.values()]
            with open(self.vault_path, "w") as f:
                json.dump(data, f, indent=2)
            with open(DELETED_EVIDENCE_FILE, "w") as f:
                json.dump(self.deleted_evidence_timestamps, f, indent=2)
        except Exception as e:
            print(f"[EvidenceManager] Error saving vault: {e}")

    def generate_evidence(self, incident: CorrelatedIncident, state_engine: BehaviorStateEngine) -> Optional[ForensicEvidencePackage]:
        """Captures telemetry snapshot, computes SHA-256 checksum, and seals package for an incident (combining telemetry into a single bundle per incident)."""
        now = time.time()

        # Check if evidence was deleted for this incident and no new alert has fired since deletion
        del_ts = (
            self.deleted_evidence_timestamps.get(incident.id) or
            self.deleted_evidence_timestamps.get(f"EVD-{incident.id}") or
            self.deleted_evidence_timestamps.get(f"evd-{incident.id}".lower())
        )
        if del_ts:
            if incident.updated_at <= del_ts:
                return None
            else:
                self.deleted_evidence_timestamps.pop(incident.id, None)
                self.deleted_evidence_timestamps.pop(f"EVD-{incident.id}", None)

        from pipeline.self_protection import asset_trust_manager, get_primary_host_ip
        host_ip = get_primary_host_ip()

        # Determine dynamic attacker source IP from incident, assets, or related detections
        attacker_ip = incident.primary_source_ip
        if not attacker_ip or attacker_ip in asset_trust_manager.local_ips or attacker_ip in ("127.0.0.1", "localhost", "::1"):
            for asset in incident.affected_assets:
                if asset not in asset_trust_manager.local_ips and asset not in ("127.0.0.1", "localhost", "::1") and ":" not in asset:
                    attacker_ip = asset
                    break
        if not attacker_ip:
            for det in incident.related_detections:
                meta = det.get("metadata", {})
                cand = meta.get("src_ip") or meta.get("attacker_ip") or meta.get("remote_ip")
                if cand and cand not in asset_trust_manager.local_ips and cand not in ("127.0.0.1", "localhost", "::1"):
                    attacker_ip = cand
                    break

        # Search if an evidence bundle ALREADY EXISTS for this exact incident or attacker IP
        existing_evd_id = None
        for pkg_id, pkg in self.vault.items():
            pkg_assets = pkg.payload.get("affected_assets", [])
            if (pkg.incident_id == incident.id or
                (attacker_ip and attacker_ip in pkg_assets and attacker_ip not in asset_trust_manager.local_ips)):
                existing_evd_id = pkg_id
                break

        if existing_evd_id:
            evd_id = existing_evd_id
        else:
            evd_id = f"EVD-{incident.id}"

        # 1. CAPTURE telemetry artifacts around incident timeframe
        packets_captured = []
        logs_captured = []
        processes_captured = []
        connections_captured = []
        listeners_captured = []

        affected_set = set(incident.affected_assets)
        if attacker_ip:
            affected_set.add(attacker_ip)

        is_icmp_incident = "ICMP" in incident.title or any("ICMP" in str(r) for r in incident.timeline)

        for ev in state_engine.events:
            # Strictly filter events related to incident assets
            if is_icmp_incident:
                if ev.event_type == "PACKET":
                    if ev.protocol != "ICMP":
                        continue
                    if ev.src_ip.startswith("fe80:") or ev.dst_ip.startswith("fe80:"):
                        continue
                    is_relevant = (
                        (attacker_ip and (ev.src_ip == attacker_ip or ev.dst_ip == attacker_ip)) or
                        ev.src_ip in affected_set or
                        ev.dst_ip in affected_set or
                        (not ev.src_ip.startswith("127.") and ev.src_ip not in asset_trust_manager.local_ips)
                    )
                    if not is_relevant:
                        continue
                else:
                    if not any(a in str(ev.details.get("message", "")) for a in ("ICMP", attacker_ip or "flood")):
                        continue
            else:
                is_relevant = (
                    ev.src_ip in affected_set or
                    ev.dst_ip in affected_set or
                    ev.process_name in affected_set or
                    any(a in str(ev.details.get("message", "")) for a in affected_set)
                )
                if not is_relevant:
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

        from pipeline.self_protection import get_primary_host_ip
        host_ip = get_primary_host_ip()
        attacker_ip = incident.primary_source_ip or "Remote IP"
        if (attacker_ip in ("127.0.0.1", "localhost", "::1", host_ip)) and packets_captured:
            for p in packets_captured:
                if p.get("src_ip") and p.get("src_ip") not in ("127.0.0.1", "localhost", "::1", host_ip):
                    attacker_ip = p.get("src_ip")
                    break

        payload = {
            "incident_id": incident.id,
            "incident_title": incident.title,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "attacker_ip": attacker_ip,
            "affected_assets": [host_ip] if (is_icmp_incident and not incident.affected_assets) else incident.affected_assets,
            "mitre_stages": incident.mitre_stages,
            "packets": packets_captured if is_icmp_incident else packets_captured[:100],
            "logs": logs_captured,
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
            status=self.vault[evd_id].status if (evd_id in self.vault) else "Sealed",
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

    def delete_evidence(self, evidence_id: str) -> bool:
        clean_id = evidence_id.strip().lower()
        target_id = None
        now = time.time()
        for k, pkg in list(self.vault.items()):
            if (
                k.strip().lower() == clean_id 
                or pkg.incident_id.strip().lower() == clean_id 
                or f"evd-{pkg.incident_id}".strip().lower() == clean_id
                or pkg.evidence_id.strip().lower() == clean_id
            ):
                target_id = k
                self.deleted_evidence_timestamps[target_id] = now
                self.deleted_evidence_timestamps[pkg.evidence_id] = now
                self.deleted_evidence_timestamps[pkg.incident_id] = now
                self.deleted_evidence_timestamps[f"EVD-{pkg.incident_id}"] = now
                break

        if target_id and target_id in self.vault:
            del self.vault[target_id]

        self.deleted_evidence_timestamps[evidence_id] = now
        self.deleted_evidence_timestamps[evidence_id.lower()] = now
        self.deleted_evidence_timestamps[clean_id] = now
        self._save_vault()
        return True

    def get_all_evidence(self) -> List[Dict[str, Any]]:
        return [pkg.to_dict() for pkg in sorted(self.vault.values(), key=lambda p: p.timestamp)]

    def clear_vault(self) -> None:
        self.vault = {}
        try:
            with open(self.vault_path, "w") as f:
                json.dump([], f)
        except Exception as e:
            print(f"[EvidenceManager] Error clearing vault: {e}")
