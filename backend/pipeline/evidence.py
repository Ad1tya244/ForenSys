"""
ForenSys Forensic Evidence Collection & Sealing Engine

For every incident the engine captures the telemetry that explains the attack (packets, logs, sockets, processes),
derives attack-specific details (e.g. scanner IP + every probed port for a port scan), writes a packet capture
(headers-only .pcap) and an evidence.json artifact to disk, then computes an immutable SHA-256 digest and seals the
package in the vault:  Captured -> Hashed -> Sealed.
"""

import hashlib
import json
import os
import re
import shutil
import socket
import time
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Set
from pipeline.correlation_engine import CorrelatedIncident
from pipeline.state_engine import BehaviorStateEngine, _v4

BACKEND_DIR = os.path.dirname(os.path.dirname(__file__))
EVIDENCE_FILE = os.path.join(BACKEND_DIR, "evidence_vault.json")
EVIDENCE_DIR = os.path.join(BACKEND_DIR, "evidence")

CAPTURE_WINDOW_SEC = 120.0
MAX_PACKETS_IN_PAYLOAD = 300
MAX_PACKETS_IN_PCAP = 5000
ISO = "%Y-%m-%dT%H:%M:%SZ"


def _iso(ts: Optional[float]) -> Optional[str]:
    return time.strftime(ISO, time.gmtime(ts)) if ts else None


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
            "timestamp": _iso(self.timestamp),
            "status": self.status,
            "hash": f"SHA256: {self.sha256_hash}",
            "sealedAt": _iso(self.sealed_at),
            "payload": self.payload,
            "chain": [
                f"Captured at {time.strftime('%H:%M:%S UTC', time.gmtime(self.timestamp))}",
                f"Hashed via SHA-256 digest ({self.sha256_hash[:16]}...)",
                f"Sealed in Forensic Vault at {time.strftime('%H:%M:%S UTC', time.gmtime(self.sealed_at or self.timestamp))}"
            ]
        }


def _service_name(port: int, proto: str = "tcp") -> str:
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


class EvidenceManager:
    def __init__(self, vault_path: str = EVIDENCE_FILE, artifacts_dir: str = EVIDENCE_DIR) -> None:
        self.vault_path = vault_path
        self.artifacts_dir = artifacts_dir
        self.vault: Dict[str, ForensicEvidencePackage] = {}
        self._load_vault()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_vault(self) -> None:
        if not os.path.exists(self.vault_path):
            return
        try:
            import calendar
            with open(self.vault_path, "r") as f:
                data = json.load(f)
            for item in data:
                pkg = ForensicEvidencePackage(
                    evidence_id=item["id"],
                    incident_id=item["incidentId"],
                    timestamp=calendar.timegm(time.strptime(item["timestamp"], ISO)),
                    status=item["status"],
                    payload=item.get("payload", {}),
                    sha256_hash=item.get("hash", "").replace("SHA256: ", ""),
                    sealed_at=calendar.timegm(time.strptime(item["sealedAt"], ISO)) if item.get("sealedAt") else None,
                )
                self.vault[pkg.evidence_id] = pkg
        except Exception as e:
            print(f"[EvidenceManager] Error loading vault: {e}")

    def _save_vault(self) -> None:
        try:
            with open(self.vault_path, "w") as f:
                json.dump([pkg.to_dict() for pkg in self.vault.values()], f, indent=2)
        except Exception as e:
            print(f"[EvidenceManager] Error saving vault: {e}")

    # ── Capture ───────────────────────────────────────────────────────────────

    @staticmethod
    def _incident_entities(incident: CorrelatedIncident) -> Dict[str, Set[str]]:
        ips: Set[str] = set(incident.block_ips)
        domains: Set[str] = set(incident.block_domains)
        procs: Set[str] = set(incident.quarantine_processes)
        for det in incident.related_detections:
            md = det.get("metadata", {})
            for k in ("block_ip", "src_ip", "src_ip_raw", "attacker_ip", "remote_ip"):
                if md.get(k):
                    ips.add(md[k])
            if md.get("domain"):
                domains.add(md["domain"])
            if md.get("process"):
                procs.add(md["process"])
        from pipeline.state_engine import is_local_ip
        ips = {ip for ip in ips if not is_local_ip(ip)}
        return {"ips": ips, "domains": domains, "procs": procs}

    def collect(self, incident: CorrelatedIncident, state_engine: BehaviorStateEngine, now: Optional[float] = None) -> Dict[str, Any]:
        """Captures the incident's telemetry out of the state engine and derives attack-specific details."""
        now = now if now else time.time()
        ent = self._incident_entities(incident)
        ips = ent["ips"] | {_v4(ip) for ip in ent["ips"]}
        packets: List[Dict[str, Any]] = []
        logs: List[Dict[str, Any]] = []
        processes: List[Dict[str, Any]] = []
        connections: List[Dict[str, Any]] = []
        listeners: List[Dict[str, Any]] = []
        raw_events = []

        for ev in state_engine.recent_events(CAPTURE_WINDOW_SEC, now):
            if ev.event_type == "PACKET":
                relevant = (ev.src_ip in ips or ev.dst_ip in ips or _v4(ev.src_ip) in ips or _v4(ev.dst_ip) in ips
                            or (ev.dns_query and ev.dns_query in ent["domains"]))
                if not relevant:
                    continue
                raw_events.append(ev)
                packets.append({
                    "ts": ev.timestamp, "time": _iso(ev.timestamp), "protocol": ev.protocol,
                    "src_ip": ev.src_ip, "src_port": ev.src_port, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
                    "length": ev.byte_count, "flags": ev.details.get("flags"), "icmp_type": ev.details.get("icmp_type"),
                    "info": ev.details.get("info", ""),
                })
            elif ev.event_type == "LOG":
                msg = str(ev.details.get("message", ""))
                if ev.src_ip in ips or any(ip in msg for ip in ent["ips"]):
                    raw_events.append(ev)
                    logs.append({
                        "time": _iso(ev.timestamp), "process": ev.process_name, "pid": ev.pid,
                        "level": ev.details.get("level", "info"), "src_ip": ev.src_ip,
                        "auth_failure": ev.auth_failure, "auth_success": ev.auth_success, "message": msg,
                    })
            elif ev.event_type == "CONNECTION":
                if ev.dst_ip in ips or ev.src_ip in ips or ev.process_name in ent["procs"]:
                    raw_events.append(ev)
                    connections.append({
                        "time": _iso(ev.timestamp), "local_ip": ev.src_ip, "local_port": ev.src_port,
                        "remote_ip": ev.dst_ip, "remote_port": ev.dst_port, "process": ev.process_name, "pid": ev.pid,
                    })
            elif ev.event_type == "PROCESS":
                if ev.process_name in ent["procs"] or ev.parent_process in ent["procs"]:
                    raw_events.append(ev)
                    processes.append({
                        "time": _iso(ev.timestamp), "process": ev.process_name, "parent_process": ev.parent_process,
                        "pid": ev.pid, "ppid": ev.ppid,
                    })
            elif ev.event_type == "LISTENER":
                if ev.process_name in ent["procs"]:
                    raw_events.append(ev)
                    listeners.append({"time": _iso(ev.timestamp), "ip": ev.src_ip, "port": ev.src_port,
                                      "process": ev.process_name, "pid": ev.pid})

        # Alerts already carry the facts for process/listener style detections; make sure they are in the bundle
        for det in incident.related_detections:
            md = det.get("metadata", {})
            if md.get("attack_type") == "process_chain" and not processes:
                processes.append({"time": det.get("timestamp"), "process": md.get("child_process"),
                                  "parent_process": md.get("parent_process"), "pid": md.get("pid"), "ppid": md.get("ppid")})
            if md.get("attack_type") == "suspicious_listener" and not listeners:
                listeners.append({"time": det.get("timestamp"), "ip": "0.0.0.0", "port": md.get("port"),
                                  "process": md.get("process"), "pid": None})

        attack_details = self._attack_details(incident, packets, logs)
        target_ip = next((d.get("metadata", {}).get("target_ip") for d in incident.related_detections
                          if d.get("metadata", {}).get("target_ip")), incident.primary_dest_ip)
        attacker_ip = incident.block_ips[0] if incident.block_ips else (incident.primary_source_ip or "")

        return {
            "incident_id": incident.id,
            "incident_title": incident.title,
            "captured_at": _iso(now),
            "severity": incident.severity,
            "attack_types": incident.attack_types,
            "attacker_ip": attacker_ip,
            "attacker_ips": sorted(ent["ips"]),
            "target_ip": target_ip,
            "affected_assets": incident.affected_assets,
            "mitre_stages": incident.mitre_stages,
            "summary": self._summary(incident, attack_details),
            "attack_details": attack_details,
            "detections": [{"id": d.get("id"), "rule": d.get("title"), "severity": d.get("severity"),
                            "time": d.get("timestamp"), "description": d.get("description")}
                           for d in incident.related_detections],
            "packets": packets[-MAX_PACKETS_IN_PAYLOAD:],
            "packet_total": len(packets),
            "logs": logs[-200:],
            "processes": processes[:50],
            "connections": connections[:50],
            "listeners": listeners[:20],
            "_raw_packets": packets[-MAX_PACKETS_IN_PCAP:],  # stripped before sealing (used for the pcap artifact)
        }

    # ── Attack-specific analysis ──────────────────────────────────────────────

    def _attack_details(self, incident: CorrelatedIncident, packets: List[Dict], logs: List[Dict]) -> Dict[str, Any]:
        details: Dict[str, Any] = {}
        for det in incident.related_detections:
            md = det.get("metadata", {})
            kind = md.get("attack_type")
            if not kind or kind in details:
                continue
            builder = getattr(self, f"_detail_{kind}", None)
            info: Dict[str, Any] = builder(md, packets, logs) if builder else {}
            info["detection_threshold"] = md.get("threshold")
            info["window_sec"] = md.get("window_sec")
            info["mttd_sec"] = md.get("mttd_sec")
            details[kind] = {k: v for k, v in info.items() if v is not None}
        return details

    @staticmethod
    def _span(pkts: List[Dict]) -> Dict[str, Any]:
        if not pkts:
            return {}
        first, last = min(p["ts"] for p in pkts), max(p["ts"] for p in pkts)
        dur = round(max(last - first, 0.001), 3)
        return {"first_packet_at": _iso(first), "last_packet_at": _iso(last), "duration_sec": dur,
                "packets_per_second": round(len(pkts) / dur, 1) if dur > 0.05 else float(len(pkts))}

    def _from_attacker(self, md: Dict, pkts: List[Dict]) -> List[Dict]:
        ips = {md.get("src_ip"), md.get("src_ip_raw")} - {None, ""}
        return [p for p in pkts if p["src_ip"] in ips or _v4(p["src_ip"]) in ips]

    def _detail_port_scan(self, md, pkts, logs):
        mine = [p for p in self._from_attacker(md, pkts) if p["dst_port"]]
        ports = sorted({p["dst_port"] for p in mine}) or md.get("sample_ports", [])
        flags = Counter((p.get("flags") or "?") for p in mine)
        return {
            "scanner_ip": md.get("src_ip"), "scanner_ip_raw": md.get("src_ip_raw"), "target_ip": md.get("target_ip"),
            "scan_type": "TCP SYN (half-open) scan" if flags and set(flags) <= {"SYN"} else "TCP connect/other scan",
            "ports_probed": ports, "port_count": len(ports),
            "port_services": {str(p): n for p in ports[:1024] if (n := _service_name(p)) != "unknown"},
            "tcp_flags_seen": dict(flags), "probe_packets": len(mine),
            "source_ports_used": sorted({p["src_port"] for p in mine})[:20],
            **self._span(mine),
        }

    def _detail_icmp_flood(self, md, pkts, logs):
        mine = [p for p in self._from_attacker(md, pkts) if p["protocol"] == "ICMP"]
        return {
            "attacker_ip": md.get("src_ip"), "attacker_ip_raw": md.get("src_ip_raw"), "target_ip": md.get("target_ip"),
            "echo_requests": md.get("count"), "captured_packets": len(mine),
            "icmp_types": dict(Counter(str(p.get("icmp_type", "echo-request")) for p in mine)),
            "total_bytes": sum(p["length"] for p in mine),
            "avg_packet_size": round(sum(p["length"] for p in mine) / len(mine), 1) if mine else None,
            "unique_targets": md.get("unique_targets"),
            **self._span(mine),
        }

    def _detail_syn_flood(self, md, pkts, logs):
        mine = [p for p in self._from_attacker(md, pkts) if p.get("flags") == "SYN"]
        return {
            "attacker_ip": md.get("src_ip"), "attacker_ip_raw": md.get("src_ip_raw"), "target_ip": md.get("target_ip"),
            "target_ports": md.get("target_ports"), "syn_packets": md.get("syn_count"), "captured_packets": len(mine),
            "distinct_source_ports": len({p["src_port"] for p in mine}),
            **self._span(mine),
        }

    def _auth_info(self, md, logs):
        ip = md.get("src_ip") or md.get("entity")
        mine = [l for l in logs if l.get("src_ip") == ip or (ip and ip in l.get("message", ""))] or logs
        users = Counter()
        for l in mine:
            m = re.search(r"for (?:invalid user )?(\S+) from", l.get("message", ""))
            if m and l.get("auth_failure"):
                users[m.group(1)] += 1
        return {
            "attacker_ip": md.get("src_ip"), "target_ip": md.get("target_ip"), "services": md.get("services"),
            "failed_attempts": sum(1 for l in mine if l.get("auth_failure")) or md.get("failed_attempts") or md.get("total_failures"),
            "service_port": md.get("service_port"), "connection_attempts": md.get("connection_attempts"),
            "successful_logins": sum(1 for l in mine if l.get("auth_success")),
            "usernames_targeted": dict(users),
            "log_excerpt": [l["message"] for l in mine[-15:]],
        }

    def _detail_brute_force(self, md, pkts, logs):
        info = self._auth_info(md, logs)
        info["compromised"] = bool(md.get("successful_login"))
        return info

    def _detail_auth_attack(self, md, pkts, logs):
        return self._auth_info(md, logs)

    def _detail_dns_beacon(self, md, pkts, logs):
        q = [p for p in pkts if p["protocol"] == "DNS" and md.get("domain", "~") in str(p.get("info", "")).lower()]
        stamps = sorted(p["ts"] for p in q)
        return {
            "domain": md.get("domain"), "queried_by": md.get("process"), "query_count": md.get("query_count"),
            "mean_interval_sec": md.get("interval_sec"), "variance_coefficient": md.get("cov"),
            "intervals_sec": [round(stamps[i] - stamps[i - 1], 2) for i in range(1, len(stamps))][:30],
            "resolver_ips": sorted({p["dst_ip"] for p in q}), "source_hosts": sorted({p["src_ip"] for p in q}),
            "first_query_at": _iso(stamps[0]) if stamps else None, "last_query_at": _iso(stamps[-1]) if stamps else None,
        }

    def _detail_reverse_shell(self, md, pkts, logs):
        return {
            "process": md.get("process"), "pid": md.get("pid"), "c2_ip": md.get("remote_ip"),
            "c2_port": md.get("remote_port"), "local_port": md.get("local_port"),
            "service_guess": _service_name(md["remote_port"]) if md.get("remote_port") else None,
        }

    def _detail_data_exfil(self, md, pkts, logs):
        mine = [p for p in pkts if p["dst_ip"] in (md.get("dst_ip"), md.get("remote_ip")) and p["length"] > 0]
        span = self._span(mine)
        dur = span.get("duration_sec")
        return {
            "destination_ip": md.get("dst_ip"), "source_host": md.get("src_ip"),
            "transferred_bytes": md.get("transferred_bytes"), "transferred_mb": md.get("transferred_mb"),
            "downloaded_bytes": md.get("downloaded_bytes"), "upload_ratio": md.get("upload_ratio"),
            "threshold_bytes": md.get("threshold_bytes"), "captured_packets": len(mine),
            "destination_ports": sorted({p["dst_port"] for p in mine if p["dst_port"]}),
            "throughput_mb_per_sec": round(md["transferred_mb"] / dur, 2) if dur and md.get("transferred_mb") else None,
            **span,
        }

    def _detail_suspicious_listener(self, md, pkts, logs):
        return {"process": md.get("process"), "listening_port": md.get("port"),
                "service_guess": _service_name(md["port"]) if md.get("port") else None}

    def _detail_process_chain(self, md, pkts, logs):
        return {"parent_process": md.get("parent_process"), "child_process": md.get("child_process"),
                "pid": md.get("pid"), "ppid": md.get("ppid")}

    @staticmethod
    def _summary(incident: CorrelatedIncident, details: Dict[str, Any]) -> str:
        parts = [incident.title]
        scan = details.get("port_scan")
        if scan:
            ports = scan.get("ports_probed", [])
            parts.append(f"Scanner {scan.get('scanner_ip')} probed {len(ports)} ports "
                         f"({', '.join(map(str, ports[:12]))}{'...' if len(ports) > 12 else ''}).")
        icmp = details.get("icmp_flood")
        if icmp:
            parts.append(f"{icmp.get('echo_requests')} ICMP echo requests from {icmp.get('attacker_ip')}.")
        return " ".join(parts)

    # ── Seal ──────────────────────────────────────────────────────────────────

    def _write_pcap(self, evd_id: str, packets: List[Dict]) -> Optional[Dict[str, Any]]:
        """Writes a headers-only packet capture of the incident traffic. Returns artifact metadata or None."""
        if not packets:
            return None
        try:
            from scapy.all import wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP  # type: ignore
            pkts = []
            for p in packets:
                v6 = ":" in (p["src_ip"] or "")
                net = (IPv6(src=p["src_ip"], dst=p["dst_ip"]) if v6 else IP(src=p["src_ip"], dst=p["dst_ip"]))
                if p["protocol"] == "TCP":
                    fl = "".join({"FIN": "F", "SYN": "S", "RST": "R", "PSH": "P", "ACK": "A"}.get(f, "")
                                 for f in str(p.get("flags") or "").split("+"))
                    layer = TCP(sport=p["src_port"], dport=p["dst_port"], flags=fl or "A")
                elif p["protocol"] in ("UDP", "DNS"):
                    layer = UDP(sport=p["src_port"], dport=p["dst_port"])
                elif p["protocol"] == "ICMP" and not v6:
                    layer = ICMP(type=int(p.get("icmp_type") if p.get("icmp_type") is not None else 8))
                else:
                    layer = None
                eth = Ether(src="00:00:00:00:00:00", dst="ff:ff:ff:ff:ff:ff")  # fixed MACs: no ARP lookups while building
                frame = eth / net / layer if layer is not None else eth / net
                frame.time = p["ts"]
                pkts.append(frame)
            folder = os.path.join(self.artifacts_dir, evd_id)
            os.makedirs(folder, exist_ok=True)
            path = os.path.join(folder, "capture.pcap")
            wrpcap(path, pkts)
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            return {"name": "capture.pcap", "path": os.path.relpath(path, BACKEND_DIR), "packets": len(pkts),
                    "bytes": os.path.getsize(path), "sha256": digest, "note": "headers-only reconstruction of captured packets"}
        except Exception as e:
            print(f"[EvidenceManager] pcap artifact skipped: {e}")
            return None

    def seal(self, incident: CorrelatedIncident, payload: Dict[str, Any],
             remediation_actions: Optional[List[Dict[str, Any]]] = None, now: Optional[float] = None) -> ForensicEvidencePackage:
        """Writes artifacts, hashes the payload with SHA-256 and seals it in the vault."""
        now = now if now else time.time()
        evd_id = f"EVD-{incident.id}"
        raw_packets = payload.pop("_raw_packets", [])
        artifacts = []
        pcap = self._write_pcap(evd_id, raw_packets)
        if pcap:
            artifacts.append(pcap)
        payload["artifacts"] = artifacts
        payload["remediation_actions"] = remediation_actions or []
        first_seen = [d.get("metadata", {}).get("first_seen") for d in incident.related_detections if d.get("metadata", {}).get("first_seen")]
        payload["timing"] = {
            "first_activity_at": _iso(min(first_seen)) if first_seen else None,
            "detected_at": _iso(incident.created_at),
            "sealed_at": _iso(now),
            "mttd_sec": next((d["metadata"]["mttd_sec"] for d in incident.related_detections if d.get("metadata", {}).get("mttd_sec")), None),
            "detection_to_seal_sec": round(max(0.0, now - incident.created_at), 3),
        }

        canonical_json = json.dumps(payload, sort_keys=True, default=str)
        digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        pkg = ForensicEvidencePackage(
            evidence_id=evd_id, incident_id=incident.id, timestamp=now, status="Sealed",
            payload=payload, sha256_hash=digest, sealed_at=now,
        )
        self.vault[evd_id] = pkg
        if evd_id not in incident.evidence_ids:
            incident.evidence_ids.append(evd_id)
        self._save_vault()

        try:  # on-disk copy of the sealed package next to the pcap
            folder = os.path.join(self.artifacts_dir, evd_id)
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, "evidence.json"), "w") as f:
                json.dump(pkg.to_dict(), f, indent=2, default=str)
        except Exception as e:
            print(f"[EvidenceManager] evidence.json artifact skipped: {e}")
        return pkg

    def generate_evidence(self, incident: CorrelatedIncident, state_engine: BehaviorStateEngine,
                          now: Optional[float] = None) -> Optional[ForensicEvidencePackage]:
        """Capture + seal in one step (used by tests and the offline simulation)."""
        payload = self.collect(incident, state_engine, now)
        return self.seal(incident, payload, [], now)

    # ── Vault access ──────────────────────────────────────────────────────────

    def get_evidence(self, evidence_id: str) -> Optional[ForensicEvidencePackage]:
        return self.vault.get(evidence_id)

    def delete_evidence(self, evidence_id: str) -> bool:
        clean = evidence_id.strip().lower()
        for k, pkg in list(self.vault.items()):
            if clean in (k.lower(), pkg.incident_id.lower(), f"evd-{pkg.incident_id}".lower()):
                del self.vault[k]
                self._remove_artifacts(k)
        self._save_vault()
        return True

    def _remove_artifacts(self, evd_id: str) -> None:
        folder = os.path.abspath(os.path.join(self.artifacts_dir, evd_id))
        if folder.startswith(os.path.abspath(self.artifacts_dir) + os.sep) and os.path.isdir(folder):
            shutil.rmtree(folder, ignore_errors=True)

    def get_all_evidence(self) -> List[Dict[str, Any]]:
        return [pkg.to_dict() for pkg in sorted(self.vault.values(), key=lambda p: p.timestamp)]

    def clear_vault(self) -> None:
        self.vault = {}
        if os.path.isdir(self.artifacts_dir):
            for name in os.listdir(self.artifacts_dir):
                if name.startswith("EVD-"):
                    self._remove_artifacts(name)
        try:
            with open(self.vault_path, "w") as f:
                json.dump([], f)
        except Exception as e:
            print(f"[EvidenceManager] Error clearing vault: {e}")
