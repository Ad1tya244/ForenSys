"""
ForenSys Event Normalizer
Converts raw telemetry collections into unified NormalizedEvent objects.
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: float
    event_type: str  # PACKET, CONNECTION, PROCESS, LOG, LISTENER
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "UNKNOWN"
    process_name: str = "unknown"
    parent_process: str = "unknown"
    pid: Optional[int] = None
    ppid: Optional[int] = None
    packet_count: int = 1
    byte_count: int = 0
    auth_failure: bool = False
    auth_success: bool = False
    dns_query: str = ""
    is_trusted: bool = False
    trust_reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "process": self.process_name,
            "parent_process": self.parent_process,
            "pid": self.pid,
            "ppid": self.ppid,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "auth_failure": self.auth_failure,
            "auth_success": self.auth_success,
            "dns_query": self.dns_query,
            "is_trusted": self.is_trusted,
            "trust_reason": self.trust_reason,
            "details": self.details,
        }

class EventNormalizer:
    """Standardizes incoming telemetry data dictionaries into NormalizedEvent lists."""
    
    @staticmethod
    def normalize_packet(packet: Dict[str, Any], now: Optional[float] = None) -> NormalizedEvent:
        ts = now if now else time.time()
        proto = str(packet.get("protocol", "UNKNOWN")).upper()
        info = str(packet.get("info", ""))
        dns_q = ""
        if "DNS" in info or "Standard query" in info:
            proto = "DNS"
            parts = info.split()
            if len(parts) > 1:
                dns_q = parts[-1]

        return NormalizedEvent(
            event_id=packet.get("id") or str(uuid.uuid4()),
            timestamp=ts,
            event_type="PACKET",
            src_ip=packet.get("src_ip", ""),
            dst_ip=packet.get("dst_ip", ""),
            src_port=int(packet.get("src_port", 0)),
            dst_port=int(packet.get("dst_port", 0)),
            protocol=proto,
            packet_count=1,
            byte_count=int(packet.get("length", 0)),
            dns_query=dns_q,
            details=packet
        )

    @staticmethod
    def normalize_connection(conn: Dict[str, Any], now: Optional[float] = None) -> NormalizedEvent:
        ts = now if now else time.time()
        return NormalizedEvent(
            event_id=conn.get("id") or str(uuid.uuid4()),
            timestamp=ts,
            event_type="CONNECTION",
            src_ip=conn.get("local_ip", ""),
            dst_ip=conn.get("remote_ip", ""),
            src_port=int(conn.get("local_port", 0)),
            dst_port=int(conn.get("remote_port", 0)),
            protocol=str(conn.get("protocol", "TCP")).upper(),
            process_name=conn.get("process", "unknown"),
            pid=conn.get("pid"),
            details=conn
        )

    @staticmethod
    def normalize_process(proc: Dict[str, Any], now: Optional[float] = None) -> NormalizedEvent:
        ts = now if now else time.time()
        return NormalizedEvent(
            event_id=f"proc-{proc.get('pid')}-{int(ts)}",
            timestamp=ts,
            event_type="PROCESS",
            process_name=proc.get("name", "unknown"),
            parent_process=proc.get("parent_name", "unknown"),
            pid=proc.get("pid"),
            ppid=proc.get("ppid"),
            details=proc
        )

    @staticmethod
    def normalize_log(log_item: Dict[str, Any], now: Optional[float] = None) -> NormalizedEvent:
        ts = now if now else time.time()
        proc = log_item.get("process", "unknown")
        msg = str(log_item.get("message", "")).lower()
        level = log_item.get("level", "info")
        
        auth_fail = False
        auth_succ = False
        
        if level in ("error", "warn") and proc in ("sshd", "sudo", "loginwindow", "SecurityAgent"):
            if any(k in msg for k in ("fail", "denied", "invalid", "incorrect", "failure")):
                auth_fail = True
        if proc in ("sshd", "sudo", "loginwindow", "SecurityAgent"):
            if any(k in msg for k in ("accepted", "success", "session opened", "succeeded")):
                auth_succ = True

        return NormalizedEvent(
            event_id=log_item.get("id") or str(uuid.uuid4()),
            timestamp=ts,
            event_type="LOG",
            process_name=proc,
            pid=log_item.get("pid"),
            auth_failure=auth_fail,
            auth_success=auth_succ,
            details=log_item
        )

    @staticmethod
    def normalize_listener(port_info: Dict[str, Any], now: Optional[float] = None) -> NormalizedEvent:
        ts = now if now else time.time()
        return NormalizedEvent(
            event_id=f"listen-{port_info.get('port')}-{port_info.get('process')}",
            timestamp=ts,
            event_type="LISTENER",
            src_ip=port_info.get("ip", "0.0.0.0"),
            src_port=int(port_info.get("port", 0)),
            process_name=port_info.get("process", "unknown"),
            pid=port_info.get("pid"),
            details=port_info
        )

    def normalize_all(
        self,
        connections: List[Dict[str, Any]],
        processes: List[Dict[str, Any]],
        logs: List[Dict[str, Any]],
        packets: List[Dict[str, Any]],
        listeners: List[Dict[str, Any]],
        now: Optional[float] = None
    ) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        ts = now if now else time.time()

        for pkt in packets:
            events.append(self.normalize_packet(pkt, ts))
        for conn in connections:
            events.append(self.normalize_connection(conn, ts))
        for proc in processes:
            events.append(self.normalize_process(proc, ts))
        for log in logs:
            events.append(self.normalize_log(log, ts))
        for lis in listeners:
            events.append(self.normalize_listener(lis, ts))

        return events
