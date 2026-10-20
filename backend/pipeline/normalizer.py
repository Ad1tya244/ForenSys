"""
ForenSys Event Normalizer
Converts raw telemetry collections into unified NormalizedEvent objects.
"""

import re
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

_LOG_SRC_IP_RE = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})\b")
_ANY_IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
_AUTH_PROCESSES = ("sshd", "sudo", "su", "loginwindow", "SecurityAgent", "screensharingd")
_AUTH_FAIL_WORDS = ("fail", "denied", "invalid", "incorrect", "failure", "authentication error", "not allowed",
                    "too many authentication", "bad password", "wrong password")
_AUTH_OK_WORDS = ("accepted", "success", "session opened", "succeeded")
_LOG_RHOST_RE = re.compile(r"rhost=((?:\d{1,3}\.){3}\d{1,3})")
_DNS_RE = re.compile(r"(?:query|Query)[^A-Za-z0-9]*(?:0x[0-9a-fA-F]+\s+)?(?:[A-Z]{1,5}\s+)?([A-Za-z0-9._-]+\.[A-Za-z]{2,})\.?\s*$")


class EventNormalizer:
    """Standardizes incoming telemetry data dictionaries into NormalizedEvent lists."""
    
    @staticmethod
    def normalize_packet(packet: Dict[str, Any], now: Optional[float] = None) -> NormalizedEvent:
        # Prefer the capture time stamped by the sniffer so detection latency/MTTD is measured from the wire
        ts = float(packet.get("ts") or 0) or (now if now else time.time())
        proto = str(packet.get("protocol", "UNKNOWN")).upper()
        info = str(packet.get("info", ""))
        dns_q = ""
        if "DNS" in info or "Standard query" in info:
            proto = "DNS"
            # Only *queries* count (responses would double every beacon timestamp)
            m = _DNS_RE.search(info.strip())
            if m:
                dns_q = m.group(1).lower()

        return NormalizedEvent(
            event_id=packet.get("id") or str(uuid.uuid4()),
            timestamp=ts,
            event_type="PACKET",
            src_ip=packet.get("src_ip", ""),
            dst_ip=packet.get("dst_ip", ""),
            src_port=int(packet.get("src_port", 0) or 0),
            dst_port=int(packet.get("dst_port", 0) or 0),
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

        # sshd shows up as "sshd" or (macOS 15+/OpenSSH split) "sshd-session"; level is irrelevant, the text decides
        is_auth_proc = any(proc == p or proc.startswith(p + "-") for p in _AUTH_PROCESSES)
        if is_auth_proc:
            if any(k in msg for k in _AUTH_FAIL_WORDS) and not any(k in msg for k in ("accepted", "session opened")):
                auth_fail = True
            if any(k in msg for k in _AUTH_OK_WORDS) and not auth_fail:
                auth_succ = True

        # Pull the remote (attacker) address out of sshd/sudo style messages so it can be attributed and contained
        src_ip = ""
        if auth_fail or auth_succ:
            raw_msg = str(log_item.get("message", ""))
            m = _LOG_SRC_IP_RE.search(raw_msg) or _LOG_RHOST_RE.search(raw_msg) or _ANY_IPV4_RE.search(raw_msg)
            if m:
                src_ip = m.group(1)

        # One SSH login attempt writes several lines (Invalid user / PAM error / Failed ...) sharing the client port:
        # remember it so the state engine counts the attempt once.
        details = log_item
        port_m = re.search(r"\bport\s+(\d{2,5})\b", str(log_item.get("message", "")))
        if auth_fail and src_ip and port_m:
            details = {**log_item, "attempt_key": f"{src_ip}:{port_m.group(1)}"}

        return NormalizedEvent(
            event_id=log_item.get("id") or str(uuid.uuid4()),
            timestamp=ts,
            event_type="LOG",
            src_ip=src_ip,
            process_name=proc,
            pid=log_item.get("pid"),
            auth_failure=auth_fail,
            auth_success=auth_succ,
            details=details
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
