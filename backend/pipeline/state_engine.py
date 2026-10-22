"""
ForenSys Behavior State Engine
Maintains rolling behavioral state over 5s, 10s, 30s, 1m (60s), and 5m (300s) windows.
Tracks metrics per IP, process, parent process, port, protocol, DNS queries, and listening sockets.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Any, List, Set, Tuple, Optional
from pipeline.normalizer import NormalizedEvent
from pipeline.self_protection import asset_trust_manager
from config import get_config

WINDOWS = {
    "5s": 5.0,
    "10s": 10.0,
    "30s": 30.0,
    "1m": 60.0,
    "5m": 300.0,
}

# Events are appended almost (but not perfectly) in chronological order, so window scans walk the buffer
# from the newest end and only stop once they are this far past the window edge.
_ORDER_SLACK_SEC = 6.0


@lru_cache(maxsize=4096)
def _v4(ip: str) -> str:
    from analyzers.ip_intel import ensure_ipv4
    return ensure_ipv4(ip)


def is_local_ip(ip: str) -> bool:
    """True for loopback and any address that belongs to this host."""
    if not ip:
        return False
    return ip.startswith("127.") or ip in ("localhost", "::1") or ip in asset_trust_manager.local_ips


@dataclass
class WindowStateSnapshot:
    """Snapshot of aggregated metrics for a specific rolling window."""
    window_name: str
    window_sec: float
    total_events: int
    icmp_packets_by_src: Dict[str, int]
    syn_packets_by_src: Dict[str, int]
    unique_dst_ports_by_src: Dict[str, Set[int]]
    outbound_bytes_by_dst: Dict[str, int]
    upload_bytes_by_peer: Dict[str, int]
    download_bytes_by_peer: Dict[str, int]
    auth_failures_by_src: Dict[str, int]
    auth_successes_by_src: Dict[str, int]
    dns_query_timestamps: Dict[Tuple[str, str], List[float]]
    active_listeners: Set[Tuple[str, int]]
    process_chains: List[Tuple[str, str]] = field(default_factory=list)
    first_seen_by_src: Dict[str, float] = field(default_factory=dict)
    syn_ports_by_src: Dict[str, Set[int]] = field(default_factory=dict)
    icmp_dsts_by_src: Dict[str, Set[str]] = field(default_factory=dict)
    last_seen_by_src: Dict[str, float] = field(default_factory=dict)
    auth_fail_events: Dict[str, List[NormalizedEvent]] = field(default_factory=dict)
    syn_by_src_port: Dict[str, Dict[int, int]] = field(default_factory=dict)
    first_upload_by_peer: Dict[str, float] = field(default_factory=dict)

class BehaviorStateEngine:
    def __init__(self, max_retention_sec: float = 300.0, max_events: int = 60000) -> None:
        self.max_retention_sec = max_retention_sec
        self.events: deque[NormalizedEvent] = deque(maxlen=max_events)
        self.seen_listeners_history: Set[Tuple[str, int]] = set()
        self.known_processes_history: Set[str] = set()
        self._audited_listeners: Set[Tuple[str, int]] = set()

    def process_event(self, event: NormalizedEvent, config: Optional[Dict[str, Any]] = None) -> None:
        """Ingests a normalized event and adds it to the sliding event buffer."""
        cfg = config if config is not None else get_config()
        is_trusted, reason = asset_trust_manager.is_trusted_event(event.to_dict(), cfg)
        if is_trusted and reason:
            event.is_trusted = True
            event.trust_reason = reason
            # Listening sockets are re-asserted every second; audit each one once, not once per cycle
            if event.event_type == "LISTENER":
                key = (event.process_name, event.src_port)
                if key not in self._audited_listeners:
                    self._audited_listeners.add(key)
                    asset_trust_manager.log_ignored_event(event.to_dict(), reason)
            else:
                asset_trust_manager.log_ignored_event(event.to_dict(), reason)

        self.events.append(event)

        # Track historical baselines
        if event.event_type == "LISTENER" and event.src_port > 0 and not event.is_trusted:
            self.seen_listeners_history.add((event.process_name, event.src_port))
        if event.process_name and event.process_name != "unknown" and not event.is_trusted:
            self.known_processes_history.add(event.process_name)

        # Prune expired events older than max_retention_sec
        self._prune(event.timestamp)

    def process_events(self, events: List[NormalizedEvent], config: Optional[Dict[str, Any]] = None) -> None:
        """Ingests multiple normalized events."""
        for ev in events:
            self.process_event(ev, config)

    def _prune(self, now: float) -> None:
        cutoff = now - self.max_retention_sec
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def purge_ip(self, ip: str) -> int:
        """Drops buffered events to/from `ip` (used once an IP is blocked, so stale events cannot re-trigger rules)."""
        if not ip:
            return 0
        before = len(self.events)
        self.events = deque(
            (e for e in self.events if not (ip in (e.src_ip, e.dst_ip) or ip in (_v4(e.src_ip), _v4(e.dst_ip)))),
            maxlen=self.events.maxlen,
        )
        return before - len(self.events)

    def recent_events(self, window_sec: float, now: Optional[float] = None) -> List[NormalizedEvent]:
        """Returns the non-trusted events inside the window in chronological order."""
        current_time = now if now else time.time()
        cutoff = current_time - window_sec
        out: List[NormalizedEvent] = []
        for ev in reversed(self.events):
            if ev.timestamp < cutoff - _ORDER_SLACK_SEC:
                break
            if ev.timestamp >= cutoff and not ev.is_trusted:
                out.append(ev)
        out.reverse()
        return out

    def get_window_snapshot(self, window_sec: float, now: Optional[float] = None) -> WindowStateSnapshot:
        """Computes a state snapshot for the requested window duration (e.g. 5, 10, 30, 60, 300)."""
        current_time = now if now else (self.events[-1].timestamp if self.events else time.time())

        # Window-specific aggregates
        icmp_by_src: Dict[str, int] = defaultdict(int)
        icmp_dsts: Dict[str, Set[str]] = defaultdict(set)
        syn_by_src: Dict[str, int] = defaultdict(int)
        syn_ports: Dict[str, Set[int]] = defaultdict(set)
        unique_ports_by_src: Dict[str, Set[int]] = defaultdict(set)
        outbound_bytes_by_dst: Dict[str, int] = defaultdict(int)
        upload_by_peer: Dict[str, int] = defaultdict(int)
        download_by_peer: Dict[str, int] = defaultdict(int)
        first_upload: Dict[str, float] = {}
        auth_fails: Dict[str, int] = defaultdict(int)
        auth_succs: Dict[str, int] = defaultdict(int)
        auth_fail_events: Dict[str, List[NormalizedEvent]] = defaultdict(list)
        dns_queries: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        listeners: Set[Tuple[str, int]] = set()
        chains: List[Tuple[str, str]] = []
        first_seen_by_src: Dict[str, float] = {}
        last_seen_by_src: Dict[str, float] = {}
        matching_count = 0
        seen_attempts: Set[str] = set()
        syn_by_port: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

        for ev in self.recent_events(window_sec, current_time):
            matching_count += 1
            remote_src = bool(ev.src_ip) and not is_local_ip(ev.src_ip)
            if remote_src:
                first_seen_by_src.setdefault(ev.src_ip, ev.timestamp)
                last_seen_by_src[ev.src_ip] = ev.timestamp

            # ICMP Echo Requests from remote sources (IPv4 Type 8, ICMPv6 Type 128)
            if ev.protocol == "ICMP" and remote_src:
                icmp_type = ev.details.get("icmp_type")
                info_str = str(ev.details.get("info", "")).lower()
                if icmp_type is not None:
                    is_reply = icmp_type in (0, 129)
                else:
                    is_reply = ("type=0" in info_str) or ("echo reply" in info_str)
                if not is_reply:
                    icmp_by_src[ev.src_ip] += ev.packet_count
                    if ev.dst_ip:
                        icmp_dsts[ev.src_ip].add(ev.dst_ip)

            # Connection attempts: bare TCP SYN packets (and connection records) from remote sources
            if remote_src and ev.dst_port > 0:
                if ev.event_type == "PACKET":
                    is_attempt = ev.protocol == "TCP" and ev.details.get("flags") == "SYN"
                    if is_attempt:
                        syn_by_src[ev.src_ip] += ev.packet_count
                        syn_ports[ev.src_ip].add(ev.dst_port)
                        syn_by_port[ev.src_ip][ev.dst_port] += ev.packet_count
                else:
                    is_attempt = ev.event_type == "CONNECTION"
                if is_attempt:
                    unique_ports_by_src[ev.src_ip].add(ev.dst_port)

            # Data Exfiltration tracking: bucket bytes per EXTERNAL peer, split by direction (local->peer is an
            # upload, peer->local is a download). A big download (streaming, a software update, a webpage) is
            # receive-heavy and never counts as exfiltration here - only a send-heavy transfer does, which is
            # what the rule actually checks (pipeline/rules/data_exfiltration.py requires an upload-dominant ratio).
            if ev.byte_count > 0:
                if ev.dst_ip:
                    outbound_bytes_by_dst[ev.dst_ip] += ev.byte_count   # kept for backward compatibility
                src_local = bool(ev.src_ip) and is_local_ip(ev.src_ip)
                dst_local = bool(ev.dst_ip) and is_local_ip(ev.dst_ip)
                if src_local and ev.dst_ip and not is_local_ip(ev.dst_ip):
                    upload_by_peer[ev.dst_ip] += ev.byte_count
                    first_upload.setdefault(ev.dst_ip, ev.timestamp)
                elif dst_local and ev.src_ip and not is_local_ip(ev.src_ip):
                    download_by_peer[ev.src_ip] += ev.byte_count

            # Authentication Failure / Success tracking
            key = ev.src_ip if ev.src_ip else ev.process_name
            if ev.auth_failure:
                attempt = ev.details.get("attempt_key")
                if attempt:
                    if attempt in seen_attempts:
                        continue
                    seen_attempts.add(attempt)
                auth_fails[key] += 1
                auth_fail_events[key].append(ev)
            if ev.auth_success:
                auth_succs[key] += 1

            # DNS Beaconing tracking (entity = owning process, or the querying host when the process is unknown)
            if ev.dns_query:
                entity = ev.process_name if ev.process_name != "unknown" else (ev.src_ip or "unknown")
                dns_queries[(entity, ev.dns_query)].append(ev.timestamp)

            # Active Listening Sockets
            if ev.event_type == "LISTENER" and ev.src_port > 0:
                listeners.add((ev.process_name, ev.src_port))

            # Process Chain tracking
            if ev.event_type == "PROCESS" and ev.parent_process != "unknown":
                chains.append((ev.parent_process, ev.process_name))

        # Determine window name key
        window_name = "custom"
        for name, duration in WINDOWS.items():
            if abs(duration - window_sec) < 0.1:
                window_name = name
                break

        return WindowStateSnapshot(
            window_name=window_name,
            window_sec=window_sec,
            total_events=matching_count,
            icmp_packets_by_src=dict(icmp_by_src),
            syn_packets_by_src=dict(syn_by_src),
            unique_dst_ports_by_src=dict(unique_ports_by_src),
            outbound_bytes_by_dst=dict(outbound_bytes_by_dst),
            upload_bytes_by_peer=dict(upload_by_peer),
            download_bytes_by_peer=dict(download_by_peer),
            auth_failures_by_src=dict(auth_fails),
            auth_successes_by_src=dict(auth_succs),
            dns_query_timestamps=dict(dns_queries),
            active_listeners=listeners,
            process_chains=chains,
            first_seen_by_src=first_seen_by_src,
            syn_ports_by_src=dict(syn_ports),
            icmp_dsts_by_src=dict(icmp_dsts),
            last_seen_by_src=last_seen_by_src,
            auth_fail_events=dict(auth_fail_events),
            syn_by_src_port={k: dict(v) for k, v in syn_by_port.items()},
            first_upload_by_peer=first_upload,
        )

    def get_all_window_snapshots(self, now: Optional[float] = None) -> Dict[str, WindowStateSnapshot]:
        """Returns state snapshots for all standard windows: 5s, 10s, 30s, 1m, 5m."""
        current_time = now if now else (self.events[-1].timestamp if self.events else time.time())
        snapshots: Dict[str, WindowStateSnapshot] = {}
        for name, duration in WINDOWS.items():
            snapshots[name] = self.get_window_snapshot(duration, current_time)
        return snapshots

    def get_summary(self) -> Dict[str, Any]:
        """Provides a high-level summary of the current behavior state."""
        snaps = self.get_all_window_snapshots()
        return {
            "total_buffered_events": len(self.events),
            "historical_listeners_count": len(self.seen_listeners_history),
            "known_processes_count": len(self.known_processes_history),
            "window_summaries": {
                name: {
                    "total_events": snap.total_events,
                    "active_sources": len(snap.unique_dst_ports_by_src),
                    "active_listeners": len(snap.active_listeners),
                    "auth_failures": sum(snap.auth_failures_by_src.values())
                }
                for name, snap in snaps.items()
            }
        }

    def clear(self) -> None:
        """Clears all buffered telemetry events."""
        self.events.clear()
