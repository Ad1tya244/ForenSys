"""
ForenSys Behavior State Engine
Maintains rolling behavioral state over 5s, 10s, 30s, 1m (60s), and 5m (300s) windows.
Tracks metrics per IP, process, parent process, port, protocol, DNS queries, and listening sockets.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
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
    auth_failures_by_src: Dict[str, int]
    auth_successes_by_src: Dict[str, int]
    dns_query_timestamps: Dict[Tuple[str, str], List[float]]
    active_listeners: Set[Tuple[str, int]]
    process_chains: List[Tuple[str, str]] = field(default_factory=list)
    first_seen_by_src: Dict[str, float] = field(default_factory=dict)

class BehaviorStateEngine:
    def __init__(self, max_retention_sec: float = 300.0) -> None:
        self.max_retention_sec = max_retention_sec
        self.events: deque[NormalizedEvent] = deque()
        self.seen_listeners_history: Set[Tuple[str, int]] = set()
        self.known_processes_history: Set[str] = set()

    def process_event(self, event: NormalizedEvent, config: Optional[Dict[str, Any]] = None) -> None:
        """Ingests a normalized event and adds it to the sliding event buffer."""
        cfg = config if config is not None else get_config()
        is_trusted, reason = asset_trust_manager.is_trusted_event(event.to_dict(), cfg)
        if is_trusted and reason:
            event.is_trusted = True
            event.trust_reason = reason
            asset_trust_manager.log_ignored_event(event.to_dict(), reason)

        self.events.append(event)
        
        # Track historical baselines
        if event.event_type == "LISTENER" and event.src_port > 0 and not event.is_trusted:
            self.seen_listeners_history.add((event.process_name, event.src_port))
        if event.process_name and event.process_name != "unknown" and not event.is_trusted:
            self.known_processes_history.add(event.process_name)

        # Prune expired events older than max_retention_sec (300s / 5 minutes)
        now = event.timestamp
        self._prune(now)

    def process_events(self, events: List[NormalizedEvent], config: Optional[Dict[str, Any]] = None) -> None:
        """Ingests multiple normalized events."""
        for ev in events:
            self.process_event(ev, config)

    def _prune(self, now: float) -> None:
        cutoff = now - self.max_retention_sec
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def get_window_snapshot(self, window_sec: float, now: Optional[float] = None) -> WindowStateSnapshot:
        """Computes a state snapshot for the requested window duration (e.g. 5, 10, 30, 60, 300)."""
        current_time = now if now else (self.events[-1].timestamp if self.events else time.time())
        cutoff = current_time - window_sec
        
        # Window-specific aggregates
        icmp_by_src: Dict[str, int] = defaultdict(int)
        syn_by_src: Dict[str, int] = defaultdict(int)
        unique_ports_by_src: Dict[str, Set[int]] = defaultdict(set)
        outbound_bytes_by_dst: Dict[str, int] = defaultdict(int)
        auth_fails: Dict[str, int] = defaultdict(int)
        auth_succs: Dict[str, int] = defaultdict(int)
        dns_queries: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        listeners: Set[Tuple[str, int]] = set()
        chains: List[Tuple[str, str]] = []
        first_seen_by_src: Dict[str, float] = {}
        matching_count = 0

        for ev in self.events:
            if ev.timestamp < cutoff or ev.is_trusted:
                continue
            matching_count += 1
            if ev.src_ip and ev.src_ip not in first_seen_by_src:
                first_seen_by_src[ev.src_ip] = ev.timestamp
            
            # ICMP Flood tracking (count Echo Requests from any non-loopback source IP)
            if (
                ev.protocol == "ICMP" 
                and ev.src_ip 
                and not ev.src_ip.startswith("127.")
                and ev.src_ip not in ("localhost", "::1")
            ):
                icmp_type = ev.details.get("icmp_type")
                info_str = str(ev.details.get("info", "")).lower()
                # ICMP Echo Requests: IPv4 Type 8, ICMPv6 Type 128
                # ICMP Echo Replies: IPv4 Type 0, ICMPv6 Type 129
                is_reply = False
                if icmp_type is not None:
                    is_reply = (icmp_type in (0, 129))
                else:
                    is_reply = ("type=0" in info_str) or ("echo reply" in info_str)
                if not is_reply:
                    icmp_by_src[ev.src_ip] += ev.packet_count

            # SYN Flood tracking
            if ev.protocol == "TCP" and ev.src_ip and ev.details.get("flags") == "SYN":
                syn_by_src[ev.src_ip] += ev.packet_count

            # Port Scan tracking (unique dst ports per src IP)
            if ev.src_ip and ev.dst_port > 0:
                unique_ports_by_src[ev.src_ip].add(ev.dst_port)

            # Data Exfiltration tracking
            if ev.dst_ip and ev.byte_count > 0:
                outbound_bytes_by_dst[ev.dst_ip] += ev.byte_count

            # Authentication Failure / Success tracking
            key = ev.src_ip if ev.src_ip else ev.process_name
            if ev.auth_failure:
                auth_fails[key] += 1
            if ev.auth_success:
                auth_succs[key] += 1

            # DNS Beaconing tracking
            if ev.dns_query:
                dns_queries[(ev.process_name, ev.dns_query)].append(ev.timestamp)

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
            auth_failures_by_src=dict(auth_fails),
            auth_successes_by_src=dict(auth_succs),
            dns_query_timestamps=dict(dns_queries),
            active_listeners=listeners,
            process_chains=chains,
            first_seen_by_src=first_seen_by_src
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
