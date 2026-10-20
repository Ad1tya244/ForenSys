"""
Synthetic telemetry inbox (test hook; real attacks are detected from live traffic - see docs/REAL_ATTACK_DEMOS.md).

Tests push raw telemetry (logs, connections, processes, listeners) here; the detection loop drains it
every cycle and feeds it through exactly the same normalizer -> state engine -> rules -> correlation -> SOAR ->
evidence pipeline as real host telemetry. Packets are injected straight into the sniffer queue instead
(see collectors.traffic.inject_packet) so the blocklist is honoured exactly like for real captured traffic.
"""

import collections
import threading
from typing import Dict, List

_KINDS = ("log", "connection", "process", "listener")
_inbox: Dict[str, collections.deque] = {k: collections.deque(maxlen=2000) for k in _KINDS}
_lock = threading.Lock()


def push(kind: str, item: dict) -> None:
    if kind not in _inbox:
        raise ValueError(f"Unknown telemetry kind '{kind}'")
    with _lock:
        _inbox[kind].append(item)


def drain() -> Dict[str, List[dict]]:
    with _lock:
        out = {k: list(q) for k, q in _inbox.items()}
        for q in _inbox.values():
            q.clear()
    return out
