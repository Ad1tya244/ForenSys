"""
ForenSys Modular Base Detection Rule & DetectionAlert Schema
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from pipeline.state_engine import BehaviorStateEngine

@dataclass
class DetectionAlert:
    alert_id: str
    rule_name: str
    severity: str  # critical, high, medium, low
    title: str
    description: str
    datasource: str
    timestamp: float
    affected_assets: List[str]
    mitre_tactics: List[str]
    confidence: float  # 0.0 - 1.0
    remediation: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.alert_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source": self.datasource,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)),
            "status": "new",
            "affectedAssets": self.affected_assets,
            "mitreTactics": self.mitre_tactics,
            "confidence": self.confidence,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }

class BaseRule:
    """Base class for all ForenSys modular detection rules."""
    # An attack "episode" ends once its rule stays silent for this many seconds.
    episode_gap_sec: float = 30.0
    name: str = "Base Rule"
    description: str = "Base rule class"
    datasource: str = "general"
    time_window: str = "10s"
    threshold: Any = None
    severity: str = "medium"
    mitre_tactics: List[str] = []
    confidence: float = 0.8
    recommended_remediation: str = "Investigate event"

    def __init__(self) -> None:
        self._episodes: Dict[str, List[float]] = {}  # key -> [episode_start, last_seen]

    def episode_id(self, key: str, now: float) -> str:
        """Stable id for one continuous attack episode of `key`.

        Alert ids built from this stay identical while the attack is ongoing (so the same attack is never
        reported twice) and change only after the rule has been quiet for `episode_gap_sec` (a genuinely
        new attack, e.g. after a manual unblock).
        """
        ep = self._episodes.get(key)
        if ep is None or now - ep[1] > self.episode_gap_sec:
            ep = [now, now]
            self._episodes[key] = ep
        ep[1] = now
        return str(int(ep[0]))

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        """Runs detection logic against the current behavior state. Must return a list of DetectionAlerts."""
        raise NotImplementedError("Subclasses must implement evaluate()")
