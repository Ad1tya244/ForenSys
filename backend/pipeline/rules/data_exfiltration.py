"""
Rule 8: Data Exfiltration
Detects an unusually large, send-dominant transfer to an external peer within a short window.

Volume alone is a poor signal on a real laptop: a single video stream, cloud-sync pass, or app update can push
well over 50 MB in 30s - and that is receive-heavy (mostly peer -> host), not exfiltration. Genuine exfiltration
looks like the host pushing data OUT with little coming back, so this rule requires both a high upload volume
AND an upload-dominant ratio (upload / (upload + download)) for that peer, which routine downloads never satisfy.
"""

import time
from typing import Dict, Any, List, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine, is_local_ip
from analyzers.ip_intel import is_private_ip

class DataExfiltrationRule(BaseRule):
    name = "Data Exfiltration"
    description = "Detects a send-dominant transfer of unusually high volume to an external peer within a short window."
    datasource = "network"
    time_window = "20s"
    severity = "high"
    mitre_tactics = ["Exfiltration"]
    confidence = 0.82
    recommended_remediation = "Add the external destination IP to the perimeter blocklist"

    def evaluate(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        current_time = now if now else time.time()
        limit_bytes = config.get("data_exfiltration_bytes", 104857600)  # 100 MB default
        window_sec = config.get("data_exfiltration_window_sec", 20.0)
        min_ratio = config.get("data_exfiltration_upload_ratio", 0.75)  # share of traffic that must be outbound

        snapshot = state_engine.get_window_snapshot(window_sec, current_time)
        from analyzers.ip_intel import ensure_ipv4
        from pipeline.self_protection import get_primary_host_ip
        host_ip = get_primary_host_ip()

        for peer, uploaded in snapshot.upload_bytes_by_peer.items():
            if not peer or is_local_ip(peer) or uploaded < limit_bytes:
                continue
            if is_private_ip(peer) and not config.get("exfil_monitor_private_dst", False):
                continue
            downloaded = snapshot.download_bytes_by_peer.get(peer, 0)
            ratio = uploaded / (uploaded + downloaded) if (uploaded + downloaded) > 0 else 1.0
            if ratio < min_ratio:
                continue  # receive-heavy (or balanced) traffic - a normal download/stream/call, not exfil

            peer_v4 = ensure_ipv4(peer)
            first_seen = snapshot.first_upload_by_peer.get(peer, current_time)
            mb = uploaded / (1024 * 1024)
            episode = self.episode_id(f"exfil-{peer_v4}", current_time)
            alerts.append(DetectionAlert(
                alert_id=f"exfil-{peer_v4}-{episode}",
                rule_name=self.name,
                severity=self.severity,
                title=f"Potential Data Exfiltration to {peer_v4}",
                description=(
                    f"Sent {mb:.2f} MB to external IP {peer_v4} in {window_sec:g}s with only "
                    f"{downloaded / (1024 * 1024):.2f} MB received back ({ratio * 100:.0f}% upload-dominant) - "
                    f"exceeded threshold ({limit_bytes / (1024 * 1024):.1f} MB)."
                ),
                datasource=self.datasource,
                timestamp=current_time,
                affected_assets=[host_ip, peer_v4],
                mitre_tactics=self.mitre_tactics,
                confidence=self.confidence,
                remediation=self.recommended_remediation,
                metadata={
                    "dst_ip": peer_v4, "remote_ip": peer_v4, "block_ip": peer_v4, "src_ip": host_ip,
                    "transferred_bytes": uploaded, "transferred_mb": round(mb, 2),
                    "downloaded_bytes": downloaded, "upload_ratio": round(ratio, 2),
                    "threshold_bytes": limit_bytes, "window_sec": window_sec,
                    "first_seen": first_seen, "detected_at": current_time,
                    "mttd_sec": round(max(0.0, current_time - first_seen), 3), "attack_type": "data_exfil",
                }
            ))

        return alerts
