"""
Incident ledger + response metrics (MTTD / MTTR).

Definitions (per incident, all measured on the backend's wall clock):

  MTTD  Mean Time To Detect   = detected_at - first_activity_at
        first_activity_at = earliest observed attacker activity feeding the incident (first packet / log line /
        socket from the attacker that the rule's window saw); detected_at = when the incident was raised.

  MTTR  Mean Time To Remediate = contained_at - detected_at
        contained_at = when the last planned containment action (block / sinkhole / process flag) finished.
        Evidence capture happens after containment and is deliberately NOT part of MTTR.
        Incidents that were never contained (alert-only detections, or actions skipped by self-protection)
        have no MTTR and are excluded from the MTTR statistics instead of being counted as zero.

The ledger is one small record per incident, persisted separately from the audit log and the evidence vault, so
analytics survive backend restarts, "Clear History" and evidence deletion. Only "Reset Lab" clears it.
"""

import calendar
import json
import os
import threading
import time
from typing import Any, Dict, Iterable, List, Optional

LEDGER_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "incident_ledger.json")
ISO = "%Y-%m-%dT%H:%M:%SZ"

RANGE_SECONDS: Dict[str, Optional[int]] = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "all": None}


def iso(ts: Optional[float]) -> Optional[str]:
    return time.strftime(ISO, time.gmtime(ts)) if ts else None


def parse_iso(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return float(calendar.timegm(time.strptime(value, ISO)))
    except (ValueError, TypeError):
        return None


def incident_timing(incident: Any) -> Dict[str, Optional[float]]:
    """first_activity_at / detected_at / mttd_sec for a CorrelatedIncident (earliest evidence across its alerts)."""
    firsts = [d.get("metadata", {}).get("first_seen") for d in incident.related_detections]
    firsts = [f for f in firsts if isinstance(f, (int, float)) and f > 0]
    detected_at = float(incident.created_at)
    first = float(min(firsts)) if firsts else None
    mttd = round(max(0.0, detected_at - first), 3) if first is not None else None
    return {"first_activity_at": first, "detected_at": detected_at, "mttd_sec": mttd}


# ── Ledger ───────────────────────────────────────────────────────────────────

class IncidentLedger:
    def __init__(self, path: str = LEDGER_FILE) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._records: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            self._records = {r["id"]: r for r in data if isinstance(r, dict) and "id" in r}
        except Exception as e:
            print(f"[IncidentLedger] Error loading ledger: {e}")

    def _save(self) -> None:
        try:
            with open(self.path, "w") as f:
                json.dump(list(self._records.values()), f, indent=2)
        except Exception as e:
            print(f"[IncidentLedger] Error saving ledger: {e}")

    @staticmethod
    def build_record(incident: Any, contained_at: Optional[float], evidence_id: Optional[str]) -> Dict[str, Any]:
        timing = incident_timing(incident)
        mttr = round(max(0.0, contained_at - incident.created_at), 3) if contained_at else None
        target_ip = next((d.get("metadata", {}).get("target_ip") for d in incident.related_detections
                          if d.get("metadata", {}).get("target_ip")), incident.primary_dest_ip or "")
        return {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "risk_score": incident.risk_score,
            "confidence": round(incident.confidence, 2),
            "attack_types": list(incident.attack_types),
            "rules": sorted({t.get("rule", "") for t in incident.timeline if t.get("rule")}),
            "attacker_ips": list(incident.block_ips),
            "domains": list(incident.block_domains),
            "processes": list(incident.quarantine_processes),
            "mitre_stages": list(incident.mitre_stages),
            "target_ip": target_ip,
            "alert_count": len(incident.related_detections),
            "first_activity_at": timing["first_activity_at"],
            "detected_at": timing["detected_at"],
            "contained_at": contained_at,
            "contained": contained_at is not None,
            "mttd_sec": timing["mttd_sec"],
            "mttr_sec": mttr,
            "evidence_id": evidence_id,
            "updated_at": time.time(),
        }

    def backfill(self, evidence_manager: Any, soar_engine: Any) -> int:
        """Adds ledger rows for incidents that predate the ledger (found via their sealed evidence).

        Their MTTD/MTTR are left unknown on purpose: older builds produced MTTD values from clamped/constant
        placeholders and only second-resolution action timestamps, so importing them would pollute the averages.
        Returns the number of rows added.
        """
        added = 0
        for pkg in list(evidence_manager.vault.values()):
            if pkg.incident_id in self._records:
                continue
            pl = pkg.payload or {}
            timing = pl.get("timing", {})
            acts = [a for a in soar_engine.remediation_history
                    if a.incident_id == pkg.incident_id and a.status == "success"
                    and a.action_type in ("block_ip", "add_pf_rule", "sinkhole_domain", "quarantine_process", "kill_process")]
            types = pl.get("attack_types") or list((pl.get("attack_details") or {}).keys())
            attackers = pl.get("attacker_ips") or ([pl["attacker_ip"]] if pl.get("attacker_ip") else [])
            detected = parse_iso(timing.get("detected_at")) or pkg.timestamp
            contained_at = min((a.timestamp for a in acts), default=None)
            with self._lock:
                self._records[pkg.incident_id] = {
                    "id": pkg.incident_id, "title": pl.get("incident_title", pkg.incident_id),
                    "severity": pl.get("severity", "medium"), "status": "contained" if acts else "investigating",
                    "risk_score": None, "confidence": None, "attack_types": types, "rules": [],
                    "attacker_ips": attackers, "domains": [], "processes": [], "mitre_stages": pl.get("mitre_stages", []),
                    "target_ip": pl.get("target_ip", ""), "alert_count": len(pl.get("detections", [])),
                    "first_activity_at": parse_iso(timing.get("first_activity_at")), "detected_at": detected,
                    "contained_at": contained_at, "contained": bool(acts), "mttd_sec": None, "mttr_sec": None,
                    "evidence_id": pkg.evidence_id, "updated_at": time.time(), "legacy": True,
                }
            added += 1
        if added:
            with self._lock:
                self._save()
        return added

    def upsert(self, record: Dict[str, Any]) -> None:
        with self._lock:
            old = self._records.get(record["id"], {})
            # Containment time is a fact about the first containment; a later pass must not move it.
            if old.get("contained_at") and not record.get("contained_at"):
                record["contained_at"], record["contained"], record["mttr_sec"] = (
                    old["contained_at"], True, old.get("mttr_sec"))
            self._records[record["id"]] = record
            self._save()

    def get(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            rec = self._records.get(incident_id)
            return dict(rec) if rec else None

    def all(self) -> List[Dict[str, Any]]:
        """Newest detection first."""
        with self._lock:
            return sorted((dict(r) for r in self._records.values()), key=lambda r: r.get("detected_at") or 0, reverse=True)

    def ids(self) -> List[str]:
        with self._lock:
            return list(self._records)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._save()


# ── Statistics ───────────────────────────────────────────────────────────────

def percentile(sorted_values: List[float], p: float) -> float:
    """Linear-interpolation percentile (p in 0..100) of an already sorted, non-empty list."""
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (p / 100.0) * (len(sorted_values) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (rank - lo)


def describe(values: Iterable[Optional[float]]) -> Dict[str, Any]:
    vals = sorted(float(v) for v in values if isinstance(v, (int, float)))
    if not vals:
        return {"n": 0, "mean": None, "median": None, "p95": None, "min": None, "max": None}
    return {
        "n": len(vals),
        "mean": round(sum(vals) / len(vals), 3),
        "median": round(percentile(vals, 50), 3),
        "p95": round(percentile(vals, 95), 3),
        "min": round(vals[0], 3),
        "max": round(vals[-1], 3),
    }


def _delta_pct(current: Optional[float], previous: Optional[float]) -> Optional[float]:
    if current is None or previous is None or previous <= 0:
        return None
    return round((current - previous) / previous * 100.0, 1)


def _in_window(records: List[Dict[str, Any]], start: Optional[float], end: Optional[float]) -> List[Dict[str, Any]]:
    out = []
    for r in records:
        t = r.get("detected_at") or 0
        if (start is None or t >= start) and (end is None or t < end):
            out.append(r)
    return out


def _bucket_series(records: List[Dict[str, Any]], range_key: str, now: float) -> List[Dict[str, Any]]:
    """Incident counts per bucket (hourly for 24h, daily otherwise) - a real trend, no synthetic padding."""
    hourly = range_key == "24h"
    step = 3600 if hourly else 86400
    if range_key == "all":
        first = min((r.get("detected_at") or now for r in records), default=now)
        n = max(1, min(60, int((now - first) // step) + 1))
    else:
        n = 24 if hourly else (7 if range_key == "7d" else 30)
    end_bucket = int(now // step) * step
    buckets = [{"start": end_bucket - (n - 1 - i) * step, "incidents": 0, "contained": 0} for i in range(n)]
    for r in records:
        t = r.get("detected_at") or 0
        idx = (int(t // step) * step - buckets[0]["start"]) // step
        if 0 <= idx < n:
            buckets[idx]["incidents"] += 1
            if r.get("contained"):
                buckets[idx]["contained"] += 1
    for b in buckets:
        b["time"] = iso(b["start"])
    return buckets


def response_metrics(records: List[Dict[str, Any]], range_key: str = "all", now: Optional[float] = None) -> Dict[str, Any]:
    """Everything the Analytics page shows, computed from the incident ledger."""
    now = now or time.time()
    range_key = range_key if range_key in RANGE_SECONDS else "all"
    span = RANGE_SECONDS[range_key]
    current = _in_window(records, (now - span) if span else None, None)
    previous = _in_window(records, now - 2 * span, now - span) if span else []

    mttd, mttr = describe(r.get("mttd_sec") for r in current), describe(r.get("mttr_sec") for r in current)
    prev_mttd, prev_mttr = describe(r.get("mttd_sec") for r in previous), describe(r.get("mttr_sec") for r in previous)

    contained = sum(1 for r in current if r.get("contained"))
    prev_rate = (sum(1 for r in previous if r.get("contained")) / len(previous)) if previous else None
    rate = (contained / len(current)) if current else None

    by_type: Dict[str, Dict[str, Any]] = {}
    for r in current:
        key = (r.get("attack_types") or ["unknown"])[0]
        by_type.setdefault(key, {"attack_type": key, "incidents": [], })["incidents"].append(r)
    by_attack = []
    for key, grp in by_type.items():
        inc = grp["incidents"]
        by_attack.append({
            "attack_type": key, "count": len(inc),
            "mttd": describe(r.get("mttd_sec") for r in inc), "mttr": describe(r.get("mttr_sec") for r in inc),
        })
    by_attack.sort(key=lambda x: x["count"], reverse=True)

    tactics: Dict[str, int] = {}
    for r in current:
        for t in r.get("mitre_stages", []):
            tactics[t] = tactics.get(t, 0) + 1

    ordered = sorted(current, key=lambda r: r.get("detected_at") or 0)
    return {
        "range": range_key,
        "generated_at": iso(now),
        "total_incidents": len(current),
        "contained_incidents": contained,
        "containment_rate": round(rate, 4) if rate is not None else None,
        "containment_rate_change": _delta_pct(rate, prev_rate),
        "mttd": mttd,
        "mttr": mttr,
        "mttd_change_pct": _delta_pct(mttd["mean"], prev_mttd["mean"]),
        "mttr_change_pct": _delta_pct(mttr["mean"], prev_mttr["mean"]),
        "previous_total_incidents": len(previous) if span else None,
        "by_severity": {s: sum(1 for r in current if r.get("severity") == s) for s in ("critical", "high", "medium", "low")},
        "by_attack_type": by_attack,
        "by_tactic": [{"tactic": k, "count": v} for k, v in sorted(tactics.items(), key=lambda kv: -kv[1])],
        "trend": _bucket_series(current, range_key, now),
        "series": [
            {"id": r["id"], "detected_at": iso(r.get("detected_at")), "severity": r.get("severity"),
             "attack_type": (r.get("attack_types") or ["unknown"])[0],
             "mttd_sec": r.get("mttd_sec"), "mttr_sec": r.get("mttr_sec")}
            for r in ordered[-50:]
        ],
    }
