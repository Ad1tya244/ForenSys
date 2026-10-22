"""
SOC summary PDF for a date range: KPIs (MTTD / MTTR with median and p95), breakdowns, a daily trend, top attackers
and the full incident register. Built from the persisted incident ledger, so it is accurate across restarts.
"""

import time
from typing import Any, Dict, List

from pipeline.metrics import describe, iso, response_metrics
from reporting.incident_report import ATTACK_LABELS, fmt_dur, fmt_ts
from reporting.pdf import MUTED, PdfReport, SEVERITY_COLORS, STATUS_COLORS


def _stat(d: Dict[str, Any], key: str) -> str:
    return fmt_dur(d.get(key)) if d.get("n") else "n/a"


def render_summary_report(records: List[Dict[str, Any]], start: float, end: float, generated_by: str = "") -> bytes:
    """`records` must already be limited to incidents detected in [start, end]."""
    m = response_metrics(records, "all", now=end)
    label = f"{time.strftime('%Y-%m-%d', time.gmtime(start))} to {time.strftime('%Y-%m-%d', time.gmtime(end))}"
    rep = PdfReport(
        title=f"ForenSys SOC Summary {label}",
        running_head=f"ForenSys SOC  |  SOC Summary Report  |  {label}",
        footer_note="CONFIDENTIAL  |  ForenSys SOC Summary Report",
    )
    rep.banner("FORENSYS SOC  |  SUMMARY REPORT", "SOC Incident & Response Summary",
               f"Period {label} (UTC)  |  Generated {fmt_ts(time.time())}" + (f" by {generated_by}" if generated_by else ""),
               chips=[(f"{m['total_incidents']} INCIDENTS", SEVERITY_COLORS["info"])])

    rep.heading("1. Key Metrics")
    rate = m["containment_rate"]
    rep.kv_table([
        ("Incidents detected", m["total_incidents"]),
        ("Contained automatically", f"{m['contained_incidents']}  ({round(rate * 100)}%)" if rate is not None else "n/a"),
        ("MTTD (mean / median / p95)", f"{_stat(m['mttd'], 'mean')}  /  {_stat(m['mttd'], 'median')}  /  {_stat(m['mttd'], 'p95')}"
                                       f"   (n={m['mttd']['n']})"),
        ("MTTR (mean / median / p95)", f"{_stat(m['mttr'], 'mean')}  /  {_stat(m['mttr'], 'median')}  /  {_stat(m['mttr'], 'p95')}"
                                       f"   (n={m['mttr']['n']})"),
        ("Slowest detection", _stat(m["mttd"], "max")),
        ("Slowest containment", _stat(m["mttr"], "max")),
    ])
    rep.paragraph("MTTD = detection time minus first observed attacker activity. MTTR = detection to completion of the last "
                  "containment action. Incidents that were not contained are excluded from MTTR instead of counted as zero.",
                  size=7.8, color=MUTED)

    rep.heading("2. Breakdown")
    sev = m["by_severity"]
    rep.table(["Severity", "Incidents"], [[s.capitalize(), sev[s]] for s in ("critical", "high", "medium", "low")], [3, 1], size=8,
              empty_text="No incidents.")
    rep.table(["Attack type", "Incidents", "MTTD mean", "MTTD p95", "MTTR mean", "MTTR p95"],
              [[ATTACK_LABELS.get(a["attack_type"], a["attack_type"]), a["count"], _stat(a["mttd"], "mean"), _stat(a["mttd"], "p95"),
                _stat(a["mttr"], "mean"), _stat(a["mttr"], "p95")] for a in m["by_attack_type"]],
              [4, 1.3, 1.6, 1.6, 1.6, 1.6], size=8, empty_text="No incidents in this period.")
    if m["by_tactic"]:
        rep.table(["MITRE ATT&CK tactic", "Incidents"], [[t["tactic"], t["count"]] for t in m["by_tactic"]], [3, 1], size=8)

    # Daily trend over the whole period
    days = max(1, min(60, int((end - start) // 86400) + 1))
    day0 = int(start // 86400) * 86400
    counts = [0] * days
    for r in records:
        idx = int(((r.get("detected_at") or 0) - day0) // 86400)
        if 0 <= idx < days:
            counts[idx] += 1
    rep.heading("3. Incident Trend")
    rep.bar_chart([time.strftime("%m-%d", time.gmtime(day0 + i * 86400)) for i in range(days)], counts, title="Incidents detected per day (UTC)")

    rep.heading("4. Top Attackers")
    by_ip: Dict[str, Dict[str, Any]] = {}
    for r in records:
        for ip in r.get("attacker_ips") or []:
            e = by_ip.setdefault(ip, {"ip": ip, "count": 0, "types": set(), "last": 0})
            e["count"] += 1
            e["types"].update(r.get("attack_types") or [])
            e["last"] = max(e["last"], r.get("detected_at") or 0)
    top = sorted(by_ip.values(), key=lambda e: (-e["count"], -e["last"]))[:15]
    rep.table(["Source", "Incidents", "Attack types", "Last seen (UTC)"],
              [[e["ip"], e["count"], ", ".join(ATTACK_LABELS.get(t, t) for t in sorted(e["types"])), fmt_ts(e["last"])] for e in top],
              [2, 1, 4, 2.4], size=7.8, mono_cols=(0,), empty_text="No attacker addresses recorded.")

    rep.heading("5. Incident Register")
    ordered = sorted(records, key=lambda r: r.get("detected_at") or 0, reverse=True)[:200]
    rep.table(["ID", "Severity", "Incident", "Detected (UTC)", "MTTD", "MTTR", "Status"],
              [[r["id"], str(r.get("severity", "")).upper(), r.get("title", ""), fmt_ts(r.get("detected_at")),
                fmt_dur(r.get("mttd_sec")), fmt_dur(r.get("mttr_sec")) if r.get("contained") else "n/a", r.get("status", "")]
               for r in ordered],
              [1.3, 1.2, 5, 2.6, 1.1, 1.1, 1.5], size=7.2, max_lines=3, mono_cols=(0,),
              empty_text="No incidents were detected in this period.")
    if len(records) > 200:
        rep.paragraph(f"Showing the 200 most recent of {len(records)} incidents.", size=8, color=MUTED)
    return rep.to_bytes()
