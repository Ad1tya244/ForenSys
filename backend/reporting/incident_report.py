"""
Incident report PDF: everything ForenSys knows about one incident, in a form an analyst can hand to someone else.

assemble_incident_data()  gathers it from the live correlation engine, the persisted incident ledger, the sealed
                          evidence package and the remediation history (so it still works after a backend restart).
render_incident_report()  turns that dict into PDF bytes.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from pipeline.metrics import iso, parse_iso
from reporting.pdf import (
    ACCENT, MUTED, PdfReport, SEVERITY_COLORS, STATUS_COLORS,
)

ATTACK_LABELS = {
    "port_scan": "Port Scan", "icmp_flood": "ICMP Flood / Ping Sweep", "syn_flood": "TCP SYN Flood",
    "brute_force": "Brute-Force Authentication (compromised)", "auth_attack": "Authentication Attack",
    "dns_beacon": "DNS Beaconing (C2)", "reverse_shell": "Reverse Shell", "data_exfil": "Data Exfiltration",
    "suspicious_listener": "Suspicious Listening Port", "process_chain": "Suspicious Process Chain",
}
ACTION_LABELS = {
    "block_ip": "Block IP (perimeter blocklist)", "add_pf_rule": "Block IP (perimeter blocklist)",
    "sinkhole_domain": "DNS sinkhole", "quarantine_process": "Process contained (simulated)",
    "kill_process": "Process contained (simulated)", "capture_forensics": "Forensic evidence sealed",
    "capture_pcap": "Packet capture saved", "notify_analyst": "Analyst notified",
}
RECOMMENDATIONS: Dict[str, List[str]] = {
    "port_scan": [
        "Review which of the probed ports are actually reachable on the target and close or firewall anything not required.",
        "Check whether the scanning source is an authorised vulnerability scanner or an unknown host on your network.",
        "Watch for follow-up activity (authentication attempts or exploit traffic) from the same source.",
    ],
    "icmp_flood": [
        "Confirm the source is not a misconfigured monitoring tool; rate-limit ICMP echo at the network edge if the traffic is hostile.",
    ],
    "syn_flood": [
        "Enable SYN cookies / connection rate limiting on the targeted service and consider upstream filtering of the source.",
    ],
    "brute_force": [
        "Treat the account as compromised: force a credential reset and review every session opened after the successful login.",
        "Disable password logins for the affected service in favour of key-based authentication or MFA.",
    ],
    "auth_attack": [
        "Review the targeted usernames for valid accounts and enforce lockout / rate limiting on the affected service.",
        "Restrict the service (SSH/RDP/VNC/SMB) to trusted source ranges.",
    ],
    "dns_beacon": [
        "Identify the process or host generating the periodic lookups and inspect it for malware; block the domain at your DNS filter.",
        "Search other hosts' DNS logs for the same domain to scope the infection.",
    ],
    "reverse_shell": [
        "Isolate the host, identify how the shell process was started, and review commands executed in the session.",
        "Rotate any credentials or keys that were accessible to the shell's user.",
    ],
    "data_exfil": [
        "Determine what data left the host (see captured flow) and whether the destination is an approved service.",
        "If the transfer was unauthorised, begin breach assessment and notify the data owner.",
    ],
    "suspicious_listener": [
        "Identify the binary behind the listening socket, verify its origin, and remove it if it is not expected.",
    ],
    "process_chain": [
        "Inspect the parent document/application for malicious macros or exploits and review the child process's actions.",
    ],
}


_ACRONYMS = {"ip": "IP", "ips": "IPs", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "dns": "DNS", "pid": "PID",
             "ppid": "PPID", "mttd": "MTTD", "mttr": "MTTR", "syn": "SYN", "c2": "C2", "mb": "MB", "id": "ID",
             "sec": "(s)", "raw": "(raw)", "ssh": "SSH", "pcap": "PCAP", "sha256": "SHA-256", "ack": "ACK"}


def _humanize(key: str) -> str:
    words = key.replace("_", " ").split()
    return " ".join(_ACRONYMS.get(w.lower(), w.capitalize() if i == 0 else w) for i, w in enumerate(words))


def fmt_ts(epoch: Optional[float]) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(epoch)) if epoch else "-"


def fmt_dur(sec: Optional[float]) -> str:
    if sec is None:
        return "n/a"
    if sec < 1:
        return f"{sec * 1000:.0f} ms"
    if sec < 60:
        return f"{sec:.2f} s"
    m, s = divmod(int(round(sec)), 60)
    return f"{m} m {s:02d} s"


def _value_text(value: Any) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return ", ".join(_value_text(v) for v in value) if value else "none"
    if isinstance(value, dict):
        return "; ".join(f"{k}: {_value_text(v)}" for k, v in value.items()) if value else "none"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


# ── Assembly ─────────────────────────────────────────────────────────────────

def _strip_title(summary: str, title: str) -> str:
    """The evidence summary starts with the incident title; the report already shows it, so drop the repeat."""
    return summary[len(title):].strip(" .") if title and summary.startswith(title) else summary

def assemble_incident_data(incident_id: str, correlation_engine: Any, ledger: Any, evidence_manager: Any,
                           soar_engine: Any, generated_by: str = "") -> Optional[Dict[str, Any]]:
    live = next((i for i in correlation_engine.incidents if i.id == incident_id), None)
    rec = ledger.get(incident_id) if ledger is not None else None
    pkg = evidence_manager.get_evidence(f"EVD-{incident_id}")
    actions = sorted((log.to_dict() for log in soar_engine.remediation_history if log.incident_id == incident_id),
                     key=lambda a: (a.get("epoch") or 0, a["id"]))
    if not (live or rec or pkg or actions):
        return None

    payload: Dict[str, Any] = pkg.payload if pkg else {}
    rec = rec or {}
    ptime = payload.get("timing", {})
    live_d = live.to_dict() if live else {}

    def pick(*vals: Any, default: Any = None) -> Any:
        return next((v for v in vals if v not in (None, "", [])), default)

    detections: List[Dict[str, Any]] = live_d.get("relatedDetections") or [
        {"id": d.get("id"), "title": d.get("rule"), "severity": d.get("severity"),
         "timestamp": d.get("time"), "description": d.get("description"), "metadata": {}}
        for d in payload.get("detections", [])
    ]
    detected_at = pick(rec.get("detected_at"), parse_iso(ptime.get("detected_at")), live.created_at if live else None)
    first_activity = pick(rec.get("first_activity_at"), parse_iso(ptime.get("first_activity_at")),
                          live.first_activity_at if live else None)
    contained_at = pick(rec.get("contained_at"), parse_iso(ptime.get("contained_at")), live.contained_at if live else None)

    return {
        "id": incident_id,
        "title": pick(live_d.get("title"), rec.get("title"), payload.get("incident_title"), default=incident_id),
        "severity": pick(live_d.get("severity"), rec.get("severity"), payload.get("severity"), default="medium"),
        "status": pick(live_d.get("status"), rec.get("status"), default="unknown"),
        "risk_score": pick(live_d.get("riskScore"), rec.get("risk_score")),
        "confidence": pick(live_d.get("confidence"), rec.get("confidence")),
        "attack_types": pick(live_d.get("attackTypes"), rec.get("attack_types"), payload.get("attack_types"), default=[]),
        "mitre_stages": pick(live_d.get("mitreStages"), rec.get("mitre_stages"), payload.get("mitre_stages"), default=[]),
        "attacker_ips": pick(live_d.get("blockIps"), rec.get("attacker_ips"), payload.get("attacker_ips"), default=[]),
        "domains": pick(live_d.get("blockDomains"), rec.get("domains"), default=[]),
        "processes": pick(live_d.get("quarantineProcesses"), rec.get("processes"), default=[]),
        "target_ip": pick(rec.get("target_ip"), payload.get("target_ip"), live_d.get("primaryDestIp"), default=""),
        "affected_assets": pick(live_d.get("affectedAssets"), payload.get("affected_assets"), default=[]),
        "first_activity_at": first_activity,
        "detected_at": detected_at,
        "contained_at": contained_at,
        "mttd_sec": pick(rec.get("mttd_sec"), ptime.get("mttd_sec"), live.mttd_sec if live else None),
        "mttr_sec": pick(rec.get("mttr_sec"), ptime.get("mttr_sec"), live.mttr_sec if live else None),
        "detections": detections,
        "actions": actions,
        "evidence": None if not pkg else {
            "id": pkg.evidence_id, "status": pkg.status, "sha256": pkg.sha256_hash,
            "sealed_at": pkg.sealed_at, "verified": evidence_manager.verify(pkg),
            "artifacts": payload.get("artifacts", []), "chain": pkg.to_dict().get("chain", []),
        },
        "attack_details": payload.get("attack_details", {}),
        "summary": _strip_title(payload.get("summary", ""), pick(live_d.get("title"), rec.get("title"), payload.get("incident_title"), default="")),
        "packets": payload.get("packets", []),
        "packet_total": payload.get("packet_total", len(payload.get("packets", []))),
        "logs": payload.get("logs", []),
        "connections": payload.get("connections", []),
        "processes_captured": payload.get("processes", []),
        "listeners": payload.get("listeners", []),
        "generated_by": generated_by,
        "generated_at": time.time(),
    }


# ── Rendering ────────────────────────────────────────────────────────────────

def _timeline(d: Dict[str, Any]) -> List[Tuple[float, str, str]]:
    events: List[Tuple[float, str, str]] = []
    if d["first_activity_at"]:
        events.append((d["first_activity_at"], "First attacker activity observed",
                       f"Earliest traffic/log activity the detection engine tied to this incident."))
    for det in d["detections"]:
        ts = (det.get("metadata") or {}).get("detected_at") or parse_iso(det.get("timestamp")) or d["detected_at"]
        if ts:
            events.append((ts, f"Detection: {det.get('title', '')}", (det.get("description") or "")[:300]))
    if d["detected_at"]:
        events.append((d["detected_at"], f"Incident {d['id']} raised", f"Severity {d['severity'].upper()}, "
                       f"risk score {d['risk_score'] if d['risk_score'] is not None else 'n/a'}."))
    for a in d["actions"]:
        ts = a.get("epoch") or parse_iso(a["timestamp"])
        if ts:
            msg = (a.get("resultDetails") or {}).get("message", "")
            events.append((ts, f"{ACTION_LABELS.get(a['actionType'], a['actionType'])}: {a['target']}",
                           f"[{a['status']}] {msg}"[:300]))
    if d["evidence"] and d["evidence"]["sealed_at"]:
        events.append((d["evidence"]["sealed_at"], f"Evidence {d['evidence']['id']} sealed",
                       f"SHA-256 {d['evidence']['sha256']}"))
    events.sort(key=lambda e: e[0])
    return events


def render_incident_report(d: Dict[str, Any]) -> bytes:
    sev = (d["severity"] or "medium").lower()
    rep = PdfReport(
        title=f"ForenSys Incident Report {d['id']}",
        running_head=f"ForenSys SOC  |  Incident Report {d['id']}",
        footer_note=f"CONFIDENTIAL - contains forensic evidence  |  Incident {d['id']}",
    )
    rep.banner(
        "FORENSYS SOC  |  INCIDENT REPORT", f"{d['id']}  -  {d['title']}",
        f"Generated {fmt_ts(d['generated_at'])}" + (f" by {d['generated_by']}" if d["generated_by"] else ""),
        chips=[(sev.upper(), SEVERITY_COLORS.get(sev, MUTED)),
               (str(d["status"]).upper(), STATUS_COLORS.get(str(d["status"]).lower(), MUTED))],
    )

    # 1. Executive summary
    rep.heading("1. Executive Summary")
    types = ", ".join(ATTACK_LABELS.get(t, t) for t in d["attack_types"]) or "n/a"
    contained_txt = (f"contained {fmt_dur(d['mttr_sec'])} after detection" if d["contained_at"]
                     else "was NOT contained automatically")
    rep.paragraph(
        f"ForenSys detected {types} against {d['target_ip'] or 'the monitored host'}"
        + (f" originating from {', '.join(d['attacker_ips'])}" if d["attacker_ips"] else "")
        + f". The activity was detected {fmt_dur(d['mttd_sec'])} after it first appeared and {contained_txt}."
        + (f" {d['summary'].rstrip('.')}." if d["summary"] and d["summary"] != d["title"] else ""))
    rep.kv_table([
        ("Incident ID", d["id"]),
        ("Severity / Status", f"{sev.upper()} / {str(d['status']).upper()}"),
        ("Risk score / Confidence", f"{d['risk_score'] if d['risk_score'] is not None else 'n/a'} / "
                                   f"{round((d['confidence'] or 0) * 100)}%" if d["confidence"] is not None else "n/a"),
        ("Attack type(s)", types),
        ("Attacker (source) IP(s)", ", ".join(d["attacker_ips"]) or "n/a"),
        ("Sinkholed domain(s)", ", ".join(d["domains"]) or "-"),
        ("Contained process(es)", (", ".join(d["processes"]) + "  (simulated flag only)") if d["processes"] else "-"),
        ("Target host", d["target_ip"] or "n/a"),
        ("MITRE ATT&CK tactics", " > ".join(d["mitre_stages"]) or "n/a"),
        ("First activity", fmt_ts(d["first_activity_at"])),
        ("Detected", fmt_ts(d["detected_at"])),
        ("Contained", fmt_ts(d["contained_at"])),
        ("MTTD (time to detect)", fmt_dur(d["mttd_sec"])),
        ("MTTR (time to remediate)", fmt_dur(d["mttr_sec"]) if d["contained_at"] else "n/a (not contained)"),
    ])

    # 2. Timeline
    rep.heading("2. Incident Timeline")
    rep.table(["Time (UTC)", "Event", "Detail"],
              [[time.strftime("%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}", ev, det] for t, ev, det in _timeline(d)],
              [62, 150, 300], size=7.6, max_lines=3)

    # 3. Detections
    rep.heading("3. Detections")
    for det in d["detections"]:
        md = det.get("metadata", {}) or {}
        rep.heading(det.get("title") or "Detection", level=2)
        rep.kv_table([
            ("Rule / Source", f"{det.get('title', '')}  |  {det.get('source', md.get('attack_type', ''))}"),
            ("Severity / Confidence", f"{str(det.get('severity', '')).upper()}  |  "
                                      f"{round((det.get('confidence') or 0) * 100)}%" if det.get("confidence") is not None
             else str(det.get("severity", "")).upper()),
            ("Raised", det.get("timestamp") or "-"),
            ("Description", det.get("description") or "-"),
            ("Recommended response", det.get("remediation") or "-"),
        ], size=8)

    # 4. Attack forensics
    rep.heading("4. Attack Forensics")
    if not d["attack_details"]:
        rep.paragraph("No attack-specific forensic details were captured for this incident.", color=MUTED)
    for kind, info in d["attack_details"].items():
        rep.heading(ATTACK_LABELS.get(kind, _humanize(kind)), level=2)
        rows: List[Tuple[str, str]] = []
        for key, value in info.items():
            if value in (None, "", [], {}):
                continue
            if key == "port_services" and isinstance(value, dict):
                rows.append(("Services identified", ", ".join(f"{p}/{n}" for p, n in value.items())))
            elif key in ("log_excerpt",):
                continue  # rendered in the log section instead
            else:
                rows.append((_humanize(key), _value_text(value)))
        rep.kv_table(rows, size=8, max_lines=60)

    # 5. Containment
    rep.heading("5. Containment & Response Actions")
    rep.paragraph("Containment in ForenSys is logical: a block adds the address to the perimeter blocklist so the packet "
                  "sniffer ignores it until an analyst releases it; a sinkhole makes the sniffer ignore DNS traffic for "
                  "the domain; a process flag is a registry marker. No OS firewall rule was changed and no process was "
                  "signalled, killed or modified.", size=8, color=MUTED)
    rep.table(["Action ID", "Time (UTC)", "Action", "Target", "Status", "Result"],
              [[a["id"], a["timestamp"][11:19], ACTION_LABELS.get(a["actionType"], a["actionType"]), a["target"], a["status"],
                (a.get("resultDetails") or {}).get("message", "")] for a in d["actions"]],
              [52, 44, 82, 90, 42, 200], size=7.3, max_lines=4, mono_cols=(0, 3), empty_text="No response actions were recorded.")

    # 6. Evidence & chain of custody
    rep.heading("6. Forensic Evidence & Integrity")
    ev = d["evidence"]
    if not ev:
        rep.paragraph("No sealed evidence package is on file for this incident (it may have been deleted from the vault).",
                      color=MUTED)
    else:
        verdict = ("VERIFIED - the SHA-256 recomputed from the stored payload matches the digest recorded when the "
                   "package was sealed." if ev["verified"] else
                   "MISMATCH - the stored payload no longer matches the digest recorded at sealing time. Treat this "
                   "evidence as potentially altered.")
        rep.kv_table([
            ("Evidence package", f"{ev['id']}  ({ev['status']})"),
            ("Sealed at", fmt_ts(ev["sealed_at"])),
            ("SHA-256", ev["sha256"]),
            ("Integrity check", verdict),
            ("Packets captured", f"{d['packet_total']} (first {min(len(d['packets']), 300)} stored in package)"),
            ("Log lines / sockets", f"{len(d['logs'])} / {len(d['connections'])}"),
        ], size=8, value_font="F1")
        for art in ev["artifacts"]:
            rep.kv_table([("Artifact", f"{art.get('path')}  ({art.get('packets', '?')} packets, {art.get('bytes', '?')} bytes)"),
                          ("Artifact SHA-256", art.get("sha256", "-")), ("Note", art.get("note", "-"))], size=7.6)
        for line in ev["chain"]:
            rep.paragraph(f"- {line}", size=8, color=MUTED, space_after=1)
        rep.space(4)

    # 7. Network evidence
    rep.heading("7. Network Evidence (captured packets)")
    pk = d["packets"][:80]
    rows = []
    for i, p in enumerate(pk, start=1):
        src = f"{p.get('src_ip', '')}:{p.get('src_port')}" if p.get("src_port") else p.get("src_ip", "")
        dst = f"{p.get('dst_ip', '')}:{p.get('dst_port')}" if p.get("dst_port") else p.get("dst_ip", "")
        rows.append([i, (p.get("time") or "")[11:19], p.get("protocol", ""), src, dst, p.get("flags") or "", p.get("length", ""),
                     p.get("info", "")])
    rep.table(["#", "Time", "Proto", "Source", "Destination", "Flags", "Len", "Info"], rows,
              [14, 36, 26, 84, 84, 38, 28, 104], size=6.9, max_lines=2, mono_cols=(3, 4),
              empty_text="No packets were captured for this incident (it was detected from logs or socket telemetry).")
    if d["packet_total"] > len(pk):
        rep.paragraph(f"Showing the first {len(pk)} of {d['packet_total']} captured packets; the full capture is stored "
                      f"in the evidence package.", size=8, color=MUTED)

    # 8. Logs
    log_rows = [[(l.get("time") or "")[11:19], l.get("process", ""), l.get("src_ip") or "", l.get("level", ""), l.get("message", "")]
                for l in d["logs"][:100]]
    rep.heading("8. Log Evidence")
    rep.table(["Time", "Process", "Source IP", "Level", "Message"], log_rows, [36, 50, 66, 34, 330], size=7, max_lines=4,
              mono_cols=(2,), empty_text="No related log lines were captured for this incident.")

    # 9. Host context
    rep.heading("9. Host Context (sockets, processes, listeners)")
    rep.heading("Network connections", level=2)
    rep.table(["Local", "Remote", "Process", "PID"],
              [[f"{c.get('local_ip')}:{c.get('local_port')}", f"{c.get('remote_ip')}:{c.get('remote_port')}",
                c.get("process"), c.get("pid")] for c in d["connections"][:40]],
              [110, 130, 80, 40], size=7.2, mono_cols=(0, 1), empty_text="No related connections.")
    rep.heading("Processes", level=2)
    rep.table(["Process", "Parent", "PID", "PPID"],
              [[p.get("process"), p.get("parent_process"), p.get("pid"), p.get("ppid")] for p in d["processes_captured"][:30]],
              [110, 110, 50, 50], size=7.2, empty_text="No related processes.")
    rep.heading("Listening sockets", level=2)
    rep.table(["Address", "Process", "PID"],
              [[f"{l.get('ip')}:{l.get('port')}", l.get("process"), l.get("pid")] for l in d["listeners"][:20]],
              [120, 110, 50], size=7.2, mono_cols=(0,), empty_text="No related listeners.")

    # 10. Recommendations
    rep.heading("10. Recommended Follow-up")
    recs: List[str] = []
    for t in d["attack_types"]:
        recs.extend(RECOMMENDATIONS.get(t, []))
    recs.append("If real network-level blocking is required, apply it on your firewall or router - ForenSys's containment "
                "is logical only and does not alter the host's firewall.")
    recs.append(f"Release the blocklist entries from the Playbooks page once the threat is resolved, so legitimate "
                f"traffic from those addresses is monitored again.")
    rep.bullets(recs)

    # Definitions
    rep.heading("Metric definitions", level=2)
    rep.paragraph("MTTD = detection time minus the first observed attacker activity. MTTR = time from detection to completion "
                  "of the last containment action (evidence sealing is excluded). Both are measured on the ForenSys "
                  "host's clock.", size=8, color=MUTED)
    return rep.to_bytes()
