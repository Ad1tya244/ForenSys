# ForenSys - Enterprise EDR/XDR & SOC Response Platform

ForenSys is a modern, real-time Security Operations Center (SOC) dashboard and behavior-based EDR/XDR response platform built for high-performance security teams. It integrates a **real-time system telemetry & behavioral rule engine** written in Python (FastAPI) with an interactive Next.js (TypeScript) cyber-themed dashboard using WebSockets.

---

## 🚀 Key Features & Capabilities

ForenSys streams real host telemetry and runs local behavioral threat analysis to drive all platform components:

- **Self-Protection Mode & Trusted Context Filter**: Built-in platform self-preservation layer (`AssetTrustManager`) that dynamically registers ForenSys platform PIDs, project installation paths, local listening ports, and active network interface IPs (`192.168.1.x`, `127.0.0.1`). System internal activity is logged in a **Self-Protection Audit** while strictly suppressing false-alarm alerts, risk score inflation, and auto-remediation containment actions against ForenSys itself.
- **Behavior-Based EDR Rule Engine & Incident Correlation**: Modular stateful rule engine (auto-discovers every `pipeline/rules/*.py`) evaluating 10 behavioral rules - ICMP Flood, Port Scan, SYN Flood, Brute Force Authentication, Authentication Attack Correlation, DNS Beaconing, Reverse Shell, Data Exfiltration (upload-dominant transfer volume, not raw byte count - a download never counts), Suspicious Listening Port, and Suspicious Process Chain. Each rule tracks its own attack "episode" so a sustained attack is reported once, not repeatedly, until it goes quiet or is manually unblocked. Deterministically maps IPv6 attack source addresses to public IPv4 addresses (via SHA-256 hashing) for consistent threat visualization and SOAR integration, while preserving original telemetry logs. `IncidentCorrelationEngine` clusters multi-stage alerts into unified `CorrelatedIncident` (`ICMP01`, `SCAN01`, `AUTH01`, `EXFIL01`) timelines mapped to MITRE ATT&CK tactics with confidence and risk scores.
- **Consolidated Security Alerts Workspace (`/dashboard/alerts`)**: Merged security workspace displaying active threat alerts and correlated intrusion sequences. Features severity counters that dynamically exclude resolved alerts, subtle non-glowing card backgrounds for resolved items, and a dedicated **Resolved** tab filter.
- **Master-Detail EDR Rules Catalog & Dynamic Thresholds (`/dashboard/rules`)**: Master-detail 2-column rule catalog allowing SOC administrators to adjust behavioral thresholds (e.g. ICMP Flood limit, sliding time windows) in real-time. Configuration changes immediately persist to `config.json` and in-memory detection rule evaluations, restricted strictly to **Admin** role users.
- **Accurate MTTD & MTTR Performance Analytics (`/dashboard/analytics`)**:
  - **MTTD (Mean Time to Detect)**: Measures exact latency from the first packet arrival of an attack stream to rule alert generation (e.g., ~1.4s).
  - **MTTR (Mean Time to Remediate)**: Measures exact latency from alert generation to automated SOAR containment completion (IP block and evidence vault sealing) (e.g., ~0.9s).
- **Forensic Evidence Vault & SHA-256 Sealing**: Automated forensic evidence collection engine (`EvidenceManager`) that captures process hierarchies, socket history, packet headers, and system logs upon incident creation. Evidence packages (`EVD-ICMP01`, `EVD-EXFIL01`) are hashed using SHA-256 digests and immutably sealed.
- **SOAR Auto-Remediation (logical containment)**: every incident follows one workflow - **attack detected → incident raised → auto-remediation → forensic evidence captured & sealed → logged in history**. Remediation never touches the OS firewall, processes or files: *Block IP* adds the attacker to the perimeter blocklist so the BPF/Scapy packet sniffer **ignores all telemetry to/from it until an analyst manually unblocks it**; DNS beacons get a domain sinkhole (sniffer ignores that domain's DNS traffic); malicious processes are only flagged as contained in the ForenSys registry (simulated). Every action is in the history with one-click **Rollback**.
- **Per-attack Forensic Evidence**: at containment time `EvidenceManager` seals a SHA-256 package containing the attack-specific facts - e.g. for a port scan the scanner IP, target, every probed port + service name, TCP flags, timing and packet rate; for brute force the targeted usernames and log lines; for DNS beaconing the domain, intervals and resolvers - plus the packets/logs/sockets, a headers-only `capture.pcap` and `evidence.json` under `backend/evidence/<EVD-ID>/`.
- **Real two-laptop attack demos**: run ForenSys in privileged mode (`npm run dev:privileged`) and drive it with genuine traffic from a second machine on the LAN - `nmap` port scans, `ping`/`hping3` floods, SSH brute force, a real reverse shell, bulk exfil, rogue listeners and suspicious process chains. See [docs/REAL_ATTACK_DEMOS.md](docs/REAL_ATTACK_DEMOS.md) for exact commands per attack. A live `sshd`/`sudo` log stream (`log stream` on macOS) also means SSH brute force is detected within ~1s, not just from periodic log polling.
- **Auto Remediation History Console (`/dashboard/automation`)**: Dedicated audit trail view displaying all executed containment actions, target IPs, triggering EDR rules, execution statuses (`success`, `rolled_back`, `skipped`), and instant single-click **Rollback**. **Clear History** clears this audit log only - it never releases active containment, by design, so tidying up old rows can't silently let a blocked attacker's traffic back through. **Reset Lab** (separate, confirmation-gated) is the full wipe: alerts, incidents, evidence, history, and every active block/sinkhole/quarantine, for starting a clean demo.
- **Firewall Rules & IP Blocklist Console (`/dashboard/playbooks`)**: Dedicated perimeter defense console displaying the perimeter blocklist (IPs the sniffer ignores), block reasons, registered EDR rule catalogs, and **Block / Unblock IP** controls with zero-delay cursor feedback. An unblocked IP stays listed (marked *released*, not deleted) so it can be re-blocked with one click instead of needing to be retyped.
- **Command Center Dashboard**: Live host metrics (real CPU, RAM, Disk, Uptime), threat level gauges, real-time alert tickers, and active IP blocklist counters. Features a high-fidelity user profile dropdown menu with active status tags, role labels, and user management access.
- **Real-Time Network Telemetry**: Streams active TCP/UDP connections and local listening sockets. Uses a non-root `lsof` fallback collector on macOS to map sockets to their owner process names and PIDs.
- **Network Intelligence Console**: Displays active network indicators of compromise, geolocated peers, and active network connections. Features interactive Recharts density/type breakdown graphs, regex-powered search filter fields, CSV/JSON report exporters, and direct Iris AI deep-dives for forensic analysis.
- **Real-Time Network Traffic Audit**: Live packet capture stream powered by **Scapy (BPF-based packet capture)** that sniffs TCP/UDP/ICMP traffic across host interfaces. Ignores telemetry from blocked IPs in real-time (logical block, no firewall changes). Includes custom live charts (Top Active Talkers, Protocol Distribution), search and protocol filtering, clear logs, and pause/resume control.
- **Log Explorer**: Live streaming log explorer capturing active system log streams with level, process, subsystem, and category filters. Features regex search mode with real-time error syntax feedback, inline query term highlighting, CSV/JSON exporters, and direct Iris analyzer hooks.
- **Context-Aware AI Security Assistant (Iris)**: Built-in Security Assistant analyzing live SOC state to reconstruct attack chains and answer analysis questions.
- **JWT Authentication & Granular RBAC**: Token-based user sessions using JSON Web Tokens (JWT) with password verification via bcrypt. Supports custom roles (`Admin`, `Analyst`, `Responder`, `Viewer`) and department-based permissions across all dashboards and automation workspaces.

---

## 🛠 Tech Stack

### Frontend (Next.js)
- **Framework**: Next.js 16 (App Router / Turbopack)
- **Language**: TypeScript
- **State Management**: Zustand
- **Real-Time Delivery**: WebSocket Client (`lib/api-client.ts`)
- **Styling**: Tailwind CSS & Glassmorphism design tokens
- **Visuals**: Shadcn UI, Framer Motion, Recharts, Lucide Icons, Sonner

### Backend (Python)
- **Framework**: FastAPI & Uvicorn
- **Rule Engine & EDR**: `BehaviorStateEngine`, `RuleEngine`, `IncidentCorrelationEngine`, `AssetTrustManager`, `SOAREngine`, `EvidenceManager`
- **Collectors**: `psutil` (System resources), `lsof` / `netstat` (Socket-to-Process mapping), `scapy` (BPF packet capture via libpcap), live `log stream` / `tail -F` auth log tail (macOS/Linux) for sub-second SSH/sudo brute-force detection
- **Network Intelligence**: Emerging Threats Blocklist IP loader & IP Geolocator
- **Transport**: JSON-serialized WebSocket server

---

## 📦 Getting Started

### Prerequisites
- **Node.js**: v18+ and `npm`
- **Python**: v3.10+ (with `venv` support)

### Environment Configuration

#### Frontend Configuration (`.env.local` in the root)
```env
# Google Gemini API key for Iris AI Security Assistant (Optional, defaults to local rules-based fallback)
GEMINI_API_KEY=your_api_key_here

# Backend FastAPI server URL (Optional, defaults to http://localhost:8000)
NEXT_PUBLIC_BACKEND_URL=http://localhost:8000
```

#### Backend Configuration (`backend/.env`)
```env
# Secret key used for signing JWT access and refresh tokens
JWT_SECRET_KEY=your_jwt_secret_key
```

### Installation & Launch

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/forensys.git
   cd forensys
   ```

2. **Install Frontend Dependencies:**
   ```bash
   npm install
   ```

3. **Start the Unified Dev Environment:**
   You can start both the Next.js frontend and the FastAPI backend concurrently using one of the following commands:
   * **Standard Mode (Simulated telemetries fallback):**
     ```bash
     npm run dev
     ```
   * **Privileged Mode (Real BPF-based packet capture for nmap/ping demos; blocking stays logical):**
     ```bash
     npm run dev:privileged
     ```

4. **Access the SOC Console:**
   Open [http://localhost:3000](http://localhost:3000) in your browser. The dashboard will connect to the backend WebSocket automatically.

5. **Run End-to-End EDR Simulation & Verification Tests:**
   ```bash
   # Run the full backend test suite (workflow, phases 1-5, self-protection)
   cd backend && .venv/bin/python -m unittest discover -s tests -p "test_*.py" -t .

   # Run End-to-End Attack Pipeline Simulation
   backend/.venv/bin/python backend/scripts/simulate_attacks.py
   ```

6. **Run a real attack demo:** start ForenSys with `npm run dev:privileged` on one laptop and follow [docs/REAL_ATTACK_DEMOS.md](docs/REAL_ATTACK_DEMOS.md) from a second laptop on the same LAN (nmap scan, ping/SYN flood, SSH brute force, reverse shell, exfil, rogue listener, process chain). Watch the incident appear, the attacker get blocked, evidence get sealed in **Forensics**, and the actions land in the automation history. Unblock the IP from **Playbooks** to re-arm detection for the next run.

   > **Containment is logical only.** ForenSys never changes the OS firewall, processes or files - a "block" just makes the packet sniffer ignore the IP (or sinkholed domain) until you manually unblock it.

### Troubleshooting: `npm run dev` crashes if the project lives in a cloud-synced folder

If `next dev` throws `Failed to open database... invalid digit found in string` (or similar Turbopack panics) and deleting
`.next` only fixes it temporarily, the project directory is probably being live-synced by iCloud Drive ("Desktop &
Documents Folders"), Dropbox, or OneDrive. Turbopack's dev-mode persistent cache (stable and on by default since
Next.js 16.1) continuously rewrites a small database of `.sst`/`.meta` files under `.next/dev/cache/turbopack/`; a
sync client racing those writes creates "conflicted copy" files (`name 2.ext`), which Turbopack's loader can't parse
as a cache-entry number. This repo's `next.config.mjs` already disables that cache
(`experimental.turbopackFileSystemCacheForDev: false`) to avoid it - if you still hit this, delete `.next` once more
and confirm that setting is in place.

---

## 📁 Project Structure

```text
├── app/                      # Next.js App Router Pages
│   └── dashboard/            # EDR/SOC Modules (Alerts, Forensics, Automation, Playbooks, Rules, etc.)
├── backend/                  # Python Telemetry & EDR/XDR Engine
│   ├── analyzers/            # Threat detection & IP blocklist matching
│   ├── collectors/           # Telemetry scripts (system, logs, network, processes, traffic, demo injector)
│   ├── pipeline/             # EDR Architecture: RuleEngine, Correlation, Self-Protection, SOAR, Evidence, Response workflow
│   ├── evidence/             # (generated, git-ignored) per-incident pcap + evidence.json artifacts
│   ├── scripts/              # Attack simulation scripts
│   ├── tests/                # Unit test suites
│   ├── main.py               # FastAPI server entrypoint
│   └── requirements.txt      # Backend Python dependencies
├── CLAUDE.md                 # Project rules for AI agents (logical-only remediation, no auto-commits)
├── docs/                     # REAL_ATTACK_DEMOS.md: two-laptop real-traffic demo runbook
├── components/               # React UI Components
├── lib/                      # Next.js client integration
│   ├── api-client.ts         # WebSocket / REST client setup
│   └── app-store.ts          # Zustand global state manager
└── scripts/                  # Development automation scripts
```

---

## 📄 License
This project is for security analysis, EDR/XDR engineering, and SOC portfolio purposes only.
