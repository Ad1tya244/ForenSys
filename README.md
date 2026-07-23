# ForenSys - Enterprise EDR/XDR & SOC Response Platform

ForenSys is a modern, real-time Security Operations Center (SOC) dashboard and behavior-based EDR/XDR response platform built for high-performance security teams. It integrates a **real-time system telemetry & behavioral rule engine** written in Python (FastAPI) with an interactive Next.js (TypeScript) cyber-themed dashboard using WebSockets.

---

## 🚀 Key Features & Capabilities

ForenSys streams real host telemetry and runs local behavioral threat analysis to drive all platform components:

- **Self-Protection Mode & Trusted Context Filter**: Built-in platform self-preservation layer (`AssetTrustManager`) that dynamically registers ForenSys platform PIDs, project installation paths, local listening ports, and active network interface IPs (`192.168.1.x`, `127.0.0.1`). System internal activity is logged in a **Self-Protection Audit** while strictly suppressing false-alarm alerts, risk score inflation, and auto-remediation containment actions against ForenSys itself.
- **Behavior-Based EDR Rule Engine & Incident Correlation**: Modular stateful rule engine that evaluates ICMP Floods, Port Scans, Brute Force Authentication, DNS Beaconing, Reverse Shells, and Data Exfiltration. `IncidentCorrelationEngine` clusters multi-stage alerts into unified `CorrelatedIncident` (`INC-XXXXXX`) timelines mapped to MITRE ATT&CK tactics with confidence and risk scores.
- **Forensic Evidence Vault & SHA-256 Sealing**: Automated forensic evidence collection engine (`EvidenceManager`) that captures process hierarchies, socket history, packet headers, and system logs upon incident creation. Evidence packages (`EVD-XXXXXX`) are hashed using SHA-256 digests and immutably sealed.
- **SOAR Auto-Remediation & Perimeter Defense Engine**: Automated SOAR containment execution engine (`SOAREngine`) that blocks attacking remote IPs via macOS `pfctl` packet filter rules, captures packet snapshots (`.pcap`), dumps process environment metadata, and dispatches analyst notifications with one-click **Rollback** capabilities.
- **Auto Remediation History Console (`/dashboard/automation`)**: Dedicated audit trail view displaying all executed containment actions, target IPs, triggering EDR rules, execution statuses (`success`, `rolled_back`, `skipped`), and instant single-click **Rollback** and **Clear History** controls.
- **Firewall Rules & IP Blocklist Console (`/dashboard/playbooks`)**: Dedicated perimeter defense console displaying active macOS PF firewall rules, active perimeter blocklists, block reasons, registered EDR rule catalogs, and **Unblock / Rollback IP** controls.
- **Command Center Dashboard**: Live host metrics (real CPU, RAM, Disk, Uptime), threat level gauges, real-time alert tickers, EDR intrusion sequences, and self-protection audit logs. Features a high-fidelity user profile dropdown menu with active status tags, role labels, and user management access.
- **Real-Time Network Telemetry**: Streams active TCP/UDP connections and local listening sockets. Uses a non-root `lsof` fallback collector on macOS to map sockets to their owner process names and PIDs.
- **Network Intelligence Console**: Displays active network indicators of compromise, geolocated peers, and active network connections. Features interactive Recharts density/type breakdown graphs, regex-powered search filter fields, CSV/JSON report exporters, and direct Iris AI deep-dives for forensic analysis.
- **Real-Time Network Traffic Audit**: Live packet capture stream powered by **Scapy (BPF-based packet capture)** that sniffs TCP/UDP/ICMP traffic across host interfaces. Includes custom live charts (Top Active Talkers, Protocol Distribution), search and protocol filtering, clear logs, and pause/resume control.
- **Threat Hunting Workspace**: Interactive threat hunter module with floating query consoles directly on the dashboard's cyber-grid background.
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
- **Collectors**: `psutil` (System resources), `lsof` / `netstat` (Socket-to-Process mapping), `scapy` (BPF packet capture via libpcap)
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
   * **Privileged Mode (Real BPF-based packet capture & macOS PF Firewall control):**
     ```bash
     npm run dev:privileged
     ```

4. **Access the SOC Console:**
   Open [http://localhost:3000](http://localhost:3000) in your browser. The dashboard will connect to the backend WebSocket automatically.

5. **Run End-to-End EDR Simulation & Verification Tests:**
   ```bash
   # Run Self-Protection Unit Test Suite
   backend/.venv/bin/python -m unittest backend/tests/test_self_protection.py

   # Run End-to-End Attack Pipeline Simulation
   backend/.venv/bin/python backend/scripts/simulate_attacks.py
   ```

---

## 📁 Project Structure

```text
├── app/                      # Next.js App Router Pages
│   └── dashboard/            # EDR/SOC Modules (Alerts, Incidents, Forensics, Automation, Playbooks, etc.)
├── backend/                  # Python Telemetry & EDR/XDR Engine
│   ├── analyzers/            # Threat detection & IP blocklist matching
│   ├── collectors/           # Telemetry scripts (system, logs, network, processes)
│   ├── pipeline/             # EDR Architecture: RuleEngine, Correlation, Self-Protection, SOAR, Evidence
│   ├── scripts/              # Attack simulation scripts
│   ├── tests/                # Unit test suites
│   ├── main.py               # FastAPI server entrypoint
│   └── requirements.txt      # Backend Python dependencies
├── components/               # React UI Components
├── lib/                      # Next.js client integration
│   ├── api-client.ts         # WebSocket / REST client setup
│   └── app-store.ts          # Zustand global state manager
└── scripts/                  # Development automation scripts
```

---

## 📄 License
This project is for security analysis, EDR/XDR engineering, and SOC portfolio purposes.
