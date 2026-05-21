# ForenSys - Enterprise SOC Platform

ForenSys is a modern, real-time Security Operations Center (SOC) dashboard and response platform built for high-performance security teams. It integrates a **real-time system telemetry engine** written in Python (FastAPI) with an interactive Next.js (TypeScript) cyber-themed dashboard using WebSockets.

---

## 🚀 Features

ForenSys streams real host telemetry and runs local threat analysis to drive all dashboard components:

- **Command Center Dashboard**: Live host metrics (real CPU, RAM, Disk, Uptime), threat level gauges, real-time alert tickers, and connection metrics.
- **Real-Time Network Telemetry**: Streams active TCP/UDP connections and local listening sockets. Uses a non-root `lsof` fallback collector on macOS to map sockets to their owner process names and PIDs.
- **Network Intelligence Console**: Displays active network indicators of compromise, geolocated peers, and active network connections. Features interactive Recharts density/type breakdown graphs, regex-powered search filter fields, CSV/JSON report exporters, and direct SOC Copilot AI deep-dives for forensic analysis.
- **Local Asset Discovery**: Discovers devices on the local network in real-time via local ARP table extraction.
- **Security Analytics**: Visualizes Mean Time to Detect (MTTD), Mean Time to Resolve (MTTR), asset risk distribution (Radar charts), and alert severity trends.
- **Network Architecture Map**: Interactive SVG-based network topology mapping that highlights compromised nodes, local interfaces, and traffic pathways.
- **Log Explorer**: Live streaming log explorer capturing active system log streams with level, process, subsystem, and category filters. Features a dynamic stacked level density distribution bar, regex search mode with real-time error syntax feedback, inline query term highlighting, CSV/JSON exporters, and an expanded drawer with direct Copilot analyzer hooks.
- **Context-Aware AI Copilot**: A built-in Security Assistant analyzing live SOC state to reconstruct attack chains and answer analysis questions.
- **SOAR Automation & RBAC**: Automated "If/Then" containment rules and role-based access control permission configurations.

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
- **Collectors**: `psutil` (System resources, fallback metrics), `lsof` / `netstat` (Socket-to-Process mapping), `arp` (Device discovery)
- **Network Intelligence**: Emerging Threats Blocklist IP loader & IP Geolocator (`ipapi.co`)
- **Transport**: JSON-serialized WebSocket server

---

## 📦 Getting Started

### Prerequisites
- **Node.js**: v18+ and `npm`
- **Python**: v3.10+ (with `venv` support)

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
   ```bash
   npm run dev
   ```
   *Note: This launcher script automatically initializes the Python virtual environment in `backend/.venv`, installs requirements from `backend/requirements.txt`, and spins up both the FastAPI backend (port `8000`) and the Next.js dev server (port `3000`) concurrently.*

4. **Access the SOC Console:**
   Open [http://localhost:3000](http://localhost:3000) in your browser. The dashboard will connect to the backend WebSocket automatically.

---

## 📁 Project Structure

```text
├── app/                      # Next.js App Router Pages
│   └── dashboard/            # SOC Modules (Alerts, Analytics, Threat Intel, etc.)
├── backend/                  # Python Telemetry Backend
│   ├── analyzers/            # Threat detection & IP blocklist matching
│   ├── collectors/           # Telemetry scripts (system, logs, network, processes)
│   ├── main.py               # FastAPI server entrypoint
│   └── requirements.txt      # Backend Python dependencies
├── components/               # React UI Components
│   ├── copilot/              # AI Security Assistant panels
│   └── ui/                   # Shared design system components
├── lib/                      # Next.js client integration
│   ├── api-client.ts         # WebSocket / REST client setup
│   └── app-store.ts          # Zustand global state manager
└── scripts/                  # Development automation scripts
```

---

## 🎨 Design Philosophy

ForenSys uses a high-contrast dark "cyber deck" aesthetic optimized for security analysts:
- **Alert Prioritization**: Explicit alert color tokens (Critical: Red, High: Orange, Medium: Yellow).
- **Interactive Layers**: Glassmorphic backings (`glass` class) and hover interactions (`hover:scale-[1.01]`) to maintain usability during high-intensity alerts.
- **Monospaced Scannability**: IP addresses, logs, process listings, and terminal consoles use clean monospace typography for rapid technical analysis.

---

## 📄 License
This project is for demonstration and security analysis portfolio purposes.
