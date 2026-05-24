# ForenSys - Enterprise SOC Platform

ForenSys is a modern, real-time Security Operations Center (SOC) dashboard and response platform built for high-performance security teams. It integrates a **real-time system telemetry engine** written in Python (FastAPI) with an interactive Next.js (TypeScript) cyber-themed dashboard using WebSockets.

---

## 🚀 Features

ForenSys streams real host telemetry and runs local threat analysis to drive all dashboard components:

- **Immersive Split-Screen Login Page**: Features a real-time simulated telemetry log streamer, a CSS-animated SVG HUD radar/node scanner, regulatory disclaimer overlays, and integrated password visibility toggles. Features brand logo corrected and formatted in all-caps styling: `FOREN` in white and `SYS` in cyan (`FOREN` + `SYS` accents).
- **Command Center Dashboard**: Live host metrics (real CPU, RAM, Disk, Uptime), threat level gauges, real-time alert tickers, and connection metrics. Includes a redesigned, high-fidelity user profile dropdown menu with active status tags, role labels, and a fixed profile settings router.
- **Real-Time Network Telemetry**: Streams active TCP/UDP connections and local listening sockets. Uses a non-root `lsof` fallback collector on macOS to map sockets to their owner process names and PIDs.
- **Network Intelligence Console**: Displays active network indicators of compromise, geolocated peers, and active network connections. Features interactive Recharts density/type breakdown graphs, regex-powered search filter fields, CSV/JSON report exporters, and direct Iris AI deep-dives for forensic analysis.
- **Real-Time Network Traffic Audit**: Live packet capture stream powered by **Scapy (BPF-based packet capture)** that sniffs TCP/UDP/ICMP traffic across host interfaces. Includes custom live charts (Top Active Talkers, Protocol Distribution), search and protocol filtering, clear logs, and pause/resume control. Gracefully falls back to a high-fidelity simulator representing active host connections when run in non-privileged mode.
- **Threat Hunting Workspace**: An interactive threat hunter module that uses flat layouts and borderless headers and search consoles floating directly on the dashboard's cyber-grid background for a clean, professional aesthetic.
- **Local Asset Discovery**: Discovers devices on the local network in real-time via local ARP table extraction.
- **Security Analytics**: Visualizes Mean Time to Detect (MTTD), Mean Time to Resolve (MTTR), asset risk distribution (Radar charts), and alert severity trends.
- **Network Architecture Map**: Interactive SVG-based network topology mapping that highlights compromised nodes, local interfaces, and traffic pathways.
- **Log Explorer**: Live streaming log explorer capturing active system log streams with level, process, subsystem, and category filters. Features a dynamic stacked level density distribution bar, regex search mode with real-time error syntax feedback, inline query term highlighting, CSV/JSON exporters, and an expanded drawer with direct Iris analyzer hooks.
- **Platform-Wide Uniform Search & Filters**: All core modules (Logs, Threat Hunting, Network Intel, Alerts) utilize a perfectly aligned, unified controls row. Features a standardized height (`h-9`/`36px`), relative alignment wrappers, absolute query/regex toggles, and customized form-styled native select dropdowns to deliver a consistent user experience.
- **Context-Aware AI Security Assistant (Iris)**: A built-in Security Assistant analyzing live SOC state to reconstruct attack chains and answer analysis questions.
- **SOAR Automation & Containment Rules**: Set up active threat response rules ("If/Then" logic) to contain security incidents and automate platform responses.
- **JWT Authentication & Granular RBAC**: Secure, token-based user sessions utilizing JSON Web Tokens (JWT) with password verification via bcrypt. Supports custom roles (`Super Admin`, `Admin`, `Analyst`, `Guest`) and department-based permissions to control access across all dashboards and automation workspaces. Includes interactive visibility toggles on login, operator creation, and password reset interfaces.


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
- **Collectors**: `psutil` (System resources, fallback metrics), `lsof` / `netstat` (Socket-to-Process mapping), `arp` (Device discovery), `scapy` (BPF packet sniffing via libpcap)
- **Network Intelligence**: Emerging Threats Blocklist IP loader & IP Geolocator (`ipapi.co`)
- **Transport**: JSON-serialized WebSocket server

---

## 📦 Getting Started

### Prerequisites
- **Node.js**: v18+ and `npm`
- **Python**: v3.10+ (with `venv` support)
- **MySQL / MariaDB**: A local or remote database server running on port 3306

### Environment Configuration

The application uses environment variables for both the Next.js frontend and the FastAPI backend.

#### Frontend Configuration (`.env.local` in the root)
Create a `.env.local` file in the root of the project to configure the frontend (this file is ignored by Git):
```env
# Google Gemini API key for Iris AI Security Assistant (Optional, defaults to local rules-based fallback)
GEMINI_API_KEY=your_api_key_here

# Backend FastAPI server URL (Optional, defaults to http://localhost:8000)
NEXT_PUBLIC_BACKEND_URL=http://localhost:8000
```

#### Backend Configuration (`backend/.env`)
Create or modify the `.env` file in the `backend/` directory to configure the database and security settings (this file is ignored by Git):
```env
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=root
MYSQL_DB=forensys

# Secret key used for signing JWT access and refresh tokens
JWT_SECRET_KEY=super-secret-key-replace-in-prod-with-32-bytes
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

3. **Initialize the Database Schema:**
   Ensure your MySQL/MariaDB server is running with the credentials specified in your `backend/.env` file. Then run the database initializer script to create the database and tables:
   ```bash
   python backend/init_db.py
   ```
   *Note: If your Python virtual environment at `backend/.venv` is not yet created, you can run the dev launcher in the next step first, which automatically creates the virtual environment and installs dependencies from `backend/requirements.txt` before attempting to run the database script.*

4. **Start the Unified Dev Environment:**
   You can start both the Next.js frontend and the FastAPI backend concurrently using one of the following commands:
   * **Standard Mode (Simulated telemetries fallback):**
     ```bash
     npm run dev
     ```
   * **Privileged Mode (Real BPF-based packet capture):**
     ```bash
     npm run dev:privileged
     ```
     *Note: The privileged command prompts for your administrator password to initialize the Python backend with `sudo` (required to capture packets from raw interfaces via `/dev/bpf*`), while keeping the Next.js dev server running safely under standard user permissions. Both launcher configurations automatically initialize the Python virtual environment in `backend/.venv` and install dependencies concurrently.*

5. **Access the SOC Console:**
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
│   ├── copilot/              # Iris AI Security Assistant panels
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
