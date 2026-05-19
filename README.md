# ForenSys - Enterprise SOC Platform

ForenSys is a modern, real-time Security Operations Center (SOC) dashboard and response platform built for high-performance security teams. It offers a comprehensive suite of tools for monitoring alerts, investigating incidents, automating responses, and analyzing threat intelligence, all driven by an interactive cyber-themed user interface.

## 🚀 Features

ForenSys features a fully interactive global state simulating live SOC operations:

- **Command Center Dashboard**: Live KPIs, threat level indicators, alert trends (Area/Bar charts), and real-time streaming alert consoles.
- **Alert Triage & Escalation**: End-to-end alert management with severity filters, deep-dive investigation sheets, and single-click escalation to Incidents.
- **Incident Response**: Master/detail incident views with timeline tracking, status KPIs, and interactive resolution workflows.
- **Threat Intelligence**: IOC (Indicator of Compromise) feed with confidence scoring, MITRE ATT&CK tactic mapping, and watchlist support.
- **Live Threat Hunting**: Interactive hunt console featuring simulated terminal outputs, pre-built KQL/Splunk style queries, and live result tables.
- **Security Analytics**: Rich visualizations including MTTD/MTTR trends, asset risk distribution (Radar charts), and historical incident analysis.
- **Network Architecture Map**: Interactive SVG-based network topology mapping that highlights compromised nodes and encrypted traffic pathways.
- **SOAR Automation Rules**: "If/Then" rule engine interface to manage automated containment, notification, and enrichment workflows.
- **Log Explorer**: Live streaming log viewer with pause/resume functionality, severity filtering, and JSON payload inspection.
- **Context-Aware AI Copilot**: A built-in "Security Assistant" that analyzes live store data to answer questions about active alerts, threat levels, and attack chain reconstruction.
- **RBAC**: Role-based access control interface with granular permission toggles and role KPIs.

## 🛠 Tech Stack

- **Framework**: [Next.js 16](https://nextjs.org/) (App Router)
- **Language**: [TypeScript](https://www.typescriptlang.org/)
- **Styling**: [Tailwind CSS](https://tailwindcss.com/) with custom Cyber/Glassmorphism tokens
- **State Management**: [Zustand](https://github.com/pmndrs/zustand)
- **UI Components**: [Shadcn UI](https://ui.shadcn.com/) / Radix UI
- **Animations**: [Framer Motion](https://www.framer.com/motion/)
- **Charts**: [Recharts](https://recharts.org/)
- **Icons**: [Lucide React](https://lucide.dev/)
- **Notifications**: [Sonner](https://sonner.emilkowal.ski/)

## 📦 Getting Started

### Prerequisites
Make sure you have Node.js (v18+) and npm installed on your machine.

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/forensys.git
   cd forensys
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm run dev
   ```

4. **Open the application:**
   Navigate to [http://localhost:3000](http://localhost:3000) in your browser. The application will automatically redirect you to the main `/dashboard`.

## 📁 Project Structure

- `app/` - Next.js App Router pages and layouts.
  - `app/dashboard/` - Contains all core SOC modules (alerts, analytics, hunting, etc.).
- `components/` - Reusable UI components.
  - `components/ui/` - Shadcn UI base components.
  - `components/copilot/` - The Context-Aware AI Security Assistant.
- `lib/` - Utility functions, mock data generators, and store definitions.
  - `lib/app-store.ts` - The global Zustand store managing live application state.
  - `lib/mock-data.ts` - Generators and interfaces for the simulated data stream.

## 🔧 Building for Production

To create an optimized production build, run:
```bash
npm run build
```

To start the production server:
```bash
npm start
```

## 🎨 Design Philosophy

ForenSys embraces a "Cyber SOC" aesthetic, designed specifically for dark environments with:
- High-contrast alert coloring (Critical: Red, High: Orange, Medium: Yellow).
- Custom animated background utilities (`cyber-grid`, `scan-line`).
- Blurred glassmorphism (`glass` utility) to provide depth to modular cards and panels without overwhelming the data visualizations.
- Clean typography and monospace fonts for logs, IPs, and code blocks to improve scannability for analysts.

## 📄 License
This project is for demonstration and portfolio purposes.
