/**
 * ForenSys API Client
 * Connects the Next.js frontend to the Python backend.
 * Uses WebSocket for live streaming, REST for initial data load.
 */

export const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
export const WS_URL = BACKEND_URL.replace('http', 'ws') + '/ws';

// ── Types matching the Python backend output ──────────────────────────────────

export interface RealMetrics {
  cpu_percent: number;
  cpu_count: number;
  memory_percent: number;
  memory_used: number;
  memory_total: number;
  disk_percent: number;
  bytes_sent: number;
  bytes_recv: number;
  connections_total: number;
  uptime_seconds: number;
  platform: string;
  platform_version?: string;
  hostname: string;
  threat_level: 'low' | 'medium' | 'high' | 'critical';
  alerts_total: number;
  blocklist_size: number;
}

export interface NetworkConnection {
  id: string;
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  status: string;
  pid: number | null;
  process: string;
  protocol: string;
  geo?: {
    country: string;
    country_code: string;
    city: string;
    org: string;
    lat: number | null;
    lon: number | null;
  };
}

export interface RealProcess {
  pid: number;
  name: string;
  cpu_percent: number;
  memory_percent: number;
  status: string;
  username: string;
  suspicious: boolean;
  high_resource: boolean;
}

export interface RealLogEntry {
  id: string;
  timestamp: string;
  process: string;
  pid?: number;
  subsystem?: string;
  message: string;
  category: string;
  level: 'info' | 'warn' | 'error';
  source: string;
}

export interface RealAlert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  source: string;
  timestamp: string;
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved';
  affectedAssets: string[];
  mitreTactics: string[];
}

export interface ArpDevice {
  hostname: string;
  ip: string;
  mac: string;
  interface: string;
}

export interface BackendSnapshot {
  timestamp: string;
  metrics: RealMetrics;
  connections: NetworkConnection[];
  processes: RealProcess[];
  logs: RealLogEntry[];
  new_alerts: RealAlert[];
  all_alerts: RealAlert[];
  devices: ArpDevice[];
  listening_ports: { port: number; ip: string; process: string; pid: number }[];
}

// ── REST helpers ──────────────────────────────────────────────────────────────

export async function fetchHealth(): Promise<{ status: string; clients: number; alerts: number }> {
  const res = await fetch(`${BACKEND_URL}/api/health`);
  return res.json();
}

export async function fetchAlerts(): Promise<RealAlert[]> {
  const res = await fetch(`${BACKEND_URL}/api/alerts`);
  return res.json();
}

export async function fetchMetrics(): Promise<RealMetrics> {
  const res = await fetch(`${BACKEND_URL}/api/metrics`);
  return res.json();
}

export async function checkBackendAlive(): Promise<boolean> {
  try {
    const res = await fetch(`${BACKEND_URL}/api/health`, { signal: AbortSignal.timeout(2000) });
    return res.ok;
  } catch {
    return false;
  }
}

// ── WebSocket manager ─────────────────────────────────────────────────────────

type SnapshotHandler = (snapshot: BackendSnapshot) => void;

export class BackendSocket {
  private ws: WebSocket | null = null;
  private handler: SnapshotHandler;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private alive = true;

  constructor(handler: SnapshotHandler) {
    this.handler = handler;
  }

  connect(): void {
    if (this.ws) return;
    try {
      this.ws = new WebSocket(WS_URL);

      this.ws.onmessage = (event) => {
        try {
          const data: BackendSnapshot = JSON.parse(event.data);
          this.handler(data);
        } catch {
          /* ignore malformed frames */
        }
      };

      this.ws.onclose = () => {
        this.ws = null;
        if (this.alive) {
          // Reconnect after 3 seconds
          this.reconnectTimer = setTimeout(() => this.connect(), 3000);
        }
      };

      this.ws.onerror = () => {
        this.ws?.close();
        this.ws = null;
      };
    } catch {
      this.reconnectTimer = setTimeout(() => this.connect(), 3000);
    }
  }

  disconnect(): void {
    this.alive = false;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.ws?.close();
    this.ws = null;
  }

  ping(): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send('ping');
    }
  }
}
