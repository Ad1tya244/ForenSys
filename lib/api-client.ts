/**
 * ForenSys API Client
 * Connects the Next.js frontend to the Python backend.
 * Uses WebSocket for live streaming, REST for initial data load.
 */

export const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
export const WS_URL = BACKEND_URL.replace('http', 'ws') + '/ws';

// ── Token & Auth Management ──────────────────────────────────────────────────

let accessToken: string | null = null;
let onAuthErrorCallback: (() => void) | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function registerAuthErrorCallback(callback: () => void) {
  onAuthErrorCallback = callback;
}

// Helper wrapper to append Bearer token and handle 401 automatic token refresh
async function authFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const headers = new Headers(options.headers || {});
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  const mergedOptions = { ...options, headers };
  let res = await fetch(url, mergedOptions);

  // If unauthorized, attempt to refresh session
  if (res.status === 401 && !url.includes('/api/auth/login') && !url.includes('/api/auth/setup') && !url.includes('/api/auth/refresh')) {
    try {
      const refreshRes = await fetch(`${BACKEND_URL}/api/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
      });

      if (refreshRes.ok) {
        const data = await refreshRes.json();
        if (data && data.access_token) {
          accessToken = data.access_token;
          headers.set('Authorization', `Bearer ${accessToken}`);
          // Retry the request
          res = await fetch(url, { ...options, headers });
          return res;
        }
      }
    } catch (e) {
      console.error('Session refresh failed:', e);
    }

    // Trigger logout or redirection if refresh failed
    if (onAuthErrorCallback) {
      onAuthErrorCallback();
    }
  }

  return res;
}

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

export interface RealNetworkPacket {
  id: string;
  timestamp: string;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  length: number;
  info: string;
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
  network_traffic: RealNetworkPacket[];
}

// ── REST helpers ──────────────────────────────────────────────────────────────

export async function fetchHealth(): Promise<{ status: string; clients: number; alerts: number }> {
  const res = await authFetch(`${BACKEND_URL}/api/health`);
  return res.json();
}

export async function fetchAlerts(): Promise<RealAlert[]> {
  const res = await authFetch(`${BACKEND_URL}/api/alerts`);
  return res.json();
}

export async function fetchMetrics(): Promise<RealMetrics> {
  const res = await authFetch(`${BACKEND_URL}/api/metrics`);
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

// ── Reports REST helpers ──────────────────────────────────────────────────────

export interface SavedReport {
  id: string;
  name: string;
  type: string;
  date: string;
  startDate: string;
  endDate: string;
  pages: number;
  size: string;
  data: any;
}

export async function fetchReports(): Promise<SavedReport[]> {
  const res = await authFetch(`${BACKEND_URL}/api/reports`);
  return res.json();
}

export async function saveReport(report: SavedReport): Promise<SavedReport> {
  const res = await authFetch(`${BACKEND_URL}/api/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(report),
  });
  return res.json();
}

export async function deleteReport(id: string): Promise<{ status: string }> {
  const res = await authFetch(`${BACKEND_URL}/api/reports/${id}`, {
    method: 'DELETE',
  });
  return res.json();
}

// ── Settings REST helpers ─────────────────────────────────────────────────────

export interface UserProfile {
  name: string;
  email: string;
  role: string;
}

export interface AppSettings {
  notifyOnCritical: boolean;
  notifyOnHigh: boolean;
  dailySummary: boolean;
  criticalThreshold: number;
  highThreshold: number;
  mediumThreshold: number;
  profile: UserProfile;
  integrations: { name: string; connected: boolean }[];
}

export async function fetchSettings(): Promise<AppSettings> {
  const res = await authFetch(`${BACKEND_URL}/api/settings`);
  return res.json();
}

export async function saveSettings(settings: AppSettings): Promise<AppSettings> {
  const res = await authFetch(`${BACKEND_URL}/api/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
  return res.json();
}

// ── RBAC REST helpers ─────────────────────────────────────────────────────────

export interface RbacUser {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer' | 'responder';
  department: string;
  status: 'active' | 'inactive';
  permissions: string[];
  password?: string;
}

export const ALL_PERMISSIONS = [
  'view_alerts',
  'manage_alerts',
  'view_incidents',
  'manage_incidents',
  'view_forensics',
  'export_forensics',
  'view_analytics',
  'run_hunt',
  'manage_playbooks',
  'view_logs',
  'manage_settings',
  'manage_users',
];

export const DEFAULT_PERMISSIONS: Record<string, string[]> = {
  admin: ALL_PERMISSIONS,
  analyst: ['view_alerts', 'manage_alerts', 'view_incidents', 'manage_incidents', 'view_forensics', 'view_analytics', 'run_hunt', 'view_logs'],
  responder: ['view_alerts', 'manage_alerts', 'view_incidents', 'manage_incidents', 'manage_playbooks', 'view_logs'],
  viewer: ['view_alerts', 'view_incidents', 'view_analytics', 'view_logs'],
};

export async function fetchUsers(): Promise<RbacUser[]> {
  const res = await authFetch(`${BACKEND_URL}/api/users`);
  return res.json();
}

export async function saveUser(user: RbacUser | Omit<RbacUser, 'id'>): Promise<RbacUser> {
  const res = await authFetch(`${BACKEND_URL}/api/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(user),
  });
  return res.json();
}

export async function deleteUser(id: string): Promise<{ status: string }> {
  const res = await authFetch(`${BACKEND_URL}/api/users/${id}`, {
    method: 'DELETE',
  });
  return res.json();
}

// ── Auth REST helpers ─────────────────────────────────────────────────────────

export interface AuthResponse {
  access_token: string;
  user: RbacUser;
}

export async function checkSetupRequired(): Promise<{ setup_required: boolean }> {
  const res = await fetch(`${BACKEND_URL}/api/auth/setup-status`);
  return res.json();
}

export async function bootstrapAdmin(name: string, email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${BACKEND_URL}/api/auth/setup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
    credentials: 'include',
  });
  if (!res.ok) {
    const errorData = await res.json();
    throw new Error(errorData.detail || 'Failed to bootstrap administrator');
  }
  return res.json();
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${BACKEND_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include',
  });
  if (!res.ok) {
    const errorData = await res.json();
    throw new Error(errorData.detail || 'Invalid credentials');
  }
  return res.json();
}

export async function refreshSession(): Promise<AuthResponse> {
  const res = await fetch(`${BACKEND_URL}/api/auth/refresh`, {
    method: 'POST',
    credentials: 'include',
  });
  if (!res.ok) {
    const errorData = await res.json();
    throw new Error(errorData.detail || 'Session expired');
  }
  return res.json();
}

export async function logoutSession(): Promise<{ status: string }> {
  const res = await fetch(`${BACKEND_URL}/api/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  });
  return res.json();
}

export async function updateProfile(name: string, email: string): Promise<RbacUser> {
  const res = await authFetch(`${BACKEND_URL}/api/auth/update-profile`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email }),
  });
  if (!res.ok) {
    const errorData = await res.json();
    throw new Error(errorData.detail || 'Failed to update profile');
  }
  return res.json();
}

// ── Automation Rules API helpers ─────────────────────────────────────────────

export interface AutomationRule {
  id: string;
  name: string;
  description: string;
  trigger: string;
  action: string;
  severity: 'critical' | 'high' | 'medium' | 'any';
  enabled: boolean;
  lastFired: string | null;
  firedCount: number;
  category: 'containment' | 'notification' | 'enrichment' | 'ticketing';
}

export async function fetchRules(): Promise<AutomationRule[]> {
  const res = await authFetch(`${BACKEND_URL}/api/rules`);
  return res.json();
}

export async function saveRule(rule: AutomationRule): Promise<AutomationRule> {
  const res = await authFetch(`${BACKEND_URL}/api/rules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(rule),
  });
  return res.json();
}

export async function deleteRule(ruleId: string): Promise<{ status: string }> {
  const res = await authFetch(`${BACKEND_URL}/api/rules/${ruleId}`, {
    method: 'DELETE',
  });
  return res.json();
}

export async function triggerRule(ruleId: string): Promise<AutomationRule> {
  const res = await authFetch(`${BACKEND_URL}/api/rules/${ruleId}/trigger`, {
    method: 'POST',
  });
  return res.json();
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

  connect(token?: string): void {
    if (this.ws) return;
    try {
      const url = token ? `${WS_URL}?token=${encodeURIComponent(token)}` : WS_URL;
      this.ws = new WebSocket(url);

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
          this.reconnectTimer = setTimeout(() => this.connect(accessToken || undefined), 3000);
        }
      };

      this.ws.onerror = () => {
        this.ws?.close();
        this.ws = null;
      };
    } catch {
      this.reconnectTimer = setTimeout(() => this.connect(accessToken || undefined), 3000);
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
