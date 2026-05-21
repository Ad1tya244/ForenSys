/**
 * ForenSys Global Store — powered by real backend data
 * Replaces all mock generators with live WebSocket telemetry.
 */

import { create } from 'zustand';
import {
  BackendSocket,
  BackendSnapshot,
  RealMetrics,
  NetworkConnection,
  RealProcess,
  RealLogEntry,
  RealAlert,
  ArpDevice,
  checkBackendAlive,
} from './api-client';

// ── Re-export types so pages don't need to change their imports ──────────────
export type { RealAlert as Alert, RealLogEntry as LogEntry, NetworkConnection, RealProcess, RealMetrics };

// Kept for compatibility with escalation flow
export interface Incident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  createdAt: Date;
  lastUpdated: Date;
  affectedSystems: string[];
  investigator: string;
  description: string;
  evidenceCount: number;
  relatedAlerts: string[];
}

export interface AppNotification {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: Date;
  read: boolean;
}

export interface AppSettings {
  notifyOnCritical: boolean;
  notifyOnHigh: boolean;
  dailySummary: boolean;
  criticalThreshold: number;
  highThreshold: number;
  mediumThreshold: number;
  integrations: { name: string; connected: boolean }[];
}

// ── Store state ───────────────────────────────────────────────────────────────

interface AppState {
  // Connection status
  backendConnected: boolean;
  backendChecked: boolean;
  lastUpdate: string | null;

  // Real live data
  alerts: RealAlert[];
  incidents: Incident[];
  metrics: RealMetrics | null;
  metricsHistory: (RealMetrics & { timestamp: string })[];
  connections: NetworkConnection[];
  processes: RealProcess[];
  logs: RealLogEntry[];
  devices: ArpDevice[];
  listeningPorts: { port: number; ip: string; process: string; pid: number }[];

  // App state
  notifications: AppNotification[];
  settings: AppSettings;

  // Actions
  connectBackend: () => void;
  disconnectBackend: () => void;

  acknowledgeAlert: (id: string) => void;
  resolveAlert: (id: string) => void;
  escalateAlertToIncident: (alertId: string) => void;
  updateIncidentStatus: (id: string, status: Incident['status']) => void;

  addNotification: (n: Omit<AppNotification, 'id' | 'timestamp' | 'read'>) => void;
  markAllRead: () => void;
  unreadCount: () => number;
  updateSettings: (patch: Partial<AppSettings>) => void;

  // Internal
  _applySnapshot: (snapshot: BackendSnapshot) => void;
}

// ── Socket singleton (one WS for entire app lifetime) ────────────────────────
let _socket: BackendSocket | null = null;

// ── Store ─────────────────────────────────────────────────────────────────────
export const useAppStore = create<AppState>((set, get) => ({
  backendConnected: false,
  backendChecked: false,
  lastUpdate: null,

  alerts: [],
  incidents: [],
  metrics: null,
  metricsHistory: [],
  connections: [],
  processes: [],
  logs: [],
  devices: [],
  listeningPorts: [],
  notifications: [],

  settings: {
    notifyOnCritical: true,
    notifyOnHigh: true,
    dailySummary: true,
    criticalThreshold: 90,
    highThreshold: 70,
    mediumThreshold: 40,
    integrations: [
      { name: 'Emerging Threats Blocklist', connected: true },
      { name: 'ipapi.co Geolocation', connected: true },
      { name: 'psutil System Monitor', connected: true },
      { name: 'macOS Log Stream', connected: true },
      { name: 'AbuseIPDB (optional)', connected: false },
    ],
  },

  // ── Backend connection ──────────────────────────────────────────────────────
  connectBackend: () => {
    if (_socket) return; // already connected

    // First check if backend is reachable
    checkBackendAlive().then((alive) => {
      set({ backendChecked: true, backendConnected: alive });
    });

    _socket = new BackendSocket((snapshot) => {
      get()._applySnapshot(snapshot);
    });
    _socket.connect();

    // Keep-alive ping every 10 seconds
    setInterval(() => _socket?.ping(), 10000);
  },

  disconnectBackend: () => {
    _socket?.disconnect();
    _socket = null;
    set({ backendConnected: false });
  },

  // ── Snapshot handler ────────────────────────────────────────────────────────
  _applySnapshot: (snapshot: BackendSnapshot) => {
    const state = get();

    // Merge incoming alerts with manually-status-updated ones
    const existingById = new Map(state.alerts.map((a) => [a.id, a]));
    for (const a of snapshot.all_alerts) {
      if (!existingById.has(a.id)) {
        existingById.set(a.id, a);
      }
      // Don't override status if analyst already acknowledged/resolved it
    }
    const mergedAlerts = Array.from(existingById.values()).slice(0, 200);

    // Build notifications for new critical/high alerts
    const newNotifs: AppNotification[] = snapshot.new_alerts
      .filter((a) => {
        if (a.severity === 'critical') return state.settings.notifyOnCritical;
        if (a.severity === 'high') return state.settings.notifyOnHigh;
        return false;
      })
      .map((a) => ({
        id: `notif-${a.id}`,
        title: a.title,
        severity: a.severity,
        timestamp: new Date(a.timestamp),
        read: false,
      }));

    const newMetricsPoint = snapshot.metrics ? {
      ...snapshot.metrics,
      timestamp: snapshot.timestamp || new Date().toISOString()
    } : null;

    const nextMetricsHistory = newMetricsPoint
      ? [...state.metricsHistory, newMetricsPoint].slice(-30)
      : state.metricsHistory;

    set({
      backendConnected: true,
      lastUpdate: snapshot.timestamp,
      alerts: mergedAlerts,
      metrics: snapshot.metrics,
      metricsHistory: nextMetricsHistory,
      connections: snapshot.connections,
      processes: snapshot.processes,
      logs: snapshot.logs,
      devices: snapshot.devices,
      listeningPorts: snapshot.listening_ports,
      notifications: [...newNotifs, ...state.notifications].slice(0, 30),
    });
  },

  // ── Alert actions ───────────────────────────────────────────────────────────
  acknowledgeAlert: (id) =>
    set((s) => ({
      alerts: s.alerts.map((a) =>
        a.id === id ? { ...a, status: 'acknowledged' as const } : a
      ),
    })),

  resolveAlert: (id) =>
    set((s) => ({
      alerts: s.alerts.map((a) =>
        a.id === id ? { ...a, status: 'resolved' as const } : a
      ),
    })),

  escalateAlertToIncident: (alertId) => {
    const alert = get().alerts.find((a) => a.id === alertId);
    if (!alert) return;
    const incident: Incident = {
      id: `INC-${Date.now()}`,
      title: `ESCALATED: ${alert.title}`,
      severity: alert.severity,
      status: 'open',
      createdAt: new Date(),
      lastUpdated: new Date(),
      affectedSystems: alert.affectedAssets,
      investigator: 'Unassigned',
      description: alert.description,
      evidenceCount: 1,
      relatedAlerts: [alertId],
    };
    set((s) => ({
      incidents: [incident, ...s.incidents],
      alerts: s.alerts.map((a) =>
        a.id === alertId ? { ...a, status: 'investigating' as const } : a
      ),
    }));
  },

  updateIncidentStatus: (id, status) =>
    set((s) => ({
      incidents: s.incidents.map((inc) =>
        inc.id === id ? { ...inc, status, lastUpdated: new Date() } : inc
      ),
    })),

  // ── Notifications ───────────────────────────────────────────────────────────
  addNotification: (n) =>
    set((s) => ({
      notifications: [
        { ...n, id: `notif-${Date.now()}`, timestamp: new Date(), read: false },
        ...s.notifications.slice(0, 29),
      ],
    })),

  markAllRead: () =>
    set((s) => ({
      notifications: s.notifications.map((n) => ({ ...n, read: true })),
    })),

  unreadCount: () => get().notifications.filter((n) => !n.read).length,

  // ── Settings ────────────────────────────────────────────────────────────────
  updateSettings: (patch) =>
    set((s) => ({ settings: { ...s.settings, ...patch } })),
}));
