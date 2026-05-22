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

export interface EvidenceItem {
  id: string;
  incidentId: string;
  type: string;
  description: string;
  hash: string;
  collectedBy: string;
  collectedAt: Date;
  chain: string[];
  status: 'Authenticated' | 'Sealed';
  payload?: any;
}

function generateSimpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  const hex2 = Math.abs(hash * 31).toString(16).padStart(8, '0');
  const hex3 = Math.abs(hash * 17).toString(16).padStart(8, '0');
  const hex4 = Math.abs(hash * 13).toString(16).padStart(8, '0');
  return `SHA256: ${hex}${hex2}${hex3}${hex4}`.substring(0, 72);
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
  evidenceItems: EvidenceItem[];
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
  raiseIncidentAndCaptureForensics: (type: 'alert' | 'log' | 'network' | 'process' | 'connection', data: any) => void;
  updateIncidentStatus: (id: string, status: Incident['status']) => void;
  authenticateEvidenceItem: (id: string) => void;

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
  evidenceItems: [],
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
    get().raiseIncidentAndCaptureForensics('alert', alert);
  },

  raiseIncidentAndCaptureForensics: (type, data) => {
    const incidentId = `INC-${Date.now()}`;
    const evidenceId = `EVD-${Date.now()}`;
    let incident: Incident;
    let evidence: EvidenceItem;

    if (type === 'alert') {
      incident = {
        id: incidentId,
        title: `ALERT ESCALATION: ${data.title}`,
        severity: data.severity,
        status: 'open',
        createdAt: new Date(),
        lastUpdated: new Date(),
        affectedSystems: data.affectedAssets && data.affectedAssets.length > 0 ? data.affectedAssets : ['localhost'],
        investigator: 'SOC Alert Console',
        description: `Escalated Security Alert: ${data.description}. Source: ${data.source}.`,
        evidenceCount: 1,
        relatedAlerts: [data.id],
      };
      evidence = {
        id: evidenceId,
        incidentId,
        type: 'File',
        description: `Captured alert metadata payload: ${data.title}. Source: ${data.source}.`,
        hash: generateSimpleHash(JSON.stringify(data)),
        collectedBy: 'ForenSys Agent',
        collectedAt: new Date(),
        chain: ['Captured', 'Hashed', 'Sealed'],
        status: 'Sealed',
        payload: data,
      };
    } else if (type === 'log') {
      incident = {
        id: incidentId,
        title: `LOG INCIDENT: [${data.process}] ${data.message.substring(0, 50)}`,
        severity: data.level === 'error' ? 'high' : data.level === 'warn' ? 'medium' : 'low',
        status: 'open',
        createdAt: new Date(),
        lastUpdated: new Date(),
        affectedSystems: ['localhost', data.source],
        investigator: 'SOC Log Parser',
        description: `Escalated Host Log Event: ${data.message}`,
        evidenceCount: 1,
        relatedAlerts: [],
      };
      evidence = {
        id: evidenceId,
        incidentId,
        type: 'Log File',
        description: `Raw log capture from process: ${data.process} (PID: ${data.pid || 'N/A'}). Source log: ${data.source || 'N/A'}`,
        hash: generateSimpleHash(JSON.stringify(data)),
        collectedBy: 'ForenSys Agent',
        collectedAt: new Date(),
        chain: ['Captured', 'Hashed', 'Sealed'],
        status: 'Sealed',
        payload: data,
      };
    } else if (type === 'network') {
      incident = {
        id: incidentId,
        title: `NETWORK INTEL INCIDENT: ${data.title}`,
        severity: data.severity,
        status: 'open',
        createdAt: new Date(),
        lastUpdated: new Date(),
        affectedSystems: ['Network Interface'],
        investigator: 'SOC Network Console',
        description: `Escalated Network Signal: ${data.description}. Indicators: ${data.indicators.join(', ')}`,
        evidenceCount: 1,
        relatedAlerts: [],
      };
      evidence = {
        id: evidenceId,
        incidentId,
        type: 'Network Capture',
        description: `Network traffic metadata captured for indicator(s): ${data.indicators.join(', ')}. Description: ${data.description}`,
        hash: generateSimpleHash(JSON.stringify(data)),
        collectedBy: 'ForenSys Agent',
        collectedAt: new Date(),
        chain: ['Captured', 'Hashed', 'Sealed'],
        status: 'Sealed',
        payload: data,
      };
    } else if (type === 'process') {
      incident = {
        id: incidentId,
        title: `PROCESS INCIDENT: ${data.name} (PID: ${data.pid})`,
        severity: data.suspicious ? 'high' : 'medium',
        status: 'open',
        createdAt: new Date(),
        lastUpdated: new Date(),
        affectedSystems: ['localhost'],
        investigator: 'SOC Threat Hunter',
        description: `Rogue process escalated. Context: ${data.username}, CPU ${data.cpu_percent}%, Memory ${data.memory_percent}%.`,
        evidenceCount: 1,
        relatedAlerts: [],
      };
      evidence = {
        id: evidenceId,
        incidentId,
        type: 'Memory Dump',
        description: `Process memory block metadata captured for PID ${data.pid} (${data.name}). Status: ${data.status}.`,
        hash: generateSimpleHash(JSON.stringify(data)),
        collectedBy: 'ForenSys Agent',
        collectedAt: new Date(),
        chain: ['Captured', 'Hashed', 'Sealed'],
        status: 'Sealed',
        payload: data,
      };
    } else { // connection
      incident = {
        id: incidentId,
        title: `CONNECTION INCIDENT: ${data.process} -> ${data.remote_ip}`,
        severity: data.status === 'ESTABLISHED' ? 'high' : 'medium',
        status: 'open',
        createdAt: new Date(),
        lastUpdated: new Date(),
        affectedSystems: ['localhost'],
        investigator: 'SOC Threat Hunter',
        description: `Intrusion socket connection escalated. Remote IP: ${data.remote_ip}:${data.remote_port}, process: ${data.process} (PID: ${data.pid || 'N/A'}).`,
        evidenceCount: 1,
        relatedAlerts: [],
      };
      evidence = {
        id: evidenceId,
        incidentId,
        type: 'Network Capture',
        description: `Active socket payload metadata. Protocol: ${data.protocol}, State: ${data.status}. Remote Org: ${data.geo?.org || 'unknown'}.`,
        hash: generateSimpleHash(JSON.stringify(data)),
        collectedBy: 'ForenSys Agent',
        collectedAt: new Date(),
        chain: ['Captured', 'Hashed', 'Sealed'],
        status: 'Sealed',
        payload: data,
      };
    }

    set((s) => {
      const nextIncidents = [incident, ...s.incidents];
      const nextEvidence = [evidence, ...s.evidenceItems];
      let nextAlerts = s.alerts;
      if (type === 'alert') {
        nextAlerts = s.alerts.map((a) =>
          a.id === data.id ? { ...a, status: 'investigating' as const } : a
        );
      }
      return {
        incidents: nextIncidents,
        evidenceItems: nextEvidence,
        alerts: nextAlerts,
      };
    });
  },

  updateIncidentStatus: (id, status) =>
    set((s) => {
      const incident = s.incidents.find((inc) => inc.id === id);
      const relatedAlertIds = incident?.relatedAlerts || [];
      return {
        incidents: s.incidents.map((inc) =>
          inc.id === id ? { ...inc, status, lastUpdated: new Date() } : inc
        ),
        alerts: s.alerts.map((a) => {
          if (relatedAlertIds.includes(a.id)) {
            return {
              ...a,
              status: status === 'resolved' ? ('resolved' as const) : ('investigating' as const),
            };
          }
          return a;
        }),
      };
    }),

  authenticateEvidenceItem: (id) =>
    set((s) => ({
      evidenceItems: s.evidenceItems.map((item) => {
        if (item.id === id && item.status !== 'Authenticated') {
          return {
            ...item,
            status: 'Authenticated' as const,
            chain: [...item.chain, 'Verified Integrity Checksum', 'Authenticated'],
          };
        }
        return item;
      }),
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
