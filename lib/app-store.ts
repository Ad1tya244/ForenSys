// FORENSYS Global Application Store
// Single source of truth for all live data across pages

import { create } from 'zustand';
import {
  Alert,
  Incident,
  generateMockAlert,
  generateMockIncidents,
  generateRealtimeMetrics,
} from './mock-data';

// ─── Notification ────────────────────────────────────────────────────────────
export interface AppNotification {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: Date;
  read: boolean;
}

// ─── Settings ────────────────────────────────────────────────────────────────
export interface AppSettings {
  notifyOnCritical: boolean;
  notifyOnHigh: boolean;
  dailySummary: boolean;
  criticalThreshold: number;
  highThreshold: number;
  mediumThreshold: number;
  integrations: { name: string; connected: boolean }[];
}

// ─── Store State ─────────────────────────────────────────────────────────────
interface AppState {
  // Live data
  alerts: Alert[];
  incidents: Incident[];
  metrics: ReturnType<typeof generateRealtimeMetrics>;
  notifications: AppNotification[];

  // Settings
  settings: AppSettings;

  // Actions — Alerts
  addAlert: (alert: Alert) => void;
  acknowledgeAlert: (id: string) => void;
  resolveAlert: (id: string) => void;

  // Actions — Incidents
  addIncident: (incident: Incident) => void;
  updateIncidentStatus: (id: string, status: Incident['status']) => void;
  escalateAlertToIncident: (alertId: string) => void;

  // Actions — Metrics
  refreshMetrics: () => void;

  // Actions — Notifications
  addNotification: (n: Omit<AppNotification, 'id' | 'timestamp' | 'read'>) => void;
  markAllRead: () => void;
  unreadCount: () => number;

  // Actions — Settings
  updateSettings: (patch: Partial<AppSettings>) => void;
}

// ─── Initial Data ─────────────────────────────────────────────────────────────
const INITIAL_ALERTS: Alert[] = Array.from({ length: 30 }, () => generateMockAlert());
const INITIAL_INCIDENTS = generateMockIncidents(15);
const INITIAL_METRICS = generateRealtimeMetrics();

// ─── Store ────────────────────────────────────────────────────────────────────
export const useAppStore = create<AppState>((set, get) => ({
  alerts: INITIAL_ALERTS,
  incidents: INITIAL_INCIDENTS,
  metrics: INITIAL_METRICS,
  notifications: INITIAL_ALERTS
    .filter((a) => a.severity === 'critical' || a.severity === 'high')
    .slice(0, 5)
    .map((a) => ({
      id: a.id,
      title: a.title,
      severity: a.severity,
      timestamp: a.timestamp,
      read: false,
    })),

  settings: {
    notifyOnCritical: true,
    notifyOnHigh: true,
    dailySummary: true,
    criticalThreshold: 90,
    highThreshold: 70,
    mediumThreshold: 40,
    integrations: [
      { name: 'Splunk SIEM', connected: true },
      { name: 'Email Gateway', connected: true },
      { name: 'SOAR Platform', connected: true },
      { name: 'Vulnerability Scanner', connected: false },
      { name: 'Threat Intelligence Feed', connected: true },
    ],
  },

  // ── Alert actions ───────────────────────────────────────────────────────────
  addAlert: (alert) =>
    set((s) => {
      const newAlerts = [alert, ...s.alerts.slice(0, 49)];
      // Push notification for critical/high
      if (alert.severity === 'critical' || alert.severity === 'high') {
        const notif: AppNotification = {
          id: `notif-${Date.now()}`,
          title: alert.title,
          severity: alert.severity,
          timestamp: alert.timestamp,
          read: false,
        };
        return {
          alerts: newAlerts,
          notifications: [notif, ...s.notifications.slice(0, 19)],
        };
      }
      return { alerts: newAlerts };
    }),

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

  // ── Incident actions ────────────────────────────────────────────────────────
  addIncident: (incident) =>
    set((s) => ({ incidents: [incident, ...s.incidents] })),

  updateIncidentStatus: (id, status) =>
    set((s) => ({
      incidents: s.incidents.map((inc) =>
        inc.id === id ? { ...inc, status, lastUpdated: new Date() } : inc
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
      description: `Escalated from alert ${alert.id}. ${alert.description}`,
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

  // ── Metrics ────────────────────────────────────────────────────────────────
  refreshMetrics: () => set({ metrics: generateRealtimeMetrics() }),

  // ── Notifications ──────────────────────────────────────────────────────────
  addNotification: (n) =>
    set((s) => ({
      notifications: [
        {
          ...n,
          id: `notif-${Date.now()}`,
          timestamp: new Date(),
          read: false,
        },
        ...s.notifications.slice(0, 19),
      ],
    })),

  markAllRead: () =>
    set((s) => ({
      notifications: s.notifications.map((n) => ({ ...n, read: true })),
    })),

  unreadCount: () => get().notifications.filter((n) => !n.read).length,

  // ── Settings ───────────────────────────────────────────────────────────────
  updateSettings: (patch) =>
    set((s) => ({ settings: { ...s.settings, ...patch } })),
}));
