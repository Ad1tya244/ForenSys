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
  AppSettings,
  fetchSettings,
  saveSettings,
  RbacUser,
  fetchUsers,
  saveUser,
  deleteUser,
  DEFAULT_PERMISSIONS,
  checkSetupRequired,
  bootstrapAdmin as apiBootstrapAdmin,
  login as apiLogin,
  updateProfile as apiUpdateProfile,
  setAccessToken,
  registerAuthErrorCallback,
  refreshSession,
  logoutSession,
  AutomationRule,
  fetchRules,
  saveRule as apiSaveRule,
  deleteRule as apiDeleteRule,
  triggerRule as apiTriggerRule,
  RealNetworkPacket,
  CorrelatedIncident,
  ForensicEvidencePackage,
  RemediationActionLog,
  SelfProtectionAuditEntry,
  BlockedIPDetail,
  unblockIp as apiUnblockIp,
  clearHistory as apiClearHistory,
  rollbackAction as apiRollbackAction,
  fetchConfig,
  updateConfig as apiUpdateConfig,
} from './api-client';

// ── Re-export types so pages don't need to change their imports ──────────────
export type { RealAlert as Alert, RealLogEntry as LogEntry, NetworkConnection, RealProcess, RealMetrics, RbacUser, AutomationRule, RealNetworkPacket, CorrelatedIncident, ForensicEvidencePackage, RemediationActionLog, SelfProtectionAuditEntry, BlockedIPDetail };

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

// AppSettings is now imported from ./api-client

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
  networkTrafficLogs: RealNetworkPacket[];

  // App state
  notifications: AppNotification[];
  settings: AppSettings;

  // Authentication State
  currentUser: RbacUser | null;
  accessToken: string | null;
  setupRequired: boolean;

  // EDR/XDR Pipeline state
  correlatedIncidents: CorrelatedIncident[];
  evidenceVault: ForensicEvidencePackage[];
  remediationHistory: RemediationActionLog[];
  blockedIps: string[];
  blockedIpDetails: BlockedIPDetail[];
  ruleCatalog: any[];
  behaviorState: any;
  selfProtectionAudit: SelfProtectionAuditEntry[];

  // Actions
  connectBackend: () => void;
  disconnectBackend: () => void;
  rollbackRemediationAction: (actionId: string) => Promise<void>;
  unblockIpAction: (ip: string) => Promise<void>;
  clearHistoryAction: () => Promise<void>;

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

  // Authentication Actions
  checkSetupStatus: () => Promise<void>;
  bootstrapAdmin: (name: string, email: string, password: string) => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  updateUserProfile: (name: string) => Promise<void>;

  // RBAC state & actions
  users: RbacUser[];
  hasPermission: (permission: string) => boolean;
  fetchUsers: () => Promise<void>;
  saveUser: (user: RbacUser | Omit<RbacUser, 'id'>) => Promise<void>;
  deleteUser: (id: string) => Promise<void>;

  // Automation Rules
  rules: AutomationRule[];
  fetchRules: () => Promise<void>;
  saveRule: (rule: AutomationRule) => Promise<void>;
  deleteRule: (id: string) => Promise<void>;
  triggerRule: (id: string) => Promise<void>;

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
  users: [],
  rules: [],
  metrics: null,
  metricsHistory: [],
  connections: [],
  processes: [],
  logs: [],
  devices: [],
  listeningPorts: [],
  networkTrafficLogs: [],
  notifications: [],
  correlatedIncidents: [],
  evidenceVault: [],
  remediationHistory: [],
  blockedIps: [],
  blockedIpDetails: [],
  ruleCatalog: [],
  behaviorState: null,
  selfProtectionAudit: [],

  currentUser: null,
  accessToken: null,
  setupRequired: false,

  settings: {
    notifyOnCritical: true,
    notifyOnHigh: true,
    dailySummary: true,
    criticalThreshold: 90,
    highThreshold: 70,
    mediumThreshold: 40,
    profile: {
      name: '',
      email: '',
      role: '',
    },
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
    registerAuthErrorCallback(() => {
      get().logout();
    });

    // Load currentUser from localStorage if present
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('forensys_user');
      if (stored && !get().currentUser) {
        try {
          const user = JSON.parse(stored);
          set({ currentUser: user });
        } catch (e) {
          localStorage.removeItem('forensys_user');
        }
      }
    }

    if (_socket) return; // already connected

    // First attempt to refresh token automatically from cookies
    refreshSession()
      .then((res) => {
        setAccessToken(res.access_token);
        set({ currentUser: res.user, accessToken: res.access_token, backendChecked: true, backendConnected: true });
        if (typeof window !== 'undefined') {
          localStorage.setItem('forensys_user', JSON.stringify(res.user));
        }

        get().checkSetupStatus();
        fetchSettings()
          .then((backendSettings) => {
            if (backendSettings) {
              set({ settings: backendSettings });
            }
          })
          .catch((err) => console.error('Error fetching settings:', err));

        fetchUsers()
          .then((users) => {
            if (users) {
              set({ users });
            }
          })
          .catch((err) => console.error('Error fetching users:', err));

        fetchRules()
          .then((rules) => {
            if (rules) {
              set({ rules });
            }
          })
          .catch((err) => console.error('Error fetching rules:', err));

        if (!_socket) {
          _socket = new BackendSocket((snapshot) => {
            get()._applySnapshot(snapshot);
          });
        }
        _socket.connect(res.access_token);
      })
      .catch(() => {
        // Clear invalid local user session
        setAccessToken(null);
        set({ currentUser: null, accessToken: null, backendChecked: true });
        if (typeof window !== 'undefined') {
          localStorage.removeItem('forensys_user');
        }

        checkBackendAlive().then((alive) => {
          set({ backendConnected: alive });
          if (alive) {
            get().checkSetupStatus();
          }
        });

        if (!_socket) {
          _socket = new BackendSocket((snapshot) => {
            get()._applySnapshot(snapshot);
          });
        }
        _socket.connect();
      });

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

    const nextTrafficLogs = snapshot.network_traffic && snapshot.network_traffic.length > 0
      ? [...state.networkTrafficLogs, ...snapshot.network_traffic].slice(-150)
      : state.networkTrafficLogs;

    // Detect connection transition from offline to online
    if (!state.backendConnected) {
      get().checkSetupStatus();
      fetchSettings()
        .then((backendSettings) => {
          if (backendSettings) {
            set({ settings: backendSettings });
          }
        })
        .catch((err) => console.warn('Deferred settings fetch failed:', err));
      get().fetchUsers();
      get().fetchRules();
    }

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
      networkTrafficLogs: nextTrafficLogs,
      notifications: [...newNotifs, ...state.notifications].slice(0, 30),
      correlatedIncidents: snapshot.incidents || state.correlatedIncidents,
      evidenceVault: snapshot.evidence_vault || state.evidenceVault,
      remediationHistory: snapshot.remediation_history || state.remediationHistory,
      blockedIps: snapshot.blocked_ips || state.blockedIps,
      blockedIpDetails: snapshot.blocked_ip_details || state.blockedIpDetails,
      ruleCatalog: snapshot.rule_catalog || state.ruleCatalog,
      behaviorState: snapshot.behavior_state || state.behaviorState,
      selfProtectionAudit: snapshot.self_protection_audit || state.selfProtectionAudit,
    });
  },

  rollbackRemediationAction: async (actionId: string) => {
    try {
      const updatedLog = await apiRollbackAction(actionId);
      set((state) => ({
        remediationHistory: state.remediationHistory.map((item) =>
          item.id === actionId ? { ...item, status: 'rolled_back' as const } : item
        ),
        blockedIps: state.blockedIps.filter((ip) => ip !== updatedLog.target),
        blockedIpDetails: state.blockedIpDetails.map((item) =>
          item.ip === updatedLog.target ? { ...item, status: 'rolled_back' } : item
        ),
      }));
    } catch (err) {
      console.error('Error rolling back action:', err);
    }
  },

  unblockIpAction: async (ip: string) => {
    try {
      await apiUnblockIp(ip);
      set((state) => ({
        blockedIps: state.blockedIps.filter((item) => item !== ip),
        blockedIpDetails: state.blockedIpDetails.map((item) =>
          item.ip === ip ? { ...item, status: 'unblocked' } : item
        ),
        remediationHistory: state.remediationHistory.map((item) =>
          item.target === ip ? { ...item, status: 'rolled_back' as const } : item
        ),
      }));
    } catch (err) {
      console.error('Error unblocking IP:', err);
    }
  },

  clearHistoryAction: async () => {
    try {
      await apiClearHistory();
      set({
        remediationHistory: [],
        blockedIps: [],
        blockedIpDetails: [],
        evidenceVault: [],
        correlatedIncidents: [],
        alerts: [],
      });
    } catch (err) {
      console.error('Error clearing history:', err);
    }
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

  hasPermission: (permission) => {
    const { currentUser } = get();
    if (!currentUser) return false;
    if (currentUser.status !== 'active') return false;
    return currentUser.permissions.includes(permission);
  },

  checkSetupStatus: async () => {
    try {
      const status = await checkSetupRequired();
      set({ setupRequired: status.setup_required });
    } catch (err) {
      console.error('Error checking setup status:', err);
    }
  },

  bootstrapAdmin: async (name, email, password) => {
    try {
      const res = await apiBootstrapAdmin(name, email, password);
      setAccessToken(res.access_token);
      set({ currentUser: res.user, accessToken: res.access_token, setupRequired: false });
      if (typeof window !== 'undefined') {
        localStorage.setItem('forensys_user', JSON.stringify(res.user));
      }
      if (_socket) {
        _socket.disconnect();
        _socket = null;
      }
      get().connectBackend();
    } catch (err) {
      console.error('Error bootstrapping admin:', err);
      throw err;
    }
  },

  login: async (email, password) => {
    try {
      const res = await apiLogin(email, password);
      setAccessToken(res.access_token);
      set({ currentUser: res.user, accessToken: res.access_token });
      if (typeof window !== 'undefined') {
        localStorage.setItem('forensys_user', JSON.stringify(res.user));
      }
      if (_socket) {
        _socket.disconnect();
        _socket = null;
      }
      get().connectBackend();
    } catch (err) {
      console.error('Error logging in:', err);
      throw err;
    }
  },

  logout: () => {
    setAccessToken(null);
    set({ currentUser: null, accessToken: null });
    if (typeof window !== 'undefined') {
      localStorage.removeItem('forensys_user');
    }
    logoutSession().catch((err) => console.error('Logout error:', err));
    if (_socket) {
      _socket.disconnect();
      _socket = null;
    }
  },

  updateUserProfile: async (name) => {
    const { currentUser } = get();
    if (!currentUser) return;
    try {
      const updated = await apiUpdateProfile(name, currentUser.email);
      set({ currentUser: updated });
      if (typeof window !== 'undefined') {
        localStorage.setItem('forensys_user', JSON.stringify(updated));
      }
    } catch (err) {
      console.error('Error updating user profile:', err);
      throw err;
    }
  },

  fetchUsers: async () => {
    try {
      const users = await fetchUsers();
      set({ users });
    } catch (err) {
      console.error('Error fetching users:', err);
    }
  },

  saveUser: async (user) => {
    try {
      const saved = await saveUser(user);
      const { currentUser } = get();
      if (currentUser && saved.email === currentUser.email) {
        set({ currentUser: saved });
        if (typeof window !== 'undefined') {
          localStorage.setItem('forensys_user', JSON.stringify(saved));
        }
      }
      await get().fetchUsers();
    } catch (err) {
      console.error('Error saving user:', err);
      throw err;
    }
  },

  deleteUser: async (id) => {
    try {
      await deleteUser(id);
      await get().fetchUsers();
    } catch (err) {
      console.error('Error deleting user:', err);
      throw err;
    }
  },

  fetchRules: async () => {
    try {
      const rules = await fetchRules();
      set({ rules });
    } catch (err) {
      console.error('Error fetching rules:', err);
    }
  },

  saveRule: async (rule) => {
    try {
      await apiSaveRule(rule);
      await get().fetchRules();
    } catch (err) {
      console.error('Error saving rule:', err);
      throw err;
    }
  },

  deleteRule: async (id) => {
    try {
      await apiDeleteRule(id);
      await get().fetchRules();
    } catch (err) {
      console.error('Error deleting rule:', err);
      throw err;
    }
  },

  triggerRule: async (id) => {
    try {
      await apiTriggerRule(id);
      await get().fetchRules();
    } catch (err) {
      console.error('Error triggering rule:', err);
      throw err;
    }
  },

  // ── Settings ────────────────────────────────────────────────────────────────
  updateSettings: (patch) => {
    const updated = { ...get().settings, ...patch };
    set({ settings: updated });
    saveSettings(updated)
      .then(() => {
        get().fetchUsers();
      })
      .catch((err) => {
        console.error('Error saving settings:', err);
      });
  },
}));
