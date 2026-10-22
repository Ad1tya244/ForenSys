/**
 * Compact, real SOC snapshot handed to the Iris copilot (Gemini prompt and the local fallback share it).
 * Only live backend data goes in here - nothing is invented client-side.
 */
import { useAppStore } from './app-store';

export interface SocContext {
  host: { hostname: string; platform: string; threatLevel: string; cpu: number; memory: number; connections: number } | null;
  alerts: {
    total: number;
    open: number;
    bySeverity: Record<string, number>;
    items: { id: string; severity: string; title: string; status: string; source: string; assets: string[]; mitre: string[]; description: string; time: string }[];
  };
  incidents: {
    id: string; title: string; severity: string; status: string; attackerIp: string | null; assets: string[];
    mitre: string[]; riskScore: number; mttdSec: number | null; mttrSec: number | null; evidenceCount: number; time: string;
  }[];
  remediation: { id: string; incidentId: string; rule: string; action: string; target: string; status: string; time: string }[];
  blocklist: { ip: string; status: string; reason: string; incidentId: string }[];
  evidence: { packages: number; sealed: number };
}

const clip = (s: string, n: number) => (s && s.length > n ? `${s.slice(0, n - 1)}…` : s || '');

export function buildSocContext(): SocContext {
  const s = useAppStore.getState();
  const alerts = s.alerts || [];
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  alerts.filter((a) => a.status !== 'resolved').forEach((a) => { bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1; });

  return {
    host: s.metrics ? {
      hostname: s.metrics.hostname, platform: s.metrics.platform, threatLevel: s.metrics.threat_level || 'low',
      cpu: s.metrics.cpu_percent, memory: s.metrics.memory_percent, connections: s.metrics.connections_total,
    } : null,
    alerts: {
      total: alerts.length,
      open: alerts.filter((a) => a.status !== 'resolved').length,
      bySeverity,
      items: alerts.slice(0, 20).map((a) => ({
        id: a.id, severity: a.severity, title: a.title, status: a.status, source: a.source,
        assets: a.affectedAssets || [], mitre: a.mitreTactics || [], description: clip(a.description, 220), time: a.timestamp,
      })),
    },
    incidents: (s.correlatedIncidents || []).slice(0, 15).map((i: any) => ({
      id: i.id, title: i.title, severity: i.severity, status: i.status,
      attackerIp: i.primarySourceIp || null, assets: i.affectedAssets || [], mitre: i.mitreStages || [],
      riskScore: i.riskScore, mttdSec: i.mttdSec ?? null, mttrSec: i.mttrSec ?? null,
      evidenceCount: i.evidenceCount || 0, time: i.createdAt,
    })),
    remediation: (s.remediationHistory || []).slice(0, 20).map((r) => ({
      id: r.id, incidentId: r.incidentId, rule: r.ruleName, action: r.actionType, target: r.target, status: r.status, time: r.timestamp,
    })),
    blocklist: (s.blockedIpDetails || []).map((b) => ({ ip: b.ip, status: b.status, reason: clip(b.reason, 120), incidentId: b.incident_id })),
    evidence: {
      packages: (s.evidenceVault || []).length,
      sealed: (s.evidenceVault || []).filter((e) => e.status === 'Sealed').length,
    },
  };
}
