'use client';

import { useEffect, useState } from 'react';
import { useAppStore } from '@/lib/app-store';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { AlertCircle, TrendingUp, Zap, Shield, Activity, Clock, ArrowRight, Play, ServerOff } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import Link from 'next/link';

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical': return 'bg-red-900/30 text-red-300 border-red-700/50';
    case 'high': return 'bg-orange-900/30 text-orange-300 border-orange-700/50';
    case 'medium': return 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50';
    default: return 'bg-blue-900/30 text-blue-300 border-blue-700/50';
  }
};

export default function Dashboard() {
  const {
    alerts,
    incidents,
    metrics,
    backendConnected,
    backendChecked,
    correlatedIncidents,
    evidenceVault,
    remediationHistory,
    blockedIps,
    blockedIpDetails,
    behaviorState,
    selfProtectionAudit,
    rollbackRemediationAction,
    unblockIpAction,
  } = useAppStore();
  const [mounted, setMounted] = useState(false);
  const [alertTrend, setAlertTrend] = useState<Array<{ time: string; count: number; critical: number }>>([]);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Maintain local chart history when alerts update
  useEffect(() => {
    if (!mounted || !metrics) return;

    setAlertTrend((prev) => {
      const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const currentCount = alerts.length;
      const criticalCount = alerts.filter(a => a.severity === 'critical').length;

      // Avoid adding duplicate timestamps
      if (prev.length > 0 && prev[prev.length - 1].time === nowStr) {
        return prev;
      }

      const updated = [
        ...prev,
        { time: nowStr, count: currentCount, critical: criticalCount }
      ];
      return updated.slice(-20); // Keep last 20 entries
    });
  }, [alerts, metrics, mounted]);

  if (!mounted) return null;

  // Render a detailed placeholder if backend is not connected
  if (backendChecked && !backendConnected) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-8 text-center cyber-grid">
        <div className="glass rounded-xl border border-red-500/30 p-8 max-w-md w-full space-y-6 bg-card/40 backdrop-blur-md">
          <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center border border-red-500/30 mx-auto animate-pulse">
            <ServerOff className="w-8 h-8 text-red-400" />
          </div>
          <div className="space-y-2">
            <h2 className="text-xl font-bold text-foreground">SOC API Offline</h2>
            <p className="text-sm text-muted-foreground">
              The ForenSys telemetry engine is not running on your host machine.
            </p>
          </div>
          <div className="p-4 bg-black/40 rounded border border-border/30 text-left font-mono text-xs space-y-2">
            <p className="text-accent">// Start the Python backend collector</p>
            <p className="text-muted-foreground">$ cd backend</p>
            <p className="text-muted-foreground">$ python main.py</p>
          </div>
          <div className="flex gap-2 justify-center">
            <Button
              className="bg-accent hover:bg-accent/80 text-accent-foreground text-xs gap-2"
              onClick={() => window.location.reload()}
            >
              Retry Connection
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // Loading state
  if (!metrics) {
    return (
      <div className="flex-1 flex items-center justify-center text-accent font-mono text-sm animate-pulse">
        [INITIALIZING TELEMETRY STREAM...]
      </div>
    );
  }

  const severityCounts = {
    critical: alerts.filter((a) => a.severity === 'critical').length,
    high: alerts.filter((a) => a.severity === 'high').length,
    medium: alerts.filter((a) => a.severity === 'medium').length,
    low: alerts.filter((a) => a.severity === 'low').length,
  };

  // Dynamically compute sources from actual alerts
  const sourceCountMap = alerts.reduce((acc, curr) => {
    acc[curr.source] = (acc[curr.source] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const sourceData = Object.entries(sourceCountMap).map(([source, count]) => ({
    source,
    count,
  })).sort((a, b) => b.count - a.count).slice(0, 5);

  const fallbackSourceData = sourceData.length > 0 ? sourceData : [
    { source: 'Network Monitor', count: 0 },
    { source: 'Process Monitor', count: 0 },
    { source: 'Log Monitor', count: 0 },
  ];

  const activeAlerts = alerts.filter((a) => a.status !== 'resolved');
  const recentAlerts = activeAlerts.slice(0, 10);
  const openIncidents = incidents.filter((i) => i.status === 'open' || i.status === 'investigating').slice(0, 3);

  const kpis = [
    { label: 'CPU Usage', value: `${metrics.cpu_percent}%`, color: 'text-accent', icon: Activity, sub: `${metrics.cpu_count} Cores` },
    { label: 'RAM Usage', value: `${metrics.memory_percent}%`, color: 'text-yellow-400', icon: Shield, sub: 'Active Memory' },
    { label: 'Connections', value: String(metrics.connections_total), color: 'text-green-400', icon: TrendingUp, sub: 'Active TCP/UDP' },
    { label: 'Disk Space', value: `${metrics.disk_percent}%`, color: 'text-blue-400', icon: Clock, sub: 'Root Disk' },
    { label: 'Total Alerts', value: String(metrics.alerts_total), color: 'text-red-400', icon: AlertCircle, sub: 'Live Detections' },
    { label: 'Blocklist Size', value: String(metrics.blocklist_size), color: 'text-purple-400', icon: Shield, sub: 'IP Threats' },
  ];

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5 cyber-grid">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Activity className="w-6 h-6 text-accent" />
            SOC Command Center
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Real-time local telemetry · Node: {metrics.hostname} ({metrics.platform})</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-accent rounded-full animate-pulse" />
          <span className="text-xs text-accent font-mono">LIVE FEED</span>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {kpis.map((kpi, i) => {
          const Icon = kpi.icon;
          return (
            <motion.div
              key={kpi.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.04 }}
              className="glass rounded-lg p-3 space-y-1.5 border border-border/50"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">{kpi.label}</span>
                <Icon className={`w-3.5 h-3.5 ${kpi.color}`} />
              </div>
              <motion.div
                key={kpi.value}
                initial={{ scale: 1.2, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                className={`text-xl font-bold font-mono ${kpi.color}`}
              >
                {kpi.value}
              </motion.div>
              <div className="text-xs text-muted-foreground">{kpi.sub}</div>
            </motion.div>
          );
        })}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alert Trend */}
        <div className="lg:col-span-2 glass rounded-lg p-4 border border-border/50">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-foreground">Alert Velocity Trend</h2>
            <Badge className="bg-accent/20 text-accent border-accent/50 text-xs">Live Update</Badge>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            {alertTrend.length > 0 ? (
              <AreaChart data={alertTrend}>
                <defs>
                  <linearGradient id="colorAlert" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00c8ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00c8ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="#555" style={{ fontSize: '10px' }} />
                <YAxis stroke="#555" style={{ fontSize: '10px' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: 'rgba(20,30,50,0.95)', border: '1px solid #00c8ff', borderRadius: '8px', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="count" stroke="#00c8ff" fill="url(#colorAlert)" dot={false} name="Total Alerts" />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#colorCrit)" dot={false} name="Critical" />
              </AreaChart>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-muted-foreground font-mono">
                [Awaiting baseline data packets...]
              </div>
            )}
          </ResponsiveContainer>
        </div>

        {/* Alert by Source */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h2 className="text-sm font-semibold text-foreground mb-3">Threat Vector Distribution</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={fallbackSourceData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
              <XAxis type="number" stroke="#555" style={{ fontSize: '10px' }} />
              <YAxis dataKey="source" type="category" stroke="#555" style={{ fontSize: '10px' }} width={80} />
              <Tooltip contentStyle={{ backgroundColor: 'rgba(20,30,50,0.95)', border: '1px solid #00c8ff', borderRadius: '8px', fontSize: '12px' }} />
              <Bar dataKey="count" fill="#00c8ff" fillOpacity={0.8} radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Live Alert Console */}
        <div className="glass rounded-lg border border-border/50 overflow-hidden">
          <div className="p-3 border-b border-border/50 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-accent rounded-full animate-pulse" />
              <h2 className="text-sm font-semibold text-foreground">Suspicious Activity Logs</h2>
            </div>
            <Link href="/dashboard/alerts">
              <Button variant="ghost" size="sm" className="h-6 text-xs text-accent hover:text-accent/80 gap-1">
                Investigate <ArrowRight className="w-3 h-3" />
              </Button>
            </Link>
          </div>
          <ScrollArea className="h-52 w-full [&_[data-slot=scroll-area-viewport]>div]:block!">
            <div className="space-y-1.5 p-3 pr-5 w-full overflow-hidden">
              <AnimatePresence>
                {recentAlerts.map((alert) => (
                  <motion.div
                    key={alert.id}
                    initial={{ x: -20, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    exit={{ x: 20, opacity: 0 }}
                    className={`w-full p-2.5 rounded border ${getSeverityColor(alert.severity)} flex items-start justify-between gap-2`}
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold truncate">{alert.title}</p>
                      <p className="text-xs mt-0.5 opacity-70 truncate">{alert.description}</p>
                    </div>
                    <span className="text-xs font-mono text-muted-foreground shrink-0">
                      {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  </motion.div>
                ))}
              </AnimatePresence>
              {recentAlerts.length === 0 && (
                <div className="py-12 text-center text-xs text-muted-foreground font-mono">
                  [SYSTEM STATUS NOMINAL - NO THREATS DETECTED]
                </div>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* Open Incidents & Correlated EDR Sequences */}
        <div className="glass rounded-lg border border-border/50 overflow-hidden">
          <div className="p-3 border-b border-border/50 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-foreground">Correlated EDR Intrusion Sequences</h2>
            <Link href="/dashboard/incidents">
              <Button variant="ghost" size="sm" className="h-6 text-xs text-accent hover:text-accent/80 gap-1">
                View All ({correlatedIncidents.length}) <ArrowRight className="w-3 h-3" />
              </Button>
            </Link>
          </div>
          <div className="p-3 space-y-2">
            {correlatedIncidents.slice(0, 4).map((inc, idx) => (
              <div key={`${inc.id}-${idx}`} className="p-3 bg-card/50 rounded border border-border/50 space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-bold text-accent">{inc.id}</span>
                  <div className="flex items-center gap-1.5">
                    <Badge className="bg-purple-900/30 text-purple-300 border-purple-700/50 text-[10px]">
                      Risk: {inc.riskScore}
                    </Badge>
                    <Badge className={`${getSeverityColor(inc.severity)} text-[10px]`}>
                      {inc.severity.toUpperCase()}
                    </Badge>
                  </div>
                </div>
                <p className="font-medium text-foreground text-xs">{inc.title}</p>
                <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/20">
                  <span className="truncate">Kill Chain: {inc.mitreStages.join(' → ') || 'Correlated'}</span>
                  <span className="shrink-0 font-mono text-[10px] text-accent/80">
                    {inc.evidenceIds?.length || 0} Sealed Bundles
                  </span>
                </div>
              </div>
            ))}
            {correlatedIncidents.length === 0 && (
              <div className="py-12 text-center text-xs text-muted-foreground font-mono">[NO CORRELATED INTRUSIONS DETECTED]</div>
            )}
          </div>
        </div>
      </div>

      {/* EDR SOAR Auto-Remediation & Sealed Forensic Vault Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* SOAR Auto-Remediation Execution & Rollback */}
        <div className="glass rounded-lg border border-border/50 overflow-hidden">
          <div className="p-3 border-b border-border/50 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-accent" />
              <h2 className="text-sm font-semibold text-foreground">SOAR Remediation & Active Rollback</h2>
            </div>
            <Badge className="bg-accent/20 text-accent border-accent/50 text-xs">
              {blockedIps.length} IPs Blocked
            </Badge>
          </div>
          <ScrollArea className="h-56 w-full">
            <div className="p-3 space-y-2">
              {remediationHistory.slice(0, 8).map((log, idx) => (
                <div key={`${log.id}-${idx}`} className="p-2.5 bg-black/40 rounded border border-border/40 flex items-center justify-between gap-3 text-xs">
                  <div className="flex-1 min-w-0 space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-accent font-bold text-[11px]">{log.id}</span>
                      <span className="font-medium text-foreground">{log.actionType}</span>
                      <Badge className={log.status === 'success' ? 'bg-green-900/30 text-green-300 text-[10px]' : log.status === 'rolled_back' ? 'bg-yellow-900/30 text-yellow-300 text-[10px]' : 'bg-red-900/30 text-red-300 text-[10px]'}>
                        {log.status}
                      </Badge>
                    </div>
                    <p className="text-[11px] text-muted-foreground truncate">
                      Target: <span className="font-mono text-foreground">{log.target}</span> ({log.ruleName})
                    </p>
                  </div>
                  {log.status === 'success' && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-6 text-[10px] border-amber-500/40 text-amber-400 hover:bg-amber-500/20 shrink-0"
                      onClick={() => rollbackRemediationAction(log.id)}
                    >
                      Rollback
                    </Button>
                  )}
                </div>
              ))}
              {remediationHistory.length === 0 && (
                <div className="py-12 text-center text-xs text-muted-foreground font-mono">
                  [NO AUTOMATED REMEDIATION ACTIONS EXECUTED]
                </div>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* SHA-256 Sealed Forensic Vault */}
        <div className="glass rounded-lg border border-border/50 overflow-hidden">
          <div className="p-3 border-b border-border/50 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-accent" />
              <h2 className="text-sm font-semibold text-foreground">SHA-256 Sealed Forensic Vault</h2>
            </div>
            <Badge className="bg-accent/15 text-accent border-accent/30 text-xs">
              {evidenceVault.length} Packages
            </Badge>
          </div>
          <ScrollArea className="h-56 w-full">
            <div className="p-3 space-y-2">
              {evidenceVault.slice(0, 8).map((evd, idx) => (
                <div key={`${evd.id}-${idx}`} className="p-2.5 bg-black/40 rounded border border-border/30 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-accent">{evd.id}</span>
                    <Badge className="bg-green-950/40 text-green-400 border-green-800/50 text-[10px]">
                      {evd.status}
                    </Badge>
                  </div>
                  <p className="font-mono text-[10px] text-muted-foreground truncate">{evd.hash}</p>
                  <div className="text-[10px] text-muted-foreground flex justify-between pt-1 border-t border-border/20">
                    <span>Incident: {evd.incidentId}</span>
                    <span>{evd.sealedAt || evd.timestamp}</span>
                  </div>
                </div>
              ))}
              {evidenceVault.length === 0 && (
                <div className="py-12 text-center text-xs text-muted-foreground font-mono">
                  [FORENSIC EVIDENCE VAULT EMPTY]
                </div>
              )}
            </div>
          </ScrollArea>
        </div>
      </div>

      {/* Self-Protection Audit Log Section */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden">
        <div className="p-3 border-b border-border/50 flex items-center justify-between bg-black/40">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold text-foreground">Self-Protection Audit Log (Trusted Internal Activity)</h2>
          </div>
          <Badge className="bg-accent/15 text-accent border-accent/30 text-xs">
            Self-Protection Layer Active ({selfProtectionAudit.length})
          </Badge>
        </div>
        <ScrollArea className="h-44 w-full">
          <div className="p-3 space-y-1.5 font-mono text-xs">
            {selfProtectionAudit.slice(0, 10).map((audit, idx) => (
              <div key={`${audit.id}-${idx}`} className="p-2 bg-black/40 rounded border border-border/30 flex items-center justify-between gap-3">
                <div className="flex-1 min-w-0 space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-accent font-bold text-[11px]">{audit.id}</span>
                    <span className="text-foreground">{audit.process}</span>
                    {audit.pid && <span className="text-muted-foreground text-[10px]">(PID: {audit.pid})</span>}
                    <Badge className="bg-cyan-950/50 text-cyan-300 border-cyan-800/40 text-[10px]">
                      Ignored (Trusted Internal Activity)
                    </Badge>
                  </div>
                  <p className="text-[11px] text-muted-foreground truncate">
                    Reason: <span className="text-foreground">{audit.reason}</span> ({audit.src_ip} → {audit.dst_ip})
                  </p>
                </div>
                <div className="text-right shrink-0 space-y-0.5">
                  <span className="text-[10px] text-green-400 font-semibold block">No Incident Created</span>
                  <span className="text-[10px] text-muted-foreground block">No Remediation Executed</span>
                </div>
              </div>
            ))}
            {selfProtectionAudit.length === 0 && (
              <div className="py-8 text-center text-xs text-muted-foreground font-mono">
                [SELF-PROTECTION MODE MONITORING - NO IGNORED INTERNAL EVENTS]
              </div>
            )}
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}
