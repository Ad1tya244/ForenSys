'use client';

import { useEffect, useState } from 'react';
import { BarChart3, TrendingUp, TrendingDown, Clock, Shield, Cpu, Activity, ShieldCheck, AlertTriangle } from 'lucide-react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  Legend, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from 'recharts';
import { motion } from 'framer-motion';
import { Badge } from '@/components/ui/badge';
import { useAppStore } from '@/lib/app-store';
import { fetchResponseMetrics, MetricsRange, ResponseMetrics } from '@/lib/api-client';
import { formatDuration } from '@/lib/format';

const SEVERITY_COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6'];

const CustomTooltipStyle = {
  backgroundColor: 'rgba(15, 23, 42, 0.95)',
  border: '1px solid rgba(0, 200, 255, 0.3)',
  borderRadius: '8px',
  fontSize: '12px',
  color: '#e2e8f0',
};

const CustomTooltipItemStyle = {
  color: '#e2e8f0',
};

const CustomTooltipLabelStyle = {
  color: '#e2e8f0',
};

const RANGES: { key: MetricsRange; label: string }[] = [
  { key: '24h', label: 'Last 24 h' },
  { key: '7d', label: '7 days' },
  { key: '30d', label: '30 days' },
  { key: 'all', label: 'All time' },
];

const ATTACK_LABELS: Record<string, string> = {
  port_scan: 'Port Scan', icmp_flood: 'ICMP Flood', syn_flood: 'SYN Flood', brute_force: 'Brute Force',
  auth_attack: 'Auth Attack', dns_beacon: 'DNS Beaconing', reverse_shell: 'Reverse Shell', data_exfil: 'Data Exfiltration',
  suspicious_listener: 'Suspicious Listener', process_chain: 'Process Chain', unknown: 'Unknown',
};

export default function AnalyticsPage() {
  const { alerts, correlatedIncidents, metrics, metricsHistory, processes } = useAppStore();
  const [range, setRange] = useState<MetricsRange>('24h');
  const [rm, setRm] = useState<ResponseMetrics | null>(null);
  const [rmFailed, setRmFailed] = useState(false);

  // MTTD / MTTR and every incident statistic come from the backend incident ledger (real timestamps), never from
  // heuristics on the client. Reload on range change, when a new incident appears, and on a slow timer.
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const data = await fetchResponseMetrics(range);
        if (alive) { setRm(data); setRmFailed(false); }
      } catch {
        if (alive) setRmFailed(true);
      }
    };
    load();
    const timer = setInterval(load, 10000);
    return () => { alive = false; clearInterval(timer); };
  }, [range, correlatedIncidents.length]);

  const activeAlerts = alerts.filter((a) => a.status !== 'resolved');

  // Alert severity distribution (actual alerts currently in the stream)
  const severityData = [
    { name: 'Critical', value: activeAlerts.filter((a) => a.severity === 'critical').length },
    { name: 'High', value: activeAlerts.filter((a) => a.severity === 'high').length },
    { name: 'Medium', value: activeAlerts.filter((a) => a.severity === 'medium').length },
    { name: 'Low', value: activeAlerts.filter((a) => a.severity === 'low').length },
  ];

  const rangeLabel = RANGES.find((r) => r.key === range)?.label.toLowerCase();
  const timingSub = (t?: { n: number; median: number | null; p95: number | null }) =>
    t && t.n > 0 ? `median ${formatDuration(t.median)} · p95 ${formatDuration(t.p95)} · n=${t.n}` : 'no samples in this period';

  const kpis = [
    {
      label: 'MTTD (mean time to detect)', value: formatDuration(rm?.mttd.mean), sub: timingSub(rm?.mttd),
      change: rm?.mttd_change_pct ?? null, icon: TrendingDown, color: 'text-green-400', lowerIsBetter: true,
    },
    {
      label: 'MTTR (mean time to remediate)', value: formatDuration(rm?.mttr.mean), sub: timingSub(rm?.mttr),
      change: rm?.mttr_change_pct ?? null, icon: Clock, color: 'text-accent', lowerIsBetter: true,
    },
    {
      label: 'Containment rate',
      value: rm?.containment_rate == null ? 'n/a' : `${Math.round(rm.containment_rate * 100)}%`,
      sub: rm ? `${rm.contained_incidents} of ${rm.total_incidents} incidents contained` : '',
      change: rm?.containment_rate_change ?? null, icon: ShieldCheck, color: 'text-accent', lowerIsBetter: false,
    },
    {
      label: 'Incidents', value: rm ? String(rm.total_incidents) : '–',
      sub: rm?.previous_total_incidents != null ? `${rm.previous_total_incidents} in the previous period` : 'since the last reset',
      change: null, icon: AlertTriangle, color: 'text-orange-400', lowerIsBetter: true,
    },
  ];

  // Incident trend: hourly buckets for 24h, daily otherwise (real counts, no padding)
  const trendData = (rm?.trend || []).map((b) => {
    const d = new Date(b.time);
    return {
      time: range === '24h' ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : d.toLocaleDateString([], { month: 'short', day: 'numeric' }),
      incidents: b.incidents,
      contained: b.contained,
    };
  });

  // Per-incident MTTD (seconds) and MTTR (milliseconds): the two live on very different scales
  const timingData = (rm?.series || []).map((p) => ({
    id: p.id,
    mttd: p.mttd_sec,
    mttr: p.mttr_sec == null ? null : Math.round(p.mttr_sec * 1000),
  }));

  const tacticData = (rm?.by_tactic || []).map((t) => ({ subject: t.tactic, value: t.count }));

  // 6. Compute top assets dynamically from alert frequency & suspicious processes
  const assetCounts = activeAlerts.reduce((acc, alert) => {
    alert.affectedAssets.forEach((asset) => {
      acc[asset] = (acc[asset] || 0) + 1;
    });
    return acc;
  }, {} as Record<string, number>);

  processes.forEach((p) => {
    if (p.suspicious) {
      assetCounts[`Process: ${p.name} (PID ${p.pid})`] = (assetCounts[`Process: ${p.name} (PID ${p.pid})`] || 0) + 2;
    }
  });

  const calculatedAssets = Object.entries(assetCounts)
    .map(([name, count]) => {
      const risk = Math.min(10 + count * 20, 100);
      return { name, alerts: count, risk };
    })
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 5);

  const topAssets = calculatedAssets.length > 0 ? calculatedAssets : [
    { name: 'localhost (Host Machine)', alerts: 0, risk: 5 },
  ];

  // 7. Format live metrics history for system resource tracking
  const formattedMetricsHistory = metricsHistory.map((m) => {
    let timeStr = '';
    try {
      timeStr = new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      timeStr = m.timestamp;
    }
    return {
      time: timeStr,
      cpu: m.cpu_percent,
      memory: m.memory_percent,
    };
  });

  // Calculate live network throughput (KB/s) based on differences in cumulative bytes
  const throughputHistory = [];
  for (let i = 1; i < metricsHistory.length; i++) {
    const prev = metricsHistory[i - 1];
    const curr = metricsHistory[i];
    const timeDiffSec = (new Date(curr.timestamp).getTime() - new Date(prev.timestamp).getTime()) / 1000;
    
    if (timeDiffSec > 0) {
      const sentSpeedKb = ((curr.bytes_sent - prev.bytes_sent) / 1024) / timeDiffSec;
      const recvSpeedKb = ((curr.bytes_recv - prev.bytes_recv) / 1024) / timeDiffSec;
      
      let timeStr = '';
      try {
        timeStr = new Date(curr.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      } catch {
        timeStr = curr.timestamp;
      }
      
      throughputHistory.push({
        time: timeStr,
        sent: Math.max(0, Math.round(sentSpeedKb * 10) / 10),
        recv: Math.max(0, Math.round(recvSpeedKb * 10) / 10),
      });
    }
  }

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <BarChart3 className="w-6 h-6 text-accent" />
            Security Analytics
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Detection &amp; response performance, computed from recorded incidents ({rangeLabel})
          </p>
        </div>
        <div className="flex items-center gap-1 bg-black/40 border border-border/50 rounded-lg p-1 self-start">
          {RANGES.map((r) => (
            <button key={r.key} onClick={() => setRange(r.key)}
              className={`px-3 py-1 rounded-md text-xs transition-colors ${range === r.key ? 'bg-accent/20 text-accent font-semibold' : 'text-muted-foreground hover:text-foreground'}`}>
              {r.label}
            </button>
          ))}
        </div>
      </div>
      {rmFailed && (
        <div className="text-xs text-yellow-300 bg-yellow-950/30 border border-yellow-800/40 rounded px-3 py-2">
          Could not load incident analytics from the backend - showing the last known values.
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {kpis.map((kpi, i) => {
          const Icon = kpi.icon;
          return (
            <motion.div
              key={kpi.label}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.07 }}
              className="glass rounded-lg p-4 border border-border/50 space-y-2"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">{kpi.label}</span>
                <Icon className={`w-4 h-4 ${kpi.color}`} />
              </div>
              <div className={`text-2xl font-bold font-mono ${kpi.color}`}>{kpi.value}</div>
              {kpi.sub && <div className="text-[11px] text-muted-foreground font-mono leading-snug">{kpi.sub}</div>}
              {kpi.change !== null && kpi.change !== undefined ? (
                <div className={`text-xs flex items-center gap-1 ${
                  kpi.change === 0 ? 'text-muted-foreground' : 
                  (kpi.change < 0 === kpi.lowerIsBetter ? 'text-green-400' : 'text-red-400')
                }`}>
                  {kpi.change > 0 ? (
                    <TrendingUp className="w-3 h-3" />
                  ) : kpi.change < 0 ? (
                    <TrendingDown className="w-3 h-3" />
                  ) : null}
                  {Math.abs(kpi.change)}% vs previous period
                </div>
              ) : (
                <div className="text-xs text-muted-foreground">{range === 'all' ? 'All-time figure' : 'No previous-period data to compare'}</div>
              )}
            </motion.div>
          );
        })}
      </div>

      {/* Chart Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Incident Trends */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h3 className="text-sm font-semibold text-foreground mb-4">Incident Trend (detected vs contained)</h3>
          {trendData.every((d) => d.incidents === 0) ? (
            <div className="h-55 flex flex-col items-center justify-center space-y-2 text-muted-foreground text-sm">
              <Shield className="w-8 h-8 text-green-400 opacity-60" />
              <span>No incidents in this period.</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="time" stroke="#555" style={{ fontSize: '11px' }} interval="preserveStartEnd" />
                <YAxis stroke="#555" style={{ fontSize: '11px' }} allowDecimals={false} />
                <Tooltip contentStyle={CustomTooltipStyle} itemStyle={CustomTooltipItemStyle} labelStyle={CustomTooltipLabelStyle} />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Line type="monotone" dataKey="incidents" stroke="#f97316" dot={false} strokeWidth={2} name="Incidents detected" />
                <Line type="monotone" dataKey="contained" stroke="#22c55e" dot={false} strokeWidth={2} strokeDasharray="5 5" name="Contained" />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Severity Distribution */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h3 className="text-sm font-semibold text-foreground mb-4">Alert Severity Distribution (Actual Alerts)</h3>
          {activeAlerts.length === 0 ? (
            <div className="h-55 flex flex-col items-center justify-center space-y-2 text-muted-foreground text-sm">
              <Shield className="w-8 h-8 text-green-400 opacity-60" />
              <span>No alerts recorded. System is secure.</span>
            </div>
          ) : (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width="60%" height={220}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[index % SEVERITY_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={CustomTooltipStyle} itemStyle={CustomTooltipItemStyle} labelStyle={CustomTooltipLabelStyle} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex-1 space-y-2">
                {severityData.map((item, i) => (
                  <div key={item.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ background: SEVERITY_COLORS[i] }} />
                      <span className="text-muted-foreground">{item.name}</span>
                    </div>
                    <span className="font-mono font-medium text-foreground">{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* MTTD / MTTR per incident */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h3 className="text-sm font-semibold text-foreground mb-4">MTTD &amp; MTTR per Incident</h3>
          {timingData.length === 0 ? (
            <div className="h-55 flex items-center justify-center text-muted-foreground text-sm">No incidents in this period.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={timingData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="id" stroke="#555" style={{ fontSize: '10px' }} />
                <YAxis yAxisId="left" stroke="#00c8ff" style={{ fontSize: '11px' }} unit=" s" />
                <YAxis yAxisId="right" orientation="right" stroke="#f97316" style={{ fontSize: '11px' }} unit=" ms" />
                <Tooltip contentStyle={CustomTooltipStyle} itemStyle={CustomTooltipItemStyle} labelStyle={CustomTooltipLabelStyle}
                  formatter={(v: any, name: any) => (v == null ? 'n/a' : name === 'MTTD (s)' ? `${v} s` : `${v} ms`)} />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Bar yAxisId="left" dataKey="mttd" name="MTTD (s)" fill="#00c8ff" fillOpacity={0.8} radius={[4, 4, 0, 0]} />
                <Bar yAxisId="right" dataKey="mttr" name="MTTR (ms)" fill="#f97316" fillOpacity={0.8} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
          <p className="text-[10px] text-muted-foreground mt-2">
            MTTD: first attacker activity to detection. MTTR: detection to containment. Uncontained incidents have no MTTR.
          </p>
        </div>

        {/* MITRE tactics (replaces the formula-driven "maturity" radar) */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h3 className="text-sm font-semibold text-foreground mb-4">Incidents by MITRE ATT&amp;CK Tactic</h3>
          {tacticData.length === 0 ? (
            <div className="h-55 flex items-center justify-center text-muted-foreground text-sm">No incidents in this period.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <RadarChart data={tacticData}>
                <PolarGrid stroke="rgba(255,255,255,0.1)" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: '#888', fontSize: 11 }} />
                <PolarRadiusAxis angle={30} tick={{ fill: '#666', fontSize: 10 }} allowDecimals={false} />
                <Radar name="Incidents" dataKey="value" stroke="#00c8ff" fill="#00c8ff" fillOpacity={0.2} />
                <Tooltip contentStyle={CustomTooltipStyle} itemStyle={CustomTooltipItemStyle} labelStyle={CustomTooltipLabelStyle} />
              </RadarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Live System Resources (CPU & Memory) */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-accent animate-pulse" />
              Live System Resources (CPU & Memory)
            </h3>
            {metrics && (
              <span className="text-[11px] text-muted-foreground font-mono">
                CPU: {metrics.cpu_percent}% | RAM: {metrics.memory_percent}%
              </span>
            )}
          </div>
          <ResponsiveContainer width="100%" height={220}>
            {formattedMetricsHistory.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-muted-foreground py-20">
                Waiting for WebSocket telemetry streams...
              </div>
            ) : (
              <LineChart data={formattedMetricsHistory}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="time" stroke="#555" style={{ fontSize: '10px' }} />
                <YAxis domain={[0, 100]} stroke="#555" style={{ fontSize: '10px' }} />
                <Tooltip contentStyle={CustomTooltipStyle} itemStyle={CustomTooltipItemStyle} labelStyle={CustomTooltipLabelStyle} />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Line type="monotone" dataKey="cpu" stroke="#00c8ff" dot={false} strokeWidth={2} name="CPU %" activeDot={{ r: 4 }} />
                <Line type="monotone" dataKey="memory" stroke="#eab308" dot={false} strokeWidth={2} name="Memory %" activeDot={{ r: 4 }} />
              </LineChart>
            )}
          </ResponsiveContainer>
        </div>

        {/* Live Network Throughput */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-accent animate-pulse" />
              Live Network Throughput
            </h3>
            {metrics && (
              <span className="text-[11px] text-muted-foreground font-mono">
                Connections: {metrics.connections_total} | Blocklist: {metrics.blocklist_size}
              </span>
            )}
          </div>
          <ResponsiveContainer width="100%" height={220}>
            {throughputHistory.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-muted-foreground py-20">
                Calculating real-time bandwidth consumption...
              </div>
            ) : (
              <LineChart data={throughputHistory}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="time" stroke="#555" style={{ fontSize: '10px' }} />
                <YAxis stroke="#555" style={{ fontSize: '10px' }} name="KB/s" />
                <Tooltip contentStyle={CustomTooltipStyle} itemStyle={CustomTooltipItemStyle} labelStyle={CustomTooltipLabelStyle} />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Line type="monotone" dataKey="recv" stroke="#22c55e" dot={false} strokeWidth={2} name="Download (KB/s)" activeDot={{ r: 4 }} />
                <Line type="monotone" dataKey="sent" stroke="#ef4444" dot={false} strokeWidth={2} name="Upload (KB/s)" activeDot={{ r: 4 }} />
              </LineChart>
            )}
          </ResponsiveContainer>
        </div>
      </div>

      {/* Response performance by attack type */}
      <div className="glass rounded-lg border border-border/50 p-4">
        <h3 className="text-sm font-semibold text-foreground mb-3">Response Performance by Attack Type</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="text-muted-foreground uppercase tracking-wider text-[10px] border-b border-border/50">
                <th className="py-2 pr-3">Attack type</th>
                <th className="py-2 pr-3 text-right">Incidents</th>
                <th className="py-2 pr-3 text-right">MTTD mean</th>
                <th className="py-2 pr-3 text-right">MTTD p95</th>
                <th className="py-2 pr-3 text-right">MTTR mean</th>
                <th className="py-2 text-right">MTTR p95</th>
              </tr>
            </thead>
            <tbody className="font-mono divide-y divide-border/20">
              {(rm?.by_attack_type || []).map((a) => (
                <tr key={a.attack_type}>
                  <td className="py-2 pr-3 text-foreground font-sans">{ATTACK_LABELS[a.attack_type] || a.attack_type}</td>
                  <td className="py-2 pr-3 text-right">{a.count}</td>
                  <td className="py-2 pr-3 text-right">{formatDuration(a.mttd.mean)}</td>
                  <td className="py-2 pr-3 text-right">{formatDuration(a.mttd.p95)}</td>
                  <td className="py-2 pr-3 text-right">{formatDuration(a.mttr.mean)}</td>
                  <td className="py-2 text-right">{formatDuration(a.mttr.p95)}</td>
                </tr>
              ))}
              {(rm?.by_attack_type || []).length === 0 && (
                <tr><td colSpan={6} className="py-6 text-center text-muted-foreground font-sans">No incidents in this period.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Top At-Risk Assets */}
      <div className="glass rounded-lg border border-border/50 p-4">
        <h3 className="text-sm font-semibold text-foreground mb-4">Top At-Risk Assets</h3>
        <div className="space-y-2">
          {topAssets.map((asset, i) => (
            <div key={asset.name} className="flex items-center gap-3 p-2.5 bg-card/40 rounded border border-border/50">
              <div className="w-5 h-5 rounded bg-accent/20 text-accent text-xs font-bold flex items-center justify-center shrink-0">
                {i + 1}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono text-foreground truncate max-w-60 sm:max-w-none">{asset.name}</span>
                  <span className="text-xs text-muted-foreground">{asset.alerts} alerts / risk events</span>
                </div>
                <div className="w-full h-1.5 bg-card rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${asset.risk}%` }}
                    transition={{ delay: 0.3 + i * 0.1, duration: 0.8 }}
                    className={`h-full rounded-full ${asset.risk > 80 ? 'bg-red-500' : asset.risk > 60 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                  />
                </div>
              </div>
              <Badge
                className={`text-xs shrink-0 ${
                  asset.risk > 80 ? 'bg-red-900/30 text-red-300 border-red-700/50' :
                  asset.risk > 60 ? 'bg-orange-900/30 text-orange-300 border-orange-700/50' :
                  'bg-yellow-900/30 text-yellow-300 border-yellow-700/50'
                }`}
              >
                {asset.risk}% risk
              </Badge>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
