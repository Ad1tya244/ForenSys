'use client';

import { BarChart3, TrendingUp, TrendingDown, Clock, Shield } from 'lucide-react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  Legend, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from 'recharts';
import { motion } from 'framer-motion';
import { Badge } from '@/components/ui/badge';
import { useAppStore } from '@/lib/app-store';

const trendData = [
  { month: 'Jan', incidents: 45, detected: 234, resolved: 40 },
  { month: 'Feb', incidents: 52, detected: 267, resolved: 49 },
  { month: 'Mar', incidents: 38, detected: 189, resolved: 36 },
  { month: 'Apr', incidents: 61, detected: 312, resolved: 55 },
  { month: 'May', incidents: 55, detected: 289, resolved: 51 },
  { month: 'Jun', incidents: 67, detected: 345, resolved: 60 },
];

const mttrData = [
  { week: 'W1', mttd: 2.1, mttr: 34 },
  { week: 'W2', mttd: 1.8, mttr: 29 },
  { week: 'W3', mttd: 2.4, mttr: 42 },
  { week: 'W4', mttd: 1.5, mttr: 26 },
  { week: 'W5', mttd: 1.9, mttr: 31 },
  { week: 'W6', mttd: 1.2, mttr: 22 },
];

const radarData = [
  { subject: 'Detection', value: 88 },
  { subject: 'Response', value: 76 },
  { subject: 'Containment', value: 82 },
  { subject: 'Recovery', value: 70 },
  { subject: 'Eradication', value: 65 },
  { subject: 'Lessons', value: 55 },
];

const SEVERITY_COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6'];

const CustomTooltipStyle = {
  backgroundColor: 'rgba(15, 23, 42, 0.95)',
  border: '1px solid rgba(0,200,255,0.3)',
  borderRadius: '8px',
  fontSize: '12px',
  color: '#e2e8f0',
};

export default function AnalyticsPage() {
  const { alerts, incidents } = useAppStore();

  const severityData = [
    { name: 'Critical', value: alerts.filter((a) => a.severity === 'critical').length },
    { name: 'High', value: alerts.filter((a) => a.severity === 'high').length },
    { name: 'Medium', value: alerts.filter((a) => a.severity === 'medium').length },
    { name: 'Low', value: alerts.filter((a) => a.severity === 'low').length },
  ];

  // Compute top assets dynamically from alert frequency
  const assetCounts = alerts.reduce((acc, alert) => {
    alert.affectedAssets.forEach((asset) => {
      acc[asset] = (acc[asset] || 0) + 1;
    });
    return acc;
  }, {} as Record<string, number>);

  const calculatedAssets = Object.entries(assetCounts)
    .map(([name, count]) => {
      const risk = Math.min(15 + count * 15, 100);
      return { name, alerts: count, risk };
    })
    .sort((a, b) => b.alerts - a.alerts)
    .slice(0, 5);

  const topAssets = calculatedAssets.length > 0 ? calculatedAssets : [
    { name: 'localhost (Host Machine)', alerts: 0, risk: 5 },
  ];

  const kpis = [
    { label: 'Avg Response Time', value: '34 min', change: -12, icon: Clock, color: 'text-accent', good: true },
    { label: 'MTTD', value: '1.8 hrs', change: -8, icon: TrendingDown, color: 'text-green-400', good: true },
    { label: 'Playbook Success', value: '91%', change: +3, icon: Shield, color: 'text-accent', good: true },
    { label: 'SLA Compliance', value: '98.5%', change: +0.5, icon: TrendingUp, color: 'text-green-400', good: true },
  ];

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <BarChart3 className="w-6 h-6 text-accent" />
          Security Analytics
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">Threat metrics, incident analytics, and SOC performance</p>
      </div>

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
              <div className={`text-xs flex items-center gap-1 ${kpi.change > 0 === kpi.good ? 'text-green-400' : 'text-red-400'}`}>
                {kpi.change > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                {Math.abs(kpi.change)}% vs last month
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Chart Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Incident Trends */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h3 className="text-sm font-semibold text-foreground mb-4">Incident Trends (6 months)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis dataKey="month" stroke="#555" style={{ fontSize: '11px' }} />
              <YAxis stroke="#555" style={{ fontSize: '11px' }} />
              <Tooltip contentStyle={CustomTooltipStyle} />
              <Legend wrapperStyle={{ fontSize: '11px' }} />
              <Line type="monotone" dataKey="incidents" stroke="#f97316" dot={false} strokeWidth={2} name="Incidents" />
              <Line type="monotone" dataKey="detected" stroke="#00c8ff" dot={false} strokeWidth={2} name="Detections" />
              <Line type="monotone" dataKey="resolved" stroke="#22c55e" dot={false} strokeWidth={2} strokeDasharray="5 5" name="Resolved" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h3 className="text-sm font-semibold text-foreground mb-4">Alert Severity Distribution</h3>
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
                <Tooltip contentStyle={CustomTooltipStyle} />
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
        </div>

        {/* MTTD / MTTR */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h3 className="text-sm font-semibold text-foreground mb-4">MTTD & MTTR Trends (weekly)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={mttrData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis dataKey="week" stroke="#555" style={{ fontSize: '11px' }} />
              <YAxis yAxisId="left" stroke="#555" style={{ fontSize: '11px' }} />
              <YAxis yAxisId="right" orientation="right" stroke="#555" style={{ fontSize: '11px' }} />
              <Tooltip contentStyle={CustomTooltipStyle} />
              <Legend wrapperStyle={{ fontSize: '11px' }} />
              <Bar yAxisId="left" dataKey="mttd" name="MTTD (hrs)" fill="#00c8ff" fillOpacity={0.8} radius={[4, 4, 0, 0]} />
              <Bar yAxisId="right" dataKey="mttr" name="MTTR (min)" fill="#f97316" fillOpacity={0.8} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* SOC Capability Radar */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h3 className="text-sm font-semibold text-foreground mb-4">SOC Capability Maturity</h3>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="rgba(255,255,255,0.1)" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: '#888', fontSize: 11 }} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#666', fontSize: 10 }} />
              <Radar name="Maturity" dataKey="value" stroke="#00c8ff" fill="#00c8ff" fillOpacity={0.15} />
              <Tooltip contentStyle={CustomTooltipStyle} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top At-Risk Assets */}
      <div className="glass rounded-lg border border-border/50 p-4">
        <h3 className="text-sm font-semibold text-foreground mb-4">Top At-Risk Assets</h3>
        <div className="space-y-2">
          {topAssets.map((asset, i) => (
            <div key={asset.name} className="flex items-center gap-3 p-2.5 bg-card/40 rounded border border-border/50">
              <div className="w-5 h-5 rounded bg-accent/20 text-accent text-xs font-bold flex items-center justify-center flex-shrink-0">
                {i + 1}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono text-foreground">{asset.name}</span>
                  <span className="text-xs text-muted-foreground">{asset.alerts} alerts</span>
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
                className={`text-xs flex-shrink-0 ${
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
