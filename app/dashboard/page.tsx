'use client';

import { useEffect, useState } from 'react';
import { useAppStore } from '@/lib/app-store';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { AlertCircle, TrendingUp, Zap, Shield, Activity, Clock, ArrowRight } from 'lucide-react';
import { generateMockAlert } from '@/lib/mock-data';
import { motion, AnimatePresence } from 'framer-motion';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

import Link from 'next/link';

const CHART_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
};

export default function Dashboard() {
  const { alerts, incidents, metrics, refreshMetrics, addAlert } = useAppStore();
  const [mounted, setMounted] = useState(false);
  const [alertTrend, setAlertTrend] = useState<Array<{ time: string; count: number; critical: number }>>([]);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    const initial = Array.from({ length: 12 }, (_, i) => ({
      time: new Date(Date.now() - (12 - i) * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      count: Math.floor(Math.random() * 40) + 20,
      critical: Math.floor(Math.random() * 10) + 2,
    }));
    setAlertTrend(initial);
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      refreshMetrics();
      addAlert(generateMockAlert());
      setAlertTrend((prev) => {
        const updated = [
          ...prev,
          {
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            count: Math.floor(Math.random() * 40) + 20,
            critical: Math.floor(Math.random() * 10) + 2,
          },
        ];
        return updated.slice(-20);
      });
    }, 4000);
    return () => clearInterval(interval);
  }, [refreshMetrics, addAlert]);

  const severityCounts = {
    critical: alerts.filter((a) => a.severity === 'critical').length,
    high: alerts.filter((a) => a.severity === 'high').length,
    medium: alerts.filter((a) => a.severity === 'medium').length,
    low: alerts.filter((a) => a.severity === 'low').length,
  };

  const sourceData = [
    { source: 'EDR', count: Math.floor(Math.random() * 80) + 40 },
    { source: 'NIDS', count: Math.floor(Math.random() * 60) + 30 },
    { source: 'Firewall', count: Math.floor(Math.random() * 50) + 20 },
    { source: 'Email GW', count: Math.floor(Math.random() * 40) + 15 },
    { source: 'WAF', count: Math.floor(Math.random() * 30) + 10 },
  ];

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      default: return 'text-green-400';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-900/30 text-red-300 border-red-700/50';
      case 'high': return 'bg-orange-900/30 text-orange-300 border-orange-700/50';
      case 'medium': return 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50';
      default: return 'bg-blue-900/30 text-blue-300 border-blue-700/50';
    }
  };

  const recentAlerts = alerts.slice(0, 10);
  const openIncidents = incidents.filter((i) => i.status === 'open' || i.status === 'investigating').slice(0, 3);

  if (!mounted) return null;

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5 cyber-grid">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Activity className="w-6 h-6 text-accent" />
            SOC Command Center
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Real-time threat monitoring · Updated every 4s</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-accent rounded-full animate-pulse" />
          <span className="text-xs text-accent font-mono">LIVE</span>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Alerts/sec', value: metrics.alertsPerSecond, color: 'text-accent', icon: AlertCircle, sub: 'Live stream' },
          { label: 'Critical', value: severityCounts.critical, color: 'text-red-400', icon: Shield, sub: 'Unresolved' },
          { label: 'Open Incidents', value: metrics.incidentsOpen, color: 'text-orange-400', icon: Zap, sub: 'Investigating' },
          { label: 'Devices at Risk', value: metrics.devicesAtRisk, color: 'text-yellow-400', icon: Shield, sub: 'Quarantine rec.' },
          { label: 'Detection Rate', value: `${metrics.detectionRate}%`, color: 'text-green-400', icon: TrendingUp, sub: 'Threat detect' },
          { label: 'Avg Response', value: `${metrics.avgResponseTime}m`, color: 'text-blue-400', icon: Clock, sub: 'MTTR' },
        ].map((kpi, i) => {
          const Icon = kpi.icon;
          return (
            <motion.div
              key={kpi.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              className="glass rounded-lg p-3 space-y-1.5 border border-border/50"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">{kpi.label}</span>
                <Icon className={`w-3.5 h-3.5 ${kpi.color}`} />
              </div>
              <motion.div
                key={mounted ? String(kpi.value) : `kpi-${i}`}
                initial={{ scale: 1.2, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                className={`text-xl font-bold font-mono ${kpi.color}`}
              >
                {mounted ? kpi.value : '-'}
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
            <h2 className="text-sm font-semibold text-foreground">Alert Trend</h2>
            <Badge className="bg-accent/20 text-accent border-accent/50 text-xs">Live</Badge>
          </div>
          <ResponsiveContainer width="100%" height={200}>
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
              <Area type="monotone" dataKey="count" stroke="#00c8ff" fill="url(#colorAlert)" dot={false} name="Alerts" />
              <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#colorCrit)" dot={false} name="Critical" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Alert by Source */}
        <div className="glass rounded-lg p-4 border border-border/50">
          <h2 className="text-sm font-semibold text-foreground mb-3">Alerts by Source</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={sourceData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
              <XAxis type="number" stroke="#555" style={{ fontSize: '10px' }} />
              <YAxis dataKey="source" type="category" stroke="#555" style={{ fontSize: '10px' }} width={55} />
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
              <h2 className="text-sm font-semibold text-foreground">Alert Console</h2>
            </div>
            <Link href="/dashboard/alerts">
              <Button variant="ghost" size="sm" className="h-6 text-xs text-accent hover:text-accent/80 gap-1">
                View all <ArrowRight className="w-3 h-3" />
              </Button>
            </Link>
          </div>
          <ScrollArea className="h-52">
            <div className="space-y-1.5 p-3">
              <AnimatePresence mode="popLayout">
                {recentAlerts.map((alert) => (
                  <motion.div
                    key={alert.id}
                    initial={{ x: -20, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    exit={{ x: 20, opacity: 0 }}
                    className={`p-2.5 rounded border ${getSeverityColor(alert.severity)} flex items-start justify-between gap-2`}
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold truncate">{alert.title}</p>
                      <p className="text-xs mt-0.5 opacity-70 truncate">{alert.source}</p>
                    </div>
                    <span className="text-xs font-mono text-muted-foreground flex-shrink-0">
                      {alert.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </ScrollArea>
        </div>

        {/* Open Incidents */}
        <div className="glass rounded-lg border border-border/50 overflow-hidden">
          <div className="p-3 border-b border-border/50 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-foreground">Open Incidents</h2>
            <Link href="/dashboard/incidents">
              <Button variant="ghost" size="sm" className="h-6 text-xs text-accent hover:text-accent/80 gap-1">
                View all <ArrowRight className="w-3 h-3" />
              </Button>
            </Link>
          </div>
          <div className="p-3 space-y-2">
            {openIncidents.map((incident) => (
              <div key={incident.id} className="p-3 bg-card/50 rounded border border-border/50 flex items-center justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-foreground text-xs truncate">{incident.title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {incident.affectedSystems.length} systems · {incident.evidenceCount} evidence items
                  </p>
                </div>
                <Badge className={`${getSeverityColor(incident.severity)} text-xs flex-shrink-0`}>
                  {incident.severity}
                </Badge>
              </div>
            ))}
            {openIncidents.length === 0 && (
              <div className="py-8 text-center text-sm text-muted-foreground">No open incidents</div>
            )}
          </div>
          {/* Quick stats */}
          <div className="px-3 pb-3 grid grid-cols-3 gap-2">
            {[
              { label: 'Devices Monitored', value: '247' },
              { label: 'Users Tracked', value: '1,240' },
              { label: 'Intel Rules', value: '3,847' },
            ].map((stat) => (
              <div key={stat.label} className="text-center p-2 bg-card/40 rounded border border-border/30">
                <div className="text-sm font-bold text-accent font-mono">{stat.value}</div>
                <div className="text-xs text-muted-foreground mt-0.5 leading-tight">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
