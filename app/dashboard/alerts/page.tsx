'use client';

import { useState, useEffect } from 'react';
import { useAppStore, Alert } from '@/lib/app-store';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import { Filter, Search, AlertTriangle, Shield, Clock, CheckCircle2, Flame } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import { AccessDenied } from '@/components/rbac/access-denied';

export default function AlertsPage() {
  const { alerts, acknowledgeAlert, resolveAlert, escalateAlertToIncident, hasPermission } = useAppStore();
  const [filter, setFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const filteredAlerts = alerts.filter((alert) => {
    if (filter === 'resolved') return alert.status === 'resolved';
    if (filter !== 'all' && filter !== alert.severity) return false;
    if (search && !alert.title.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const severityCounts = {
    critical: alerts.filter((a) => a.severity === 'critical' && a.status !== 'resolved').length,
    high: alerts.filter((a) => a.severity === 'high' && a.status !== 'resolved').length,
    medium: alerts.filter((a) => a.severity === 'medium' && a.status !== 'resolved').length,
    low: alerts.filter((a) => a.severity === 'low' && a.status !== 'resolved').length,
  };

  const getSeverityColor = (severity: string, status?: string) => {
    if (status === 'resolved') {
      return 'bg-card/40 border-border/30 opacity-70 text-muted-foreground';
    }
    switch (severity) {
      case 'critical': return 'bg-red-900/30 text-red-300 border-red-700/50';
      case 'high': return 'bg-orange-900/30 text-orange-300 border-orange-700/50';
      case 'medium': return 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50';
      default: return 'bg-blue-900/30 text-blue-300 border-blue-700/50';
    }
  };

  const getSeverityDot = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      default: return 'bg-blue-500';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'new': return 'bg-accent/20 text-accent border-accent/50';
      case 'acknowledged': return 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50';
      case 'investigating': return 'bg-purple-900/30 text-purple-300 border-purple-700/50';
      case 'resolved': return 'bg-green-900/30 text-green-300 border-green-700/50';
      default: return 'bg-muted/30 text-muted-foreground';
    }
  };

  const handleAcknowledge = (alertId: string) => {
    acknowledgeAlert(alertId);
    toast.success('Alert acknowledged', { description: 'Alert has been assigned to your queue.' });
  };

  const handleResolve = (alertId: string) => {
    resolveAlert(alertId);
    setSelectedAlert(null);
    toast.success('Alert resolved', { description: 'Alert marked as resolved and closed.' });
  };

  const handleEscalate = (alertId: string, alertTitle: string) => {
    escalateAlertToIncident(alertId);
    setSelectedAlert(null);
    toast.error(`Incident created from alert`, {
      description: alertTitle,
      duration: 5000,
    });
  };

  if (!mounted) return null;

  if (!hasPermission('view_alerts')) {
    return <AccessDenied permission="view_alerts" />;
  }

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <AlertTriangle className="w-6 h-6 text-accent" />
          Security Alerts
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">Monitor and triage security events in real-time</p>
      </div>

      {/* Severity Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Critical', count: severityCounts.critical, color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30', dot: 'bg-red-500', key: 'critical' },
          { label: 'High', count: severityCounts.high, color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-700/30', dot: 'bg-orange-500', key: 'high' },
          { label: 'Medium', count: severityCounts.medium, color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-700/30', dot: 'bg-yellow-500', key: 'medium' },
          { label: 'Low', count: severityCounts.low, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-700/30', dot: 'bg-blue-500', key: 'low' },
        ].map((item) => (
          <motion.div
            key={item.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            onClick={() => setFilter(filter === item.key ? 'all' : item.key)}
            className={`rounded-lg p-3 border cursor-pointer transition-all hover:scale-105 ${item.bg} ${
              filter === item.key ? 'ring-1 ring-accent/50' : ''
            }`}
          >
            <div className="flex items-center gap-2 mb-1">
              <div className={`w-2 h-2 rounded-full ${item.dot}`} />
              <span className="text-xs text-muted-foreground">{item.label}</span>
            </div>
            <div className={`text-2xl font-bold font-mono ${item.color}`}>{item.count}</div>
          </motion.div>
        ))}
      </div>

      {/* Filters */}
      <div className="space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
            <Input
              placeholder="Search alerts by title, source..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-10 bg-input border-border/50 text-sm h-9"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" className="h-9 text-xs border-border/50 flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5" />
              <span>Advanced Filters</span>
            </Button>
          </div>
        </div>
        <div className="flex gap-1.5 flex-wrap">
          {['all', 'critical', 'high', 'medium', 'low', 'resolved'].map((f) => {
            const count = f === 'all'
              ? alerts.length
              : f === 'resolved'
              ? alerts.filter(a => a.status === 'resolved').length
              : alerts.filter(a => a.severity === f && a.status !== 'resolved').length;
            return (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`h-7 px-3 rounded-full text-xs font-medium border transition-all duration-200 cursor-pointer hover:scale-[1.01] active:scale-[0.97] ${
                  filter === f
                    ? 'bg-accent/20 text-accent border-accent/50'
                    : 'bg-transparent border border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
                }`}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
                <span className="ml-1 opacity-60 font-mono text-[10px]">
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Alert count */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span>Showing <span className="text-foreground font-medium">{filteredAlerts.length}</span> of {alerts.length} alerts</span>
      </div>

      {/* Alerts List */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden">
        <ScrollArea className="h-[calc(100vh-480px)] min-h-64">
          <div className="space-y-1.5 p-3">
            <AnimatePresence mode="popLayout">
              {filteredAlerts.map((alert, idx) => (
                <motion.div
                  key={alert.id}
                  initial={{ x: -20, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  exit={{ x: 20, opacity: 0 }}
                  transition={{ delay: Math.min(idx * 0.02, 0.3) }}
                  className={`p-3 rounded border ${getSeverityColor(alert.severity, alert.status)} cursor-pointer transition-all hover:brightness-110`}
                  onClick={() => setSelectedAlert(alert)}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2.5 flex-1 min-w-0">
                      <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${getSeverityDot(alert.severity)}`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <p className="font-semibold text-sm truncate">{alert.title}</p>
                          <Badge variant="outline" className={`text-xs shrink-0 ${getStatusBadge(alert.status)}`}>
                            {alert.status}
                          </Badge>
                        </div>
                        <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs opacity-75">
                          <span>Source: {alert.source}</span>
                          <span>{new Date(alert.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div className="flex flex-wrap gap-1 mt-1.5">
                          {alert.affectedAssets.map((asset) => (
                            <Badge key={asset} variant="outline" className="text-xs border-border/40 h-4 px-1">
                              {asset}
                            </Badge>
                          ))}
                          {alert.mitreTactics.slice(0, 2).map((tactic) => (
                            <Badge key={tactic} variant="outline" className="text-xs border-purple-700/40 text-purple-300 bg-purple-900/20 h-4 px-1">
                              {tactic}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="border-border/50 h-7 text-xs shrink-0"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedAlert(alert);
                      }}
                    >
                      Investigate
                    </Button>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
            {filteredAlerts.length === 0 && (
              <div className="py-12 text-center text-muted-foreground text-sm">No alerts matching your filter</div>
            )}
          </div>
        </ScrollArea>
      </div>

      {/* Alert Detail Sheet */}
      <Sheet open={!!selectedAlert} onOpenChange={(open) => !open && setSelectedAlert(null)}>
        <SheetContent className="w-120 sm:w-135 bg-card border-border/50 overflow-y-auto p-6">
          {selectedAlert && (
            <>
              <SheetHeader className="space-y-3 p-0">
                <div className="flex items-center gap-2">
                  <Badge className={getSeverityColor(selectedAlert.severity)}>
                    {selectedAlert.severity.toUpperCase()}
                  </Badge>
                  <Badge className={getStatusBadge(selectedAlert.status)}>
                    {selectedAlert.status}
                  </Badge>
                </div>
                <SheetTitle className="text-foreground text-lg leading-snug">{selectedAlert.title}</SheetTitle>
                <SheetDescription className="text-muted-foreground text-sm">
                  {selectedAlert.description}
                </SheetDescription>
              </SheetHeader>

              <div className="mt-6 space-y-5">
                {/* Metadata */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Alert Details</h3>
                  <div className="space-y-1.5">
                    {[
                      { label: 'Source', value: selectedAlert.source },
                      { label: 'Alert ID', value: selectedAlert.id },
                      { label: 'Timestamp', value: new Date(selectedAlert.timestamp).toLocaleString() },
                    ].map((row) => (
                      <div key={row.label} className="flex items-center justify-between p-2.5 bg-card/50 rounded border border-border/50">
                        <span className="text-xs text-muted-foreground">{row.label}</span>
                        <span className="text-xs text-foreground font-mono">{row.value}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Affected Assets */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Affected Assets</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedAlert.affectedAssets.map((asset) => (
                      <Badge key={asset} variant="outline" className="border-border/50 text-xs">
                        {asset}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* MITRE Tactics */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">MITRE ATT&CK Tactics</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedAlert.mitreTactics.map((tactic) => (
                      <Badge key={tactic} className="bg-purple-900/30 text-purple-300 border-purple-700/50 text-xs">
                        {tactic}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div className="space-y-2 pt-2 border-t border-border/50">
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</h3>
                  <div className="space-y-2">
                    <Button
                      className="w-full bg-red-600 hover:bg-red-700 text-white gap-2 focus-visible:ring-red-600/50 focus-visible:border-red-600 focus-visible:ring-[3px]"
                      onClick={() => handleEscalate(selectedAlert.id, selectedAlert.title)}
                      disabled={selectedAlert.status === 'resolved' || !hasPermission('manage_alerts')}
                    >
                      <Flame className="w-4 h-4" />
                      Escalate to Incident
                    </Button>
                    <div className="grid grid-cols-2 gap-2">
                      <Button
                        variant="outline"
                        className="border-border/50 gap-2"
                        onClick={() => handleAcknowledge(selectedAlert.id)}
                        disabled={selectedAlert.status !== 'new' || !hasPermission('manage_alerts')}
                      >
                        <CheckCircle2 className="w-4 h-4" />
                        Acknowledge
                      </Button>
                      <Button
                        variant="outline"
                        className="border-green-700/50 text-green-400 hover:bg-green-900/20 gap-2"
                        onClick={() => handleResolve(selectedAlert.id)}
                        disabled={selectedAlert.status === 'resolved' || !hasPermission('manage_alerts')}
                      >
                        <Shield className="w-4 h-4" />
                        Resolve
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
