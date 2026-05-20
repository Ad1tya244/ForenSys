'use client';

import { useState, useEffect } from 'react';
import { useAppStore, Incident } from '@/lib/app-store';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { FileText, Clock, User, Server, ShieldAlert, CheckCircle2, AlertCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';

export default function IncidentsPage() {
  const { incidents, updateIncidentStatus } = useAppStore();
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [filter, setFilter] = useState('all');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Set default selected incident once loaded
  useEffect(() => {
    if (incidents.length > 0 && !selectedIncident) {
      setSelectedIncident(incidents[0]);
    }
  }, [incidents, selectedIncident]);

  if (!mounted) return null;

  const filteredIncidents = incidents.filter((inc) => {
    if (filter === 'all') return true;
    return inc.status === filter;
  });

  const counts = {
    open: incidents.filter((i) => i.status === 'open').length,
    investigating: incidents.filter((i) => i.status === 'investigating').length,
    contained: incidents.filter((i) => i.status === 'contained').length,
    resolved: incidents.filter((i) => i.status === 'resolved').length,
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-900/30 text-red-300 border-red-700/50';
      case 'high': return 'bg-orange-900/30 text-orange-300 border-orange-700/50';
      case 'medium': return 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50';
      default: return 'bg-blue-900/30 text-blue-300 border-blue-700/50';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'text-red-400 bg-red-900/20 border-red-700/40';
      case 'investigating': return 'text-yellow-400 bg-yellow-900/20 border-yellow-700/40';
      case 'contained': return 'text-orange-400 bg-orange-900/20 border-orange-700/40';
      default: return 'text-green-400 bg-green-900/20 border-green-700/40';
    }
  };

  const handleStatusChange = (id: string, status: Incident['status']) => {
    updateIncidentStatus(id, status);
    toast.success(`Incident status updated to "${status}"`);
    if (selectedIncident && selectedIncident.id === id) {
      setSelectedIncident({ ...selectedIncident, status, lastUpdated: new Date().toISOString() });
    }
  };

  // Generate a fake timeline for the selected incident safely
  const getTimeline = (incident: Incident) => {
    const createdTime = new Date(incident.createdAt);
    const updatedTime = new Date(incident.lastUpdated);
    
    const timeline = [
      { time: createdTime, event: 'Incident created', type: 'create' },
      { time: new Date(createdTime.getTime() + 300000), event: 'Initial triage completed', type: 'update' },
      { time: new Date(createdTime.getTime() + 900000), event: `Assigned to ${incident.investigator}`, type: 'assign' },
      { time: new Date(createdTime.getTime() + 1800000), event: `${incident.evidenceCount} evidence items collected`, type: 'evidence' },
      ...(incident.status !== 'open' ? [{ time: updatedTime, event: `Status changed to ${incident.status}`, type: 'status' }] : []),
    ];
    
    return timeline.sort((a, b) => a.time.getTime() - b.time.getTime());
  };

  const timelineIcons: Record<string, string> = {
    create: '🔴',
    update: '📋',
    assign: '👤',
    evidence: '🔍',
    status: '✅',
  };

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <FileText className="w-6 h-6 text-accent" />
          Incident Management Center
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">Escalations, forensics timelines, and active incident response</p>
      </div>

      {/* Status KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Open', count: counts.open, color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30', key: 'open' },
          { label: 'Investigating', count: counts.investigating, color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-700/30', key: 'investigating' },
          { label: 'Contained', count: counts.contained, color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-700/30', key: 'contained' },
          { label: 'Resolved', count: counts.resolved, color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/30', key: 'resolved' },
        ].map((item) => (
          <div
            key={item.label}
            onClick={() => setFilter(filter === item.key ? 'all' : item.key)}
            className={`rounded-lg p-3 border cursor-pointer transition-all hover:brightness-110 ${item.bg} ${
              filter === item.key ? 'ring-1 ring-accent/50' : ''
            }`}
          >
            <div className="text-xs text-muted-foreground mb-1">{item.label}</div>
            <div className={`text-2xl font-bold font-mono ${item.color}`}>{item.count}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap items-center">
        {['all', 'open', 'investigating', 'contained', 'resolved'].map((s) => {
          const count = s === 'all'
            ? incidents.length
            : counts[s as keyof typeof counts];
          return (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`h-7 px-3 rounded-full text-xs font-medium border transition-all duration-200 hover:scale-[1.01] active:scale-[0.97] ${
                filter === s
                  ? 'bg-accent/20 text-accent border-accent/50'
                  : 'bg-transparent border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              {s.charAt(0).toUpperCase() + s.slice(1)}
              <span className="ml-1 opacity-60 font-mono text-[10px]">{count}</span>
            </button>
          );
        })}
        <span className="ml-auto text-xs text-muted-foreground self-center">
          {filteredIncidents.length} incidents found
        </span>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Incident List */}
        <div className="lg:col-span-2 glass rounded-lg border border-border/50 overflow-hidden flex flex-col">
          <div className="p-3 border-b border-border/50">
            <h2 className="text-sm font-semibold text-foreground">Incident Queue</h2>
          </div>
          <ScrollArea className="flex-1 max-h-[600px] min-h-[300px]">
            <div className="space-y-1.5 p-3">
              <AnimatePresence mode="popLayout">
                {filteredIncidents.map((inc, idx) => (
                  <motion.div
                    key={inc.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ delay: idx * 0.03 }}
                    onClick={() => setSelectedIncident(inc)}
                    className={`p-3 rounded border cursor-pointer transition-all ${
                      selectedIncident?.id === inc.id
                        ? 'border-accent bg-accent/10'
                        : 'border-border/50 hover:border-border/80 hover:bg-card/60'
                    }`}
                  >
                    <div className="flex items-start gap-2">
                      <Badge className={`${getSeverityColor(inc.severity)} text-[10px] py-0 px-1 flex-shrink-0 mt-0.5`} variant="outline">
                        {inc.severity.toUpperCase()}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <p className="font-semibold text-xs text-foreground truncate">{inc.id}</p>
                        <p className="text-xs text-muted-foreground line-clamp-2 mt-0.5">{inc.title}</p>
                        <div className="flex items-center justify-between gap-2 mt-1">
                          <span className={`text-[10px] font-semibold px-1 py-0.5 rounded border font-mono ${getStatusColor(inc.status)}`}>
                            {inc.status}
                          </span>
                          <span className="text-[10px] text-muted-foreground">{new Date(inc.createdAt).toLocaleDateString()}</span>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
              {filteredIncidents.length === 0 && (
                <div className="py-12 text-center text-xs text-muted-foreground font-mono">
                  [NO INCIDENTS REGISTERED]
                </div>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* Incident Detail */}
        <div className="lg:col-span-3 glass rounded-lg border border-border/50 p-5 space-y-5 overflow-auto max-h-[700px] min-h-[300px]">
          {selectedIncident ? (
            <AnimatePresence mode="wait">
              <motion.div
                key={selectedIncident.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-5"
              >
                {/* Header */}
                <div>
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <Badge className={getSeverityColor(selectedIncident.severity)}>
                      {selectedIncident.severity.toUpperCase()}
                    </Badge>
                    <Badge className={getStatusColor(selectedIncident.status)} variant="outline">
                      {selectedIncident.status}
                    </Badge>
                  </div>
                  <h2 className="text-lg font-bold text-foreground leading-snug">{selectedIncident.title}</h2>
                  <p className="text-sm text-muted-foreground mt-1.5">{selectedIncident.description}</p>
                </div>

                {/* Metadata Grid */}
                <div className="grid grid-cols-2 gap-2 text-sm">
                  {[
                    { icon: Clock, label: 'Created', value: new Date(selectedIncident.createdAt).toLocaleString() },
                    { icon: Clock, label: 'Updated', value: new Date(selectedIncident.lastUpdated).toLocaleString() },
                    { icon: User, label: 'Investigator', value: selectedIncident.investigator },
                    { icon: AlertCircle, label: 'Evidence', value: `${selectedIncident.evidenceCount} items` },
                  ].map((row) => (
                    <div key={row.label} className="p-2 bg-card/50 rounded border border-border/50">
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-0.5">
                        <row.icon className="w-3 h-3" /> {row.label}
                      </div>
                      <div className="text-xs text-foreground font-medium truncate font-mono">{row.value}</div>
                    </div>
                  ))}
                </div>

                {/* Affected Systems */}
                <div>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Affected Systems</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedIncident.affectedSystems.map((sys) => (
                      <div key={sys} className="flex items-center gap-1.5 px-2 py-1 bg-card/50 rounded border border-border/50 text-xs">
                        <Server className="w-3 h-3 text-accent" /> {sys}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Timeline */}
                <div>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Incident Timeline</h3>
                  <div className="space-y-2">
                    {getTimeline(selectedIncident).map((entry, i, arr) => (
                      <div key={i} className="flex items-start gap-3">
                        <div className="flex flex-col items-center">
                          <div className="text-base leading-none">{timelineIcons[entry.type]}</div>
                          {i < arr.length - 1 && (
                            <div className="w-px h-6 bg-border/50 mt-1" />
                          )}
                        </div>
                        <div className="flex-1 pb-2">
                          <p className="text-xs text-foreground font-medium">{entry.event}</p>
                          <p className="text-[10px] text-muted-foreground mt-0.5 font-mono">
                            {entry.time.toLocaleString()}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div className="border-t border-border/50 pt-4 space-y-2">
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Update Incident Status</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {(['open', 'investigating', 'contained', 'resolved'] as Incident['status'][]).map((status) => (
                      <Button
                        key={status}
                        variant="outline"
                        size="sm"
                        onClick={() => handleStatusChange(selectedIncident.id, status)}
                        disabled={selectedIncident.status === status}
                        className={`text-xs border-border/50 ${
                          selectedIncident.status === status ? 'opacity-50' : 'hover:border-accent/50'
                        }`}
                      >
                        {status === 'resolved' ? <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" /> : <ShieldAlert className="w-3.5 h-3.5 mr-1.5" />}
                        {status.charAt(0).toUpperCase() + status.slice(1)}
                      </Button>
                    ))}
                  </div>
                </div>
              </motion.div>
            </AnimatePresence>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center p-8">
              <FileText className="w-8 h-8 text-muted-foreground mb-2 animate-pulse" />
              <p className="text-sm text-muted-foreground font-mono">[NO INCIDENT SELECTED]</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
