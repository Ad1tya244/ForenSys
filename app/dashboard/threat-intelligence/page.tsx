'use client';

import { useState, useMemo, useEffect } from 'react';
import { Shield, Search, ExternalLink, ChevronDown, ChevronUp, Star, Globe, ShieldAlert } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useAppStore } from '@/lib/app-store';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';

const TYPE_COLORS: Record<string, string> = {
  malware: 'bg-red-900/30 text-red-300 border-red-700/50',
  ioc: 'bg-orange-900/30 text-orange-300 border-orange-700/50',
  vulnerability: 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50',
  campaign: 'bg-purple-900/30 text-purple-300 border-purple-700/50',
};

const MITRE_MAPPINGS: Record<string, string[]> = {
  malware: ['Execution', 'Defense Evasion', 'Impact'],
  ioc: ['Initial Access', 'Command and Control'],
  vulnerability: ['Initial Access', 'Privilege Escalation'],
  campaign: ['Initial Access', 'Lateral Movement', 'Exfiltration'],
};

interface IntelItem {
  id: string;
  type: 'malware' | 'ioc' | 'vulnerability' | 'campaign';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  indicators: string[];
  lastSeen: Date;
  confidence: number;
}

export default function ThreatIntelligencePage() {
  const { alerts, metrics, connections } = useAppStore();
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [watchlist, setWatchlist] = useState<Set<string>>(new Set());
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Compute dynamic threat intelligence items from real connections and alerts
  const threatIntelList = useMemo<IntelItem[]>(() => {
    const list: IntelItem[] = [];

    // 1. Map active blocklisted IPs from alerts
    const blocklistAlerts = alerts.filter(a => a.title.includes('Blocklisted IP') || a.title.includes('Suspicious Port'));
    blocklistAlerts.forEach((alert, i) => {
      // Find remote IP in description/affectedAssets
      const ip = alert.affectedAssets.find(a => !a.includes('/') && a.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) || '127.0.0.1';
      list.push({
        id: `intel-alert-${alert.id}-${i}`,
        type: 'ioc',
        title: `IOC Match — Suspicious Outbound Activity`,
        severity: alert.severity,
        description: alert.description,
        indicators: [ip],
        lastSeen: new Date(alert.timestamp),
        confidence: alert.severity === 'critical' ? 95 : 85,
      });
    });    // 2. Add dynamic campaigns based on active network connections geolocations
    const activeRemoteIPs = connections.filter(c => c.geo);
    activeRemoteIPs.forEach((conn, i) => {
      if (conn.remote_ip && conn.geo) {
        const orgName = conn.geo.org || 'Unknown Organization';
        const cityName = conn.geo.city || 'Unknown City';
        const countryName = conn.geo.country || 'Unknown Country';
        const procName = conn.process || 'unknown';
        const proto = conn.protocol || 'TCP';
        const pidNum = conn.pid !== undefined && conn.pid !== null ? conn.pid : 'N/A';
        const isLan = conn.geo.country_code === 'LAN';
        const title = isLan ? `Local Connection: ${orgName}` : `Active Remote Peer Activity: ${orgName}`;
        list.push({
          id: `intel-conn-${conn.remote_ip}-${i}`,
          type: 'campaign',
          title: title,
          severity: 'low',
          description: `Established ${proto} connection to IP in ${cityName}, ${countryName}. Process: ${procName} (PID: ${pidNum}).`,
          indicators: [conn.remote_ip],
          lastSeen: new Date(),
          confidence: 60,
        });
      }
    });
    return list;
  }, [alerts, connections]);

  const filtered = useMemo(
    () =>
      threatIntelList.filter((t) => {
        if (typeFilter !== 'all' && t.type !== typeFilter) return false;
        if (search && !t.title.toLowerCase().includes(search.toLowerCase()) && !t.description.toLowerCase().includes(search.toLowerCase())) return false;
        return true;
      }),
    [threatIntelList, search, typeFilter]
  );

  const counts = {
    all: threatIntelList.length,
    malware: threatIntelList.filter((t) => t.type === 'malware').length,
    ioc: threatIntelList.filter((t) => t.type === 'ioc').length,
    vulnerability: threatIntelList.filter((t) => t.type === 'vulnerability').length,
    campaign: threatIntelList.filter((t) => t.type === 'campaign').length,
  };

  const toggleWatchlist = (id: string, title: string) => {
    setWatchlist((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
        toast.info('Removed from watchlist');
      } else {
        next.add(id);
        toast.success('Added to watchlist', { description: title });
      }
      return next;
    });
  };

  if (!mounted) return null;

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Shield className="w-6 h-6 text-accent" />
            Threat Intelligence
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Active indicators of compromise, blocklists, and host connection geolocations
          </p>
        </div>

        {/* Global Blocklist Status Card */}
        {metrics && (
          <div className="glass px-4 py-2 border border-purple-500/20 rounded-md flex items-center gap-3">
            <Globe className="w-5 h-5 text-purple-400" />
            <div>
              <p className="text-[10px] text-muted-foreground uppercase font-mono">Active Blocklist IP Count</p>
              <p className="text-sm font-bold font-mono text-purple-300">{metrics.blocklist_size.toLocaleString()} IPs</p>
            </div>
          </div>
        )}
      </div>

      {/* Type filter pills */}
      <div className="flex flex-wrap gap-2">
        {(['all', 'malware', 'ioc', 'vulnerability', 'campaign'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTypeFilter(t)}
            className={`h-7 px-3 rounded-full text-xs font-medium border transition-all duration-200 hover:scale-[1.01] active:scale-[0.97] ${
              typeFilter === t
                ? 'bg-accent/20 text-accent border-accent/50'
                : 'bg-transparent border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
            <span className="ml-1.5 opacity-60 font-mono text-[10px]">
              {counts[t as keyof typeof counts]}
            </span>
          </button>
        ))}
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
        <Input
          placeholder="Search indicators, IP addresses, or campaigns..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9 bg-input border-border/50 text-sm h-9"
        />
      </div>

      {/* Feed count */}
      <div className="text-xs text-muted-foreground">
        Showing <span className="text-foreground font-medium">{filtered.length}</span> threat entries
      </div>

      {/* Intelligence Feed */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden">
        {/* Table Header */}
        <div className="grid grid-cols-[30px_1fr_90px_90px_130px_170px_30px] gap-4 px-4 py-2.5 border-b border-border/50 text-xs text-muted-foreground font-medium bg-card/50">
          <div className="flex justify-center"></div>
          <div>Threat</div>
          <div>Type</div>
          <div>Severity</div>
          <div>Confidence</div>
          <div>Last Seen</div>
          <div className="flex justify-end"></div>
        </div>
        <ScrollArea className="h-[calc(100vh-400px)] min-h-80">
          <div className="divide-y divide-border/30">
            <AnimatePresence>
              {filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
                  <ShieldAlert className="w-8 h-8 text-muted-foreground/60 mb-2" />
                  <p className="text-sm font-semibold text-muted-foreground">No Local Telemetry Threats Detected</p>
                  <p className="text-xs text-muted-foreground/80 mt-1 max-w-md">
                    No active outbound connections to blocklisted IPs or malicious external geolocations are currently active on your system.
                  </p>
                </div>
              ) : (
                filtered.map((intel, idx) => {
                  const isExpanded = expandedId === intel.id;
                  const isWatched = watchlist.has(intel.id);
                  return (
                    <motion.div
                      key={intel.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.01 }}
                      className="hover:bg-card/60 transition-colors"
                    >
                      {/* Row */}
                      <div
                        className="grid grid-cols-[30px_1fr_90px_90px_130px_170px_30px] gap-4 px-4 py-3 cursor-pointer items-center"
                        onClick={() => setExpandedId(isExpanded ? null : intel.id)}
                      >
                        <div className="flex items-center justify-center">
                          <button
                            onClick={(e) => { e.stopPropagation(); toggleWatchlist(intel.id, intel.title); }}
                            className={`transition-colors ${isWatched ? 'text-yellow-400' : 'text-muted-foreground hover:text-yellow-400'}`}
                          >
                            <Star className="w-3.5 h-3.5" fill={isWatched ? 'currentColor' : 'none'} />
                          </button>
                        </div>
                        <div className="min-w-0">
                          <p className="text-xs font-medium text-foreground truncate">{intel.title}</p>
                          <p className="text-xs text-muted-foreground mt-0.5 truncate">{intel.description}</p>
                        </div>
                        <div>
                          <Badge className={`${TYPE_COLORS[intel.type]} text-xs`}>
                            {intel.type}
                          </Badge>
                        </div>
                        <div>
                          <Badge className={`text-xs ${
                            intel.severity === 'critical' ? 'bg-red-900/30 text-red-300 border-red-700/50' :
                            intel.severity === 'high' ? 'bg-orange-900/30 text-orange-300 border-orange-700/50' :
                            'bg-yellow-900/30 text-yellow-300 border-yellow-700/50'
                          }`}>
                            {intel.severity}
                          </Badge>
                        </div>
                        <div>
                          <div className="flex items-center gap-1.5">
                            <div className="flex-1 h-1.5 bg-card rounded-full overflow-hidden">
                              <div
                                className="h-full bg-accent rounded-full"
                                style={{ width: `${intel.confidence}%` }}
                              />
                            </div>
                            <span className="text-xs text-accent font-mono w-8">{intel.confidence}%</span>
                          </div>
                        </div>
                        <div>
                          <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
                            {new Date(intel.lastSeen).toLocaleString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}
                          </span>
                        </div>
                        <div className="flex items-center justify-end">
                          {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
                        </div>
                      </div>

                      {/* Expanded Detail */}
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="overflow-hidden border-t border-border/30 bg-card/30"
                          >
                            <div className="px-4 py-4 grid grid-cols-1 md:grid-cols-4 gap-4">
                              {/* Description / Full Details */}
                              <div className="md:col-span-2">
                                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Description / Event Details</h4>
                                <p className="text-xs text-foreground bg-card/60 p-2.5 rounded border border-border/30 whitespace-pre-wrap leading-relaxed">
                                  {intel.description}
                                </p>
                              </div>
                              {/* Indicators */}
                              <div>
                                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Indicators</h4>
                                <div className="space-y-1">
                                  {intel.indicators.map((ioc) => (
                                    <div key={ioc} className="flex items-center gap-1.5 text-xs font-mono text-accent/80 bg-accent/5 px-2 py-1 rounded border border-accent/20">
                                      {ioc}
                                      <ExternalLink className="w-3 h-3 ml-auto cursor-pointer" />
                                    </div>
                                  ))}
                                </div>
                              </div>
                              {/* Actions & MITRE */}
                              <div className="space-y-4">
                                <div>
                                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">MITRE ATT&CK</h4>
                                  <div className="flex flex-wrap gap-1.5">
                                    {(MITRE_MAPPINGS[intel.type] || []).map((tactic) => (
                                      <Badge key={tactic} className="bg-purple-900/30 text-purple-300 border-purple-700/50 text-xs">
                                        {tactic}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                                <div className="space-y-2">
                                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Actions</h4>
                                  <Button
                                    size="sm"
                                    onClick={() => toggleWatchlist(intel.id, intel.title)}
                                    className={`w-full text-xs h-7 ${isWatched ? 'bg-yellow-900/30 text-yellow-300 border border-yellow-700/50 hover:bg-yellow-900/50' : 'bg-accent/20 text-accent border border-accent/50 hover:bg-accent/30'}`}
                                  >
                                    <Star className="w-3.5 h-3.5 mr-1.5" fill={isWatched ? 'currentColor' : 'none'} />
                                    {isWatched ? 'Remove from Watchlist' : 'Add to Watchlist'}
                                  </Button>
                                  <Button variant="outline" size="sm" className="w-full text-xs h-7 border-border/50">
                                    Create Hunt Query
                                  </Button>
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })
              )}
            </AnimatePresence>
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}
