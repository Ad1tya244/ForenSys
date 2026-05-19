'use client';

import { useState, useMemo } from 'react';
import { Shield, Search, ExternalLink, ChevronDown, ChevronUp, Star } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { generateMockThreatIntel } from '@/lib/mock-data';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';

const THREAT_INTEL = generateMockThreatIntel(25);

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

export default function ThreatIntelligencePage() {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [watchlist, setWatchlist] = useState<Set<string>>(new Set());

  const filtered = useMemo(
    () =>
      THREAT_INTEL.filter((t) => {
        if (typeFilter !== 'all' && t.type !== typeFilter) return false;
        if (search && !t.title.toLowerCase().includes(search.toLowerCase())) return false;
        return true;
      }),
    [search, typeFilter]
  );

  const counts = {
    all: THREAT_INTEL.length,
    malware: THREAT_INTEL.filter((t) => t.type === 'malware').length,
    ioc: THREAT_INTEL.filter((t) => t.type === 'ioc').length,
    vulnerability: THREAT_INTEL.filter((t) => t.type === 'vulnerability').length,
    campaign: THREAT_INTEL.filter((t) => t.type === 'campaign').length,
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

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <Shield className="w-6 h-6 text-accent" />
          Threat Intelligence
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Live IOC feeds, adversary campaigns, malware signatures
        </p>
      </div>

      {/* Type filter pills */}
      <div className="flex flex-wrap gap-2">
        {(['all', 'malware', 'ioc', 'vulnerability', 'campaign'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTypeFilter(t)}
            className={`px-3 py-1 rounded-full text-xs font-medium border transition-all ${
              typeFilter === t
                ? 'bg-accent/20 text-accent border-accent/50'
                : 'border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
            <span className="ml-1.5 opacity-60">
              {counts[t as keyof typeof counts]}
            </span>
          </button>
        ))}
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
        <Input
          placeholder="Search threat intelligence..."
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
        <div className="grid grid-cols-12 gap-3 px-4 py-2.5 border-b border-border/50 text-xs text-muted-foreground font-medium bg-card/50">
          <div className="col-span-1"></div>
          <div className="col-span-4">Threat</div>
          <div className="col-span-2">Type</div>
          <div className="col-span-2">Severity</div>
          <div className="col-span-2">Confidence</div>
          <div className="col-span-1">Last Seen</div>
        </div>
        <ScrollArea className="h-[calc(100vh-400px)] min-h-80">
          <div className="divide-y divide-border/30">
            <AnimatePresence>
              {filtered.map((intel, idx) => {
                const isExpanded = expandedId === intel.id;
                const isWatched = watchlist.has(intel.id);
                return (
                  <motion.div
                    key={intel.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: idx * 0.02 }}
                    className="hover:bg-card/60 transition-colors"
                  >
                    {/* Row */}
                    <div
                      className="grid grid-cols-12 gap-3 px-4 py-3 cursor-pointer items-center"
                      onClick={() => setExpandedId(isExpanded ? null : intel.id)}
                    >
                      <div className="col-span-1 flex items-center justify-center">
                        <button
                          onClick={(e) => { e.stopPropagation(); toggleWatchlist(intel.id, intel.title); }}
                          className={`transition-colors ${isWatched ? 'text-yellow-400' : 'text-muted-foreground hover:text-yellow-400'}`}
                        >
                          <Star className="w-3.5 h-3.5" fill={isWatched ? 'currentColor' : 'none'} />
                        </button>
                      </div>
                      <div className="col-span-4 min-w-0">
                        <p className="text-xs font-medium text-foreground truncate">{intel.title}</p>
                        <p className="text-xs text-muted-foreground mt-0.5 truncate">{intel.description}</p>
                      </div>
                      <div className="col-span-2">
                        <Badge className={`${TYPE_COLORS[intel.type]} text-xs`}>
                          {intel.type}
                        </Badge>
                      </div>
                      <div className="col-span-2">
                        <Badge className={`text-xs ${
                          intel.severity === 'critical' ? 'bg-red-900/30 text-red-300 border-red-700/50' :
                          intel.severity === 'high' ? 'bg-orange-900/30 text-orange-300 border-orange-700/50' :
                          'bg-yellow-900/30 text-yellow-300 border-yellow-700/50'
                        }`}>
                          {intel.severity}
                        </Badge>
                      </div>
                      <div className="col-span-2">
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
                      <div className="col-span-1 flex items-center justify-between">
                        <span className="text-xs text-muted-foreground">
                          {intel.lastSeen.toLocaleDateString('en', { month: 'short', day: 'numeric' })}
                        </span>
                        {isExpanded ? <ChevronUp className="w-3 h-3 text-muted-foreground" /> : <ChevronDown className="w-3 h-3 text-muted-foreground" />}
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
                          <div className="px-4 py-4 grid grid-cols-1 md:grid-cols-3 gap-4">
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
                            {/* MITRE Mapping */}
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
                            {/* Actions */}
                            <div className="space-y-2">
                              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Actions</h4>
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
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}
