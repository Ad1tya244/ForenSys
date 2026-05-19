'use client';

import { useState } from 'react';
import { Target, Search, Play, Loader2, CheckCircle2, XCircle, Terminal } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';

interface HuntResult {
  id: string;
  match: string;
  type: 'ip' | 'hash' | 'domain' | 'process';
  host: string;
  firstSeen: string;
  lastSeen: string;
  count: number;
  risk: 'critical' | 'high' | 'medium' | 'low';
  mitre: string;
}

const PRE_BUILT_QUERIES = [
  {
    id: 'q1',
    name: 'Suspicious PowerShell Execution',
    description: 'Detects encoded PowerShell commands and bypasses',
    type: 'Process',
    risk: 'High' as const,
    query: 'process.name:powershell.exe AND cmdline:*-EncodedCommand*',
  },
  {
    id: 'q2',
    name: 'Lateral Movement via WMI',
    description: 'Detects remote WMI execution patterns',
    type: 'Network',
    risk: 'Critical' as const,
    query: 'network.protocol:wmi AND destination.port:135',
  },
  {
    id: 'q3',
    name: 'Credential Dumping',
    description: 'Detects LSASS memory access patterns',
    type: 'Memory',
    risk: 'Critical' as const,
    query: 'process.target:lsass.exe AND operation:ReadProcessMemory',
  },
  {
    id: 'q4',
    name: 'Registry Persistence',
    description: 'Detects common persistence registry keys',
    type: 'Registry',
    risk: 'High' as const,
    query: 'registry.path:*\\Run* AND registry.type:WRITE',
  },
  {
    id: 'q5',
    name: 'DNS Exfiltration',
    description: 'Detects abnormally long DNS queries (tunneling)',
    type: 'Network',
    risk: 'Medium' as const,
    query: 'dns.query.length:>50 AND dns.type:TXT',
  },
  {
    id: 'q6',
    name: 'Scheduled Task Creation',
    description: 'Detects new scheduled task persistence mechanisms',
    type: 'System',
    risk: 'Medium' as const,
    query: 'event.id:4698 OR process.name:schtasks.exe',
  },
];

const MOCK_RESULTS: HuntResult[] = [
  { id: '1', match: '185.220.101.45', type: 'ip', host: 'WEBSERVER-01', firstSeen: '2024-01-14 08:22', lastSeen: '2024-01-15 14:33', count: 47, risk: 'critical', mitre: 'Command and Control' },
  { id: '2', match: 'powershell.exe -enc JABYA...', type: 'process', host: 'WORKSTATION-43', firstSeen: '2024-01-15 13:10', lastSeen: '2024-01-15 13:12', count: 3, risk: 'high', mitre: 'Execution' },
  { id: '3', match: 'a4f3c8e9b2d1f0a7...', type: 'hash', host: 'LAPTOP-USER-22', firstSeen: '2024-01-15 09:45', lastSeen: '2024-01-15 09:45', count: 1, risk: 'critical', mitre: 'Defense Evasion' },
  { id: '4', match: 'cdn-update.duckdns.org', type: 'domain', host: 'DBSERVER-02', firstSeen: '2024-01-13 22:01', lastSeen: '2024-01-15 11:17', count: 23, risk: 'high', mitre: 'Command and Control' },
  { id: '5', match: 'HKLM\\Run\\WindowsUpdate', type: 'process', host: 'FILESERVER-05', firstSeen: '2024-01-14 16:55', lastSeen: '2024-01-14 16:55', count: 1, risk: 'medium', mitre: 'Persistence' },
];

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-900/30 text-red-300 border-red-700/50',
  high: 'bg-orange-900/30 text-orange-300 border-orange-700/50',
  medium: 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50',
  low: 'bg-blue-900/30 text-blue-300 border-blue-700/50',
};

const TYPE_ICONS: Record<string, string> = { ip: '🌐', hash: '#️⃣', domain: '🔗', process: '⚙️' };

export default function ThreatHuntingPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [isHunting, setIsHunting] = useState(false);
  const [results, setResults] = useState<HuntResult[]>([]);
  const [hasSearched, setHasSearched] = useState(false);
  const [activeQuery, setActiveQuery] = useState<string | null>(null);
  const [consoleLog, setConsoleLog] = useState<string[]>([]);

  const executeHunt = (query?: string) => {
    const q = query || searchQuery;
    if (!q.trim()) return;

    setIsHunting(true);
    setHasSearched(false);
    setResults([]);
    setConsoleLog([]);

    const logs = [
      `[${new Date().toLocaleTimeString()}] Hunt initiated: "${q}"`,
      `[${new Date().toLocaleTimeString()}] Scanning 247 endpoints...`,
      `[${new Date().toLocaleTimeString()}] Querying event logs (48h window)...`,
      `[${new Date().toLocaleTimeString()}] Correlating with threat intel feed...`,
      `[${new Date().toLocaleTimeString()}] Analyzing network telemetry...`,
    ];

    logs.forEach((log, i) => {
      setTimeout(() => {
        setConsoleLog((prev) => [...prev, log]);
      }, i * 600);
    });

    setTimeout(() => {
      const count = Math.floor(Math.random() * 4) + 2;
      const hunted = MOCK_RESULTS.slice(0, count);
      setResults(hunted);
      setIsHunting(false);
      setHasSearched(true);
      setConsoleLog((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] Hunt complete. Found ${count} match${count > 1 ? 'es' : ''}.`,
      ]);
      toast.success(`Hunt complete`, { description: `${count} matches found` });
    }, 3200);
  };

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <Target className="w-6 h-6 text-accent" />
          Threat Hunt Mode
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">Advanced proactive threat hunting and IOC search</p>
      </div>

      {/* Search Console */}
      <div className="glass rounded-lg p-4 border border-border/50 space-y-3">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
            <Input
              placeholder="Search IOCs: IP, domain, file hash, process name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && executeHunt()}
              className="pl-9 bg-input border-border/50 text-sm h-10 font-mono"
            />
          </div>
          <Button
            onClick={() => executeHunt()}
            disabled={isHunting || !searchQuery.trim()}
            className="bg-accent hover:bg-accent/90 text-accent-foreground h-10 px-6"
          >
            {isHunting ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Target className="w-4 h-4 mr-2" /> Hunt</>}
          </Button>
        </div>

        {/* Console output */}
        {consoleLog.length > 0 && (
          <div className="bg-black/50 rounded border border-border/50 p-3">
            <div className="flex items-center gap-2 mb-2">
              <Terminal className="w-3.5 h-3.5 text-accent" />
              <span className="text-xs text-accent font-mono">Hunt Console</span>
              {isHunting && <div className="w-2 h-2 rounded-full bg-accent animate-pulse ml-auto" />}
            </div>
            {consoleLog.map((log, i) => (
              <motion.p
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="text-xs font-mono text-green-400/80 leading-relaxed"
              >
                {log}
              </motion.p>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Pre-built Queries */}
        <div className="lg:col-span-1 space-y-3">
          <h2 className="text-sm font-semibold text-foreground">Pre-built Hunt Queries</h2>
          <div className="space-y-2">
            {PRE_BUILT_QUERIES.map((query) => (
              <motion.div
                key={query.id}
                whileHover={{ scale: 1.01 }}
                onClick={() => {
                  setSearchQuery(query.query);
                  setActiveQuery(query.id);
                  executeHunt(query.query);
                }}
                className={`glass rounded-lg p-3 border cursor-pointer transition-all ${
                  activeQuery === query.id ? 'border-accent bg-accent/10' : 'border-border/50 hover:border-border'
                }`}
              >
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <p className="text-xs font-semibold text-foreground leading-tight">{query.name}</p>
                  <Badge
                    className={`text-xs flex-shrink-0 ${
                      query.risk === 'Critical'
                        ? 'bg-red-900/30 text-red-300 border-red-700/50'
                        : query.risk === 'High'
                        ? 'bg-orange-900/30 text-orange-300 border-orange-700/50'
                        : 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50'
                    }`}
                  >
                    {query.risk}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground mb-2">{query.description}</p>
                <div className="flex items-center justify-between">
                  <Badge variant="outline" className="text-xs border-border/50">{query.type}</Badge>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 text-xs text-accent hover:text-accent/80 p-0"
                    onClick={(e) => { e.stopPropagation(); setSearchQuery(query.query); setActiveQuery(query.id); executeHunt(query.query); }}
                  >
                    <Play className="w-3 h-3 mr-1" /> Run
                  </Button>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Results */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-foreground">Hunt Results</h2>
            {hasSearched && (
              <Badge className={results.length > 0 ? 'bg-red-900/30 text-red-300 border-red-700/50' : 'bg-green-900/30 text-green-300 border-green-700/50'}>
                {results.length > 0 ? <XCircle className="w-3 h-3 mr-1" /> : <CheckCircle2 className="w-3 h-3 mr-1" />}
                {results.length} match{results.length !== 1 ? 'es' : ''}
              </Badge>
            )}
          </div>

          {!hasSearched && !isHunting && (
            <div className="glass rounded-lg border border-border/50 p-12 text-center">
              <Target className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">Run a hunt query to see results</p>
            </div>
          )}

          {isHunting && (
            <div className="glass rounded-lg border border-border/50 p-12 text-center space-y-3">
              <Loader2 className="w-8 h-8 text-accent animate-spin mx-auto" />
              <p className="text-sm text-accent">Scanning environment...</p>
            </div>
          )}

          {hasSearched && results.length > 0 && (
            <div className="glass rounded-lg border border-border/50 overflow-hidden">
              <div className="grid grid-cols-12 gap-2 px-4 py-2.5 border-b border-border/50 text-xs text-muted-foreground font-medium bg-card/50">
                <div className="col-span-1">Type</div>
                <div className="col-span-4">Match</div>
                <div className="col-span-2">Host</div>
                <div className="col-span-2">MITRE Tactic</div>
                <div className="col-span-1 text-center">Hits</div>
                <div className="col-span-2">Risk</div>
              </div>
              <AnimatePresence>
                {results.map((r, i) => (
                  <motion.div
                    key={r.id}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.1 }}
                    className="grid grid-cols-12 gap-2 px-4 py-3 border-b border-border/30 hover:bg-card/60 transition-colors items-center"
                  >
                    <div className="col-span-1 text-base">{TYPE_ICONS[r.type]}</div>
                    <div className="col-span-4">
                      <p className="text-xs font-mono text-accent/90 truncate">{r.match}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">First: {r.firstSeen}</p>
                    </div>
                    <div className="col-span-2">
                      <span className="text-xs font-mono text-foreground">{r.host}</span>
                    </div>
                    <div className="col-span-2">
                      <Badge className="bg-purple-900/30 text-purple-300 border-purple-700/50 text-xs">
                        {r.mitre}
                      </Badge>
                    </div>
                    <div className="col-span-1 text-center">
                      <span className="text-xs font-bold text-foreground font-mono">{r.count}</span>
                    </div>
                    <div className="col-span-2">
                      <Badge className={`text-xs ${RISK_COLORS[r.risk]}`}>{r.risk}</Badge>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          )}

          {hasSearched && results.length === 0 && (
            <div className="glass rounded-lg border border-green-700/30 bg-green-900/10 p-8 text-center">
              <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-3" />
              <p className="text-sm text-green-400 font-medium">No matches found</p>
              <p className="text-xs text-muted-foreground mt-1">Environment appears clean for this query</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
