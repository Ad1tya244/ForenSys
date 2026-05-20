'use client';

import { useState, useEffect } from 'react';
import { Target, Search, Play, Loader2, CheckCircle2, XCircle, Terminal } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useAppStore } from '@/lib/app-store';
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
    name: 'Suspicious Terminal Shells',
    description: 'Detects suspicious command shell or python scripts running',
    type: 'Process',
    risk: 'High' as const,
    query: 'process.name:sh OR process.name:bash OR process.name:python',
  },
  {
    id: 'q2',
    name: 'Network Connection Hunting',
    description: 'Detects connections to remote/external addresses',
    type: 'Network',
    risk: 'Medium' as const,
    query: 'connection.remote_ip:!127.0.0.1 AND connection.status:ESTABLISHED',
  },
  {
    id: 'q3',
    name: 'Root / Privilege Events',
    description: 'Detects activities executing under root account or sudo access',
    type: 'System',
    risk: 'High' as const,
    query: 'process.username:root OR log.message:sudo',
  },
  {
    id: 'q4',
    name: 'Critical Service Scan',
    description: 'Detects ports associated with standard web/database endpoints',
    type: 'Network',
    risk: 'Medium' as const,
    query: 'connection.port:80 OR connection.port:443 OR connection.port:8000',
  },
  {
    id: 'q5',
    name: 'Security Log Audits',
    description: 'Audits host security logs for authentication failures and alerts',
    type: 'Logs',
    risk: 'Critical' as const,
    query: 'log.level:error OR log.message:fail',
  },
];

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-900/30 text-red-300 border-red-700/50',
  high: 'bg-orange-900/30 text-orange-300 border-orange-700/50',
  medium: 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50',
  low: 'bg-blue-900/30 text-blue-300 border-blue-700/50',
};

const TYPE_ICONS: Record<string, string> = { ip: '🌐', hash: '#️⃣', domain: '🔗', process: '⚙️' };

export default function ThreatHuntingPage() {
  const { connections, processes, logs, metrics } = useAppStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [isHunting, setIsHunting] = useState(false);
  const [results, setResults] = useState<HuntResult[]>([]);
  const [hasSearched, setHasSearched] = useState(false);
  const [activeQuery, setActiveQuery] = useState<string | null>(null);
  const [consoleLog, setConsoleLog] = useState<string[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const executeHunt = (queryText?: string) => {
    const queryStr = queryText || searchQuery;
    if (!queryStr.trim()) return;

    setIsHunting(true);
    setHasSearched(false);
    setResults([]);
    setConsoleLog([]);

    const hostname = metrics?.hostname || 'localhost';

    const outputLogs = [
      `[${new Date().toLocaleTimeString()}] Proactive hunt initiated: "${queryStr}"`,
      `[${new Date().toLocaleTimeString()}] Querying host endpoint telemetry database...`,
      `[${new Date().toLocaleTimeString()}] Scanning active system processes (${processes.length} tracked)...`,
      `[${new Date().toLocaleTimeString()}] Scanning established sockets (${connections.length} ports)...`,
      `[${new Date().toLocaleTimeString()}] Scanning current event log database (${logs.length} items)...`,
    ];

    outputLogs.forEach((log, i) => {
      setTimeout(() => {
        setConsoleLog((prev) => [...prev, log]);
      }, i * 400);
    });

    // Real search matcher logic
    setTimeout(() => {
      const q = queryStr.toLowerCase();
      const hits: HuntResult[] = [];

      // 1. Process matchers
      processes.forEach((proc, idx) => {
        const matchesName = proc.name.toLowerCase().includes(q) || q.includes(proc.name.toLowerCase());
        const matchesUser = proc.username && proc.username.toLowerCase().includes(q);
        const matchesPid = proc.pid.toString() === q;
        const matchesCommand = q.includes('process.name') && q.includes(proc.name.toLowerCase());
        const matchesRoot = q.includes('username:root') && proc.username === 'root';

        if (matchesName || matchesUser || matchesPid || matchesCommand || matchesRoot) {
          hits.push({
            id: `hunt-proc-${proc.pid}-${idx}`,
            match: `${proc.name} (PID: ${proc.pid}, USER: ${proc.username || 'unknown'})`,
            type: 'process',
            host: hostname,
            firstSeen: new Date(Date.now() - 3600000).toLocaleTimeString(),
            lastSeen: new Date().toLocaleTimeString(),
            count: 1,
            risk: proc.username === 'root' || proc.cpu_percent > 50 ? 'high' : 'low',
            mitre: proc.username === 'root' ? 'Privilege Escalation' : 'Execution',
          });
        }
      });

      // 2. Connection matchers
      connections.forEach((conn, idx) => {
        const matchesIp = conn.remote_ip && conn.remote_ip.includes(q);
        const matchesPort = conn.remote_port && conn.remote_port.toString() === q;
        const matchesProto = conn.protocol.toLowerCase().includes(q);
        const matchesProcess = conn.process && conn.process.toLowerCase().includes(q);
        
        // Complex query checks
        const checkEstablished = q.includes('status:established') && conn.status === 'ESTABLISHED';
        const checkLocal = q.includes('remote_ip:!127.0.0.1') && conn.remote_ip !== '127.0.0.1' && conn.remote_ip !== '0.0.0.0';

        if (matchesIp || matchesPort || matchesProto || matchesProcess || (checkEstablished && checkLocal)) {
          hits.push({
            id: `hunt-conn-${conn.remote_ip || 'local'}-${conn.remote_port || 0}-${idx}`,
            match: `Socket: ${conn.local_ip}:${conn.local_port} -> ${conn.remote_ip || 'LISTEN'}:${conn.remote_port || ''} [${conn.protocol}]`,
            type: 'ip',
            host: hostname,
            firstSeen: new Date(Date.now() - 1800000).toLocaleTimeString(),
            lastSeen: new Date().toLocaleTimeString(),
            count: 1,
            risk: conn.remote_ip && conn.remote_ip !== '127.0.0.1' && conn.remote_ip !== '::1' ? 'medium' : 'low',
            mitre: conn.status === 'ESTABLISHED' ? 'Command and Control' : 'Discovery',
          });
        }
      });

      // 3. Logs matchers
      logs.forEach((log) => {
        const matchesMsg = log.message.toLowerCase().includes(q);
        const matchesProc = log.process.toLowerCase().includes(q);
        const matchesLevel = q.includes('level:error') && log.level === 'error';
        const matchesFail = q.includes('message:fail') && log.message.toLowerCase().includes('fail');

        if (matchesMsg || matchesProc || matchesLevel || matchesFail) {
          hits.push({
            id: `hunt-log-${log.id}`,
            match: `Log Event: [${log.process}] ${log.message}`,
            type: 'domain',
            host: hostname,
            firstSeen: new Date(log.timestamp).toLocaleTimeString(),
            lastSeen: new Date(log.timestamp).toLocaleTimeString(),
            count: 1,
            risk: log.level === 'error' ? 'high' : 'medium',
            mitre: 'Defense Evasion',
          });
        }
      });

      // Deduplicate results
      const uniqueHits = hits.filter((v, i, a) => a.findIndex(t => t.match === v.match) === i);

      setResults(uniqueHits);
      setIsHunting(false);
      setHasSearched(true);
      setConsoleLog((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] Hunt complete. Found ${uniqueHits.length} match${uniqueHits.length !== 1 ? 'es' : ''} across telemetry channels.`,
      ]);
      toast.success(`Hunt complete`, { description: `${uniqueHits.length} matches found` });
    }, 2000);
  };

  if (!mounted) return null;

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <Target className="w-6 h-6 text-accent" />
          Proactive Threat Hunting
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">Advanced live telemetries query processor and active IOC cross-referencing</p>
      </div>

      {/* Search Console */}
      <div className="glass rounded-lg p-4 border border-border/50 space-y-3">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
            <Input
              placeholder="Query active processes, network sockets, or event logs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && executeHunt()}
              className="pl-9 bg-input border-border/50 text-sm h-10 font-mono text-accent"
            />
          </div>
          <Button
            onClick={() => executeHunt()}
            disabled={isHunting || !searchQuery.trim()}
            className="bg-accent hover:bg-accent/90 text-accent-foreground h-10 px-6 font-mono"
          >
            {isHunting ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Target className="w-4 h-4 mr-2" /> EXECUTE</>}
          </Button>
        </div>

        {/* Console output */}
        {consoleLog.length > 0 && (
          <div className="bg-black/50 rounded border border-border/50 p-3">
            <div className="flex items-center gap-2 mb-2">
              <Terminal className="w-3.5 h-3.5 text-accent" />
              <span className="text-xs text-accent font-mono">Telemetry Correlation Engine</span>
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
          <h2 className="text-sm font-semibold text-foreground">Pre-built Hunt Templates</h2>
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
                  <Badge variant="outline" className="text-xs border-border/50 font-mono">{query.type}</Badge>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 text-xs text-accent hover:text-accent/80 p-0 font-mono"
                    onClick={(e) => { e.stopPropagation(); setSearchQuery(query.query); setActiveQuery(query.id); executeHunt(query.query); }}
                  >
                    <Play className="w-3 h-3 mr-1" /> RUN
                  </Button>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Results */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-foreground">Correlation Hits</h2>
            {hasSearched && (
              <Badge className={results.length > 0 ? 'bg-red-900/30 text-red-300 border-red-700/50 font-mono' : 'bg-green-900/30 text-green-300 border-green-700/50 font-mono'}>
                {results.length > 0 ? <XCircle className="w-3 h-3 mr-1" /> : <CheckCircle2 className="w-3 h-3 mr-1" />}
                {results.length} MATCH{results.length !== 1 ? 'ES' : ''}
              </Badge>
            )}
          </div>

          {!hasSearched && !isHunting && (
            <div className="glass rounded-lg border border-border/50 p-12 text-center">
              <Target className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">Select a template query or enter a keyword search to correlation scan</p>
            </div>
          )}

          {isHunting && (
            <div className="glass rounded-lg border border-border/50 p-12 text-center space-y-3">
              <Loader2 className="w-8 h-8 text-accent animate-spin mx-auto" />
              <p className="text-sm text-accent font-mono">Searching telemetry channels...</p>
            </div>
          )}

          {hasSearched && results.length > 0 && (
            <div className="glass rounded-lg border border-border/50 overflow-hidden">
              <div className="grid grid-cols-12 gap-2 px-4 py-2.5 border-b border-border/50 text-xs text-muted-foreground font-medium bg-card/50 font-mono">
                <div className="col-span-1">Type</div>
                <div className="col-span-4">Matched Endpoint Value</div>
                <div className="col-span-2">Host Node</div>
                <div className="col-span-2">MITRE Mapping</div>
                <div className="col-span-1 text-center">Hits</div>
                <div className="col-span-2 font-sans">Risk</div>
              </div>
              <ScrollArea className="h-[calc(100vh-420px)] min-h-80">
                <div className="divide-y divide-border/30">
                  <AnimatePresence>
                    {results.map((r, i) => (
                      <motion.div
                        key={`${r.id}-${i}`}
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.05 }}
                        className="grid grid-cols-12 gap-2 px-4 py-3 border-b border-border/30 hover:bg-card/60 transition-colors items-center font-mono"
                      >
                        <div className="col-span-1 text-base">{TYPE_ICONS[r.type]}</div>
                        <div className="col-span-4">
                          <p className="text-xs font-semibold text-accent/90 truncate">{r.match}</p>
                          <p className="text-[10px] text-muted-foreground mt-0.5">Scanned: {r.lastSeen}</p>
                        </div>
                        <div className="col-span-2">
                          <span className="text-xs text-foreground truncate block">{r.host}</span>
                        </div>
                        <div className="col-span-2">
                          <Badge className="bg-purple-900/30 text-purple-300 border-purple-700/50 text-xs font-sans">
                            {r.mitre}
                          </Badge>
                        </div>
                        <div className="col-span-1 text-center">
                          <span className="text-xs font-bold text-foreground font-mono">{r.count}</span>
                        </div>
                        <div className="col-span-2 font-sans">
                          <Badge className={`text-xs ${RISK_COLORS[r.risk]}`}>{r.risk}</Badge>
                        </div>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </div>
              </ScrollArea>
            </div>
          )}

          {hasSearched && results.length === 0 && (
            <div className="glass rounded-lg border border-green-700/30 bg-green-900/10 p-8 text-center font-mono">
              <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-3" />
              <p className="text-sm text-green-400 font-medium">System Telemetry Nominal</p>
              <p className="text-xs text-muted-foreground mt-1">No indicators matching &apos;{searchQuery}&apos; detected on this host.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
