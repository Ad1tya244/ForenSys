'use client';

import { useState, useEffect, useRef } from 'react';
import { GitBranch, Search, Filter, ChevronDown, ChevronRight } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { motion, AnimatePresence } from 'framer-motion';

const LOG_SOURCES = ['syslog', 'auth', 'firewall', 'endpoint', 'network', 'application'];
const LOG_LEVELS = ['INFO', 'WARN', 'ERROR', 'CRITICAL', 'DEBUG'];
const LOG_HOSTS = ['WEBSERVER-01', 'DBSERVER-02', 'WORKSTATION-43', 'DOMAIN-CONTROLLER', 'VPNGATEWAY-01', 'MAILSERVER-01'];

interface LogEntry {
  id: string;
  timestamp: Date;
  level: string;
  source: string;
  host: string;
  message: string;
  details?: Record<string, string>;
}

function generateLog(): LogEntry {
  const level = LOG_LEVELS[Math.floor(Math.random() * LOG_LEVELS.length)];
  const source = LOG_SOURCES[Math.floor(Math.random() * LOG_SOURCES.length)];
  const host = LOG_HOSTS[Math.floor(Math.random() * LOG_HOSTS.length)];

  const messages: Record<string, string[]> = {
    syslog: ['System startup', 'Process crashed: httpd', 'Memory pressure high', 'Disk usage 89%'],
    auth: ['User login: john.smith', 'Failed auth attempt from 185.220.101.45', 'sudo: john.smith executed command', 'SSH key accepted'],
    firewall: ['BLOCK: inbound 185.220.101.45:4444', 'ALLOW: 10.0.1.45:443 → WEBSERVER-01', 'BLOCK: outbound suspicious domain', 'NAT translation table full'],
    endpoint: ['Process created: cmd.exe', 'Registry write: HKLM\\Run', 'File created in temp dir', 'Network connection to external IP'],
    network: ['TCP SYN flood detected', 'DNS query for unknown domain', 'Lateral movement pattern', 'Port scan from 10.0.1.99'],
    application: ['HTTP 500 error burst', 'DB connection timeout', 'Cache miss ratio 94%', 'API rate limit exceeded'],
  };

  const msgArr = messages[source] || ['Unknown event'];
  const message = msgArr[Math.floor(Math.random() * msgArr.length)];

  return {
    id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date(),
    level,
    source,
    host,
    message,
    details: {
      pid: String(Math.floor(Math.random() * 50000) + 1000),
      user: ['root', 'john.smith', 'SYSTEM', 'svchost'][Math.floor(Math.random() * 4)],
      event_id: String(Math.floor(Math.random() * 9000) + 1000),
    },
  };
}

const LEVEL_COLORS: Record<string, string> = {
  INFO: 'text-blue-400 bg-blue-900/20 border-blue-700/40',
  WARN: 'text-yellow-400 bg-yellow-900/20 border-yellow-700/40',
  ERROR: 'text-red-400 bg-red-900/20 border-red-700/40',
  CRITICAL: 'text-red-300 bg-red-900/40 border-red-600/60',
  DEBUG: 'text-gray-400 bg-gray-900/20 border-gray-700/40',
};

const LEVEL_TEXT: Record<string, string> = {
  INFO: 'text-blue-400',
  WARN: 'text-yellow-400',
  ERROR: 'text-red-400',
  CRITICAL: 'text-red-300',
  DEBUG: 'text-gray-500',
};

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>(() =>
    Array.from({ length: 40 }, generateLog).map((l, i) => ({
      ...l,
      timestamp: new Date(Date.now() - i * 12000),
    })).reverse()
  );
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (paused) return;
    const interval = setInterval(() => {
      setLogs((prev) => {
        const newLog = generateLog();
        return [...prev.slice(-99), newLog];
      });
    }, 1500);
    return () => clearInterval(interval);
  }, [paused]);

  const filtered = logs.filter((log) => {
    if (levelFilter !== 'all' && log.level !== levelFilter) return false;
    if (sourceFilter !== 'all' && log.source !== sourceFilter) return false;
    if (search && !log.message.toLowerCase().includes(search.toLowerCase()) && !log.host.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  }).slice().reverse();

  return (
    <div className="flex-1 overflow-auto p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <GitBranch className="w-6 h-6 text-accent" />
            Log Explorer
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Real-time log stream from all monitored systems</p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${paused ? 'bg-yellow-500' : 'bg-accent animate-pulse'}`} />
          <span className={`text-xs font-mono ${paused ? 'text-yellow-400' : 'text-accent'}`}>
            {paused ? 'PAUSED' : 'LIVE'}
          </span>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs border-border/50"
            onClick={() => setPaused(!paused)}
          >
            {paused ? 'Resume' : 'Pause'}
          </Button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="flex gap-3 flex-wrap">
        {LOG_LEVELS.map((level) => {
          const count = logs.filter((l) => l.level === level).length;
          return (
            <button
              key={level}
              onClick={() => setLevelFilter(levelFilter === level ? 'all' : level)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs transition-all ${
                levelFilter === level
                  ? LEVEL_COLORS[level]
                  : 'border-border/50 text-muted-foreground hover:text-foreground'
              }`}
            >
              <span>{level}</span>
              <span className="font-mono font-bold">{count}</span>
            </button>
          );
        })}
        <span className="ml-auto text-xs text-muted-foreground self-center font-mono">
          {filtered.length} / {logs.length} entries
        </span>
      </div>

      {/* Filters */}
      <div className="glass rounded-lg p-3 border border-border/50 flex flex-col sm:flex-row gap-3">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
          <Input
            placeholder="Search messages, hosts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9 bg-input border-border/50 text-sm h-9 font-mono"
          />
        </div>
        <div className="flex gap-2">
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1 h-9"
          >
            <option value="all">All Sources</option>
            {LOG_SOURCES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Log Table */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden">
        {/* Table Header */}
        <div className="grid grid-cols-12 gap-2 px-4 py-2 border-b border-border/50 text-xs text-muted-foreground font-medium bg-card/60 sticky top-0">
          <div className="col-span-2">Timestamp</div>
          <div className="col-span-1">Level</div>
          <div className="col-span-2">Source</div>
          <div className="col-span-2">Host</div>
          <div className="col-span-4">Message</div>
          <div className="col-span-1"></div>
        </div>
        <ScrollArea className="h-[calc(100vh-440px)] min-h-64">
          <div>
            <AnimatePresence initial={false}>
              {filtered.map((log) => (
                <motion.div
                  key={log.id}
                  initial={{ opacity: 0, backgroundColor: 'rgba(0,200,255,0.08)' }}
                  animate={{ opacity: 1, backgroundColor: 'rgba(0,0,0,0)' }}
                  transition={{ duration: 0.8 }}
                  className="border-b border-border/20 hover:bg-card/50 transition-colors"
                >
                  <div
                    className="grid grid-cols-12 gap-2 px-4 py-2 cursor-pointer items-center"
                    onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                  >
                    <div className="col-span-2 text-xs font-mono text-muted-foreground">
                      {log.timestamp.toLocaleTimeString('en', { hour12: false })}
                    </div>
                    <div className="col-span-1">
                      <span className={`text-xs font-bold font-mono ${LEVEL_TEXT[log.level]}`}>
                        {log.level}
                      </span>
                    </div>
                    <div className="col-span-2">
                      <Badge variant="outline" className="text-xs border-border/40 font-mono">{log.source}</Badge>
                    </div>
                    <div className="col-span-2 text-xs font-mono text-foreground/80 truncate">{log.host}</div>
                    <div className="col-span-4 text-xs text-foreground truncate">{log.message}</div>
                    <div className="col-span-1 flex justify-end">
                      {expanded === log.id
                        ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
                        : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
                    </div>
                  </div>

                  {/* Expanded Details */}
                  <AnimatePresence>
                    {expanded === log.id && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden border-t border-border/20 bg-black/30"
                      >
                        <div className="px-4 py-3 grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                          {log.details && Object.entries(log.details).map(([k, v]) => (
                            <div key={k}>
                              <span className="text-muted-foreground font-medium">{k}: </span>
                              <span className="font-mono text-accent/80">{v}</span>
                            </div>
                          ))}
                          <div>
                            <span className="text-muted-foreground font-medium">timestamp: </span>
                            <span className="font-mono text-accent/80">{log.timestamp.toISOString()}</span>
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              ))}
            </AnimatePresence>
            <div ref={bottomRef} />
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}
