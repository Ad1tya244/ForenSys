'use client';

import { useState, useEffect, useRef } from 'react';
import { GitBranch, Search, Filter, ChevronDown, ChevronRight, Pause, Play } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppStore, LogEntry } from '@/lib/app-store';

const LEVEL_COLORS: Record<string, string> = {
  info: 'text-blue-400 bg-blue-900/20 border-blue-700/40',
  warn: 'text-yellow-400 bg-yellow-900/20 border-yellow-700/40',
  error: 'text-red-400 bg-red-900/20 border-red-700/40',
};

const LEVEL_TEXT: Record<string, string> = {
  info: 'text-blue-400',
  warn: 'text-yellow-400',
  error: 'text-red-400',
};

export default function LogsPage() {
  const storeLogs = useAppStore((state) => state.logs);
  const [displayLogs, setDisplayLogs] = useState<LogEntry[]>([]);
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState('all');
  const [processFilter, setProcessFilter] = useState('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const [mounted, setMounted] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Update displayed logs from store, respecting pause
  useEffect(() => {
    if (!paused) {
      setDisplayLogs(storeLogs);
    }
  }, [storeLogs, paused]);

  if (!mounted) return null;

  // Extract unique process list
  const processes = Array.from(new Set(displayLogs.map((l) => l.process))).sort();

  const filtered = displayLogs.filter((log) => {
    if (levelFilter !== 'all' && log.level !== levelFilter) return false;
    if (processFilter !== 'all' && log.process !== processFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const inMsg = log.message.toLowerCase().includes(q);
      const inProc = log.process.toLowerCase().includes(q);
      const inSrc = log.source.toLowerCase().includes(q);
      if (!inMsg && !inProc && !inSrc) return false;
    }
    return true;
  });

  return (
    <div className="flex-1 overflow-auto p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <GitBranch className="w-6 h-6 text-accent" />
            Host Log Stream
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Real-time local system and security logs</p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${paused ? 'bg-yellow-500' : 'bg-accent animate-pulse'}`} />
          <span className={`text-xs font-mono ${paused ? 'text-yellow-400' : 'text-accent'}`}>
            {paused ? 'PAUSED' : 'LIVE'}
          </span>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs border-border/50 gap-1"
            onClick={() => setPaused(!paused)}
          >
            {paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
            {paused ? 'Resume' : 'Pause'}
          </Button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="flex gap-1.5 flex-wrap">
        <button
          onClick={() => setLevelFilter('all')}
          className={`h-7 px-3 rounded-full text-xs font-medium border transition-all duration-200 hover:scale-[1.01] active:scale-[0.97] ${
            levelFilter === 'all'
              ? 'bg-accent/20 text-accent border-accent/50'
              : 'bg-transparent border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
          }`}
        >
          All <span className="ml-1 opacity-60 font-mono text-[10px]">{displayLogs.length}</span>
        </button>
        {['info', 'warn', 'error'].map((level) => {
          const count = displayLogs.filter((l) => l.level === level).length;
          const isActive = levelFilter === level;
          const colorClasses = {
            info: 'bg-blue-900/20 border-blue-700/40 text-blue-400',
            warn: 'bg-yellow-900/20 border-yellow-700/40 text-yellow-400',
            error: 'bg-red-900/20 border-red-700/40 text-red-400',
          };
          return (
            <button
              key={level}
              onClick={() => setLevelFilter(isActive ? 'all' : level)}
              className={`h-7 px-3 rounded-full text-xs font-medium border transition-all duration-200 hover:scale-[1.01] active:scale-[0.97] ${
                isActive
                  ? colorClasses[level as keyof typeof colorClasses]
                  : 'bg-transparent border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              <span className="uppercase">{level}</span>
              <span className="ml-1 opacity-60 font-mono text-[10px]">{count}</span>
            </button>
          );
        })}
        <span className="ml-auto text-xs text-muted-foreground self-center font-mono">
          {filtered.length} / {displayLogs.length} entries
        </span>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
          <Input
            placeholder="Search messages, source files, processes..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9 bg-input border-border/50 text-sm h-9 font-mono"
          />
        </div>
        <div className="flex gap-2">
          <select
            value={processFilter}
            onChange={(e) => setProcessFilter(e.target.value)}
            className="bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1 h-9"
          >
            <option value="all">All Processes</option>
            {processes.map((proc) => (
              <option key={proc} value={proc}>{proc}</option>
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
          <div className="col-span-2">Process</div>
          <div className="col-span-2">Source Log</div>
          <div className="col-span-4">Message</div>
          <div className="col-span-1"></div>
        </div>
        <ScrollArea className="h-[calc(100vh-440px)] min-h-64">
          <div className="divide-y divide-border/10">
            {filtered.map((log) => (
              <div
                key={log.id}
                className="hover:bg-card/50 transition-colors border-b border-border/10"
              >
                <div
                  className="grid grid-cols-12 gap-2 px-4 py-2 cursor-pointer items-center"
                  onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                >
                  <div className="col-span-2 text-xs font-mono text-muted-foreground truncate">
                    {log.timestamp ? new Date(log.timestamp).toLocaleString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : 'N/A'}
                  </div>
                  <div className="col-span-1">
                    <span className={`text-xs font-bold font-mono ${LEVEL_TEXT[log.level]}`}>
                      {log.level.toUpperCase()}
                    </span>
                  </div>
                  <div className="col-span-2 text-xs font-mono text-foreground/80 truncate">
                    {log.process}
                  </div>
                  <div className="col-span-2">
                    <Badge variant="outline" className="text-[10px] py-0 border-border/40 font-mono truncate max-w-full">
                      {log.source}
                    </Badge>
                  </div>
                  <div className="col-span-4 text-xs text-foreground font-mono truncate">{log.message}</div>
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
                      <div className="px-4 py-3 text-xs space-y-2">
                        <div>
                          <span className="text-muted-foreground font-medium">Log Line ID: </span>
                          <span className="font-mono text-accent/80">{log.id}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground font-medium">Full Message: </span>
                          <span className="font-mono text-foreground whitespace-pre-wrap">{log.message}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground font-medium font-mono">Category: </span>
                          <span className="font-mono text-yellow-300">{log.category || 'N/A'}</span>
                        </div>
                        {log.timestamp && (
                          <div>
                            <span className="text-muted-foreground font-medium">ISO Timestamp: </span>
                            <span className="font-mono text-accent/80">{new Date(log.timestamp).toISOString()}</span>
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}
            {filtered.length === 0 && (
              <div className="py-12 text-center text-muted-foreground text-sm font-mono">[NO LOG ENTRIES FOUND]</div>
            )}
            <div ref={bottomRef} />
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}
