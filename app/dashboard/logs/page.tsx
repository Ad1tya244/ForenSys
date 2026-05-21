'use client';

import { useState, useEffect, useRef } from 'react';
import { 
  GitBranch, Search, Filter, ChevronDown, ChevronRight, 
  Pause, Play, Download, Copy, Check, Sparkles, RefreshCw, 
  X, AlertTriangle, AlertCircle, Info, Terminal 
} from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppStore, LogEntry } from '@/lib/app-store';
import { useCopilotStore } from '@/lib/copilot-store';
import { toast } from 'sonner';

const LEVEL_COLORS: Record<string, string> = {
  info: 'text-blue-400 bg-blue-950/40 border-blue-800/40',
  warn: 'text-yellow-400 bg-yellow-950/40 border-yellow-800/40',
  error: 'text-red-400 bg-red-950/40 border-red-800/40',
};

const LEVEL_TEXT: Record<string, string> = {
  info: 'text-blue-400',
  warn: 'text-yellow-400',
  error: 'text-red-400',
};

const LEVEL_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  info: Info,
  warn: AlertTriangle,
  error: AlertCircle,
};

// Search Highlighting Helper
function HighlightedText({ text, search, isRegex }: { text: string; search: string; isRegex: boolean }) {
  if (!search) return <span>{text}</span>;
  
  try {
    let regex: RegExp;
    if (isRegex) {
      regex = new RegExp(`(${search})`, 'gi');
    } else {
      const escaped = search.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
      regex = new RegExp(`(${escaped})`, 'gi');
    }
    
    const parts = text.split(regex);
    return (
      <span>
        {parts.map((part, i) => 
          regex.test(part) ? (
            <mark key={i} className="bg-accent/30 text-accent font-bold px-0.5 rounded border border-accent/20">
              {part}
            </mark>
          ) : (
            part
          )
        )}
      </span>
    );
  } catch (e) {
    return <span>{text}</span>;
  }
}

export default function LogsPage() {
  const storeLogs = useAppStore((state) => state.logs);
  const [displayLogs, setDisplayLogs] = useState<LogEntry[]>([]);
  const [search, setSearch] = useState('');
  const [isRegex, setIsRegex] = useState(false);
  const [regexError, setRegexError] = useState(false);
  const [levelFilter, setLevelFilter] = useState('all');
  const [processFilter, setProcessFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [subsystemFilter, setSubsystemFilter] = useState('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const copilotStore = useCopilotStore();

  useEffect(() => {
    setMounted(true);
  }, []);

  // Update displayed logs from store, respecting pause
  useEffect(() => {
    if (!paused) {
      setDisplayLogs(storeLogs);
    }
  }, [storeLogs, paused]);

  // Regex validation check
  useEffect(() => {
    if (search && isRegex) {
      try {
        new RegExp(search, 'i');
        setRegexError(false);
      } catch (e) {
        setRegexError(true);
      }
    } else {
      setRegexError(false);
    }
  }, [search, isRegex]);

  if (!mounted) return null;

  // Extract unique filtering dimensions
  const processes = Array.from(new Set(displayLogs.map((l) => l.process))).sort();
  const categories = Array.from(new Set(displayLogs.map((l) => l.category || 'system'))).sort();
  const subsystems = Array.from(new Set(displayLogs.map((l) => l.subsystem || 'N/A'))).sort();

  // Filter computation
  const filtered = displayLogs.filter((log) => {
    if (levelFilter !== 'all' && log.level !== levelFilter) return false;
    if (processFilter !== 'all' && log.process !== processFilter) return false;
    if (categoryFilter !== 'all' && (log.category || 'system') !== categoryFilter) return false;
    if (subsystemFilter !== 'all' && (log.subsystem || 'N/A') !== subsystemFilter) return false;
    
    if (search && !regexError) {
      try {
        let matches = false;
        if (isRegex) {
          const rx = new RegExp(search, 'i');
          matches = rx.test(log.message) || rx.test(log.process) || rx.test(log.source) || rx.test(log.subsystem || '');
        } else {
          const q = search.toLowerCase();
          matches = log.message.toLowerCase().includes(q) || 
                    log.process.toLowerCase().includes(q) || 
                    log.source.toLowerCase().includes(q) ||
                    (log.subsystem || '').toLowerCase().includes(q);
        }
        if (!matches) return false;
      } catch (e) {
        return false;
      }
    }
    return true;
  });

  // Level breakdowns
  const totalCount = displayLogs.length;
  const infoCount = displayLogs.filter((l) => l.level === 'info').length;
  const warnCount = displayLogs.filter((l) => l.level === 'warn').length;
  const errorCount = displayLogs.filter((l) => l.level === 'error').length;
  
  // Find top process and category for diagnostics
  const processFrequency = displayLogs.reduce((acc, log) => {
    acc[log.process] = (acc[log.process] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  const topProcess = Object.entries(processFrequency).sort((a, b) => b[1] - a[1])[0]?.[0] || 'None';

  const categoryFrequency = displayLogs.reduce((acc, log) => {
    const cat = log.category || 'system';
    acc[cat] = (acc[cat] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  const topCategory = Object.entries(categoryFrequency).sort((a, b) => b[1] - a[1])[0]?.[0] || 'None';

  // Exporters
  const exportToCSV = () => {
    const headers = ['ID', 'Timestamp', 'Level', 'Process', 'PID', 'Subsystem', 'Category', 'Message', 'Source'];
    const rows = filtered.map(log => [
      log.id,
      log.timestamp || '',
      log.level.toUpperCase(),
      log.process,
      log.pid || '',
      log.subsystem || '',
      log.category || '',
      log.message,
      log.source
    ]);
    
    const csvString = [
      headers.join(','),
      ...rows.map(row => row.map(val => {
        const stringVal = String(val).replace(/"/g, '""');
        return `"${stringVal}"`;
      }).join(','))
    ].join('\n');

    const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `forensys_logs_${Date.now()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const exportToJSON = () => {
    const jsonString = JSON.stringify(filtered, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `forensys_logs_${Date.now()}.json`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleAISubmit = async (log: LogEntry) => {
    const query = `Analyze this security log entry for suspicious behavior:\n\n` +
      `Timestamp: ${log.timestamp}\n` +
      `Process: ${log.process} (PID: ${log.pid || 'N/A'})\n` +
      `Subsystem: ${log.subsystem || 'N/A'}\n` +
      `Category: ${log.category || 'N/A'}\n` +
      `Level: ${log.level.toUpperCase()}\n` +
      `Source: ${log.source}\n` +
      `Message: "${log.message}"`;
    await copilotStore.sendMessage(query);
  };

  const clearFilters = () => {
    setSearch('');
    setIsRegex(false);
    setLevelFilter('all');
    setProcessFilter('all');
    setCategoryFilter('all');
    setSubsystemFilter('all');
  };

  return (
    <div className="flex-1 overflow-auto p-5 space-y-4 cyber-grid">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <GitBranch className="w-6 h-6 text-accent" />
            Host Log Diagnostics
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">High-precision host security log collector & parser</p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${paused ? 'bg-yellow-500' : 'bg-accent animate-pulse'}`} />
          <span className={`text-xs font-mono font-bold ${paused ? 'text-yellow-400' : 'text-accent'}`}>
            {paused ? 'PAUSED' : 'LIVE'}
          </span>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs border-border/50 gap-1 bg-background/50 hover:bg-accent/10"
            onClick={() => setPaused(!paused)}
          >
            {paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
            {paused ? 'Resume' : 'Pause'}
          </Button>
        </div>
      </div>

      {/* Diagnostics Dashboard (Mini KPI Grid) */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="glass p-3 border border-border/40 rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground text-[10px] uppercase font-bold tracking-wider">
            <span>Total Streams</span>
            <Terminal className="w-3.5 h-3.5 text-accent" />
          </div>
          <div className="text-xl font-bold font-mono text-foreground mt-1.5">{totalCount}</div>
          <div className="text-[10px] text-muted-foreground mt-1 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
            Active OS listener
          </div>
        </div>

        <div className="glass p-3 border border-border/40 rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-red-400 text-[10px] uppercase font-bold tracking-wider">
            <span>Fault & Error Events</span>
            <AlertCircle className="w-3.5 h-3.5 text-red-500" />
          </div>
          <div className="text-xl font-bold font-mono text-red-400 mt-1.5">
            {errorCount}
            <span className="text-xs text-muted-foreground font-normal ml-1">
              ({totalCount > 0 ? ((errorCount / totalCount) * 100).toFixed(1) : 0}%)
            </span>
          </div>
          <div className="w-full bg-border/20 h-1 rounded-full overflow-hidden mt-1.5">
            <div className="bg-red-500 h-full rounded-full" style={{ width: `${totalCount > 0 ? (errorCount / totalCount) * 100 : 0}%` }} />
          </div>
        </div>

        <div className="glass p-3 border border-border/40 rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-yellow-400 text-[10px] uppercase font-bold tracking-wider">
            <span>Warning Events</span>
            <AlertTriangle className="w-3.5 h-3.5 text-yellow-500" />
          </div>
          <div className="text-xl font-bold font-mono text-yellow-400 mt-1.5">
            {warnCount}
            <span className="text-xs text-muted-foreground font-normal ml-1">
              ({totalCount > 0 ? ((warnCount / totalCount) * 100).toFixed(1) : 0}%)
            </span>
          </div>
          <div className="w-full bg-border/20 h-1 rounded-full overflow-hidden mt-1.5">
            <div className="bg-yellow-500 h-full rounded-full" style={{ width: `${totalCount > 0 ? (warnCount / totalCount) * 100 : 0}%` }} />
          </div>
        </div>

        <div className="glass p-3 border border-border/40 rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-blue-400 text-[10px] uppercase font-bold tracking-wider">
            <span>Noisy Process & Category</span>
            <Info className="w-3.5 h-3.5 text-blue-500" />
          </div>
          <div className="text-xs font-mono font-bold text-foreground mt-1 truncate">
            P: <span className="text-blue-400">{topProcess}</span>
          </div>
          <div className="text-xs font-mono font-bold text-foreground truncate">
            C: <span className="text-blue-400">{topCategory}</span>
          </div>
        </div>
      </div>

      {/* Visual Level Stacked Breakdown Bar */}
      {totalCount > 0 && (
        <div className="glass p-2 border border-border/40 rounded-lg space-y-1">
          <div className="flex justify-between text-[10px] text-muted-foreground font-mono">
            <span>LOG LEVEL DENSITY</span>
            <span>INFO: {infoCount} | WARN: {warnCount} | ERROR: {errorCount}</span>
          </div>
          <div className="h-2.5 rounded-full overflow-hidden flex bg-border/10">
            <div className="bg-blue-500 h-full transition-all duration-300" style={{ width: `${(infoCount / totalCount) * 100}%` }} title={`Info: ${infoCount}`} />
            <div className="bg-yellow-500 h-full transition-all duration-300" style={{ width: `${(warnCount / totalCount) * 100}%` }} title={`Warn: ${warnCount}`} />
            <div className="bg-red-500 h-full transition-all duration-300" style={{ width: `${(errorCount / totalCount) * 100}%` }} title={`Error: ${errorCount}`} />
          </div>
        </div>
      )}

      {/* Controls & Exporters */}
      <div className="flex flex-col space-y-3 md:space-y-0 md:flex-row md:items-center md:gap-3">
        {/* Search */}
        <div className="flex-1 relative flex items-center">
          <Search className="w-4 h-4 text-muted-foreground absolute left-3" />
          <Input
            placeholder="Search log messages, process name, subsystem, path..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className={`pl-9 pr-16 bg-input border-border/50 text-sm h-9 font-mono ${regexError ? 'border-red-500/80 focus-visible:ring-red-500' : ''}`}
          />
          <div className="absolute right-1 flex items-center gap-1">
            {search && (
              <button onClick={() => setSearch('')} className="p-1 hover:text-foreground text-muted-foreground transition-colors">
                <X className="w-3.5 h-3.5" />
              </button>
            )}
            <button
              onClick={() => setIsRegex(!isRegex)}
              className={`text-[10px] font-bold px-1.5 py-0.5 rounded border transition-colors ${
                isRegex 
                  ? 'bg-accent/20 text-accent border-accent/40' 
                  : 'bg-transparent text-muted-foreground border-border/40 hover:text-foreground'
              }`}
              title="Toggle Regex Match"
            >
              .*
            </button>
          </div>
        </div>

        {/* Dropdowns */}
        <div className="flex flex-wrap gap-2 items-center">
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1 h-9 font-mono"
          >
            <option value="all">All Levels</option>
            <option value="info">INFO</option>
            <option value="warn">WARN</option>
            <option value="error">ERROR</option>
          </select>

          <select
            value={processFilter}
            onChange={(e) => setProcessFilter(e.target.value)}
            className="bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1 h-9 max-w-40 font-mono"
          >
            <option value="all">All Processes</option>
            {processes.map((proc) => (
              <option key={proc} value={proc}>{proc}</option>
            ))}
          </select>

          <select
            value={subsystemFilter}
            onChange={(e) => setSubsystemFilter(e.target.value)}
            className="bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1 h-9 max-w-40 font-mono"
          >
            <option value="all">All Subsystems</option>
            {subsystems.map((sub) => (
              <option key={sub} value={sub}>{sub}</option>
            ))}
          </select>

          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1 h-9 max-w-40 font-mono"
          >
            <option value="all">All Categories</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>

          {/* Tools */}
          <Button
            size="sm"
            variant="outline"
            className="h-9 px-3 text-xs border-border/50 gap-1.5 bg-background/50 hover:bg-accent/10"
            onClick={clearFilters}
            title="Reset Filters"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>

          <div className="h-6 w-px bg-border/40 mx-1" />

          <Button
            size="sm"
            variant="outline"
            className="h-9 px-2.5 text-xs border-border/50 gap-1 bg-background/50 hover:bg-accent/10 font-mono"
            onClick={exportToCSV}
            title="Download CSV"
          >
            <Download className="w-3.5 h-3.5" />
            CSV
          </Button>

          <Button
            size="sm"
            variant="outline"
            className="h-9 px-2.5 text-xs border-border/50 gap-1 bg-background/50 hover:bg-accent/10 font-mono"
            onClick={exportToJSON}
            title="Download JSON"
          >
            <Download className="w-3.5 h-3.5" />
            JSON
          </Button>
        </div>
      </div>

      {regexError && (
        <p className="text-[10px] text-red-400 font-mono">Invalid Regular Expression syntax. Please check search parameters.</p>
      )}

      {/* Log Console Table */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden flex flex-col">
        {/* Table Header */}
        <div className="grid grid-cols-12 gap-3 px-4 py-2.5 border-b border-border/50 text-[10px] text-muted-foreground font-bold tracking-wider bg-card/60 uppercase sticky top-0 z-10">
          <div className="col-span-2">Timestamp</div>
          <div className="col-span-1">Level</div>
          <div className="col-span-2">Process (PID)</div>
          <div className="col-span-2">Subsystem</div>
          <div className="col-span-4">Message</div>
          <div className="col-span-1"></div>
        </div>

        {/* Scrollable Rows */}
        <ScrollArea className="h-[calc(100vh-420px)] min-h-[300px]">
          <div className="divide-y divide-border/10 font-mono">
            {filtered.map((log) => {
              const LogIcon = LEVEL_ICONS[log.level] || Info;
              return (
                <div
                  key={log.id}
                  className="hover:bg-card/40 transition-colors border-b border-border/5"
                >
                  <div
                    className="grid grid-cols-12 gap-3 px-4 py-2.5 cursor-pointer items-center text-xs"
                    onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                  >
                    {/* Timestamp */}
                    <div className="col-span-2 text-muted-foreground truncate">
                      {log.timestamp ? (
                        new Date(log.timestamp).toLocaleString('en', { 
                          month: 'short', day: 'numeric', 
                          hour: '2-digit', minute: '2-digit', second: '2-digit', 
                          fractionalSecondDigits: 3, hour12: false 
                        })
                      ) : 'N/A'}
                    </div>

                    {/* Level */}
                    <div className="col-span-1">
                      <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold border ${LEVEL_COLORS[log.level]}`}>
                        <LogIcon className="w-3 h-3" />
                        {log.level.toUpperCase()}
                      </span>
                    </div>

                    {/* Process (PID) */}
                    <div className="col-span-2 text-foreground/90 truncate flex items-center gap-1.5">
                      <span className="font-semibold text-accent/80">
                        <HighlightedText text={log.process} search={search} isRegex={isRegex} />
                      </span>
                      {log.pid ? (
                        <span className="text-[10px] text-muted-foreground bg-border/20 px-1 rounded font-normal">
                          {log.pid}
                        </span>
                      ) : null}
                    </div>

                    {/* Subsystem */}
                    <div className="col-span-2 text-muted-foreground truncate text-[11px]" title={log.subsystem || 'N/A'}>
                      <HighlightedText text={log.subsystem || 'N/A'} search={search} isRegex={isRegex} />
                    </div>

                    {/* Message Preview */}
                    <div className="col-span-4 text-foreground/80 truncate pr-2" title={log.message}>
                      <HighlightedText text={log.message} search={search} isRegex={isRegex} />
                    </div>

                    {/* Toggle Indicator */}
                    <div className="col-span-1 flex justify-end">
                      {expanded === log.id
                        ? <ChevronDown className="w-4 h-4 text-muted-foreground" />
                        : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
                    </div>
                  </div>

                  {/* Expanded Diagnostics Drawer */}
                  <AnimatePresence>
                    {expanded === log.id && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden border-t border-border/20 bg-black/40"
                      >
                        <div className="px-5 py-4 space-y-4 text-xs">
                          {/* Raw message block */}
                          <div className="space-y-1">
                            <span className="text-muted-foreground text-[10px] uppercase font-bold tracking-wide flex items-center gap-1">
                              <Terminal className="w-3 h-3 text-accent" /> Raw Log Message
                            </span>
                            <div className="p-3 rounded border border-border/30 bg-black/60 font-mono text-foreground whitespace-pre-wrap leading-relaxed select-text selection:bg-accent/40 selection:text-white">
                              <HighlightedText text={log.message} search={search} isRegex={isRegex} />
                            </div>
                          </div>

                          {/* Metadata grid */}
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border-t border-border/10 pt-3">
                            <div className="space-y-1.5">
                              <div>
                                <span className="text-muted-foreground">Log ID: </span>
                                <span className="font-mono text-foreground">{log.id}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Level: </span>
                                <span className={`font-mono font-bold capitalize ${LEVEL_TEXT[log.level]}`}>{log.level}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Category: </span>
                                <span className="font-mono text-yellow-300">{log.category || 'system'}</span>
                              </div>
                            </div>

                            <div className="space-y-1.5">
                              <div>
                                <span className="text-muted-foreground">Process: </span>
                                <span className="font-mono text-accent">{log.process}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">PID: </span>
                                <span className="font-mono text-foreground">{log.pid || 'N/A'}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Subsystem: </span>
                                <span className="font-mono text-purple-300">{log.subsystem || 'N/A'}</span>
                              </div>
                            </div>

                            <div className="space-y-1.5">
                              <div>
                                <span className="text-muted-foreground">Source Log: </span>
                                <span className="font-mono text-muted-foreground bg-border/20 px-1 py-0.5 rounded text-[10px]">{log.source}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">ISO Time: </span>
                                <span className="font-mono text-muted-foreground text-[10px]">{log.timestamp ? new Date(log.timestamp).toISOString() : 'N/A'}</span>
                              </div>
                            </div>
                          </div>

                          {/* Quick action buttons */}
                          <div className="flex flex-wrap gap-2 border-t border-border/10 pt-3.5">
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-8 text-xs border-border/40 gap-1 bg-background/30"
                              onClick={() => handleCopyText(log.message, `msg-${log.id}`)}
                            >
                              {copiedId === `msg-${log.id}` ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                              {copiedId === `msg-${log.id}` ? 'Copied' : 'Copy Message'}
                            </Button>

                            <Button
                              size="sm"
                              variant="outline"
                              className="h-8 text-xs border-border/40 gap-1 bg-background/30"
                              onClick={() => handleCopyText(JSON.stringify(log, null, 2), `json-${log.id}`)}
                            >
                              {copiedId === `json-${log.id}` ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                              {copiedId === `json-${log.id}` ? 'Copied' : 'Copy JSON'}
                            </Button>

                            <Button
                              size="sm"
                              variant="outline"
                              className="h-8 text-xs border-border/40 gap-1 bg-background/30 text-accent border-accent/30 hover:bg-accent/10"
                              onClick={() => {
                                setProcessFilter(log.process);
                                setExpanded(null);
                              }}
                            >
                              <Filter className="w-3.5 h-3.5" />
                              Filter Process
                            </Button>

                            <Button
                              size="sm"
                              variant="outline"
                              className="h-8 text-xs border-accent/40 gap-1 bg-accent/10 hover:bg-accent/20 text-accent font-semibold transition-all"
                              onClick={() => handleAISubmit(log)}
                            >
                              <Sparkles className="w-3.5 h-3.5" />
                              Analyze with Copilot
                            </Button>

                            <Button
                              size="sm"
                              variant="outline"
                              className="h-8 text-xs border-red-950/40 gap-1 bg-red-900/10 hover:bg-red-900/20 text-red-400 font-semibold transition-all"
                              onClick={() => {
                                useAppStore.getState().raiseIncidentAndCaptureForensics('log', log);
                                toast.success('Raised as Incident', {
                                  description: `Log entry from process ${log.process} has been escalated and captured in forensics.`
                                });
                              }}
                            >
                              <AlertTriangle className="w-3.5 h-3.5" />
                              Raise as Incident
                            </Button>
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
            {filtered.length === 0 && (
              <div className="py-16 text-center text-muted-foreground text-sm font-mono flex flex-col items-center justify-center gap-2">
                <Terminal className="w-8 h-8 opacity-25 animate-pulse" />
                [NO MATCHING LOG ENTRIES CONFIGURED]
              </div>
            )}
            <div ref={bottomRef} />
          </div>
        </ScrollArea>
      </div>
      <div className="text-right text-[10px] text-muted-foreground font-mono">
        Showing {filtered.length} of {displayLogs.length} live buffer logs
      </div>
    </div>
  );
}
