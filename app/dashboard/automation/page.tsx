'use client';

import { useState, useEffect } from 'react';
import { Zap, Shield, RotateCcw, CheckCircle, AlertTriangle, Filter, Search, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useAppStore } from '@/lib/app-store';

export default function AutoRemediationHistoryPage() {
  const { remediationHistory, rollbackRemediationAction, clearHistoryAction } = useAppStore();
  const [mounted, setMounted] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  useEffect(() => {
    setMounted(true);
  }, []);

  const filteredLogs = remediationHistory.filter((log) => {
    const matchesSearch =
      log.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.ruleName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.incidentId.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || log.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const activeCount = remediationHistory.filter((l) => l.status === 'success').length;
  const rolledBackCount = remediationHistory.filter((l) => l.status === 'rolled_back').length;
  const skippedCount = remediationHistory.filter((l) => l.status === 'skipped').length;

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Zap className="w-6 h-6 text-accent" />
            Auto Remediation History
          </h1>
          <p className="text-muted-foreground text-sm">
            Complete audit trail of automated EDR/SOAR containment actions and rollback statuses
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs">
          <Badge className="bg-green-950/60 text-green-300 border-green-700/50 px-3 py-1">
            {activeCount} Active Actions
          </Badge>
          <Badge className="bg-yellow-950/60 text-yellow-300 border-yellow-700/50 px-3 py-1">
            {rolledBackCount} Rolled Back
          </Badge>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs border-red-500/40 text-red-400 hover:bg-red-500/20 gap-1 font-sans ml-2"
            onClick={() => clearHistoryAction()}
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear History
          </Button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass p-4 rounded-lg border border-border/50">
          <p className="text-xs text-muted-foreground">Total Executed Actions</p>
          <p className="text-2xl font-bold text-foreground mt-1 font-mono">{remediationHistory.length}</p>
        </div>
        <div className="glass p-4 rounded-lg border border-green-500/30">
          <p className="text-xs text-green-400">Successful Containments</p>
          <p className="text-2xl font-bold text-green-300 mt-1 font-mono">{activeCount}</p>
        </div>
        <div className="glass p-4 rounded-lg border border-yellow-500/30">
          <p className="text-xs text-yellow-400">Rolled Back Actions</p>
          <p className="text-2xl font-bold text-yellow-300 mt-1 font-mono">{rolledBackCount}</p>
        </div>
        <div className="glass p-4 rounded-lg border border-blue-500/30">
          <p className="text-xs text-blue-400">Self-Protection Safeguards</p>
          <p className="text-2xl font-bold text-blue-300 mt-1 font-mono">{skippedCount}</p>
        </div>
      </div>

      {/* Controls Bar */}
      <div className="glass p-4 rounded-lg border border-border/50 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-muted-foreground" />
          <Input
            placeholder="Search by action ID, target IP, rule name, or incident ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 bg-black/40 border-border/50 text-xs"
          />
        </div>
        <div className="flex items-center gap-2 w-full md:w-auto">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-black/60 border border-border/50 rounded px-3 py-1.5 text-xs text-foreground focus:outline-none focus:border-accent"
          >
            <option value="all">All Statuses</option>
            <option value="success">Success</option>
            <option value="rolled_back">Rolled Back</option>
            <option value="skipped">Skipped (Self-Protection)</option>
          </select>
        </div>
      </div>

      {/* History Table */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden">
        <ScrollArea className="h-130 w-full">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-border/50 bg-black/40 text-[11px] font-mono text-muted-foreground uppercase tracking-wider">
                <th className="p-3">Action ID</th>
                <th className="p-3">Action Type</th>
                <th className="p-3">Target</th>
                <th className="p-3">Incident ID</th>
                <th className="p-3">Triggering Rule</th>
                <th className="p-3">Status</th>
                <th className="p-3 text-right">Controls</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/20 font-mono text-xs">
              {filteredLogs.map((log, idx) => (
                <tr key={`${log.id}-${idx}`} className="hover:bg-white/5 transition-colors">
                  <td className="p-3 font-bold text-accent">{log.id}</td>
                  <td className="p-3">
                    <Badge className="bg-purple-950/50 text-purple-300 border-purple-800/40 text-[10px]">
                      {log.actionType}
                    </Badge>
                  </td>
                  <td className="p-3 text-foreground font-semibold">{log.target}</td>
                  <td className="p-3 text-muted-foreground">{log.incidentId}</td>
                  <td className="p-3 text-muted-foreground truncate max-w-xs">{log.ruleName}</td>
                  <td className="p-3">
                    <Badge
                      className={
                        log.status === 'success'
                          ? 'bg-green-900/30 text-green-300 border-green-700/50 text-[10px]'
                          : log.status === 'rolled_back'
                          ? 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50 text-[10px]'
                          : 'bg-blue-900/30 text-blue-300 border-blue-700/50 text-[10px]'
                      }
                    >
                      {log.status.toUpperCase()}
                    </Badge>
                  </td>
                  <td className="p-3 text-right">
                    {log.status === 'success' && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-6 text-[10px] border-yellow-500/40 text-yellow-400 hover:bg-yellow-500/20 gap-1"
                        onClick={() => rollbackRemediationAction(log.id)}
                      >
                        <RotateCcw className="w-3 h-3" /> Rollback
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
              {filteredLogs.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-16 text-center text-xs text-muted-foreground font-mono">
                    [NO AUTO REMEDIATION ACTION LOGS FOUND]
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </ScrollArea>
      </div>
    </div>
  );
}
