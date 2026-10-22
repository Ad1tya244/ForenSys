'use client';

import { useState, useEffect } from 'react';
import { Zap, Shield, RotateCcw, CheckCircle, AlertTriangle, Filter, Search, Trash2, ShieldOff } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { useAppStore } from '@/lib/app-store';

const ACTION_LABELS: Record<string, string> = {
  block_ip: 'Perimeter Block (IP)',
  add_pf_rule: 'Perimeter Block (IP)',
  sinkhole_domain: 'DNS Sinkhole (Domain)',
  quarantine_process: 'Process Contained (simulated)',
  kill_process: 'Process Contained (simulated)',
  capture_forensics: 'Forensic Evidence Sealed',
  capture_pcap: 'PCAP Saved',
  notify_analyst: 'Analyst Notified',
};

export default function AutoRemediationHistoryPage() {
  const { remediationHistory, blockedIps, rollbackRemediationAction, clearHistoryAction, resetLabAction } = useAppStore();
  const [mounted, setMounted] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  useEffect(() => {
    setMounted(true);
  }, []);

  const autoLogs = remediationHistory.filter(
    (log) => log.incidentId !== 'MANUAL' && log.ruleName !== 'Manual Perimeter Block'
  );

  const filteredLogs = autoLogs.filter((log) => {
    const matchesSearch =
      log.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.ruleName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.incidentId.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || log.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const activeCount = autoLogs.filter((l) => l.status === 'success').length;
  const rolledBackCount = autoLogs.filter((l) => l.status === 'rolled_back').length;
  const skippedCount = autoLogs.filter((l) => l.status === 'skipped').length;

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
            title="Clears this audit log only. Active containment (blocked IPs/domains, quarantined processes) is left exactly as it is."
            className="h-7 text-xs border-border/50 text-muted-foreground hover:bg-white/5 gap-1 font-sans ml-2"
            onClick={() => clearHistoryAction()}
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear History
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                size="sm"
                variant="outline"
                title="Clears history, alerts, incidents and evidence, and unblocks every contained IP/domain/process."
                className="h-7 text-xs border-red-500/40 text-red-400 hover:bg-red-500/20 gap-1 font-sans"
              >
                <ShieldOff className="w-3.5 h-3.5" /> Reset Lab
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Reset the full lab state?</AlertDialogTitle>
                <AlertDialogDescription>
                  This clears all alerts, incidents, forensic evidence, the remediation history and the MTTD/MTTR analytics, and{' '}
                  <span className="text-red-400 font-semibold">unblocks every currently contained IP, domain and process</span>
                  {blockedIps.length > 0 && <> ({blockedIps.length} IP{blockedIps.length === 1 ? '' : 's'} currently blocked)</>}.
                  Use this between demo runs, not for routine log cleanup &mdash; that's what{' '}
                  <span className="text-foreground font-semibold">Clear History</span> is for.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  className="bg-red-600 hover:bg-red-700 text-white"
                  onClick={() => resetLabAction()}
                >
                  Reset Everything
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
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
        <div className="glass p-4 rounded-lg border border-cyan-500/30">
          <p className="text-xs text-cyan-400">Self-Protection Safeguards</p>
          <p className="text-2xl font-bold text-cyan-300 mt-1 font-mono">{skippedCount}</p>
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
                <th className="p-3">Threat Detected</th>
                <th className="p-3">Attacker IP (Source)</th>
                <th className="p-3">Affected Target</th>
                <th className="p-3">Remediation Executed</th>
                <th className="p-3">Detected Time</th>
                <th className="p-3">Remediated Time</th>
                <th className="p-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/20 font-mono text-xs">
              {filteredLogs.map((log, idx) => {
                const fmt = (t: string) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                const detectedTime = fmt(log.resultDetails?.detected_at || log.timestamp);
                const remediatedTime = fmt(log.timestamp);
                const attackerIp = log.resultDetails?.attacker_ip || (['block_ip', 'add_pf_rule'].includes(log.actionType) ? log.target : log.src_ip) || log.target || 'Remote IP';
                const affectedTarget = log.affectedTarget || log.affected_assets?.[0] || log.dst_ip || 'Local Host';

                return (
                  <tr key={`${log.id}-${idx}`} className="hover:bg-white/5 transition-colors">
                    <td className="p-3 font-bold text-accent">{log.id}</td>
                    <td className="p-3 text-foreground font-medium truncate max-w-xs" title={log.resultDetails?.message}>{log.ruleName || 'Detection'}</td>
                    <td className="p-3 text-red-400 font-semibold">{attackerIp}</td>
                    <td className="p-3 text-foreground font-semibold">{affectedTarget}</td>
                    <td className="p-3">
                      <Badge className="bg-cyan-950/50 text-cyan-300 border-cyan-800/40 text-[10px]">
                        {ACTION_LABELS[log.actionType] || log.actionType}
                      </Badge>
                    </td>
                    <td className="p-3 text-muted-foreground">{detectedTime}</td>
                    <td className="p-3 text-emerald-400">{remediatedTime}</td>
                    <td className="p-3 text-right">
                      <Badge
                        className={
                          log.status === 'success'
                            ? 'bg-green-950/40 text-green-400 border-green-800/50 text-[10px]'
                            : 'bg-blue-950/40 text-blue-300 border-blue-800/50 text-[10px]'
                        }
                      >
                        {log.status === 'success' ? 'CONTAINED' : log.status === 'rolled_back' ? 'ROLLED BACK' : log.status === 'skipped' ? 'SKIPPED' : 'EXECUTED'}
                      </Badge>
                    </td>
                  </tr>
                );
              })}
              {filteredLogs.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-16 text-center text-xs text-muted-foreground font-mono">
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
