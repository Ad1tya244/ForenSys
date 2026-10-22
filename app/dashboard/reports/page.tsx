'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { FileText, Download, Eye, RefreshCw, Search, Shield, CalendarRange, FileSearch, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { useAppStore } from '@/lib/app-store';
import {
  fetchIncidentLedger, fetchIncidentReportPdf, fetchSummaryReportPdf, saveBlob, IncidentLedgerRecord,
} from '@/lib/api-client';
import { AccessDenied } from '@/components/rbac/access-denied';
import { formatDuration } from '@/lib/format';
import { toast } from 'sonner';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-900/30 text-red-300 border-red-700/50',
  high: 'bg-orange-900/30 text-orange-300 border-orange-700/50',
  medium: 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50',
  low: 'bg-blue-900/30 text-blue-300 border-blue-700/50',
};

const ATTACK_LABELS: Record<string, string> = {
  port_scan: 'Port Scan', icmp_flood: 'ICMP Flood', syn_flood: 'SYN Flood', brute_force: 'Brute Force',
  auth_attack: 'Auth Attack', dns_beacon: 'DNS Beaconing', reverse_shell: 'Reverse Shell', data_exfil: 'Data Exfiltration',
  suspicious_listener: 'Suspicious Listener', process_chain: 'Process Chain',
};

const isoDay = (d: Date) => d.toISOString().split('T')[0];

interface PreviewState {
  url: string;
  title: string;
  filename: string;
  blob: Blob;
}

export default function ReportsPage() {
  const { hasPermission, correlatedIncidents, remediationHistory } = useAppStore();
  const [records, setRecords] = useState<IncidentLedgerRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('all');
  const [busy, setBusy] = useState<string | null>(null);
  const [preview, setPreview] = useState<PreviewState | null>(null);
  const [startDate, setStartDate] = useState(() => isoDay(new Date(Date.now() - 6 * 86400_000)));
  const [endDate, setEndDate] = useState(() => isoDay(new Date()));

  const canViewIncidents = hasPermission('view_incidents');
  const canExportIncident = hasPermission('view_forensics');
  const canSummary = hasPermission('view_analytics');

  const load = useCallback(async () => {
    if (!canViewIncidents) return;
    try {
      setRecords(await fetchIncidentLedger());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [canViewIncidents]);

  // New incidents appear without a manual refresh: reload when the live stream reports a change, and on a slow timer.
  useEffect(() => { load(); }, [load, correlatedIncidents.length, remediationHistory.length]);
  useEffect(() => {
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => () => { if (preview) URL.revokeObjectURL(preview.url); }, [preview]);

  const filtered = useMemo(() => records.filter((r) => {
    if (severity !== 'all' && r.severity !== severity) return false;
    const q = search.trim().toLowerCase();
    if (!q) return true;
    return [r.id, r.title, ...(r.attacker_ips || []), ...(r.attack_types || [])].some((v) => String(v).toLowerCase().includes(q));
  }), [records, search, severity]);

  const run = async (key: string, task: () => Promise<{ blob: Blob; filename: string }>, mode: 'download' | 'preview', title: string) => {
    setBusy(`${key}:${mode}`);
    try {
      const { blob, filename } = await task();
      if (mode === 'download') {
        saveBlob(blob, filename);
        toast.success('Report downloaded', { description: filename });
      } else {
        setPreview({ url: URL.createObjectURL(blob), title, filename, blob });
      }
    } catch (err: any) {
      toast.error('Could not generate report', { description: err.message || 'Unexpected error' });
    } finally {
      setBusy(null);
    }
  };

  const incidentReport = (r: IncidentLedgerRecord, mode: 'download' | 'preview') =>
    run(r.id, () => fetchIncidentReportPdf(r.id), mode, `${r.id} - ${r.title}`);
  const summaryReport = (mode: 'download' | 'preview') =>
    run('summary', () => fetchSummaryReportPdf(startDate, endDate), mode, `SOC Summary ${startDate} to ${endDate}`);

  if (!canViewIncidents) {
    return <AccessDenied permission="view_incidents" />;
  }

  const spinner = (key: string) => busy === key && <Loader2 className="w-3 h-3 animate-spin" />;

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <FileText className="w-6 h-6 text-accent" />
            Reports
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Download a full PDF for any incident - timeline, detections, attack forensics, containment, sealed evidence and logs
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5 h-8 text-xs self-start">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {/* Summary report */}
      <div className="glass rounded-lg border border-border/50 p-4 flex flex-col lg:flex-row lg:items-end gap-4">
        <div className="flex-1">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <CalendarRange className="w-4 h-4 text-accent" /> SOC Summary Report
          </h2>
          <p className="text-xs text-muted-foreground mt-1">
            Incidents for a date range with MTTD / MTTR (mean, median, p95), breakdowns by attack type, daily trend, top attackers and
            the full incident register.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input type="date" value={startDate} max={endDate} onChange={(e) => setStartDate(e.target.value)}
            className="bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1.5 h-8" />
          <span className="text-xs text-muted-foreground">to</span>
          <input type="date" value={endDate} min={startDate} max={isoDay(new Date())} onChange={(e) => setEndDate(e.target.value)}
            className="bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1.5 h-8" />
          <Button size="sm" variant="outline" disabled={!canSummary || busy !== null} onClick={() => summaryReport('preview')} className="h-8 text-xs gap-1.5">
            {spinner('summary:preview') || <Eye className="w-3.5 h-3.5" />} Preview
          </Button>
          <Button size="sm" disabled={!canSummary || busy !== null} onClick={() => summaryReport('download')}
            className="h-8 text-xs gap-1.5 bg-accent hover:bg-accent/90 text-accent-foreground">
            {spinner('summary:download') || <Download className="w-3.5 h-3.5" />} Download PDF
          </Button>
        </div>
      </div>

      {/* Incident reports */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden">
        <div className="p-4 border-b border-border/50 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Shield className="w-4 h-4 text-accent" /> Incident Reports
            <Badge className="bg-accent/15 text-accent border-accent/30 text-[10px]">{filtered.length} of {records.length}</Badge>
          </h2>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-muted-foreground" />
              <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search ID, title, attacker IP..."
                className="pl-8 h-8 w-64 bg-black/40 border-border/50 text-xs" />
            </div>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}
              className="bg-black/60 border border-border/50 rounded px-2 h-8 text-xs text-foreground focus:outline-none focus:border-accent">
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        <ScrollArea className="h-130 w-full">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-border/50 bg-black/40 text-[11px] font-mono text-muted-foreground uppercase tracking-wider">
                <th className="p-3">Incident</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Status</th>
                <th className="p-3">Detected</th>
                <th className="p-3 text-right" title="Time from first attacker activity to detection">MTTD</th>
                <th className="p-3 text-right" title="Time from detection to containment">MTTR</th>
                <th className="p-3">Evidence</th>
                <th className="p-3 text-right">Report</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/20">
              {filtered.map((r) => (
                <tr key={r.id} className="hover:bg-white/5 transition-colors">
                  <td className="p-3 max-w-md">
                    <div className="font-mono font-bold text-accent">{r.id}</div>
                    <div className="text-foreground truncate" title={r.title}>{r.title}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">
                      {(r.attack_types || []).map((t) => ATTACK_LABELS[t] || t).join(', ') || 'n/a'}
                      {r.attacker_ips?.length ? ` · ${r.attacker_ips.join(', ')}` : ''}
                    </div>
                  </td>
                  <td className="p-3">
                    <Badge className={`${SEVERITY_STYLES[r.severity] || SEVERITY_STYLES.low} text-[10px] uppercase`}>{r.severity}</Badge>
                  </td>
                  <td className="p-3">
                    <Badge className={r.contained
                      ? 'bg-green-950/40 text-green-400 border-green-800/50 text-[10px] uppercase'
                      : 'bg-yellow-950/40 text-yellow-300 border-yellow-800/50 text-[10px] uppercase'}>
                      {r.contained ? 'contained' : r.status}
                    </Badge>
                  </td>
                  <td className="p-3 font-mono text-muted-foreground whitespace-nowrap">
                    {r.detected_at ? new Date(r.detected_at).toLocaleString() : 'n/a'}
                  </td>
                  <td className="p-3 text-right font-mono text-foreground">{formatDuration(r.mttd_sec)}</td>
                  <td className="p-3 text-right font-mono text-foreground">{r.contained ? formatDuration(r.mttr_sec) : 'n/a'}</td>
                  <td className="p-3">
                    {r.has_evidence
                      ? <span className="text-emerald-400 font-mono text-[11px]">{r.evidence_id}</span>
                      : <span className="text-muted-foreground">none on file</span>}
                  </td>
                  <td className="p-3 text-right whitespace-nowrap">
                    <div className="flex justify-end gap-1.5">
                      <Button size="sm" variant="outline" disabled={!canExportIncident || busy !== null} onClick={() => incidentReport(r, 'preview')}
                        title={canExportIncident ? 'Preview the PDF' : 'Requires the view_forensics permission'} className="h-7 text-[11px] gap-1">
                        {spinner(`${r.id}:preview`) || <Eye className="w-3 h-3" />} Preview
                      </Button>
                      <Button size="sm" disabled={!canExportIncident || busy !== null} onClick={() => incidentReport(r, 'download')}
                        title={canExportIncident ? 'Download the PDF' : 'Requires the view_forensics permission'}
                        className="h-7 text-[11px] gap-1 bg-accent hover:bg-accent/90 text-accent-foreground">
                        {spinner(`${r.id}:download`) || <Download className="w-3 h-3" />} PDF
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
              {!loading && filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-16 text-center text-xs text-muted-foreground">
                    <FileSearch className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    {records.length === 0
                      ? 'No incidents on file yet. They appear here automatically as soon as ForenSys detects an attack.'
                      : 'No incidents match the current filters.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </ScrollArea>
      </div>

      {/* PDF preview */}
      <Dialog open={preview !== null} onOpenChange={(open) => { if (!open) setPreview(null); }}>
        <DialogContent className="sm:max-w-5xl w-[95vw] h-[90vh] flex flex-col gap-3">
          <DialogHeader>
            <DialogTitle className="text-sm">{preview?.title}</DialogTitle>
            <DialogDescription className="text-xs">{preview?.filename}</DialogDescription>
          </DialogHeader>
          {preview && <iframe src={preview.url} title={preview.title} className="flex-1 w-full rounded border border-border/50 bg-white" />}
          <div className="flex justify-end">
            <Button size="sm" onClick={() => preview && saveBlob(preview.blob, preview.filename)}
              className="gap-1.5 bg-accent hover:bg-accent/90 text-accent-foreground">
              <Download className="w-3.5 h-3.5" /> Download PDF
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
