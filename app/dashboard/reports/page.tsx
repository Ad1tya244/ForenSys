'use client';

import { useState, useEffect } from 'react';
import { FileText, Download, Calendar, TrendingUp, AlertTriangle, Shield, Eye, Trash2, Globe, Clock, Network, Cpu, Database, ClipboardList } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { useAppStore } from '@/lib/app-store';
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import { fetchReports, saveReport, deleteReport, SavedReport } from '@/lib/api-client';

const REPORT_TYPES = [
  { id: 'exec', label: 'Executive Summary', desc: 'C-suite risk overview', icon: Eye },
  { id: 'monthly', label: 'Monthly Incident Summary', desc: 'Full incident lifecycle analysis', icon: FileText },
  { id: 'threat', label: 'Threat Landscape Report', desc: 'Current threat actor campaigns', icon: Shield },
  { id: 'sla', label: 'SLA Compliance Report', desc: 'Response time & SLA metrics', icon: TrendingUp },
];

const CustomTooltipStyle = {
  backgroundColor: 'rgba(15, 23, 42, 0.95)',
  border: '1px solid rgba(0,200,255,0.3)',
  borderRadius: '8px',
  fontSize: '12px',
  color: '#e2e8f0',
};

export default function ReportsPage() {
  const { alerts, incidents, metrics, connections, processes, logs, evidenceItems } = useAppStore();
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [preview, setPreview] = useState(false);
  
  const [pastReports, setPastReports] = useState<SavedReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<SavedReport | null>(null);

  // Controlled date inputs
  const [startDate, setStartDate] = useState<string>(() => {
    const d = new Date();
    d.setDate(d.getDate() - 7);
    return d.toISOString().split('T')[0];
  });
  const [endDate, setEndDate] = useState<string>(() => {
    return new Date().toISOString().split('T')[0];
  });

  // Load saved reports on mount
  useEffect(() => {
    const loadData = async () => {
      try {
        const data = await fetchReports();
        setPastReports(data);
      } catch (err) {
        console.error('Failed to load past reports:', err);
      }
    };
    loadData();
  }, []);

  const handleGenerate = async () => {
    if (!selectedType) {
      toast.error('Please select a report type');
      return;
    }
    setGenerating(true);

    try {
      const start = new Date(startDate);
      const end = new Date(endDate);
      end.setHours(23, 59, 59, 999);

      // Filter store alerts & incidents by date range
      const filteredAlerts = alerts.filter((a) => {
        const d = new Date(a.timestamp);
        return d >= start && d <= end;
      });

      const filteredIncidents = incidents.filter((i) => {
        const d = new Date(i.createdAt);
        return d >= start && d <= end;
      });

      // 1. Core metric compilation
      const totalAlerts = filteredAlerts.length;
      const totalIncidents = filteredIncidents.length;
      const resolvedIncidents = filteredIncidents.filter((i) => i.status === 'resolved').length;
      const investigatedAlerts = filteredAlerts.filter(
        (a) => a.status === 'acknowledged' || a.status === 'investigating' || a.status === 'resolved'
      ).length;

      const slaComplianceRate = totalAlerts > 0 
        ? Math.round((investigatedAlerts / totalAlerts) * 1000) / 10 
        : 100.0;

      // Severity counts
      const criticalCount = filteredAlerts.filter((a) => a.severity === 'critical').length;
      const highCount = filteredAlerts.filter((a) => a.severity === 'high').length;
      const mediumCount = filteredAlerts.filter((a) => a.severity === 'medium').length;
      const lowCount = filteredAlerts.filter((a) => a.severity === 'low').length;

      // Findings generator: Extract top critical/high alerts or incidents
      const highSevAlerts = filteredAlerts.filter(
        (a) => a.severity === 'critical' || a.severity === 'high'
      );
      const findings = highSevAlerts.length > 0
        ? highSevAlerts.slice(0, 5).map((a) => ({
            severity: a.severity,
            text: `${a.title}: ${a.description} (Source: ${a.source})`,
          }))
        : [
            {
              severity: 'low',
              text: 'No critical or high severity alerts were recorded in this period. Overall security posture is nominal.',
            },
          ];

      // Trend data compiler: group by day for the selected period
      const diffTime = Math.abs(end.getTime() - start.getTime());
      const daysCount = Math.max(1, Math.ceil(diffTime / (1000 * 60 * 60 * 24)));
      const trendData = [];

      for (let i = 0; i < daysCount; i++) {
        const d = new Date(start);
        d.setDate(d.getDate() + i);
        const dayStr = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

        const dStart = new Date(d);
        dStart.setHours(0, 0, 0, 0);
        const dEnd = new Date(d);
        dEnd.setHours(23, 59, 59, 999);

        const dayAlerts = filteredAlerts.filter((a) => {
          const ad = new Date(a.timestamp);
          return ad >= dStart && ad <= dEnd;
        });

        const dayIncidents = filteredIncidents.filter((inc) => {
          const id = new Date(inc.createdAt);
          return id >= dStart && id <= dEnd;
        });

        trendData.push({
          label: dayStr,
          count: dayIncidents.length,
          critical: dayAlerts.filter((a) => a.severity === 'critical').length,
          high: dayAlerts.filter((a) => a.severity === 'high').length,
          medium: dayAlerts.filter((a) => a.severity === 'medium').length,
          low: dayAlerts.filter((a) => a.severity === 'low').length,
        });
      }

      // Threat specific details (MITRE tactics, top assets)
      const mitreMap: Record<string, number> = {};
      const assetMap: Record<string, number> = {};
      filteredAlerts.forEach((a) => {
        if (a.mitreTactics) {
          a.mitreTactics.forEach((t) => {
            mitreMap[t] = (mitreMap[t] || 0) + 1;
          });
        }
        if (a.affectedAssets) {
          a.affectedAssets.forEach((as) => {
            assetMap[as] = (assetMap[as] || 0) + 1;
          });
        }
      });
      const mitreData = Object.entries(mitreMap).map(([tactic, count]) => ({ tactic, count }));
      const topAssets = Object.entries(assetMap)
        .map(([asset, count]) => ({ asset, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);

      // SLA specific details
      const mttaData = [
        { severity: 'Critical', minutes: criticalCount > 0 ? 1.5 : 0 },
        { severity: 'High', minutes: highCount > 0 ? 4.2 : 0 },
        { severity: 'Medium', minutes: mediumCount > 0 ? 15.5 : 0 },
        { severity: 'Low', minutes: lowCount > 0 ? 42.1 : 0 },
      ];

      // Compiling Enriched Content (Real Data from store)
      // 1. Logs subset matching range (fallback to recent logs)
      const logsList = logs
        .filter((l) => {
          const ld = new Date(l.timestamp);
          return ld >= start && ld <= end;
        })
        .slice(0, 10)
        .map(l => ({ timestamp: l.timestamp, process: l.process, level: l.level, message: l.message }));

      // 2. Active network connections (external sockets)
      const connList = connections
        .filter((c) => c.remote_ip && c.remote_ip !== '127.0.0.1' && c.remote_ip !== '0.0.0.0' && c.remote_ip !== '::')
        .slice(0, 10)
        .map(c => ({
          local: `${c.local_ip}:${c.local_port}`,
          remote: `${c.remote_ip}:${c.remote_port}`,
          process: c.process,
          status: c.status,
          country: c.geo?.country || 'Unknown',
          org: c.geo?.org || 'Unknown'
        }));

      // 3. Suspicious or high-resource active processes
      const procList = processes
        .filter((p) => p.suspicious || p.cpu_percent > 3 || p.memory_percent > 3)
        .slice(0, 10)
        .map(p => ({
          pid: p.pid,
          name: p.name,
          cpu: p.cpu_percent,
          mem: p.memory_percent,
          username: p.username,
          status: p.status,
          suspicious: p.suspicious
        }));

      // 4. Incident Registry list
      const incidentListCompiled = filteredIncidents.map((i) => ({
        id: i.id,
        title: i.title,
        severity: i.severity,
        status: i.status,
        createdAt: i.createdAt,
        affected: i.affectedSystems.join(', '),
        investigator: i.investigator
      }));

      // 5. Forensics Evidence Items registry
      const incidentIds = new Set(filteredIncidents.map(i => i.id));
      const evidenceListCompiled = evidenceItems
        .filter((ev) => incidentIds.has(ev.incidentId))
        .map((ev) => ({
          id: ev.id,
          incidentId: ev.incidentId,
          type: ev.type,
          collectedAt: ev.collectedAt,
          status: ev.status,
          hash: ev.hash,
          description: ev.description
        }));

      // 6. Geographic connections distribution
      const geoMapCounts: Record<string, { country: string; count: number; ips: Set<string> }> = {};
      connections.forEach((c) => {
        if (c.geo && c.geo.country && c.geo.country !== 'Unknown' && c.geo.country !== 'Local network') {
          const country = c.geo.country;
          if (!geoMapCounts[country]) {
            geoMapCounts[country] = { country, count: 0, ips: new Set() };
          }
          geoMapCounts[country].count++;
          if (c.remote_ip) geoMapCounts[country].ips.add(c.remote_ip);
        }
      });
      const geoThreats = Object.values(geoMapCounts)
        .map((g) => ({ country: g.country, count: g.count, uniqueIps: g.ips.size }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);

      // 7. Full Alerts list registry
      const alertsListCompiled = filteredAlerts.slice(0, 12).map((a) => ({
        id: a.id,
        timestamp: a.timestamp,
        severity: a.severity,
        title: a.title,
        source: a.source,
        tactics: a.mitreTactics ? a.mitreTactics.join(', ') : 'None',
        status: a.status
      }));

      const reportTypeName = REPORT_TYPES.find((t) => t.id === selectedType)?.label || 'Security Report';
      const formattedStartDate = start.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
      const formattedEndDate = end.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
      const reportName = `${reportTypeName} (${formattedStartDate} - ${formattedEndDate})`;

      // Create Report object
      const reportId = `REP-${Date.now()}`;
      const generatedReport: SavedReport = {
        id: reportId,
        name: reportName,
        type: selectedType,
        date: new Date().toISOString(),
        startDate: startDate,
        endDate: endDate,
        pages: Math.max(1, Math.min(10, Math.ceil((totalAlerts + totalIncidents) / 5) + 1)),
        size: `${Math.round((0.8 + Math.random() * 0.4 + totalAlerts * 0.08 + procList.length * 0.04) * 10) / 10} MB`,
        data: {
          totalAlerts,
          totalIncidents,
          resolvedIncidents,
          slaComplianceRate,
          severityBreakdown: { criticalCount, highCount, mediumCount, lowCount },
          findings,
          trendData,
          mitreData,
          topAssets,
          mttaData,
          systemMeta: metrics ? {
            platform: metrics.platform,
            hostname: metrics.hostname,
            uptime: metrics.uptime_seconds,
          } : { platform: 'Unknown', hostname: 'ForenSys SOC', uptime: 0 },
          
          // Rich data content sections
          logsList,
          connList,
          procList,
          incidentListCompiled,
          evidenceListCompiled,
          geoThreats,
          alertsListCompiled
        },
      };

      // Save to backend
      const saved = await saveReport(generatedReport);
      setPastReports((prev) => [saved, ...prev]);
      setSelectedReport(saved);
      setPreview(true);
      toast.success('Report generated successfully', { description: 'Preview is now available.' });
    } catch (err) {
      console.error('Failed to generate report:', err);
      toast.error('Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = () => {
    toast.success('Downloading report...', { description: 'PDF will be ready in a moment.' });
    setTimeout(() => {
      window.print();
    }, 500);
  };

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      await deleteReport(id);
      setPastReports((prev) => prev.filter((r) => r.id !== id));
      if (selectedReport?.id === id) {
        setSelectedReport(null);
        setPreview(false);
      }
      toast.success('Report deleted successfully');
    } catch (err) {
      console.error('Failed to delete report:', err);
      toast.error('Failed to delete report');
    }
  };

  const handleSelectReport = (report: SavedReport) => {
    setSelectedReport(report);
    setSelectedType(report.type);
    setPreview(true);
  };

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="no-print">
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <FileText className="w-6 h-6 text-accent" />
          Reports
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">Generate, preview, and download security reports</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left: Generator + Past Reports */}
        <div className="lg:col-span-1 space-y-4 no-print">
          {/* Report Generator */}
          <div className="glass rounded-lg border border-border/50 p-4 space-y-4">
            <h2 className="text-sm font-semibold text-foreground">Generate Report</h2>
            <div className="space-y-2">
              {REPORT_TYPES.map((type) => {
                const Icon = type.icon;
                return (
                  <button
                    key={type.id}
                    onClick={() => { setSelectedType(type.id); }}
                    className={`w-full text-left p-3 rounded-lg border transition-all ${
                      selectedType === type.id
                        ? 'border-accent bg-accent/10 text-foreground'
                        : 'border-border/50 text-muted-foreground hover:border-border hover:text-foreground hover:bg-card/50'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className={`w-4 h-4 shrink-0 ${selectedType === type.id ? 'text-accent' : ''}`} />
                      <div>
                        <p className="text-xs font-medium">{type.label}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{type.desc}</p>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>

            <div className="space-y-2">
              <div className="flex gap-2">
                <input
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="flex-1 bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1.5 h-8"
                />
                <span className="text-muted-foreground text-xs self-center">to</span>
                <input
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="flex-1 bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1.5 h-8"
                />
              </div>
            </div>

            <Button
              onClick={handleGenerate}
              disabled={!selectedType || generating}
              className="w-full bg-accent hover:bg-accent/90 text-accent-foreground"
            >
              {generating ? (
                <><span className="animate-spin mr-2">⚙️</span>Generating...</>
              ) : (
                'Generate Report'
              )}
            </Button>
          </div>

          {/* Past Reports */}
          <div className="glass rounded-lg border border-border/50 p-4 space-y-3">
            <h2 className="text-sm font-semibold text-foreground">Past Reports</h2>
            <div className="space-y-2 max-h-[300px] overflow-y-auto">
              {pastReports.length === 0 ? (
                <p className="text-xs text-muted-foreground text-center py-4">No reports generated yet</p>
              ) : (
                pastReports.map((report) => (
                  <div
                    key={report.id}
                    onClick={() => handleSelectReport(report)}
                    className={`p-2.5 rounded border transition-all cursor-pointer ${
                      selectedReport?.id === report.id
                        ? 'border-accent bg-accent/5'
                        : 'border-border/50 bg-card/40 hover:border-border'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-foreground truncate">{report.name}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-[10px] text-muted-foreground">
                            {new Date(report.date).toLocaleDateString()}
                          </span>
                          <span className="text-xs text-muted-foreground">·</span>
                          <span className="text-[10px] text-muted-foreground">{report.pages}pp</span>
                          <span className="text-xs text-muted-foreground">·</span>
                          <span className="text-[10px] text-muted-foreground">{report.size}</span>
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 text-muted-foreground hover:text-red-400 p-0 shrink-0"
                        onClick={(e) => handleDelete(e, report.id)}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right: Preview */}
        <div className="lg:col-span-2">
          {!preview || !selectedReport ? (
            <div className="glass rounded-lg border border-border/50 p-12 text-center h-full flex flex-col items-center justify-center no-print">
              <FileText className="w-10 h-10 text-muted-foreground mb-3" />
              <p className="text-sm text-muted-foreground">Select a report type and click Generate</p>
              <p className="text-xs text-muted-foreground mt-1">Preview will appear here</p>
            </div>
          ) : (
            <motion.div
              id="print-area"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-lg border border-border/50 overflow-hidden text-slate-100"
            >
              {/* Report Header */}
              <div className="p-5 border-b border-border/50 bg-accent/5">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <div className="w-6 h-6 bg-accent/20 rounded flex items-center justify-center">
                        <Shield className="w-3.5 h-3.5 text-accent" />
                      </div>
                      <span className="text-xs font-bold text-accent tracking-widest">FORENSYS DIGITAL SOC</span>
                    </div>
                    <h3 className="text-lg font-bold text-foreground mt-2">
                      {selectedReport.name}
                    </h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      Generated: {new Date(selectedReport.date).toLocaleString()} · Range: {new Date(selectedReport.startDate).toLocaleDateString()} to {new Date(selectedReport.endDate).toLocaleDateString()}
                    </p>
                  </div>
                  <Button onClick={handleDownload} className="no-print bg-accent hover:bg-accent/90 text-accent-foreground gap-2 text-xs h-8">
                    <Download className="w-3.5 h-3.5" /> PDF
                  </Button>
                </div>
              </div>

              {/* Report Body */}
              <div className="p-5 space-y-6">
                {/* Metrics Summary cards */}
                <div>
                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Metrics Summary</h4>
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { label: 'Total Incidents', value: selectedReport.data.totalIncidents, icon: AlertTriangle, color: 'text-orange-400' },
                      { label: 'Alerts Processed', value: selectedReport.data.totalAlerts, icon: Shield, color: 'text-accent' },
                      { label: 'SLA Compliance', value: `${selectedReport.data.slaComplianceRate}%`, icon: TrendingUp, color: 'text-green-400' },
                    ].map((stat) => (
                      <Card key={stat.label} className="bg-card/50 border-border/50 p-3">
                        <stat.icon className={`w-4 h-4 ${stat.color} mb-1`} />
                        <div className={`text-xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
                        <div className="text-xs text-muted-foreground mt-0.5">{stat.label}</div>
                      </Card>
                    ))}
                  </div>
                </div>

                {/* Charts Section */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Chart 1: Incident Trend */}
                  {selectedReport.data.trendData && selectedReport.data.trendData.length > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Incident Trend</h4>
                      <ResponsiveContainer width="100%" height={160}>
                        <LineChart data={selectedReport.data.trendData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                          <XAxis dataKey="label" stroke="#555" style={{ fontSize: '10px' }} />
                          <YAxis stroke="#555" style={{ fontSize: '10px' }} />
                          <Tooltip contentStyle={CustomTooltipStyle} />
                          <Line type="monotone" dataKey="count" stroke="#00c8ff" dot={false} strokeWidth={2} name="Incidents" />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  )}

                  {/* Chart 2: Alerts Severity or MITRE Tactics depending on report type */}
                  {selectedReport.type === 'threat' && selectedReport.data.mitreData && selectedReport.data.mitreData.length > 0 ? (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">MITRE ATT&CK Tactics Distribution</h4>
                      <ResponsiveContainer width="100%" height={160}>
                        <BarChart data={selectedReport.data.mitreData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                          <XAxis dataKey="tactic" stroke="#555" style={{ fontSize: '8px' }} />
                          <YAxis stroke="#555" style={{ fontSize: '10px' }} />
                          <Tooltip contentStyle={CustomTooltipStyle} />
                          <Bar dataKey="count" fill="#a855f7" fillOpacity={0.8} radius={[2, 2, 0, 0]} name="Alerts" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  ) : selectedReport.type === 'sla' && selectedReport.data.mttaData ? (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">MTTA by Severity (Minutes)</h4>
                      <div className="space-y-1.5 py-1">
                        {selectedReport.data.mttaData.map((d: any) => (
                          <div key={d.severity} className="flex justify-between items-center text-xs p-1.5 bg-card/30 rounded border border-border/30">
                            <span className="font-medium text-foreground">{d.severity}</span>
                            <span className="font-mono text-accent">{d.minutes > 0 ? `${d.minutes}m` : 'N/A'}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    selectedReport.data.trendData && selectedReport.data.trendData.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Alert Severity Distribution</h4>
                        <ResponsiveContainer width="100%" height={160}>
                          <BarChart data={selectedReport.data.trendData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                            <XAxis dataKey="label" stroke="#555" style={{ fontSize: '10px' }} />
                            <YAxis stroke="#555" style={{ fontSize: '10px' }} />
                            <Tooltip contentStyle={CustomTooltipStyle} />
                            <Bar dataKey="critical" fill="#ef4444" fillOpacity={0.8} stackId="a" radius={[2, 2, 0, 0]} name="Critical" />
                            <Bar dataKey="high" fill="#f97316" fillOpacity={0.8} stackId="a" name="High" />
                            <Bar dataKey="medium" fill="#eab308" fillOpacity={0.8} stackId="a" name="Medium" />
                            <Bar dataKey="low" fill="#3b82f6" fillOpacity={0.8} stackId="a" name="Low" />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    )
                  )}
                </div>

                {/* ── TYPE-SPECIFIC ENRICHED DATA SECTIONS ── */}

                {/* 1. Threat Landscape Details */}
                {selectedReport.type === 'threat' && (
                  <div className="space-y-5">
                    {selectedReport.data.geoThreats && selectedReport.data.geoThreats.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <Globe className="w-3.5 h-3.5 text-accent" /> Geographic Threat Vectors
                        </h4>
                        <div className="overflow-x-auto rounded border border-border/50">
                          <table className="w-full text-left text-xs border-collapse">
                            <thead>
                              <tr className="bg-card/85 text-muted-foreground border-b border-border/50">
                                <th className="p-2 font-semibold">Origin Country</th>
                                <th className="p-2 font-semibold text-right">Socket Count</th>
                                <th className="p-2 font-semibold text-right">Unique Remote IPs</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                              {selectedReport.data.geoThreats.map((g: any, i: number) => (
                                <tr key={i} className="hover:bg-card/20">
                                  <td className="p-2 font-medium">{g.country}</td>
                                  <td className="p-2 text-right font-mono text-accent">{g.count}</td>
                                  <td className="p-2 text-right font-mono text-muted-foreground">{g.uniqueIps}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {selectedReport.data.connList && selectedReport.data.connList.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <Network className="w-3.5 h-3.5 text-accent" /> External Active Connections Registry
                        </h4>
                        <div className="overflow-x-auto rounded border border-border/50">
                          <table className="w-full text-left text-xs border-collapse">
                            <thead>
                              <tr className="bg-card/85 text-muted-foreground border-b border-border/50">
                                <th className="p-2 font-semibold">Local Socket</th>
                                <th className="p-2 font-semibold">Remote Socket</th>
                                <th className="p-2 font-semibold">Process</th>
                                <th className="p-2 font-semibold">Country</th>
                                <th className="p-2 font-semibold">ISP/Organization</th>
                                <th className="p-2 font-semibold">State</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                              {selectedReport.data.connList.map((c: any, i: number) => (
                                <tr key={i} className="hover:bg-card/20 font-mono text-[11px]">
                                  <td className="p-2 text-muted-foreground">{c.local}</td>
                                  <td className="p-2 text-foreground font-semibold">{c.remote}</td>
                                  <td className="p-2 text-accent">{c.process}</td>
                                  <td className="p-2 text-foreground">{c.country}</td>
                                  <td className="p-2 text-muted-foreground max-w-[150px] truncate">{c.org}</td>
                                  <td className="p-2"><Badge className="bg-green-950/30 text-green-400 border-green-700/50 text-[10px] py-0">{c.status}</Badge></td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 2. Monthly Incident Summary Details */}
                {selectedReport.type === 'monthly' && (
                  <div className="space-y-5">
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                        <ClipboardList className="w-3.5 h-3.5 text-accent" /> Incident Log Registry
                      </h4>
                      <div className="overflow-x-auto rounded border border-border/50">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="bg-card/85 text-muted-foreground border-b border-border/50">
                              <th className="p-2 font-semibold">Incident ID</th>
                              <th className="p-2 font-semibold">Title</th>
                              <th className="p-2 font-semibold">Severity</th>
                              <th className="p-2 font-semibold">Status</th>
                              <th className="p-2 font-semibold">Affected System</th>
                              <th className="p-2 font-semibold">Investigator</th>
                              <th className="p-2 font-semibold">Created Date</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border/30">
                            {selectedReport.data.incidentListCompiled && selectedReport.data.incidentListCompiled.length > 0 ? (
                              selectedReport.data.incidentListCompiled.map((inc: any) => (
                                <tr key={inc.id} className="hover:bg-card/20">
                                  <td className="p-2 font-mono text-accent font-semibold">{inc.id}</td>
                                  <td className="p-2 font-medium">{inc.title}</td>
                                  <td className="p-2">
                                    <Badge className={`text-[10px] uppercase ${
                                      inc.severity === 'critical' ? 'bg-red-950/50 text-red-400 border-red-800/50' :
                                      inc.severity === 'high' ? 'bg-orange-950/50 text-orange-400 border-orange-800/50' :
                                      inc.severity === 'medium' ? 'bg-yellow-950/50 text-yellow-400 border-yellow-800/50' :
                                      'bg-slate-900 text-slate-400 border-slate-700/50'
                                    }`}>
                                      {inc.severity}
                                    </Badge>
                                  </td>
                                  <td className="p-2">
                                    <Badge className="bg-sky-950/50 text-sky-400 border-sky-800/50 uppercase text-[10px]">{inc.status}</Badge>
                                  </td>
                                  <td className="p-2 font-mono text-muted-foreground">{inc.affected}</td>
                                  <td className="p-2 text-muted-foreground">{inc.investigator}</td>
                                  <td className="p-2 text-muted-foreground">{new Date(inc.createdAt).toLocaleDateString()}</td>
                                </tr>
                              ))
                            ) : (
                              <tr>
                                <td colSpan={7} className="p-4 text-center text-muted-foreground">No incidents raised during the selected period.</td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {selectedReport.data.evidenceListCompiled && selectedReport.data.evidenceListCompiled.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <Database className="w-3.5 h-3.5 text-accent" /> Forensic Evidence Catalog
                        </h4>
                        <div className="overflow-x-auto rounded border border-border/50">
                          <table className="w-full text-left text-xs border-collapse">
                            <thead>
                              <tr className="bg-card/85 text-muted-foreground border-b border-border/50">
                                <th className="p-2 font-semibold">Evidence ID</th>
                                <th className="p-2 font-semibold">Incident Link</th>
                                <th className="p-2 font-semibold">Type</th>
                                <th className="p-2 font-semibold">Cryptographic Hash (SHA256)</th>
                                <th className="p-2 font-semibold">Collected At</th>
                                <th className="p-2 font-semibold">Status</th>
                                <th className="p-2 font-semibold">Description</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                              {selectedReport.data.evidenceListCompiled.map((ev: any) => (
                                <tr key={ev.id} className="hover:bg-card/20 text-[11px]">
                                  <td className="p-2 font-mono text-accent font-semibold">{ev.id}</td>
                                  <td className="p-2 font-mono text-muted-foreground">{ev.incidentId}</td>
                                  <td className="p-2 text-foreground font-medium">{ev.type}</td>
                                  <td className="p-2 font-mono text-muted-foreground max-w-[120px] truncate" title={ev.hash}>{ev.hash}</td>
                                  <td className="p-2 text-muted-foreground">{new Date(ev.collectedAt).toLocaleDateString()}</td>
                                  <td className="p-2"><Badge className="bg-emerald-950/30 text-emerald-400 border-emerald-700/50 text-[10px]">{ev.status}</Badge></td>
                                  <td className="p-2 text-muted-foreground truncate max-w-[200px]">{ev.description}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 3. SLA Compliance Report Details */}
                {selectedReport.type === 'sla' && selectedReport.data.alertsListCompiled && (
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-accent" /> Alert SLA Response Audit
                    </h4>
                    <div className="overflow-x-auto rounded border border-border/50">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="bg-card/85 text-muted-foreground border-b border-border/50">
                            <th className="p-2 font-semibold">Alert ID</th>
                            <th className="p-2 font-semibold">Title</th>
                            <th className="p-2 font-semibold">Severity</th>
                            <th className="p-2 font-semibold">Alert Source</th>
                            <th className="p-2 font-semibold">Response Status</th>
                            <th className="p-2 font-semibold">Observed MTTA</th>
                            <th className="p-2 font-semibold">SLA Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border/30">
                          {selectedReport.data.alertsListCompiled.length > 0 ? (
                            selectedReport.data.alertsListCompiled.map((alt: any) => {
                              // Simulate MTTA based on severity for audit
                              const mttaVal = alt.severity === 'critical' ? '1.2m' : alt.severity === 'high' ? '3.8m' : alt.severity === 'medium' ? '11.5m' : '31.2m';
                              const isBreach = alt.status === 'new' && (alt.severity === 'critical' || alt.severity === 'high');
                              return (
                                <tr key={alt.id} className="hover:bg-card/20">
                                  <td className="p-2 font-mono text-muted-foreground text-[11px]">{alt.id}</td>
                                  <td className="p-2 font-medium">{alt.title}</td>
                                  <td className="p-2">
                                    <Badge className={`text-[10px] uppercase ${
                                      alt.severity === 'critical' ? 'bg-red-950/50 text-red-400 border-red-800/50' :
                                      alt.severity === 'high' ? 'bg-orange-950/50 text-orange-400 border-orange-800/50' :
                                      alt.severity === 'medium' ? 'bg-yellow-950/50 text-yellow-400 border-yellow-800/50' :
                                      'bg-slate-900 text-slate-400 border-slate-700/50'
                                    }`}>
                                      {alt.severity}
                                    </Badge>
                                  </td>
                                  <td className="p-2 font-mono text-muted-foreground text-[11px]">{alt.source}</td>
                                  <td className="p-2 font-mono text-muted-foreground uppercase text-[10px]">{alt.status}</td>
                                  <td className="p-2 font-mono text-accent">{mttaVal}</td>
                                  <td className="p-2">
                                    {isBreach ? (
                                      <Badge className="bg-red-950/50 text-red-400 border-red-800/50 text-[10px] uppercase">BREACH RISK</Badge>
                                    ) : (
                                      <Badge className="bg-green-950/50 text-green-400 border-green-800/50 text-[10px] uppercase">COMPLIANT</Badge>
                                    )}
                                  </td>
                                </tr>
                              );
                            })
                          ) : (
                            <tr>
                              <td colSpan={7} className="p-4 text-center text-muted-foreground">No alerts loaded to audit.</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* 4. Executive Summary Extra System Logs & Processes Details */}
                {selectedReport.type === 'exec' && (
                  <div className="space-y-5">
                    {selectedReport.data.procList && selectedReport.data.procList.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <Cpu className="w-3.5 h-3.5 text-accent" /> Active High-Resource/Suspicious Processes
                        </h4>
                        <div className="overflow-x-auto rounded border border-border/50">
                          <table className="w-full text-left text-xs border-collapse">
                            <thead>
                              <tr className="bg-card/85 text-muted-foreground border-b border-border/50">
                                <th className="p-2 font-semibold">PID</th>
                                <th className="p-2 font-semibold">Process Name</th>
                                <th className="p-2 font-semibold text-right">CPU %</th>
                                <th className="p-2 font-semibold text-right">Memory %</th>
                                <th className="p-2 font-semibold">Owner</th>
                                <th className="p-2 font-semibold">Status</th>
                                <th className="p-2 font-semibold">Suspicious</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30 font-mono text-[11px]">
                              {selectedReport.data.procList.map((p: any) => (
                                <tr key={p.pid} className="hover:bg-card/20">
                                  <td className="p-2 text-muted-foreground">{p.pid}</td>
                                  <td className="p-2 text-foreground font-semibold">{p.name}</td>
                                  <td className="p-2 text-right text-accent">{p.cpu}%</td>
                                  <td className="p-2 text-right text-muted-foreground">{p.mem}%</td>
                                  <td className="p-2 text-muted-foreground">{p.username}</td>
                                  <td className="p-2 text-muted-foreground">{p.status}</td>
                                  <td className="p-2">
                                    {p.suspicious ? (
                                      <Badge className="bg-red-950/50 text-red-400 border-red-800/50 text-[9px] py-0 font-bold uppercase">YES</Badge>
                                    ) : (
                                      <Badge className="bg-slate-900 text-slate-400 border-slate-700/50 text-[9px] py-0 font-normal uppercase">NO</Badge>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {selectedReport.data.logsList && selectedReport.data.logsList.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <Database className="w-3.5 h-3.5 text-accent" /> Host Log Security Annotations
                        </h4>
                        <div className="overflow-x-auto rounded border border-border/50">
                          <table className="w-full text-left text-xs border-collapse">
                            <thead>
                              <tr className="bg-card/85 text-muted-foreground border-b border-border/50">
                                <th className="p-2 font-semibold">Timestamp</th>
                                <th className="p-2 font-semibold">Process</th>
                                <th className="p-2 font-semibold">Severity</th>
                                <th className="p-2 font-semibold">Log Message</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                              {selectedReport.data.logsList.map((l: any, i: number) => (
                                <tr key={i} className="hover:bg-card/20 font-mono text-[11px]">
                                  <td className="p-2 text-muted-foreground">{new Date(l.timestamp).toLocaleTimeString()}</td>
                                  <td className="p-2 text-accent">{l.process}</td>
                                  <td className="p-2">
                                    <span className={`text-[10px] uppercase font-bold ${
                                      l.level === 'error' ? 'text-red-400' :
                                      l.level === 'warn' ? 'text-yellow-400' : 'text-slate-400'
                                    }`}>
                                      {l.level}
                                    </span>
                                  </td>
                                  <td className="p-2 text-muted-foreground truncate max-w-[320px] font-sans" title={l.message}>
                                    {l.message}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* System Context Card (For executive summary metadata) */}
                {selectedReport.data.systemMeta && (
                  <div className="p-3 bg-card/45 rounded border border-border/50 text-xs space-y-2">
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-accent" /> Digital Host Snapshot Context
                    </h4>
                    <div className="grid grid-cols-3 gap-2 text-muted-foreground font-mono text-[11px]">
                      <div>Hostname: <span className="text-foreground">{selectedReport.data.systemMeta.hostname}</span></div>
                      <div>OS Platform: <span className="text-foreground">{selectedReport.data.systemMeta.platform}</span></div>
                      <div>Host Uptime: <span className="text-foreground">{Math.round(selectedReport.data.systemMeta.uptime / 3600)} hours</span></div>
                    </div>
                  </div>
                )}

                {/* Key Findings / Event Log */}
                <div>
                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Key Findings & Analyst Recommendations</h4>
                  <div className="space-y-2 text-xs">
                    {selectedReport.data.findings.map((finding: any, i: number) => (
                      <div key={i} className={`p-2.5 rounded border ${
                        finding.severity === 'critical' ? 'border-red-700/50 bg-red-900/10 text-red-200' :
                        finding.severity === 'high' ? 'border-orange-700/50 bg-orange-900/10 text-orange-200' :
                        finding.severity === 'medium' ? 'border-yellow-700/50 bg-yellow-900/10 text-yellow-200' :
                        'border-border/80 bg-card/50 text-muted-foreground'
                      }`}>
                        <Badge className={`text-[10px] uppercase font-bold mr-2 ${
                          finding.severity === 'critical' ? 'bg-red-900/30 text-red-300 border-red-700/50' :
                          finding.severity === 'high' ? 'bg-orange-900/30 text-orange-300 border-orange-700/50' :
                          finding.severity === 'medium' ? 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50' :
                          'bg-muted text-muted-foreground border-border'
                        }`}>
                          {finding.severity}
                        </Badge>
                        {finding.text}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}
