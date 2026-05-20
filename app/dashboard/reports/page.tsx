'use client';

import { useState } from 'react';
import { FileText, Download, Calendar, TrendingUp, AlertTriangle, Shield, Eye } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { useAppStore } from '@/lib/app-store';
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { motion } from 'framer-motion';
import { toast } from 'sonner';

const REPORT_TYPES = [
  { id: 'monthly', label: 'Monthly Incident Summary', desc: 'Full incident lifecycle analysis', icon: FileText },
  { id: 'threat', label: 'Threat Landscape Report', desc: 'Current threat actor campaigns', icon: Shield },
  { id: 'sla', label: 'SLA Compliance Report', desc: 'Response time & SLA metrics', icon: TrendingUp },
  { id: 'exec', label: 'Executive Summary', desc: 'C-suite risk overview', icon: Eye },
];

const PAST_REPORTS = [
  { name: 'Monthly Incident Summary - January 2024', date: '2024-01-31', type: 'monthly', pages: 18, size: '2.4 MB' },
  { name: 'Threat Landscape Report - Q4 2023', date: '2024-01-05', type: 'threat', pages: 32, size: '5.1 MB' },
  { name: 'SLA Compliance Report - December 2023', date: '2024-01-02', type: 'sla', pages: 11, size: '1.8 MB' },
  { name: 'Executive Summary - Q4 2023', date: '2023-12-31', type: 'exec', pages: 8, size: '1.2 MB' },
  { name: 'Monthly Incident Summary - December 2023', date: '2023-12-31', type: 'monthly', pages: 21, size: '3.1 MB' },
];

const CustomTooltipStyle = {
  backgroundColor: 'rgba(15, 23, 42, 0.95)',
  border: '1px solid rgba(0,200,255,0.3)',
  borderRadius: '8px',
  fontSize: '12px',
  color: '#e2e8f0',
};

export default function ReportsPage() {
  const { alerts, incidents } = useAppStore();
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [preview, setPreview] = useState(false);

  const handleGenerate = () => {
    if (!selectedType) {
      toast.error('Please select a report type');
      return;
    }
    setGenerating(true);
    setTimeout(() => {
      setGenerating(false);
      setPreview(true);
      toast.success('Report generated successfully', { description: 'Preview is now available below.' });
    }, 2000);
  };

  const handleDownload = () => {
    toast.success('Downloading report...', { description: 'PDF will be ready in a moment.' });
    // Simulate PDF download
    setTimeout(() => {
      window.print();
    }, 500);
  };

  const incidentTrend = [
    { month: 'Aug', count: 38 },
    { month: 'Sep', count: 44 },
    { month: 'Oct', count: 51 },
    { month: 'Nov', count: 47 },
    { month: 'Dec', count: 39 },
    { month: 'Jan', count: incidents.length },
  ];

  const alertTrend = [
    { month: 'Aug', critical: 12, high: 34, medium: 89 },
    { month: 'Sep', critical: 18, high: 41, medium: 102 },
    { month: 'Oct', critical: 22, high: 55, medium: 128 },
    { month: 'Nov', critical: 15, high: 48, medium: 115 },
    { month: 'Dec', critical: 11, high: 37, medium: 94 },
    { month: 'Jan', critical: alerts.filter(a => a.severity === 'critical').length, high: alerts.filter(a => a.severity === 'high').length, medium: alerts.filter(a => a.severity === 'medium').length },
  ];

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <FileText className="w-6 h-6 text-accent" />
          Reports
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">Generate, preview, and download security reports</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left: Generator + Past Reports */}
        <div className="lg:col-span-1 space-y-4">
          {/* Report Generator */}
          <div className="glass rounded-lg border border-border/50 p-4 space-y-4">
            <h2 className="text-sm font-semibold text-foreground">Generate Report</h2>
            <div className="space-y-2">
              {REPORT_TYPES.map((type) => {
                const Icon = type.icon;
                return (
                  <button
                    key={type.id}
                    onClick={() => { setSelectedType(type.id); setPreview(false); }}
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
                <input type="date" className="flex-1 bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1.5 h-8" />
                <span className="text-muted-foreground text-xs self-center">to</span>
                <input type="date" className="flex-1 bg-input border border-border/50 rounded-md text-xs text-foreground px-2 py-1.5 h-8" />
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
            <div className="space-y-2">
              {PAST_REPORTS.map((report, i) => (
                <div key={i} className="p-2.5 bg-card/40 rounded border border-border/50 hover:border-border transition-colors">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-foreground truncate">{report.name}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs text-muted-foreground">{report.date}</span>
                        <span className="text-xs text-muted-foreground">·</span>
                        <span className="text-xs text-muted-foreground">{report.pages}pp</span>
                        <span className="text-xs text-muted-foreground">·</span>
                        <span className="text-xs text-muted-foreground">{report.size}</span>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 text-xs text-accent hover:text-accent/80 p-1 shrink-0"
                      onClick={() => toast.success('Downloading...', { description: report.name })}
                    >
                      <Download className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Preview */}
        <div className="lg:col-span-2">
          {!preview && (
            <div className="glass rounded-lg border border-border/50 p-12 text-center h-full flex flex-col items-center justify-center">
              <FileText className="w-10 h-10 text-muted-foreground mb-3" />
              <p className="text-sm text-muted-foreground">Select a report type and click Generate</p>
              <p className="text-xs text-muted-foreground mt-1">Preview will appear here</p>
            </div>
          )}

          {preview && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-lg border border-border/50 overflow-hidden"
            >
              {/* Report Header */}
              <div className="p-5 border-b border-border/50 bg-accent/5">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <div className="w-6 h-6 bg-accent/20 rounded flex items-center justify-center">
                        <Shield className="w-3.5 h-3.5 text-accent" />
                      </div>
                      <span className="text-xs font-bold text-accent tracking-widest">FORENSYS</span>
                    </div>
                    <h3 className="text-lg font-bold text-foreground mt-2">
                      {REPORT_TYPES.find((t) => t.id === selectedType)?.label}
                    </h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      Generated: {new Date().toLocaleDateString()} · Period: Jan 2024
                    </p>
                  </div>
                  <Button onClick={handleDownload} className="bg-accent hover:bg-accent/90 text-accent-foreground gap-2 text-xs h-8">
                    <Download className="w-3.5 h-3.5" /> PDF
                  </Button>
                </div>
              </div>

              {/* Report Body */}
              <div className="p-5 space-y-5">
                {/* Executive Summary */}
                <div>
                  <h4 className="text-sm font-semibold text-foreground mb-2">Executive Summary</h4>
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { label: 'Total Incidents', value: incidents.length, icon: AlertTriangle, color: 'text-orange-400' },
                      { label: 'Alerts Processed', value: alerts.length, icon: Shield, color: 'text-accent' },
                      { label: 'SLA Compliance', value: '98.5%', icon: TrendingUp, color: 'text-green-400' },
                    ].map((stat) => (
                      <Card key={stat.label} className="bg-card/50 border-border/50 p-3">
                        <stat.icon className={`w-4 h-4 ${stat.color} mb-1`} />
                        <div className={`text-xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
                        <div className="text-xs text-muted-foreground mt-0.5">{stat.label}</div>
                      </Card>
                    ))}
                  </div>
                </div>

                {/* Charts */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Incident Trend</h4>
                    <ResponsiveContainer width="100%" height={160}>
                      <LineChart data={incidentTrend}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                        <XAxis dataKey="month" stroke="#555" style={{ fontSize: '10px' }} />
                        <YAxis stroke="#555" style={{ fontSize: '10px' }} />
                        <Tooltip contentStyle={CustomTooltipStyle} />
                        <Line type="monotone" dataKey="count" stroke="#00c8ff" dot={false} strokeWidth={2} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Alert Severity Distribution</h4>
                    <ResponsiveContainer width="100%" height={160}>
                      <BarChart data={alertTrend}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                        <XAxis dataKey="month" stroke="#555" style={{ fontSize: '10px' }} />
                        <YAxis stroke="#555" style={{ fontSize: '10px' }} />
                        <Tooltip contentStyle={CustomTooltipStyle} />
                        <Bar dataKey="critical" fill="#ef4444" fillOpacity={0.8} stackId="a" radius={[2, 2, 0, 0]} />
                        <Bar dataKey="high" fill="#f97316" fillOpacity={0.8} stackId="a" />
                        <Bar dataKey="medium" fill="#eab308" fillOpacity={0.8} stackId="a" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Findings */}
                <div>
                  <h4 className="text-sm font-semibold text-foreground mb-2">Key Findings</h4>
                  <div className="space-y-2 text-xs">
                    {[
                      { severity: 'critical', text: 'Credential dumping activity detected on DOMAIN-CONTROLLER. Immediate remediation recommended.' },
                      { severity: 'high', text: 'C2 communication pattern identified from WEBSERVER-01 to known threat actor infrastructure.' },
                      { severity: 'medium', text: 'Elevated authentication failures suggest possible brute-force campaign against VPN gateway.' },
                    ].map((finding, i) => (
                      <div key={i} className={`p-2.5 rounded border ${
                        finding.severity === 'critical' ? 'border-red-700/50 bg-red-900/20 text-red-200' :
                        finding.severity === 'high' ? 'border-orange-700/50 bg-orange-900/20 text-orange-200' :
                        'border-yellow-700/50 bg-yellow-900/20 text-yellow-200'
                      }`}>
                        <Badge className={`text-xs mr-2 ${
                          finding.severity === 'critical' ? 'bg-red-900/30 text-red-300 border-red-700/50' :
                          finding.severity === 'high' ? 'bg-orange-900/30 text-orange-300 border-orange-700/50' :
                          'bg-yellow-900/30 text-yellow-300 border-yellow-700/50'
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
