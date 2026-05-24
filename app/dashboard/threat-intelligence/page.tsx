'use client';

import { useState, useMemo, useEffect } from 'react';
import {
  Shield,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Star,
  Globe,
  ShieldAlert,
  Copy,
  Check,
  FileDown,
  Brain,
  HelpCircle,
  Activity,
  Play,
  Pause,
  Trash2,
  X
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useAppStore, RealNetworkPacket } from '@/lib/app-store';
import { useCopilotStore } from '@/lib/copilot-store';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import {
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie
} from 'recharts';

const TYPE_COLORS: Record<string, string> = {
  malware: 'bg-red-900/30 text-red-300 border-red-700/50',
  ioc: 'bg-orange-900/30 text-orange-300 border-orange-700/50',
  vulnerability: 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50',
  campaign: 'bg-purple-900/30 text-purple-300 border-purple-700/50',
};

const MITRE_MAPPINGS: Record<string, string[]> = {
  malware: ['Execution', 'Defense Evasion', 'Impact'],
  ioc: ['Initial Access', 'Command and Control'],
  vulnerability: ['Initial Access', 'Privilege Escalation'],
  campaign: ['Initial Access', 'Lateral Movement', 'Exfiltration'],
};

const CHART_COLORS = {
  malware: '#ef4444',
  ioc: '#f97316',
  vulnerability: '#eab308',
  campaign: '#a855f7',
};

const CustomTooltipStyle = {
  backgroundColor: 'rgba(15, 23, 42, 0.95)',
  border: '1px solid rgba(0, 200, 255, 0.3)',
  borderRadius: '8px',
  fontSize: '11px',
  color: '#e2e8f0',
};

interface IntelItem {
  id: string;
  type: 'malware' | 'ioc' | 'vulnerability' | 'campaign';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  indicators: string[];
  lastSeen: Date;
  confidence: number;
}

export default function NetworkIntelligencePage() {
  const { alerts: rawAlerts, metrics, connections, networkTrafficLogs } = useAppStore();
  const alerts = rawAlerts.filter((a) => a.status !== 'resolved');
  const copilotStore = useCopilotStore();

  const [search, setSearch] = useState('');
  const [isRegex, setIsRegex] = useState(false);
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [countryFilter, setCountryFilter] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [watchlist, setWatchlist] = useState<Set<string>>(new Set());
  const [mounted, setMounted] = useState(false);
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [displayedTrafficLogs, setDisplayedTrafficLogs] = useState<RealNetworkPacket[]>([]);
  const [isLive, setIsLive] = useState(true);
  const [trafficSearch, setTrafficSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<'all' | 'TCP' | 'UDP' | 'ICMP'>('all');

  useEffect(() => {
    if (isLive) {
      setDisplayedTrafficLogs(networkTrafficLogs || []);
    }
  }, [networkTrafficLogs, isLive]);

  const filteredTraffic = useMemo(() => {
    return displayedTrafficLogs.filter((pkt) => {
      if (protocolFilter !== 'all' && pkt.protocol !== protocolFilter) return false;
      if (trafficSearch) {
        const query = trafficSearch.toLowerCase();
        return (
          pkt.src_ip.toLowerCase().includes(query) ||
          pkt.dst_ip.toLowerCase().includes(query) ||
          pkt.src_port.toString().includes(query) ||
          pkt.dst_port.toString().includes(query) ||
          pkt.info.toLowerCase().includes(query) ||
          pkt.protocol.toLowerCase().includes(query)
        );
      }
      return true;
    });
  }, [displayedTrafficLogs, protocolFilter, trafficSearch]);
  useEffect(() => {
    setMounted(true);
  }, []);

  // IP to Country resolver with realistic fallbacks
  const getCountryForIP = useMemo(() => {
    return (ip: string): string => {
      // Check active connections for real geolocation data first
      const conn = connections.find(c => c.remote_ip === ip);
      if (conn?.geo?.country) {
        return conn.geo.country;
      }

      // Predefined map for global intelligence feed IPs
      const fallbackGeo: Record<string, string> = {
        '185.220.101.45': 'Russia',
        '192.99.142.23': 'Canada',
        '45.33.32.156': 'United States',
        '162.243.155.89': 'United States',
        '185.156.74.8': 'Netherlands',
        '104.244.75.12': 'United States',
        '127.0.0.1': 'Local Loopback',
      };
      return fallbackGeo[ip] || 'United States'; // Defaults to US if geo-ip not resolved
    };
  }, [connections]);

  // Compute dynamic threat intelligence items from real connections and alerts
  const threatIntelList = useMemo<IntelItem[]>(() => {
    const list: IntelItem[] = [];

    // 1. Map active blocklisted IPs from alerts
    const blocklistAlerts = alerts.filter(a => a.title.includes('Blocklisted IP') || a.title.includes('Suspicious Port'));
    blocklistAlerts.forEach((alert, i) => {
      const ip = alert.affectedAssets.find(a => !a.includes('/') && a.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) || '127.0.0.1';
      list.push({
        id: `intel-alert-${alert.id}-${i}`,
        type: 'ioc',
        title: `IOC Match — Suspicious Outbound Activity`,
        severity: alert.severity,
        description: alert.description,
        indicators: [ip],
        lastSeen: new Date(alert.timestamp),
        confidence: alert.severity === 'critical' ? 95 : 85,
      });
    });

    // 2. Add dynamic campaigns based on active network connections geolocations
    const activeRemoteIPs = connections.filter(c => c.geo);
    activeRemoteIPs.forEach((conn, i) => {
      if (conn.remote_ip && conn.geo) {
        const orgName = conn.geo.org || 'Unknown Organization';
        const cityName = conn.geo.city || 'Unknown City';
        const countryName = conn.geo.country || 'Unknown Country';
        const procName = conn.process || 'unknown';
        const proto = conn.protocol || 'TCP';
        const pidNum = conn.pid !== undefined && conn.pid !== null ? conn.pid : 'N/A';
        const isLan = conn.geo.country_code === 'LAN';
        const title = isLan ? `Local Connection: ${orgName}` : `Active Remote Peer Activity: ${orgName}`;
        list.push({
          id: `intel-conn-${conn.remote_ip}-${i}`,
          type: 'campaign',
          title: title,
          severity: 'low',
          description: `Established ${proto} connection to IP in ${cityName}, ${countryName}. Process: ${procName} (PID: ${pidNum}).`,
          indicators: [conn.remote_ip],
          lastSeen: new Date(),
          confidence: 60,
        });
      }
    });
    return list;
  }, [alerts, connections]);

  // Compute unique countries from available threat indicators
  const uniqueCountries = useMemo(() => {
    const countries = new Set<string>();
    threatIntelList.forEach(t => {
      t.indicators.forEach(ioc => {
        const c = getCountryForIP(ioc);
        if (c && c !== 'Local Loopback' && c !== 'Unknown Region') {
          countries.add(c);
        }
      });
    });
    return Array.from(countries).sort();
  }, [threatIntelList, getCountryForIP]);

  // Apply search query, category, severity, and country filtering
  const filtered = useMemo(() => {
    return threatIntelList.filter((t) => {
      if (typeFilter !== 'all' && t.type !== typeFilter) return false;
      if (severityFilter !== 'all' && t.severity !== severityFilter) return false;
      
      if (countryFilter !== 'all') {
        const itemCountries = t.indicators.map(getCountryForIP);
        if (!itemCountries.includes(countryFilter)) return false;
      }

      if (search) {
        if (isRegex) {
          try {
            const regex = new RegExp(search, 'i');
            const matchesTitle = regex.test(t.title);
            const matchesDesc = regex.test(t.description);
            const matchesIocs = t.indicators.some(ioc => regex.test(ioc));
            if (!matchesTitle && !matchesDesc && !matchesIocs) return false;
          } catch (e) {
            // If regex is malformed, suppress matches
            return false;
          }
        } else {
          const query = search.toLowerCase();
          const matchesTitle = t.title.toLowerCase().includes(query);
          const matchesDesc = t.description.toLowerCase().includes(query);
          const matchesIocs = t.indicators.some(ioc => ioc.toLowerCase().includes(query));
          if (!matchesTitle && !matchesDesc && !matchesIocs) return false;
        }
      }
      return true;
    });
  }, [threatIntelList, search, typeFilter, severityFilter, countryFilter, isRegex, getCountryForIP]);

  // Dynamic count aggregation
  const counts = useMemo(() => {
    return {
      all: threatIntelList.length,
      malware: threatIntelList.filter((t) => t.type === 'malware').length,
      ioc: threatIntelList.filter((t) => t.type === 'ioc').length,
      vulnerability: threatIntelList.filter((t) => t.type === 'vulnerability').length,
      campaign: threatIntelList.filter((t) => t.type === 'campaign').length,
    };
  }, [threatIntelList]);

  // Generate charts data structures
  const geoChartData = useMemo(() => {
    const dict: Record<string, number> = {};
    threatIntelList.forEach(t => {
      t.indicators.forEach(ioc => {
        const country = getCountryForIP(ioc);
        if (country && country !== 'Local Loopback') {
          dict[country] = (dict[country] || 0) + 1;
        }
      });
    });
    return Object.entries(dict)
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [threatIntelList, getCountryForIP]);

  const threatTypeData = useMemo(() => {
    return [
      { name: 'Malware', value: counts.malware },
      { name: 'IOC', value: counts.ioc },
      { name: 'Vulnerability', value: counts.vulnerability },
      { name: 'Campaign', value: counts.campaign },
    ].filter(item => item.value > 0);
  }, [counts]);

  const trafficIpChartData = useMemo(() => {
    const dict: Record<string, number> = {};
    displayedTrafficLogs.forEach(pkt => {
      dict[pkt.src_ip] = (dict[pkt.src_ip] || 0) + 1;
      dict[pkt.dst_ip] = (dict[pkt.dst_ip] || 0) + 1;
    });
    return Object.entries(dict)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [displayedTrafficLogs]);

  const trafficProtocolChartData = useMemo(() => {
    const counts = { TCP: 0, UDP: 0, ICMP: 0 };
    displayedTrafficLogs.forEach(pkt => {
      if (pkt.protocol === 'TCP') counts.TCP++;
      else if (pkt.protocol === 'UDP') counts.UDP++;
      else if (pkt.protocol === 'ICMP') counts.ICMP++;
    });
    return [
      { name: 'TCP', value: counts.TCP, color: '#3b82f6' },
      { name: 'UDP', value: counts.UDP, color: '#10b981' },
      { name: 'ICMP', value: counts.ICMP, color: '#f59e0b' },
    ].filter(item => item.value > 0);
  }, [displayedTrafficLogs]);

  // Watchlist Star Trigger
  const toggleWatchlist = (id: string, title: string) => {
    setWatchlist((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
        toast.info('Removed from watchlist', { description: title });
      } else {
        next.add(id);
        toast.success('Added to watchlist', { description: title });
      }
      return next;
    });
  };

  // Copy IP Indicator to clipboard
  const handleCopyIoc = (ioc: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(ioc);
    setCopiedIoc(ioc);
    toast.success(`Copied indicator: ${ioc}`);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  // Trigger global Copilot message scan & open drawer
  const handleAnalyzeWithCopilot = (intel: IntelItem) => {
    const query = `Analyze the network intelligence indicator "${intel.indicators.join(', ')}" associated with the incident: "${intel.title}". Severity is "${intel.severity}" and confidence score is ${intel.confidence}%. Provide the observed tactic, potential attack chain, and response options.`;
    copilotStore.sendMessage(query);
    toast.success('Triggered Iris Analysis', { description: 'Opening Iris panel' });
  };

  // CSV Data Downloader
  const exportCSV = () => {
    if (filtered.length === 0) {
      toast.error('No items to export');
      return;
    }
    const headers = ['ID', 'Type', 'Title', 'Severity', 'Confidence', 'Indicators', 'Last Seen', 'Description'];
    const rows = filtered.map(t => [
      t.id,
      t.type,
      `"${t.title.replace(/"/g, '""')}"`,
      t.severity,
      t.confidence,
      `"${t.indicators.join(', ')}"`,
      t.lastSeen.toISOString(),
      `"${t.description.replace(/"/g, '""')}"`
    ]);
    const content = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `forensys_network_intel_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success('Network intelligence feed exported as CSV');
  };

  // JSON Data Downloader
  const exportJSON = () => {
    if (filtered.length === 0) {
      toast.error('No items to export');
      return;
    }
    const content = JSON.stringify(filtered, null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `forensys_network_intel_${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success('Network intelligence feed exported as JSON');
  };

  if (!mounted) return null;

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Shield className="w-6 h-6 text-accent" />
            Network Intelligence Console
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Active network indicators of compromise, blocklists, and host connection geolocations
          </p>
        </div>

        {/* Global Blocklist Status Card */}
        {metrics && (
          <div className="glass px-4 py-2 border border-purple-500/20 rounded-md flex items-center gap-3">
            <Globe className="w-5 h-5 text-purple-400" />
            <div>
              <p className="text-[10px] text-muted-foreground uppercase font-mono">Active Blocklist IP Count</p>
              <p className="text-sm font-bold font-mono text-purple-300">
                {metrics.blocklist_size.toLocaleString()} IPs
              </p>
            </div>
          </div>
        )}
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="glass rounded-lg p-3 border border-border/50 space-y-1">
          <span className="text-[10px] text-muted-foreground uppercase font-mono">Total Network Signals</span>
          <div className="text-xl font-bold font-mono text-foreground">{threatIntelList.length}</div>
        </div>
        <div className="glass rounded-lg p-3 border border-border/50 space-y-1">
          <span className="text-[10px] text-muted-foreground uppercase font-mono">Watchlisted</span>
          <div className="text-xl font-bold font-mono text-yellow-400">{watchlist.size}</div>
        </div>
        <div className="glass rounded-lg p-3 border border-border/50 space-y-1">
          <span className="text-[10px] text-muted-foreground uppercase font-mono">Critical & High</span>
          <div className="text-xl font-bold font-mono text-red-400">
            {threatIntelList.filter(t => t.severity === 'critical' || t.severity === 'high').length}
          </div>
        </div>
        <div className="glass rounded-lg p-3 border border-border/50 space-y-1">
          <span className="text-[10px] text-muted-foreground uppercase font-mono">Geolocated Peers</span>
          <div className="text-xl font-bold font-mono text-accent">
            {connections.filter(c => c.geo && c.geo.country_code !== 'LAN').length}
          </div>
        </div>
        <div className="glass rounded-lg p-3 border border-border/50 space-y-1 col-span-2 md:col-span-1">
          <span className="text-[10px] text-muted-foreground uppercase font-mono">Avg Confidence</span>
          <div className="text-xl font-bold font-mono text-green-400">
            {Math.round(threatIntelList.reduce((acc, curr) => acc + curr.confidence, 0) / (threatIntelList.length || 1))}%
          </div>
        </div>
      </div>

      {/* Real-Time Traffic Analytics Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Active Talkers Chart */}
        <div className="glass rounded-lg p-4 border border-border/50 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <Globe className="w-4 h-4 text-cyan-400" />
              Active Talkers (Live Packet Volume)
            </h3>
            <p className="text-[11px] text-muted-foreground mb-4">
              Busiest source & destination IP nodes in current traffic stream
            </p>
          </div>

          <div className="h-[180px] w-full">
            {trafficIpChartData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-muted-foreground">
                No active traffic data to analyze.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={trafficIpChartData} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" horizontal={false} />
                  <XAxis type="number" stroke="#555" style={{ fontSize: '10px' }} />
                  <YAxis dataKey="ip" type="category" stroke="#888" style={{ fontSize: '10px' }} width={100} />
                  <Tooltip
                    contentStyle={CustomTooltipStyle}
                    itemStyle={{ color: '#e2e8f0' }}
                    labelStyle={{ color: '#e2e8f0' }}
                  />
                  <Bar dataKey="count" name="Packets Count" fill="#06b6d4" radius={[0, 4, 4, 0]}>
                    {trafficIpChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fillOpacity={0.8 - index * 0.12} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Live Protocol Distribution Chart */}
        <div className="glass rounded-lg p-4 border border-border/50 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-accent" />
              Protocol Volume Distribution
            </h3>
            <p className="text-[11px] text-muted-foreground mb-4">
              Live volume breakdown by transport protocol
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-4 h-[180px]">
            <div className="w-full sm:w-[50%] h-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={trafficProtocolChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {trafficProtocolChartData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={entry.color}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={CustomTooltipStyle}
                    itemStyle={{ color: '#e2e8f0' }}
                    labelStyle={{ color: '#e2e8f0' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex-1 w-full space-y-2">
              {trafficProtocolChartData.map((item) => (
                <div key={item.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-2.5 h-2.5 rounded-full"
                      style={{
                        background: item.color
                      }}
                    />
                    <span className="text-muted-foreground font-medium">{item.name}</span>
                  </div>
                  <span className="font-mono text-foreground font-semibold">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Real-Time Network Traffic Audit */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden space-y-4 p-4">
        {/* Header Section */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/30 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Activity className={`w-4 h-4 text-accent ${isLive ? 'animate-pulse' : ''}`} />
              Real-Time Network Traffic Audit
            </h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              Live packet capture stream from interface telemetry and established sockets
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Live Indicator Badge */}
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono font-bold border transition-colors ${
              isLive 
                ? 'bg-green-500/10 text-green-400 border-green-500/20' 
                : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${isLive ? 'bg-green-400 animate-ping' : 'bg-yellow-400'}`} />
              {isLive ? 'LIVE' : 'PAUSED'}
            </div>

            {/* Play/Pause Button */}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsLive(!isLive)}
              className="h-8 text-xs border-border/50 flex items-center gap-1"
            >
              {isLive ? (
                <>
                  <Pause className="w-3 h-3 text-yellow-400" />
                  <span>Pause</span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3 text-green-400" />
                  <span>Resume</span>
                </>
              )}
            </Button>

            {/* Clear Button */}
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                useAppStore.setState({ networkTrafficLogs: [] });
                setDisplayedTrafficLogs([]);
                toast.info('Traffic console cleared');
              }}
              className="h-8 text-xs border-border/50 flex items-center gap-1 text-red-400 hover:text-red-300 hover:bg-red-950/20"
            >
              <Trash2 className="w-3 h-3" />
              <span>Clear</span>
            </Button>
          </div>
        </div>

        {/* Filter Controls Row */}
        <div className="flex flex-col sm:flex-row gap-2">
          {/* Traffic Search Input */}
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
            <Input
              placeholder="Filter by IP, Port, Protocol, or Info..."
              value={trafficSearch}
              onChange={(e) => setTrafficSearch(e.target.value)}
              className="pl-8 pr-8 bg-input border-border/50 text-xs h-8"
            />
            {trafficSearch && (
              <button
                onClick={() => setTrafficSearch('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Protocol Filter */}
          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value as any)}
            className="h-8 px-2.5 rounded-md border border-border/50 bg-input text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-accent min-w-[120px]"
          >
            <option value="all">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </div>

        {/* Terminal Logger Table */}
        <div className="border border-border/50 rounded-md overflow-hidden bg-black/40">
          <div className="overflow-x-auto">
            <div className="min-w-[900px]">
              {/* Header */}
              <div className="grid grid-cols-[140px_80px_180px_30px_180px_90px_1fr] gap-3 px-4 py-2 border-b border-border/50 text-[10px] text-muted-foreground font-semibold font-mono uppercase bg-card/60">
                <div>Timestamp (UTC)</div>
                <div>Proto</div>
                <div>Source (IP:Port)</div>
                <div className="text-center">Dir</div>
                <div>Destination (IP:Port)</div>
                <div className="text-right">Length (Bytes)</div>
                <div className="pl-2">Packet Summary / Flags</div>
              </div>

              {/* Console Rows */}
              <ScrollArea className="h-[480px]">
                <div className="divide-y divide-border/20 font-mono text-xs">
                  {filteredTraffic.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-center">
                      <Activity className="w-8 h-8 text-muted-foreground/40 mb-2 animate-pulse" />
                      <p className="text-xs font-semibold text-muted-foreground">No packets captured</p>
                      <p className="text-[11px] text-muted-foreground/60 mt-0.5">
                        Waiting for active network connections to transmit...
                      </p>
                    </div>
                  ) : (
                    [...filteredTraffic].reverse().map((pkt) => {
                      const protoColor = 
                        pkt.protocol === 'TCP' 
                          ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' 
                          : pkt.protocol === 'UDP' 
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/20';

                      return (
                        <div
                          key={pkt.id}
                          className="grid grid-cols-[140px_80px_180px_30px_180px_90px_1fr] gap-3 px-4 py-2.5 items-center hover:bg-white/[0.02] transition-colors"
                        >
                          {/* Timestamp */}
                          <div className="text-muted-foreground text-[11px]">
                            {new Date(pkt.timestamp).toLocaleTimeString('en', {
                              hour: '2-digit',
                              minute: '2-digit',
                              second: '2-digit',
                              fractionalSecondDigits: 3,
                              hour12: false
                            })}
                          </div>

                          {/* Protocol */}
                          <div>
                            <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-bold border ${protoColor}`}>
                              {pkt.protocol}
                            </span>
                          </div>

                          {/* Source Socket */}
                          <div className="truncate text-foreground/90 font-medium">
                            {pkt.src_ip}
                            <span className="text-muted-foreground/60">:{pkt.src_port}</span>
                          </div>

                          {/* Direction Arrow */}
                          <div className="text-center text-muted-foreground/60">→</div>

                          {/* Destination Socket */}
                          <div className="truncate text-foreground/90 font-medium">
                            {pkt.dst_ip}
                            <span className="text-muted-foreground/60">:{pkt.dst_port}</span>
                          </div>

                          {/* Length */}
                          <div className="text-right text-muted-foreground font-mono text-[11px]">
                            {pkt.length.toLocaleString()} B
                          </div>

                          {/* Details */}
                          <div className="pl-2 truncate text-muted-foreground hover:text-foreground transition-colors" title={pkt.info}>
                            {pkt.info}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </ScrollArea>
            </div>
          </div>
        </div>

        {/* Counter */}
        <div className="text-[10px] text-muted-foreground font-mono flex items-center justify-between">
          <div>
            Buffered: <span className="text-foreground font-semibold">{displayedTrafficLogs.length}/150</span> packets
          </div>
          <div>
            Showing: <span className="text-accent font-semibold">{filteredTraffic.length}</span> filtered packets
          </div>
        </div>
      </div>

      {/* Visual Analytics Charts Section (Moved for Threat Intel) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Geographic Threat Density Chart */}
        <div className="glass rounded-lg p-4 border border-border/50 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <Globe className="w-4 h-4 text-purple-400" />
              Geographic Network Density & Active Peers
            </h3>
            <p className="text-[11px] text-muted-foreground mb-4">
              Outbound connections and source origins correlated with known network indicators
            </p>
          </div>

          <div className="h-[180px] w-full">
            {geoChartData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-muted-foreground">
                No external peer locations detected.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={geoChartData} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" horizontal={false} />
                  <XAxis type="number" stroke="#555" style={{ fontSize: '10px' }} />
                  <YAxis dataKey="country" type="category" stroke="#888" style={{ fontSize: '10px' }} width={80} />
                  <Tooltip
                    contentStyle={CustomTooltipStyle}
                    itemStyle={{ color: '#e2e8f0' }}
                    labelStyle={{ color: '#e2e8f0' }}
                  />
                  <Bar dataKey="count" name="Network Matches" fill="#a855f7" radius={[0, 4, 4, 0]}>
                    {geoChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fillOpacity={0.8 - index * 0.12} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Threat Distribution Chart */}
        <div className="glass rounded-lg p-4 border border-border/50 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-accent" />
              Network Type Distribution
            </h3>
            <p className="text-[11px] text-muted-foreground mb-4">
              Breakdown of compiled network signals by tactical category
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-4 h-[180px]">
            <div className="w-full sm:w-[50%] h-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={threatTypeData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {threatTypeData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={CHART_COLORS[entry.name.toLowerCase() as keyof typeof CHART_COLORS] || '#8884d8'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={CustomTooltipStyle}
                    itemStyle={{ color: '#e2e8f0' }}
                    labelStyle={{ color: '#e2e8f0' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex-1 w-full space-y-2">
              {threatTypeData.map((item) => (
                <div key={item.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-2.5 h-2.5 rounded-full"
                      style={{
                        background: CHART_COLORS[item.name.toLowerCase() as keyof typeof CHART_COLORS] || '#8884d8'
                      }}
                    />
                    <span className="text-muted-foreground font-medium">{item.name}</span>
                  </div>
                  <span className="font-mono text-foreground font-semibold">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Advanced Filters & Search Bar */}
      <div className="space-y-3">
        {/* Type Filter Pills */}
        <div className="flex flex-wrap gap-2">
          {(['all', 'malware', 'ioc', 'vulnerability', 'campaign'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`h-7 px-3 rounded-full text-xs font-medium border transition-all duration-200 hover:scale-[1.01] active:scale-[0.97] ${
                typeFilter === t
                  ? 'bg-accent/20 text-accent border-accent/50'
                  : 'bg-transparent border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)}
              <span className="ml-1.5 opacity-60 font-mono text-[10px]">
                {counts[t as keyof typeof counts]}
              </span>
            </button>
          ))}
        </div>

        {/* Dynamic Filters Row */}
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search Input with Regex option */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
            <Input
              placeholder={
                isRegex
                  ? "Search using RegExp matching (e.g., ^185\\..*)..."
                  : "Search network indicator library or telemetry (IPs, campaigns)..."
              }
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-10 bg-input border-border/50 text-sm h-9"
            />
            <button
              onClick={() => setIsRegex(!isRegex)}
              className={`absolute right-2.5 top-1/2 -translate-y-1/2 h-5.5 px-1.5 rounded text-[10px] font-mono border transition-all duration-150 ${
                isRegex
                  ? 'bg-accent/20 text-accent border-accent/50 font-bold'
                  : 'bg-transparent text-muted-foreground border-border/30 hover:border-border/60'
              }`}
              title="Toggle Regular Expression Matching"
            >
              .*
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="h-9 px-3 rounded-md border border-border/50 bg-input text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-accent"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High & Above</option>
              <option value="medium">Medium & Above</option>
              <option value="low">Low & Above</option>
            </select>

            {/* Country Selector */}
            <select
              value={countryFilter}
              onChange={(e) => setCountryFilter(e.target.value)}
              className="h-9 px-3 rounded-md border border-border/50 bg-input text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-accent max-w-[150px]"
            >
              <option value="all">All Countries</option>
              {uniqueCountries.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>

            {/* Export Utilities */}
            <div className="flex items-center gap-1.5">
              <Button
                variant="outline"
                size="sm"
                onClick={exportCSV}
                className="h-9 text-xs border-border/50 flex items-center gap-1.5"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span>Export CSV</span>
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={exportJSON}
                className="h-9 text-xs border-border/50 flex items-center gap-1.5"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span>JSON</span>
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Feed Count */}
      <div className="text-xs text-muted-foreground flex items-center justify-between">
        <div>
          Showing <span className="text-foreground font-medium">{filtered.length}</span> network entries
        </div>
        {search && isRegex && (
          <div className="text-[10px] text-accent font-mono bg-accent/5 px-2 py-0.5 rounded border border-accent/20">
            Regex Mode Active
          </div>
        )}
      </div>

      {/* Intelligence Feed Section */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden">
        {/* Header Section */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/30 pb-3 px-4 pt-4">
          <div>
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Shield className="w-4 h-4 text-accent" />
              Active Network Signals & Threat Feed
            </h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              Correlated threat signals, active established connections, and indicators of compromise
            </p>
          </div>
        </div>
        {/* Table Header */}
        <div className="grid grid-cols-[30px_1fr_120px_100px_120px_150px_30px] gap-4 px-4 py-2.5 border-b border-border/50 text-xs text-muted-foreground font-medium bg-card/50">
          <div className="flex justify-center"></div>
          <div>Network Signal</div>
          <div>Type</div>
          <div>Severity</div>
          <div>Confidence</div>
          <div>Last Seen</div>
          <div className="flex justify-end"></div>
        </div>

        <ScrollArea className="h-64">
          <div className="divide-y divide-border/30">
            <AnimatePresence>
              {filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
                  <ShieldAlert className="w-8 h-8 text-muted-foreground/60 mb-2" />
                  <p className="text-sm font-semibold text-muted-foreground">No Network Indicator Matches Detected</p>
                  <p className="text-xs text-muted-foreground/80 mt-1 max-w-md">
                    No active outbound connections, geolocations, or indicators matched your current search filters.
                  </p>
                </div>
              ) : (
                filtered.map((intel, idx) => {
                  const isExpanded = expandedId === intel.id;
                  const isWatched = watchlist.has(intel.id);
                  return (
                    <motion.div
                      key={intel.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: Math.min(idx * 0.01, 0.2) }}
                      className="hover:bg-card/60 transition-colors"
                    >
                      {/* Row Item */}
                      <div
                        className="grid grid-cols-[30px_1fr_120px_100px_120px_150px_30px] gap-4 px-4 py-3 cursor-pointer items-center"
                        onClick={() => setExpandedId(isExpanded ? null : intel.id)}
                      >
                        <div className="flex items-center justify-center">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleWatchlist(intel.id, intel.title);
                            }}
                            className={`transition-colors p-1 rounded hover:bg-card/50 ${
                              isWatched ? 'text-yellow-400' : 'text-muted-foreground hover:text-yellow-400'
                            }`}
                          >
                            <Star className="w-3.5 h-3.5" fill={isWatched ? 'currentColor' : 'none'} />
                          </button>
                        </div>
                        <div className="min-w-0">
                          <p className="text-xs font-semibold text-foreground truncate">{intel.title}</p>
                          <p className="text-xs text-muted-foreground mt-0.5 truncate">{intel.description}</p>
                        </div>
                        <div>
                          <Badge className={`${TYPE_COLORS[intel.type]} text-xs uppercase font-mono`}>
                            {intel.type}
                          </Badge>
                        </div>
                        <div>
                          <Badge
                            className={`text-[10px] uppercase font-mono ${
                              intel.severity === 'critical'
                                ? 'bg-red-900/30 text-red-300 border-red-700/50'
                                : intel.severity === 'high'
                                ? 'bg-orange-900/30 text-orange-300 border-orange-700/50'
                                : intel.severity === 'medium'
                                ? 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50'
                                : 'bg-blue-900/30 text-blue-300 border-blue-700/50'
                            }`}
                          >
                            {intel.severity}
                          </Badge>
                        </div>
                        <div>
                          <div className="flex items-center gap-1.5">
                            <div className="flex-1 h-1.5 bg-card rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${
                                  intel.confidence > 90
                                    ? 'bg-red-500'
                                    : intel.confidence > 70
                                    ? 'bg-orange-500'
                                    : 'bg-yellow-500'
                                }`}
                                style={{ width: `${intel.confidence}%` }}
                              />
                            </div>
                            <span className="text-xs text-muted-foreground font-mono w-8">
                              {intel.confidence}%
                            </span>
                          </div>
                        </div>
                        <div>
                          <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
                            {new Date(intel.lastSeen).toLocaleString('en', {
                              month: 'short',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                              second: '2-digit',
                              hour12: false
                            })}
                          </span>
                        </div>
                        <div className="flex items-center justify-end">
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 text-muted-foreground" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-muted-foreground" />
                          )}
                        </div>
                      </div>

                      {/* Expanded Drawer */}
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="overflow-hidden border-t border-border/30 bg-card/30"
                          >
                            <div className="px-4 py-4 grid grid-cols-1 md:grid-cols-4 gap-4">
                              {/* Description */}
                              <div className="md:col-span-2 space-y-2">
                                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                                  Network Event Details & Logs
                                </h4>
                                <p className="text-xs text-foreground bg-card/60 p-3 rounded border border-border/30 whitespace-pre-wrap leading-relaxed">
                                  {intel.description}
                                </p>
                              </div>

                              {/* Indicators & Copy */}
                              <div className="space-y-2">
                                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                                  indicators
                                </h4>
                                <div className="space-y-1.5 max-h-32 overflow-y-auto pr-1">
                                  {intel.indicators.map((ioc) => {
                                    const isIP = ioc.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/);
                                    const lookupUrl = isIP
                                      ? `https://dnslytics.com/ip/${ioc}`
                                      : `https://dnslytics.com/search?q=${encodeURIComponent(ioc)}`;
                                    const country = getCountryForIP(ioc);

                                    return (
                                      <div
                                        key={ioc}
                                        className="flex items-center gap-1.5 text-xs font-mono text-accent/80 bg-accent/5 px-2 py-1.5 rounded border border-accent/20 hover:bg-accent/10 transition-colors"
                                      >
                                        <div className="min-w-0 flex-1">
                                          <p className="truncate font-semibold">{ioc}</p>
                                          {country && country !== 'Local Loopback' && (
                                            <p className="text-[9px] text-muted-foreground flex items-center gap-1 mt-0.5">
                                              <Globe className="w-2.5 h-2.5" />
                                              {country}
                                            </p>
                                          )}
                                        </div>
                                        <div className="flex items-center gap-1 shrink-0">
                                          <button
                                            onClick={(e) => handleCopyIoc(ioc, e)}
                                            className="p-1 text-muted-foreground hover:text-accent rounded hover:bg-card/50 transition-colors"
                                            title="Copy Indicator"
                                          >
                                            {copiedIoc === ioc ? (
                                              <Check className="w-3.5 h-3.5 text-green-400" />
                                            ) : (
                                              <Copy className="w-3.5 h-3.5" />
                                            )}
                                          </button>
                                          <a
                                            href={lookupUrl}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="p-1 text-muted-foreground hover:text-accent rounded hover:bg-card/50 transition-colors"
                                            title="External Lookup (DNSlytics)"
                                          >
                                            <ExternalLink className="w-3.5 h-3.5" />
                                          </a>
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>

                              {/* MITRE & Copilot AI Actions */}
                              <div className="space-y-4">
                                <div>
                                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                                    MITRE ATT&CK Mapping
                                  </h4>
                                  <div className="flex flex-wrap gap-1.5">
                                    {(MITRE_MAPPINGS[intel.type] || []).map((tactic) => (
                                      <Badge
                                        key={tactic}
                                        className="bg-purple-900/30 text-purple-300 border-purple-700/50 text-[10px] font-mono"
                                      >
                                        {tactic}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>

                                <div className="space-y-2">
                                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                                    Security Operations Actions
                                  </h4>
                                  <Button
                                    size="sm"
                                    onClick={() => handleAnalyzeWithCopilot(intel)}
                                    className="w-full text-xs h-7.5 bg-gradient-to-r from-cyan-900/40 to-blue-900/40 text-cyan-200 border border-cyan-700/50 hover:from-cyan-900/60 hover:to-blue-900/60 flex items-center justify-center gap-1.5 shadow-sm"
                                  >
                                    <Brain className="w-3.5 h-3.5 text-cyan-400" />
                                    <span>Ask Iris to Analyze</span>
                                  </Button>
                                  <Button
                                    size="sm"
                                    onClick={() => {
                                      useAppStore.getState().raiseIncidentAndCaptureForensics('network', intel);
                                      toast.success('Incident Created', {
                                        description: 'Network signal escalated and forensics captured.'
                                      });
                                    }}
                                    className="w-full text-xs h-7.5 bg-red-950/20 text-red-400 border border-red-800/40 hover:bg-red-950/40 flex items-center justify-center gap-1.5 shadow-sm"
                                  >
                                    <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
                                    <span>Raise as Incident</span>
                                  </Button>
                                  <div className="grid grid-cols-2 gap-2">
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      onClick={() => toggleWatchlist(intel.id, intel.title)}
                                      className={`text-xs h-7.5 ${
                                        isWatched
                                          ? 'bg-yellow-900/30 text-yellow-300 border border-yellow-700/50 hover:bg-yellow-900/40'
                                          : 'bg-accent/10 text-accent border border-accent/30 hover:bg-accent/20'
                                      }`}
                                    >
                                      <Star className="w-3.5 h-3.5 mr-1" fill={isWatched ? 'currentColor' : 'none'} />
                                      <span>Watchlist</span>
                                    </Button>
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      onClick={() => {
                                        toast.success('Hunt Query Created', {
                                          description: `Search query ready for indicator: ${intel.indicators[0]}`
                                        });
                                      }}
                                      className="text-xs h-7.5 border-border/50 hover:bg-card/50"
                                    >
                                      Create Hunt
                                    </Button>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })
              )}
            </AnimatePresence>
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}
