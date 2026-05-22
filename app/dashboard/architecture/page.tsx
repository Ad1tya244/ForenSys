'use client';

import { useState, useEffect } from 'react';
import { 
  Network, AlertTriangle, CheckCircle2, RefreshCw, Server, Shield, 
  Globe, Activity, Laptop, Database, Cpu, Terminal, Wifi, Play, 
  ArrowUpRight, BarChart3, Scan, ShieldAlert, LucideIcon
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppStore } from '@/lib/app-store';
import { toast } from 'sonner';

interface NetworkNode {
  id: string;
  label: string;
  type: 'internet' | 'firewall' | 'dmz' | 'server' | 'workstation' | 'database' | 'dc';
  status: 'healthy' | 'at-risk' | 'compromised';
  x: number;
  y: number;
  details: {
    ip: string;
    os: string;
    alerts: number;
    risk: number;
    extra?: Record<string, string>;
  };
}

interface NetworkEdge {
  from: string;
  to: string;
  label?: string;
  encrypted?: boolean;
}

const STATUS_COLORS: Record<string, string> = {
  healthy: '#22c55e',
  'at-risk': '#eab308',
  compromised: '#ef4444',
};

const TYPE_ICONS: Record<string, LucideIcon> = {
  internet: Globe,
  firewall: Shield,
  dmz: Activity,
  server: Server,
  workstation: Laptop,
  database: Database,
  dc: Cpu,
};

export default function ArchitecturePage() {
  const { 
    connections, 
    devices, 
    listeningPorts, 
    metrics, 
    alerts: rawAlerts, 
    raiseIncidentAndCaptureForensics 
  } = useAppStore();
  const alerts = rawAlerts.filter((a) => a.status !== 'resolved');
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);
  const [pinging, setPinging] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [scanningSubnet, setScanningSubnet] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) return null;

  // 1. Core host machine node
  const hostAlerts = alerts.filter(a => !a.affectedAssets.includes('remote') && a.affectedAssets.length > 0);
  const hostStatus = hostAlerts.some(a => a.severity === 'critical' || a.severity === 'high')
    ? 'compromised'
    : (hostAlerts.length > 0 ? 'at-risk' : 'healthy');

  const hostNode: NetworkNode = {
    id: 'host',
    label: metrics?.hostname || 'localhost',
    type: 'server',
    status: hostStatus,
    x: 400,
    y: 290,
    details: {
      ip: '127.0.0.1 (Local)',
      os: `${metrics?.platform || 'macOS'} (${metrics?.platform_version || 'Unknown OS Version'})`,
      alerts: hostAlerts.length,
      risk: hostAlerts.length > 0 ? Math.min(15 + hostAlerts.length * 15, 100) : 5,
      extra: {
        'Uptime': `${Math.round((metrics?.uptime_seconds || 0) / 3600)} hrs`,
        'CPU Usage': `${metrics?.cpu_percent || 0}%`,
        'RAM Usage': `${metrics?.memory_percent || 0}%`,
        'System Type': metrics?.platform || 'Host OS'
      }
    }
  };

  // 2. Gateway / Internet node
  const internetNode: NetworkNode = {
    id: 'internet',
    label: 'Internet Gateway',
    type: 'internet',
    status: 'healthy',
    x: 400,
    y: 70,
    details: {
      ip: '0.0.0.0/0 (Default Router)',
      os: 'WAN Gateway',
      alerts: 0,
      risk: 0,
      extra: {
        'Emerging Threats Feed': 'Connected',
        'Blocklist Size': `${metrics?.blocklist_size || 0} IPs`,
      }
    }
  };

  // 3. Listening services on host machine (Internal structures)
  const activeListening = listeningPorts.slice(0, 6);
  const listeningNodes: NetworkNode[] = activeListening.map((port, idx) => {
    const totalPorts = activeListening.length;
    // Semisphere arc around the host node (400, 290) pointing upwards
    const startAngle = -140 * (Math.PI / 180);
    const endAngle = -40 * (Math.PI / 180);
    const angleRange = endAngle - startAngle;
    const angle = totalPorts === 1 
      ? -Math.PI / 2 
      : startAngle + (idx / (totalPorts - 1)) * angleRange;
      
    const radius = 95;
    const x = Math.round(400 + radius * Math.cos(angle));
    const y = Math.round(290 + radius * Math.sin(angle));

    const portAlerts = alerts.filter(a => a.description.toLowerCase().includes(port.process.toLowerCase()));
    const status = portAlerts.some(a => a.severity === 'critical' || a.severity === 'high')
      ? 'compromised'
      : (portAlerts.length > 0 ? 'at-risk' : 'healthy');

    return {
      id: `port-${port.port}`,
      label: `${port.process}:${port.port}`,
      type: port.port === 8000 || port.port === 3000 ? 'server' : 'dmz',
      status,
      x,
      y,
      details: {
        ip: `${port.ip}:${port.port}`,
        os: `PID: ${port.pid || 'N/A'}`,
        alerts: portAlerts.length,
        risk: portAlerts.length > 0 ? Math.min(20 + portAlerts.length * 20, 100) : 10,
        extra: {
          'Owner Process': port.process,
          'PID': String(port.pid || 'Unknown'),
          'Socket IP': port.ip
        }
      }
    };
  });

  // 4. Remote Connected Hosts (via WAN)
  const remoteConns = connections
    .filter(c => c.remote_ip && c.remote_ip !== '127.0.0.1' && c.remote_ip !== '0.0.0.0')
    .filter((v, i, self) => self.findIndex(t => t.remote_ip === v.remote_ip) === i)
    .slice(0, 6);

  const remoteNodes: NetworkNode[] = remoteConns.map((conn, idx) => {
    const totalRemotes = remoteConns.length;
    const step = 560 / Math.max(1, totalRemotes - 1 || 1);
    const x = totalRemotes === 1 ? 400 : Math.round(120 + idx * step);
    const y = 140;

    const ipAlerts = alerts.filter(a => a.affectedAssets.includes(conn.remote_ip) || a.description.includes(conn.remote_ip));
    const isBlocklisted = alerts.some(a => a.description.includes(conn.remote_ip) && a.title.toLowerCase().includes('blocklist'));
    const status = isBlocklisted
      ? 'compromised'
      : (ipAlerts.length > 0 ? 'at-risk' : 'healthy');

    return {
      id: `ext-${conn.remote_ip}`,
      label: conn.geo?.city && conn.geo.city !== 'Unknown' ? conn.geo.city : conn.remote_ip,
      type: 'server',
      status,
      x,
      y,
      details: {
        ip: conn.remote_ip,
        os: conn.geo?.org || 'Remote Provider',
        alerts: ipAlerts.length,
        risk: isBlocklisted ? 95 : (ipAlerts.length > 0 ? 60 : 15),
        extra: {
          'Country': conn.geo?.country || 'Unknown Geolocation',
          'Protocol': conn.protocol,
          'Process': conn.process,
          'Remote Port': String(conn.remote_port)
        }
      }
    };
  });

  // 5. Discovered Local LAN Peers (ARP table)
  const lanDevices = devices
    .filter(d => d.ip !== '127.0.0.1')
    .slice(0, 6);

  const lanNodes: NetworkNode[] = lanDevices.map((device, idx) => {
    const totalDevices = lanDevices.length;
    const step = 560 / Math.max(1, totalDevices - 1 || 1);
    const x = totalDevices === 1 ? 400 : Math.round(120 + idx * step);
    const midIdx = (totalDevices - 1) / 2;
    const offset = Math.pow(idx - midIdx, 2) * 6;
    const y = Math.round(470 + offset);

    const deviceAlerts = alerts.filter(a => a.affectedAssets.includes(device.ip));
    const status = deviceAlerts.some(a => a.severity === 'critical' || a.severity === 'high')
      ? 'compromised'
      : (deviceAlerts.length > 0 ? 'at-risk' : 'healthy');

    return {
      id: `lan-${device.ip}`,
      label: device.hostname !== '?' ? device.hostname : device.ip,
      type: 'workstation',
      status,
      x,
      y,
      details: {
        ip: device.ip,
        os: 'Subnet Client',
        alerts: deviceAlerts.length,
        risk: deviceAlerts.length > 0 ? Math.min(25 + deviceAlerts.length * 20, 100) : 5,
        extra: {
          'MAC Address': device.mac,
          'Interface': device.interface,
          'Hostname Lookup': device.hostname
        }
      }
    };
  });

  // Combine NODES
  const NODES: NetworkNode[] = [
    hostNode,
    internetNode,
    ...listeningNodes,
    ...remoteNodes,
    ...lanNodes
  ];

  // Dynamic EDGES
  const EDGES: NetworkEdge[] = [];

  // Uplink from host to Internet gateway
  EDGES.push({
    from: 'host',
    to: 'internet',
    label: 'Uplink',
    encrypted: true
  });

  // Local ports to host node
  listeningNodes.forEach(n => {
    EDGES.push({
      from: 'host',
      to: n.id,
      encrypted: true
    });
  });

  // Internet gateway out to external IPs
  remoteNodes.forEach(rn => {
    const conn = remoteConns.find(c => c.remote_ip === rn.details.ip);
    const portLabel = conn ? `${conn.protocol}/${conn.remote_port}` : undefined;
    EDGES.push({
      from: 'internet',
      to: rn.id,
      label: portLabel,
      encrypted: conn?.protocol === 'TCP' && (conn?.remote_port === 443 || conn?.remote_port === 22)
    });
  });

  // Host to LAN peers
  lanNodes.forEach(ln => {
    const hasActiveConn = connections.some(c => c.remote_ip === ln.details.ip);
    EDGES.push({
      from: 'host',
      to: ln.id,
      label: hasActiveConn ? 'Active' : undefined,
      encrypted: false
    });
  });

  const viewBox = '0 0 800 560';

  const hoveredNode = NODES.find(n => n.id === hoveredId) || null;
  const selectedNode = NODES.find(n => n.id === selectedId) || null;
  const activeNode = selectedNode || hoveredNode;

  // Simulated Console Actions
  const handlePing = (ip: string) => {
    setPinging(true);
    toast.promise(
      new Promise((resolve) => setTimeout(resolve, 1200)),
      {
        loading: `ICMP Ping packets transmitting to node [${ip}]...`,
        success: () => {
          setPinging(false);
          return `Ping response from ${ip}: bytes=32 time=6ms TTL=64 (ONLINE)`;
        },
        error: () => {
          setPinging(false);
          return 'Host unreachable or filtering ICMP.';
        }
      }
    );
  };

  const handleCapture = (node: NetworkNode) => {
    setCapturing(true);
    toast.promise(
      new Promise((resolve, reject) => {
        setTimeout(() => {
          try {
            if (node.id === 'host') {
              raiseIncidentAndCaptureForensics('process', {
                pid: 1024,
                name: 'kernel_task',
                suspicious: node.status !== 'healthy',
                username: 'root',
                cpu_percent: metrics?.cpu_percent || 5,
                memory_percent: metrics?.memory_percent || 15,
                status: 'running'
              });
            } else if (node.id.startsWith('port-')) {
              const portNum = parseInt(node.id.replace('port-', ''));
              const portItem = listeningPorts.find(p => p.port === portNum);
              if (portItem) {
                raiseIncidentAndCaptureForensics('process', {
                  pid: portItem.pid || 4000,
                  name: portItem.process,
                  suspicious: node.status !== 'healthy',
                  username: 'root',
                  cpu_percent: 0.5,
                  memory_percent: 0.8,
                  status: 'listening'
                });
              } else {
                raiseIncidentAndCaptureForensics('process', {
                  pid: 9999,
                  name: node.label,
                  suspicious: true,
                  username: 'unknown',
                  cpu_percent: 0.1,
                  memory_percent: 0.1,
                  status: 'unknown'
                });
              }
            } else if (node.id.startsWith('ext-')) {
              const ipAddr = node.id.replace('ext-', '');
              const connItem = connections.find(c => c.remote_ip === ipAddr);
              if (connItem) {
                raiseIncidentAndCaptureForensics('connection', connItem);
              } else {
                raiseIncidentAndCaptureForensics('connection', {
                  protocol: 'TCP',
                  local_ip: '127.0.0.1',
                  local_port: 443,
                  remote_ip: ipAddr,
                  remote_port: 443,
                  state: 'ESTABLISHED',
                  process: 'unknown',
                  geo: { org: node.details.os, country: 'Unknown', city: node.label }
                });
              }
            } else if (node.id.startsWith('lan-')) {
              const ipAddr = node.id.replace('lan-', '');
              const devItem = devices.find(d => d.ip === ipAddr);
              if (devItem) {
                raiseIncidentAndCaptureForensics('network', {
                  title: `ANOMALOUS SUBNET ENDPOINT: ${devItem.hostname !== '?' ? devItem.hostname : devItem.ip}`,
                  severity: node.status === 'compromised' ? 'high' : 'medium',
                  description: `Subnet endpoint exhibiting unexpected activity. MAC: ${devItem.mac}, Interface: ${devItem.interface}`,
                  indicators: [devItem.ip, devItem.mac]
                });
              } else {
                raiseIncidentAndCaptureForensics('network', {
                  title: `ANOMALOUS SUBNET ENDPOINT: ${node.label}`,
                  severity: 'medium',
                  description: `Subnet endpoint at IP ${ipAddr} captured.`,
                  indicators: [ipAddr]
                });
              }
            } else {
              raiseIncidentAndCaptureForensics('network', {
                title: `MANUAL NETWORK CAPTURE: ${node.label}`,
                severity: 'low',
                description: `Manual capture triggered for endpoint node ${node.label} (${node.details.ip})`,
                indicators: [node.details.ip]
              });
            }
            resolve(true);
          } catch (err) {
            reject(err);
          }
        }, 1500);
      }),
      {
        loading: `Initializing packet capture filter [host ${node.details.ip}]...`,
        success: () => {
          setCapturing(false);
          return `Capture success! Forensic evidence sealed and logged in Incident Queue.`;
        },
        error: () => {
          setCapturing(false);
          return 'Capture error: filter expression syntax invalid.';
        }
      }
    );
  };

  const handleScanSubnet = () => {
    setScanningSubnet(true);
    toast.promise(
      new Promise((resolve) => setTimeout(resolve, 2000)),
      {
        loading: 'Scanning local network interfaces using ARP broadcast...',
        success: () => {
          setScanningSubnet(false);
          return `Subnet scan completed. Found ${devices.length} active devices.`;
        },
        error: () => {
          setScanningSubnet(false);
          return 'Subnet scan failed: Interface down.';
        }
      }
    );
  };

  const getSimulatedLogs = (node: NetworkNode) => {
    const logs = [];
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    if (node.status === 'compromised') {
      logs.push(`[${time}] SECURITY ALERT: Node compromised`);
      logs.push(`[${time}] Port scan pattern recognized on interface`);
      logs.push(`[${time}] Telemetry engine reported critical risk index: ${node.details.risk}%`);
      if (node.id.startsWith('ext-')) {
        logs.push(`[${time}] IP blocklisted in Emerging Threats database`);
      }
    } else if (node.status === 'at-risk') {
      logs.push(`[${time}] WARNING: Unusual outbound traffic payload detected`);
      logs.push(`[${time}] Keepalive delay exceeds baseline (82ms)`);
      if (node.id.startsWith('port-')) {
        logs.push(`[${time}] Socket backlog overflow threshold near limit`);
      }
    } else {
      logs.push(`[${time}] Connection status nominal`);
      if (node.id === 'host') {
        logs.push(`[${time}] Uptime state synchronized`);
        logs.push(`[${time}] Kernel socket scheduler running standard queue`);
      } else if (node.id === 'internet') {
        logs.push(`[${time}] Gateway status: online (10 Gbps duplex)`);
        logs.push(`[${time}] Blocklist database sync: SUCCESS`);
      } else if (node.id.startsWith('port-')) {
        logs.push(`[${time}] Listening socket accepts standard handshakes`);
        logs.push(`[${time}] TCP socket bound to localhost:${node.details.ip.split(':')[1]}`);
      } else {
        logs.push(`[${time}] Link nominal with response time: <2ms`);
      }
    }
    return logs;
  };

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* CSS Node transitions */}
      <style>{`
        .node-group {
          transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.2s ease-in-out;
        }
        @keyframes active-pulse {
          0%, 100% { stroke-width: 2.5px; stroke-opacity: 0.9; }
          50% { stroke-width: 4px; stroke-opacity: 0.35; }
        }
        .node-active {
          animation: active-pulse 2s infinite ease-in-out;
        }
      `}</style>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Network className="w-6 h-6 text-accent" />
            Network Architecture
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Interactive network topology map, active socket states, and subnet discovery</p>
        </div>
        <div className="flex items-center gap-3">
          {Object.entries({ healthy: '22c55e', 'at-risk': 'eab308', compromised: 'ef4444' }).map(([status, color]) => (
            <div key={status} className="flex items-center gap-1.5 text-xs text-muted-foreground font-mono">
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: `#${color}` }} />
              {status.toUpperCase()}
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* SVG Topology & LAN Discovery Row */}
        <div className="lg:col-span-3 space-y-4">
          <div className="glass rounded-lg border border-border/50 overflow-hidden relative bg-[#090d16]">
            {/* SVG Interactive Map */}
            <svg viewBox={viewBox} className="w-full" style={{ minHeight: 480 }}>
              {/* Grid Background */}
              <defs>
                <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                  <path d="M 30 0 L 0 0 0 30" fill="none" stroke="rgba(0,200,255,0.03)" strokeWidth="1" />
                </pattern>
                <radialGradient id="centralGlow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#00c8ff" stopOpacity="0.08" />
                  <stop offset="100%" stopColor="#00c8ff" stopOpacity="0" />
                </radialGradient>
              </defs>
              
              {/* Glow map */}
              <rect width="800" height="560" fill="url(#grid)" />
              <circle cx="400" cy="290" r="300" fill="url(#centralGlow)" />

              {/* Pulsing Concentric Radar Rings */}
              <circle cx="400" cy="290" r="100" fill="none" stroke="rgba(0, 200, 255, 0.04)" strokeWidth="1.5" />
              <circle cx="400" cy="290" r="200" fill="none" stroke="rgba(0, 200, 255, 0.03)" strokeWidth="1" />
              <circle cx="400" cy="290" r="300" fill="none" stroke="rgba(0, 200, 255, 0.02)" strokeWidth="1" />
              
              {/* Dynamic Zone Boundaries */}
              {/* WAN Zone */}
              <g>
                <rect x="25" y="20" width="750" height="150" rx="10" ry="10" fill="rgba(0, 200, 255, 0.01)" stroke="rgba(0, 200, 255, 0.06)" strokeWidth="1.2" strokeDasharray="5 5" />
                <text x="35" y="38" fill="rgba(0, 200, 255, 0.35)" fontSize="9" fontFamily="monospace" fontWeight="bold">ZONE: EXTERNAL WAN / EDGE NETWORK</text>
              </g>

              {/* Secure Host Zone */}
              <g>
                <rect x="25" y="185" width="750" height="240" rx="10" ry="10" fill="rgba(34, 197, 94, 0.005)" stroke="rgba(34, 197, 94, 0.05)" strokeWidth="1.2" strokeDasharray="5 5" />
                <text x="35" y="203" fill="rgba(34, 197, 94, 0.35)" fontSize="9" fontFamily="monospace" fontWeight="bold">ZONE: SECURE ENDPOINT / PRIVATE HOST</text>
              </g>

              {/* LAN Zone */}
              <g>
                <rect x="25" y="440" width="750" height="100" rx="10" ry="10" fill="rgba(139, 92, 246, 0.01)" stroke="rgba(139, 92, 246, 0.05)" strokeWidth="1.2" strokeDasharray="5 5" />
                <text x="35" y="458" fill="rgba(139, 92, 246, 0.35)" fontSize="9" fontFamily="monospace" fontWeight="bold">ZONE: TRUSTED SUBNET (INTRANET LAN)</text>
              </g>

              {/* Connection Edges */}
              {EDGES.map((edge) => {
                const from = NODES.find((n) => n.id === edge.from);
                const to = NODES.find((n) => n.id === edge.to);
                if (!from || !to) return null;

                const isAlerted = from.status === 'compromised' || to.status === 'compromised';
                const isSelected = selectedId === edge.from || selectedId === edge.to;
                const lineColor = isAlerted ? '#ef4444' : edge.encrypted ? '#00c8ff' : '#22c55e';
                
                return (
                  <g key={`${edge.from}-${edge.to}`}>
                    {/* Base link representation */}
                    <line
                      x1={from.x}
                      y1={from.y}
                      x2={to.x}
                      y2={to.y}
                      stroke={lineColor}
                      strokeWidth={isAlerted ? 2 : isSelected ? 1.8 : 1}
                      strokeDasharray={edge.encrypted ? '3 3' : undefined}
                      strokeOpacity={selectedId ? (isSelected ? 0.95 : 0.08) : 0.35}
                    />

                    {edge.label && (
                      <text
                        x={(from.x + to.x) / 2 + 8}
                        y={(from.y + to.y) / 2 - 4}
                        fill="#00c8ff"
                        fontSize={8}
                        fontFamily="monospace"
                        fontWeight="semibold"
                        opacity={selectedId ? (isSelected ? 0.95 : 0.05) : 0.4}
                      >
                        {edge.label}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Topology Nodes */}
              {NODES.map((node) => {
                const isActive = activeNode?.id === node.id;
                const NodeIcon = TYPE_ICONS[node.type] || Server;
                const statusColor = STATUS_COLORS[node.status];
                
                const isNodeSelectedOrNeighbor = !selectedId || selectedId === node.id || EDGES.some(edge => 
                  (edge.from === selectedId && edge.to === node.id) || 
                  (edge.to === selectedId && edge.from === node.id)
                );
                const isDimmed = selectedId !== null && !isNodeSelectedOrNeighbor;
                const isHovered = hoveredId === node.id;
                const isScaled = isHovered || (selectedId === node.id);
                const scale = isScaled ? (isDimmed ? 1.05 : 1.12) : 1;

                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y}) scale(${scale})`}
                    style={{ cursor: 'pointer', opacity: isDimmed ? 0.35 : 1 }}
                    className="node-group"
                    onMouseEnter={() => setHoveredId(node.id)}
                    onMouseLeave={() => setHoveredId(null)}
                    onClick={() => setSelectedId(selectedId === node.id ? null : node.id)}
                  >
                    {/* Glow outline ring */}
                    <circle
                      r={26}
                      fill="none"
                      stroke={statusColor}
                      strokeWidth={isActive ? 2.5 : 1}
                      strokeOpacity={isActive ? 0.8 : 0.15}
                      className={isActive ? 'node-active' : undefined}
                    />

                    {/* Node back-shadow */}
                    <circle
                      r={20}
                      fill="rgba(10, 16, 28, 0.95)"
                      stroke={statusColor}
                      strokeWidth={isActive ? 2 : 1.2}
                    />

                    {/* Centered Vector Icon */}
                    <foreignObject x={-11} y={-11} width={22} height={22} className="pointer-events-none">
                      <div className="flex items-center justify-center w-full h-full text-foreground">
                        <NodeIcon className="w-4 h-4" style={{ color: statusColor }} />
                      </div>
                    </foreignObject>

                    {/* Status Alert Indicator */}
                    {node.status !== 'healthy' && (
                      <circle 
                        cx={14} 
                        cy={-14} 
                        r={4.5} 
                        fill={statusColor} 
                        className="animate-pulse" 
                        stroke="rgba(0,0,0,0.5)" 
                        strokeWidth={1} 
                      />
                    )}

                    {/* Node Label Text */}
                    <text
                      textAnchor="middle"
                      y={34}
                      fill={isActive ? '#00c8ff' : '#9ca3af'}
                      fontSize={8.5}
                      fontFamily="monospace"
                      fontWeight={isActive ? 'bold' : 'normal'}
                      style={{ userSelect: 'none' }}
                    >
                      {node.label}
                    </text>
                  </g>
                );
              })}
            </svg>
            
            {NODES.length <= 2 && (
              <div className="absolute inset-0 flex items-center justify-center bg-background/50 backdrop-blur-[2px] pointer-events-none">
                <div className="text-center font-mono text-xs text-muted-foreground flex flex-col items-center gap-2">
                  <RefreshCw className="w-6 h-6 text-accent animate-spin" />
                  <span>AWAITING CORE TELEMETRY BROADCAST FEED...</span>
                </div>
              </div>
            )}
          </div>

          {/* ARP Devices List */}
          <div className="glass rounded-lg border border-border/50 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
                <Scan className="w-4 h-4 text-accent" />
                Subnet Network Map (ARP Lookup Cache)
              </h2>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground font-mono bg-accent/10 px-2 py-0.5 rounded border border-accent/20">
                  {devices.length} Devices Discovered
                </span>
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="h-7 text-[10px] font-mono px-2 gap-1 border-accent/30 text-accent hover:bg-accent/10"
                  onClick={handleScanSubnet}
                  disabled={scanningSubnet}
                >
                  <RefreshCw className={`w-3 h-3 ${scanningSubnet ? 'animate-spin' : ''}`} />
                  Scan Subnet
                </Button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {devices.map((device, i) => (
                <div 
                  key={i} 
                  onClick={() => setSelectedId(selectedId === `lan-${device.ip}` ? null : `lan-${device.ip}`)}
                  className={`p-2.5 rounded border cursor-pointer transition-all flex items-center gap-3 ${
                    selectedId === `lan-${device.ip}`
                      ? 'border-accent bg-accent/10 shadow-[0_0_12px_rgba(0,200,255,0.05)]'
                      : 'bg-card/30 border-border/50 hover:border-border hover:bg-card/50'
                  }`}
                >
                  <div className="w-8 h-8 rounded-full bg-accent/10 flex items-center justify-center shrink-0 border border-accent/20">
                    <Laptop className="w-4 h-4 text-accent" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-bold text-foreground truncate">{device.hostname !== '?' ? device.hostname : 'Host Endpoint'}</p>
                    <p className="text-[10px] text-muted-foreground font-mono truncate">{device.ip}</p>
                    <p className="text-[9px] text-muted-foreground/60 font-mono truncate">MAC: {device.mac}</p>
                  </div>
                </div>
              ))}
              {devices.length === 0 && (
                <div className="col-span-full py-8 text-center text-xs text-muted-foreground font-mono flex flex-col items-center justify-center gap-1">
                  <Wifi className="w-6 h-6 text-muted-foreground opacity-30 animate-pulse" />
                  <span>[SCANNING ARP TARGETS ON LOCAL NETWORK INTERFACE...]</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Node Details Panel */}
        <div className="glass rounded-lg border border-border/50 p-4 space-y-4 h-fit">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
            <BarChart3 className="w-4 h-4 text-accent" />
            Asset Details
          </h2>
          
          {!activeNode ? (
            <div className="text-center py-12 space-y-2">
              <Network className="w-8 h-8 text-muted-foreground/30 mx-auto" />
              <p className="text-xs text-muted-foreground">Select any terminal node inside the network map to run hardware diagnostics.</p>
            </div>
          ) : (
            <motion.div
              key={activeNode.id}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-4"
            >
              {/* Asset Header info */}
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-card/60 border border-border/60 flex items-center justify-center text-accent">
                  {(() => {
                    const Icon = TYPE_ICONS[activeNode.type] || Server;
                    return <Icon className="w-5 h-5" style={{ color: STATUS_COLORS[activeNode.status] }} />;
                  })()}
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-bold text-foreground truncate max-w-[150px]" title={activeNode.label}>{activeNode.label}</p>
                  <p className="text-xs text-muted-foreground uppercase font-mono tracking-wider">{activeNode.type}</p>
                </div>
              </div>

              {/* Status Badge */}
              <div className="w-full">
                <Badge
                  className={`w-full py-1 justify-center gap-1.5 border text-xs font-mono font-bold capitalize ${
                    activeNode.status === 'healthy'
                      ? 'bg-green-900/20 text-green-400 border-green-700/30'
                      : activeNode.status === 'at-risk'
                      ? 'bg-yellow-900/20 text-yellow-400 border-yellow-700/30'
                      : 'bg-red-900/20 text-red-400 border-red-700/30'
                  }`}
                  variant="outline"
                >
                  {activeNode.status === 'compromised' ? (
                    <><ShieldAlert className="w-3.5 h-3.5" /> COMPROMISED / INCIDENT</>
                  ) : activeNode.status === 'at-risk' ? (
                    <><AlertTriangle className="w-3.5 h-3.5" /> AT RISK</>
                  ) : (
                    <><CheckCircle2 className="w-3.5 h-3.5" /> NOMINAL STATUS</>
                  )}
                </Badge>
              </div>

              {/* Circular Threat Index Meter */}
              <div className="flex items-center gap-3.5 p-3 bg-card/30 rounded-lg border border-border/40">
                <div className="relative w-12 h-12 shrink-0">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle cx="24" cy="24" r="20" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="3" />
                    <circle 
                      cx="24" 
                      cy="24" 
                      r="20" 
                      fill="none" 
                      stroke={activeNode.details.risk > 70 ? '#ef4444' : activeNode.details.risk > 40 ? '#eab308' : '#22c55e'} 
                      strokeWidth="3" 
                      strokeDasharray={`${2 * Math.PI * 20}`}
                      strokeDashoffset={`${2 * Math.PI * 20 * (1 - activeNode.details.risk / 100)}`}
                      className="transition-all duration-1000 ease-out"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center text-[10px] font-bold font-mono">
                    {activeNode.details.risk}%
                  </div>
                </div>
                <div className="min-w-0">
                  <h4 className="text-xs font-semibold text-foreground">Threat Index</h4>
                  <p className="text-[9px] text-muted-foreground mt-0.5 leading-snug">Vulnerability risk score assigned to link endpoint.</p>
                </div>
              </div>
              
              {/* Technical Specifications */}
              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between items-center p-2 bg-card/40 rounded border border-border/40">
                  <span className="text-[10px] text-muted-foreground uppercase">IP Address</span>
                  <span className="text-foreground">{activeNode.details.ip}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-card/40 rounded border border-border/40">
                  <span className="text-[10px] text-muted-foreground uppercase font-sans">OS / Classification</span>
                  <span className="text-foreground truncate max-w-[130px]" title={activeNode.details.os}>{activeNode.details.os}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-card/40 rounded border border-border/40">
                  <span className="text-[10px] text-muted-foreground uppercase">Active Alerts</span>
                  <span className={`font-bold ${activeNode.details.alerts > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>{activeNode.details.alerts}</span>
                </div>

                {activeNode.details.extra && Object.entries(activeNode.details.extra).map(([k, v]) => (
                  <div key={k} className="flex justify-between items-center p-2 bg-card/40 rounded border border-border/40">
                    <span className="text-[10px] text-muted-foreground uppercase">{k}</span>
                    <span className="text-foreground truncate max-w-[130px]" title={v}>{v}</span>
                  </div>
                ))}
              </div>

              {/* Live Simulated Traffic Telemetry */}
              <div className="space-y-1.5">
                <h4 className="text-[10px] font-bold text-muted-foreground uppercase tracking-wide">Live Transmissions</h4>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <div className="p-2 bg-card/30 rounded border border-border/30">
                    <span className="text-[9px] text-muted-foreground block uppercase font-sans">Tx Packets</span>
                    <span className="text-accent font-semibold">
                      {activeNode.id === 'host' 
                        ? `${(metrics?.bytes_sent ? (metrics.bytes_sent / 1024 / 1024).toFixed(1) : 4.1)} MB/s` 
                        : `${(activeNode.details.risk * 0.12 + 0.1).toFixed(1)} KB/s`}
                    </span>
                  </div>
                  <div className="p-2 bg-card/30 rounded border border-border/30">
                    <span className="text-[9px] text-muted-foreground block uppercase font-sans">Rx Packets</span>
                    <span className="text-accent font-semibold">
                      {activeNode.id === 'host' 
                        ? `${(metrics?.bytes_recv ? (metrics.bytes_recv / 1024 / 1024).toFixed(1) : 12.8)} MB/s` 
                        : `${(activeNode.details.risk * 0.45 + 0.5).toFixed(1)} KB/s`}
                    </span>
                  </div>
                </div>
              </div>

              {/* Console logs */}
              <div className="space-y-1.5">
                <h4 className="text-[10px] font-bold text-muted-foreground uppercase tracking-wide flex items-center gap-1">
                  <Terminal className="w-3.5 h-3.5 text-accent" /> Console activity logs
                </h4>
                <div className="p-2 bg-black/60 rounded border border-border/40 font-mono text-[9px] text-foreground/80 space-y-1 select-none">
                  {getSimulatedLogs(activeNode).map((log, index) => (
                    <div key={index} className="truncate select-text selection:bg-accent/30">
                      <span className="text-accent/60">//</span> {log}
                    </div>
                  ))}
                </div>
              </div>

              {/* Operations Quick Actions */}
              <div className="border-t border-border/50 pt-3.5 space-y-2">
                <h4 className="text-[10px] font-bold text-muted-foreground uppercase tracking-wide">Interface Actions</h4>
                <div className="grid grid-cols-2 gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 text-xs border-border/40 gap-1 bg-background/50 hover:bg-accent/10 hover:text-accent"
                    onClick={() => handlePing(activeNode.details.ip)}
                    disabled={pinging}
                  >
                    <ArrowUpRight className="w-3.5 h-3.5" />
                    Ping Target
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 text-xs border-border/40 gap-1 bg-background/50 hover:bg-accent/10 hover:text-accent"
                    onClick={() => handleCapture(activeNode)}
                    disabled={capturing}
                  >
                    <Play className="w-3 h-3" />
                    Capture
                  </Button>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}
