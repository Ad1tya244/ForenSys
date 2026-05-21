'use client';

import { useState, useEffect } from 'react';
import { Network, AlertTriangle, CheckCircle2, RefreshCw, Server, Shield, Globe, Activity } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { motion } from 'framer-motion';
import { useAppStore } from '@/lib/app-store';

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

const TYPE_SHAPES: Record<string, { emoji: string; color: string }> = {
  internet: { emoji: '🌐', color: '#555' },
  firewall: { emoji: '🔥', color: '#f97316' },
  dmz: { emoji: '🛡️', color: '#00c8ff' },
  server: { emoji: '🖥️', color: '#3b82f6' },
  workstation: { emoji: '💻', color: '#8b5cf6' },
  database: { emoji: '🗄️', color: '#06b6d4' },
  dc: { emoji: '🏛️', color: '#f59e0b' },
};

export default function ArchitecturePage() {
  const { connections, devices, listeningPorts, metrics, alerts } = useAppStore();
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

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
    y: 280,
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
    y: 50,
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
    // Semisphere arc around the host node (400, 280) between -135deg and -45deg
    const startAngle = -135 * (Math.PI / 180);
    const endAngle = -45 * (Math.PI / 180);
    const angleRange = endAngle - startAngle;
    const angle = totalPorts === 1 
      ? -Math.PI / 2 
      : startAngle + (idx / (totalPorts - 1)) * angleRange;
      
    const radius = 100;
    const x = Math.round(400 + radius * Math.cos(angle));
    const y = Math.round(280 + radius * Math.sin(angle));

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
    // Spaced out horizontally at y = 140
    const step = 500 / Math.max(1, totalRemotes - 1 || 1);
    const x = totalRemotes === 1 ? 400 : Math.round(150 + idx * step);
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
    // Arc at the bottom y = 460-500
    const step = 500 / Math.max(1, totalDevices - 1 || 1);
    const x = totalDevices === 1 ? 400 : Math.round(150 + idx * step);
    const midIdx = (totalDevices - 1) / 2;
    const offset = Math.pow(idx - midIdx, 2) * 8;
    const y = Math.round(460 + offset);

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
      encrypted: true // Represented as dashed
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

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Network className="w-6 h-6 text-accent" />
            Network Architecture
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Interactive topology view and live local discovered LAN endpoints</p>
        </div>
        <div className="flex items-center gap-3">
          {Object.entries({ healthy: '22c55e', 'at-risk': 'eab308', compromised: 'ef4444' }).map(([status, color]) => (
            <div key={status} className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: `#${color}` }} />
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* SVG Topology & LAN Discovery Row */}
        <div className="lg:col-span-3 space-y-4">
          <div className="glass rounded-lg border border-border/50 overflow-hidden relative">
            <svg viewBox={viewBox} className="w-full" style={{ minHeight: 400 }}>
              {/* Grid background */}
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(0,200,255,0.04)" strokeWidth="1" />
                </pattern>
              </defs>
              <rect width="800" height="560" fill="url(#grid)" />

              {/* Edges */}
              {EDGES.map((edge) => {
                const from = NODES.find((n) => n.id === edge.from);
                const to = NODES.find((n) => n.id === edge.to);
                if (!from || !to) return null;

                const isAlerted = from.status === 'compromised' || to.status === 'compromised';
                const isSelected = selectedId === edge.from || selectedId === edge.to;
                
                return (
                  <g key={`${edge.from}-${edge.to}`}>
                    <line
                      x1={from.x}
                      y1={from.y}
                      x2={to.x}
                      y2={to.y}
                      stroke={isAlerted ? '#ef4444' : edge.encrypted ? '#00c8ff' : 'rgba(255,255,255,0.2)'}
                      strokeWidth={isAlerted ? 2.5 : isSelected ? 2 : 1}
                      strokeDasharray={edge.encrypted ? '4 3' : undefined}
                      strokeOpacity={isSelected ? 0.9 : 0.6}
                    />
                    {edge.label && (
                      <text
                        x={(from.x + to.x) / 2 + 6}
                        y={(from.y + to.y) / 2 - 4}
                        fill="#00c8ff"
                        fontSize={8}
                        fontFamily="monospace"
                        fontWeight="semibold"
                        opacity={0.8}
                      >
                        {edge.label}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Nodes */}
              {NODES.map((node) => {
                const isActive = activeNode?.id === node.id;
                const typeInfo = TYPE_SHAPES[node.type] || { emoji: '🖥️', color: '#3b82f6' };
                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    style={{ cursor: 'pointer' }}
                    onMouseEnter={() => setHoveredId(node.id)}
                    onMouseLeave={() => setHoveredId(null)}
                    onClick={() => setSelectedId(selectedId === node.id ? null : node.id)}
                  >
                    {/* Glow ring for compromised */}
                    {node.status === 'compromised' && (
                      <circle r={22} fill="none" stroke="#ef4444" strokeWidth={2} opacity={0.4}>
                        <animate attributeName="r" values="18;24;18" dur="2s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.5;0.1;0.5" dur="2s" repeatCount="indefinite" />
                      </circle>
                    )}

                    {/* Node circle */}
                    <circle
                      r={18}
                      fill={isActive ? `${STATUS_COLORS[node.status]}22` : 'rgba(15,23,42,0.9)'}
                      stroke={isActive ? STATUS_COLORS[node.status] : `${STATUS_COLORS[node.status]}88`}
                      strokeWidth={isActive ? 2.5 : 1.5}
                    />

                    {/* Status dot */}
                    <circle cx={13} cy={-13} r={5} fill={STATUS_COLORS[node.status]} />

                    {/* Emoji icon */}
                    <text textAnchor="middle" dominantBaseline="middle" fontSize={14} style={{ userSelect: 'none' }}>
                      {typeInfo.emoji}
                    </text>

                    {/* Label */}
                    <text
                      textAnchor="middle"
                      y={28}
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
              <div className="absolute inset-0 flex items-center justify-center bg-background/40 backdrop-blur-[1px] pointer-events-none">
                <p className="text-xs text-muted-foreground font-mono">[WAITING FOR BACKEND WEBSOCKET FEED...]</p>
              </div>
            )}
          </div>

          {/* ARP Devices List */}
          <div className="glass rounded-lg border border-border/50 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
                <RefreshCw className="w-4 h-4 text-accent animate-spin-slow" />
                Live LAN Discovered Devices (ARP Cache Scan)
              </h2>
              <span className="text-xs text-muted-foreground font-mono">{devices.length} Devices Discovered</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {devices.map((device, i) => (
                <div 
                  key={i} 
                  onClick={() => setSelectedId(selectedId === `lan-${device.ip}` ? null : `lan-${device.ip}`)}
                  className={`p-2.5 rounded border cursor-pointer transition-all flex items-center gap-3 ${
                    selectedId === `lan-${device.ip}`
                      ? 'border-accent bg-accent/15'
                      : 'bg-card/40 border-border/50 hover:border-border'
                  }`}
                >
                  <Server className="w-5 h-5 text-accent shrink-0" />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-bold text-foreground truncate">{device.hostname !== '?' ? device.hostname : 'Host IP'}</p>
                    <p className="text-[10px] text-muted-foreground font-mono truncate">{device.ip}</p>
                    <p className="text-[9px] text-muted-foreground font-mono truncate">MAC: {device.mac}</p>
                  </div>
                </div>
              ))}
              {devices.length === 0 && (
                <div className="col-span-full py-8 text-center text-xs text-muted-foreground font-mono">
                  [SCANNING ARP TABLE FOR LOCAL NETWORK PEERS...]
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Node Details Panel */}
        <div className="glass rounded-lg border border-border/50 p-4 space-y-4 h-fit">
          <h2 className="text-sm font-semibold text-foreground">Node Details</h2>
          {!activeNode ? (
            <div className="text-center py-8">
              <Network className="w-6 h-6 text-muted-foreground mx-auto mb-2" />
              <p className="text-xs text-muted-foreground">Hover or click a node in the diagram to inspect details</p>
            </div>
          ) : (
            <motion.div
              key={activeNode.id}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-3"
            >
              <div className="flex items-center gap-2">
                <span className="text-xl">{(TYPE_SHAPES[activeNode.type] || { emoji: '🖥️' }).emoji}</span>
                <div>
                  <p className="text-sm font-bold text-foreground truncate max-w-[180px]">{activeNode.label}</p>
                  <p className="text-xs text-muted-foreground capitalize">{activeNode.type}</p>
                </div>
              </div>
              <Badge
                className={
                  activeNode.status === 'healthy'
                    ? 'bg-green-900/30 text-green-300 border-green-700/50'
                    : activeNode.status === 'at-risk'
                    ? 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50'
                    : 'bg-red-900/30 text-red-300 border-red-700/50'
                }
              >
                {activeNode.status === 'compromised' ? (
                  <><AlertTriangle className="w-3 h-3 mr-1" /> Compromised / Alerted</>
                ) : activeNode.status === 'at-risk' ? (
                  <><AlertTriangle className="w-3 h-3 mr-1" /> At Risk</>
                ) : (
                  <><CheckCircle2 className="w-3 h-3 mr-1" /> Healthy</>
                )}
              </Badge>
              
              <div className="space-y-1.5 text-xs">
                <div className="flex justify-between items-center p-2 bg-card/50 rounded border border-border/50">
                  <span className="text-muted-foreground">IP Address</span>
                  <span className="font-mono text-foreground">{activeNode.details.ip}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-card/50 rounded border border-border/50">
                  <span className="text-muted-foreground">OS / Classification</span>
                  <span className="font-mono text-foreground truncate max-w-[150px]">{activeNode.details.os}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-card/50 rounded border border-border/50">
                  <span className="text-muted-foreground">Active Alerts</span>
                  <span className="font-mono text-foreground font-bold">{activeNode.details.alerts}</span>
                </div>

                {activeNode.details.extra && Object.entries(activeNode.details.extra).map(([k, v]) => (
                  <div key={k} className="flex justify-between items-center p-2 bg-card/50 rounded border border-border/50">
                    <span className="text-muted-foreground">{k}</span>
                    <span className="font-mono text-foreground truncate max-w-[140px]" title={v}>{v}</span>
                  </div>
                ))}

                <div className="p-2 bg-card/50 rounded border border-border/50">
                  <div className="flex justify-between mb-1">
                    <span className="text-muted-foreground">Risk Level</span>
                    <span className={`font-mono font-bold ${
                      activeNode.details.risk > 70 ? 'text-red-400' :
                      activeNode.details.risk > 40 ? 'text-yellow-400' : 'text-green-400'
                    }`}>
                      {activeNode.details.risk}%
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-card rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${activeNode.details.risk}%` }}
                      className={`h-full rounded-full ${
                        activeNode.details.risk > 70 ? 'bg-red-500' :
                        activeNode.details.risk > 40 ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                    />
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
