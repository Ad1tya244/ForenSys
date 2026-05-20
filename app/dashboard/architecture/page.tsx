'use client';

import { useState, useEffect } from 'react';
import { Network, AlertTriangle, CheckCircle2, RefreshCw, Cpu, Server } from 'lucide-react';
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
  };
}

interface NetworkEdge {
  from: string;
  to: string;
  label?: string;
  encrypted?: boolean;
}

const NODES: NetworkNode[] = [
  { id: 'internet', label: 'Internet', type: 'internet', status: 'healthy', x: 400, y: 30, details: { ip: '0.0.0.0/0', os: 'N/A', alerts: 0, risk: 0 } },
  { id: 'fw1', label: 'Perimeter FW', type: 'firewall', status: 'healthy', x: 400, y: 110, details: { ip: '203.0.113.1', os: 'FortiOS 7.2', alerts: 3, risk: 15 } },
  { id: 'web', label: 'WEBSERVER-01', type: 'server', status: 'compromised', x: 200, y: 210, details: { ip: '10.1.1.10', os: 'Ubuntu 22.04', alerts: 23, risk: 87 } },
  { id: 'vpn', label: 'VPN-GW-01', type: 'server', status: 'healthy', x: 400, y: 210, details: { ip: '10.1.1.5', os: 'Cisco IOS', alerts: 2, risk: 18 } },
  { id: 'mail', label: 'MAILSERVER-01', type: 'server', status: 'at-risk', x: 600, y: 210, details: { ip: '10.1.1.20', os: 'Windows Server 2022', alerts: 9, risk: 52 } },
  { id: 'fw2', label: 'Internal FW', type: 'firewall', status: 'healthy', x: 400, y: 310, details: { ip: '10.2.0.1', os: 'Palo Alto PAN-OS', alerts: 1, risk: 10 } },
  { id: 'dc', label: 'DOMAIN-CTRL', type: 'dc', status: 'at-risk', x: 200, y: 410, details: { ip: '10.2.1.1', os: 'Windows Server 2022', alerts: 19, risk: 94 } },
  { id: 'app', label: 'APPSERVER-03', type: 'server', status: 'healthy', x: 400, y: 410, details: { ip: '10.2.1.30', os: 'RHEL 8', alerts: 4, risk: 24 } },
  { id: 'db', label: 'DBSERVER-02', type: 'database', status: 'healthy', x: 600, y: 410, details: { ip: '10.2.1.50', os: 'Ubuntu 22.04', alerts: 6, risk: 32 } },
  { id: 'ws1', label: 'WORKSTATION-43', type: 'workstation', status: 'compromised', x: 130, y: 510, details: { ip: '10.2.2.43', os: 'Windows 10', alerts: 15, risk: 78 } },
  { id: 'ws2', label: 'LAPTOP-USER-22', type: 'workstation', status: 'healthy', x: 280, y: 510, details: { ip: '10.2.2.22', os: 'macOS Ventura', alerts: 1, risk: 8 } },
  { id: 'file', label: 'FILESERVER-05', type: 'server', status: 'at-risk', x: 540, y: 510, details: { ip: '10.2.1.60', os: 'Windows Server 2019', alerts: 12, risk: 65 } },
];

const EDGES: NetworkEdge[] = [
  { from: 'internet', to: 'fw1' },
  { from: 'fw1', to: 'web', label: '80/443' },
  { from: 'fw1', to: 'vpn', label: '443' },
  { from: 'fw1', to: 'mail', label: '25/587' },
  { from: 'web', to: 'fw2' },
  { from: 'vpn', to: 'fw2' },
  { from: 'mail', to: 'fw2' },
  { from: 'fw2', to: 'dc', encrypted: true },
  { from: 'fw2', to: 'app', encrypted: true },
  { from: 'fw2', to: 'db', encrypted: true },
  { from: 'dc', to: 'ws1' },
  { from: 'dc', to: 'ws2' },
  { from: 'app', to: 'db' },
  { from: 'dc', to: 'file' },
];

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
  const { devices } = useAppStore();
  const [hovered, setHovered] = useState<NetworkNode | null>(null);
  const [selected, setSelected] = useState<NetworkNode | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const viewBox = '0 0 800 560';
  const activeNode = selected || hovered;

  if (!mounted) return null;

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
          <div className="glass rounded-lg border border-border/50 overflow-hidden">
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
                const from = NODES.find((n) => n.id === edge.from)!;
                const to = NODES.find((n) => n.id === edge.to)!;
                const isAlerted =
                  NODES.find((n) => n.id === edge.from)?.status === 'compromised' ||
                  NODES.find((n) => n.id === edge.to)?.status === 'compromised';
                return (
                  <g key={`${edge.from}-${edge.to}`}>
                    <line
                      x1={from.x}
                      y1={from.y}
                      x2={to.x}
                      y2={to.y}
                      stroke={isAlerted ? '#ef4444' : edge.encrypted ? '#00c8ff' : 'rgba(255,255,255,0.2)'}
                      strokeWidth={isAlerted ? 2 : 1}
                      strokeDasharray={edge.encrypted ? '4 3' : undefined}
                      strokeOpacity={0.6}
                    />
                    {edge.label && (
                      <text
                        x={(from.x + to.x) / 2 + 4}
                        y={(from.y + to.y) / 2 - 4}
                        fill="#666"
                        fontSize={8}
                        fontFamily="monospace"
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
                const typeInfo = TYPE_SHAPES[node.type];
                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    style={{ cursor: 'pointer' }}
                    onMouseEnter={() => setHovered(node)}
                    onMouseLeave={() => setHovered(null)}
                    onClick={() => setSelected(selected?.id === node.id ? null : node)}
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
                      strokeWidth={isActive ? 2 : 1.5}
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
                      y={26}
                      fill={isActive ? '#e2e8f0' : '#9ca3af'}
                      fontSize={9}
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
                <div key={i} className="p-2.5 bg-card/40 rounded border border-border/50 flex items-center gap-3">
                  <Server className="w-5 h-5 text-accent flex-shrink-0" />
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-foreground truncate">{device.hostname}</p>
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
              <p className="text-xs text-muted-foreground">Hover a node to inspect</p>
            </div>
          ) : (
            <motion.div
              key={activeNode.id}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-3"
            >
              <div className="flex items-center gap-2">
                <span className="text-xl">{TYPE_SHAPES[activeNode.type].emoji}</span>
                <div>
                  <p className="text-sm font-bold text-foreground">{activeNode.label}</p>
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
                  <><AlertTriangle className="w-3 h-3 mr-1" /> Compromised</>
                ) : activeNode.status === 'at-risk' ? (
                  <><AlertTriangle className="w-3 h-3 mr-1" /> At Risk</>
                ) : (
                  <><CheckCircle2 className="w-3 h-3 mr-1" /> Healthy</>
                )}
              </Badge>
              <div className="space-y-1.5 text-xs">
                {[
                  { label: 'IP Address', value: activeNode.details.ip },
                  { label: 'OS', value: activeNode.details.os },
                  { label: 'Active Alerts', value: String(activeNode.details.alerts) },
                ].map((row) => (
                  <div key={row.label} className="flex justify-between items-center p-2 bg-card/50 rounded border border-border/50">
                    <span className="text-muted-foreground">{row.label}</span>
                    <span className="font-mono text-foreground">{row.value}</span>
                  </div>
                ))}
                <div className="p-2 bg-card/50 rounded border border-border/50">
                  <div className="flex justify-between mb-1">
                    <span className="text-muted-foreground">Risk Score</span>
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
