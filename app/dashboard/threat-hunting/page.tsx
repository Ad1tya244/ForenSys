'use client';

import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
  Target,
  Search,
  Play,
  Loader2,
  CheckCircle2,
  XCircle,
  Terminal,
  Plus,
  RefreshCw,
  Trash2,
  Download,
  ShieldAlert,
  Layers,
  Globe,
  Activity,
  ArrowUpRight,
  Database,
  Cpu,
  FileText,
  Sliders,
  X,
  ChevronRight,
  Info,
  ExternalLink,
  ShieldCheck
} from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useAppStore, RealProcess, NetworkConnection, LogEntry } from '@/lib/app-store';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';

// ── Search Terms Types ────────────────────────────────────────────────────────
interface SearchTerm {
  category?: 'process' | 'connection' | 'log' | 'port';
  field?: string;
  operator: 'contains' | 'equals' | 'not_equals' | 'greater_than' | 'less_than';
  value: string;
  isNegated: boolean;
}

interface QueryCondition {
  id: string;
  channel: 'process' | 'connection' | 'log' | 'port';
  field: string;
  operator: string;
  value: string;
}

// ── Pre-built Playbooks ───────────────────────────────────────────────────────
const PRE_BUILT_QUERIES = [
  {
    id: 'q1',
    name: 'Suspicious Terminal Shells',
    description: 'Detects active command interpreter instances (sh, bash, zsh, python)',
    type: 'Process',
    risk: 'High' as const,
    query: 'process.name:sh OR process.name:bash OR process.name:python OR process.name:zsh',
    conditions: [
      { id: '1', channel: 'process', field: 'name', operator: 'contains', value: 'sh' },
      { id: '2', channel: 'process', field: 'name', operator: 'contains', value: 'bash' }
    ]
  },
  {
    id: 'q2',
    name: 'External Socket Hunt',
    description: 'Detects established connections to non-local public IP blocks',
    type: 'Network',
    risk: 'Medium' as const,
    query: 'connection.remote_ip:!127.0.0.1 connection.status:ESTABLISHED',
    conditions: [
      { id: '1', channel: 'connection', field: 'remote_ip', operator: 'not_equals', value: '127.0.0.1' },
      { id: '2', channel: 'connection', field: 'status', operator: 'equals', value: 'ESTABLISHED' }
    ]
  },
  {
    id: 'q3',
    name: 'Root Execution Monitor',
    description: 'Scans processes running under root UID or sudo execution logs',
    type: 'System',
    risk: 'High' as const,
    query: 'process.username:root OR log.message:sudo',
    conditions: [
      { id: '1', channel: 'process', field: 'username', operator: 'equals', value: 'root' }
    ]
  },
  {
    id: 'q4',
    name: 'High CPU Rogue Search',
    description: 'Identifies resource hogs which may indicate cryptomining or loop exploits',
    type: 'Resources',
    risk: 'Medium' as const,
    query: 'process.cpu_percent>40',
    conditions: [
      { id: '1', channel: 'process', field: 'cpu_percent', operator: 'greater_than', value: '40' }
    ]
  },
  {
    id: 'q5',
    name: 'Security Error Events',
    description: 'Filters log directories for failures, warnings, and access denials',
    type: 'Logs',
    risk: 'Critical' as const,
    query: 'log.level:error OR log.message:fail',
    conditions: [
      { id: '1', channel: 'log', field: 'level', operator: 'equals', value: 'error' }
    ]
  },
];

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-950/40 text-red-400 border-red-800/60',
  high: 'bg-orange-950/40 text-orange-400 border-orange-800/60',
  medium: 'bg-yellow-950/40 text-yellow-400 border-yellow-800/60',
  low: 'bg-blue-950/40 text-blue-400 border-blue-800/60',
};

const CHANNEL_ICONS = {
  process: <Cpu className="w-4 h-4 text-cyan-400" />,
  connection: <Globe className="w-4 h-4 text-indigo-400" />,
  log: <FileText className="w-4 h-4 text-emerald-400" />,
  port: <ArrowUpRight className="w-4 h-4 text-purple-400" />
};

// Field options for GUI Query Builder
const FIELD_OPTIONS = {
  process: [
    { label: 'Name', value: 'name' },
    { label: 'PID', value: 'pid' },
    { label: 'User', value: 'username' },
    { label: 'CPU %', value: 'cpu_percent' },
    { label: 'Memory %', value: 'memory_percent' },
    { label: 'Suspicious Flag', value: 'suspicious' }
  ],
  connection: [
    { label: 'Remote IP', value: 'remote_ip' },
    { label: 'Remote Port', value: 'remote_port' },
    { label: 'Local Port', value: 'local_port' },
    { label: 'Process', value: 'process' },
    { label: 'Status', value: 'status' },
    { label: 'Protocol', value: 'protocol' }
  ],
  log: [
    { label: 'Level (error/warn/info)', value: 'level' },
    { label: 'Message Text', value: 'message' },
    { label: 'Process Name', value: 'process' },
    { label: 'Category', value: 'category' }
  ],
  port: [
    { label: 'Port Number', value: 'port' },
    { label: 'Process Name', value: 'process' },
    { label: 'PID', value: 'pid' }
  ]
};

const OPERATOR_OPTIONS = [
  { label: 'Contains', value: 'contains' },
  { label: 'Equals (=)', value: 'equals' },
  { label: 'Not Equals (!=)', value: 'not_equals' },
  { label: 'Greater Than (>)', value: 'greater_than' },
  { label: 'Less Than (<)', value: 'less_than' }
];

// Helper to determine private IPs
const isPrivateIp = (ip: string) => {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip === '::1' || ip === '::') return true;
  const parts = ip.split('.').map(Number);
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
};

// ── Query Parsing Engine ─────────────────────────────────────────────────────
function parseQueryString(queryStr: string): SearchTerm[] {
  const terms: SearchTerm[] = [];
  const parts = queryStr.match(/[^\s"']+|"([^"]*)"|'([^']*)'/g) || [];

  parts.forEach(part => {
    let cleanPart = part.replace(/^["']|["']$/g, '').trim();
    if (!cleanPart) return;

    // Handle uppercase OR/AND split by just treating them as items
    if (cleanPart === 'OR' || cleanPart === 'AND') return;

    const colonIndex = cleanPart.indexOf(':');
    const gtIndex = cleanPart.indexOf('>');
    const ltIndex = cleanPart.indexOf('<');

    if (colonIndex > 0) {
      const key = cleanPart.substring(0, colonIndex);
      let val = cleanPart.substring(colonIndex + 1);

      let isNegated = false;
      if (val.startsWith('!')) {
        val = val.substring(1);
        isNegated = true;
      }

      const keyParts = key.split('.');
      if (keyParts.length === 2) {
        const [cat, field] = keyParts;
        if (['process', 'connection', 'log', 'port'].includes(cat)) {
          terms.push({
            category: cat as any,
            field,
            operator: isNegated ? 'not_equals' : 'contains',
            value: val,
            isNegated
          });
          return;
        }
      }

      terms.push({
        field: key,
        operator: isNegated ? 'not_equals' : 'contains',
        value: val,
        isNegated
      });
    } else if (gtIndex > 0) {
      const key = cleanPart.substring(0, gtIndex);
      const val = cleanPart.substring(gtIndex + 1);
      const keyParts = key.split('.');
      if (keyParts.length === 2) {
        terms.push({
          category: keyParts[0] as any,
          field: keyParts[1],
          operator: 'greater_than',
          value: val,
          isNegated: false
        });
      } else {
        terms.push({
          field: key,
          operator: 'greater_than',
          value: val,
          isNegated: false
        });
      }
    } else if (ltIndex > 0) {
      const key = cleanPart.substring(0, ltIndex);
      const val = cleanPart.substring(ltIndex + 1);
      const keyParts = key.split('.');
      if (keyParts.length === 2) {
        terms.push({
          category: keyParts[0] as any,
          field: keyParts[1],
          operator: 'less_than',
          value: val,
          isNegated: false
        });
      } else {
        terms.push({
          field: key,
          operator: 'less_than',
          value: val,
          isNegated: false
        });
      }
    } else {
      let isNegated = false;
      let val = cleanPart;
      if (val.startsWith('!')) {
        val = val.substring(1);
        isNegated = true;
      }
      terms.push({
        operator: isNegated ? 'not_equals' : 'contains',
        value: val,
        isNegated
      });
    }
  });

  return terms;
}

// ── Matching Evaluators ──────────────────────────────────────────────────────
function matchProcess(p: RealProcess, terms: SearchTerm[]): boolean {
  if (terms.length === 0) return true;
  return terms.every(term => {
    if (term.category && term.category !== 'process') return true;

    const field = term.field;
    const value = term.value.toLowerCase();

    if (field) {
      let pVal = '';
      if (field in p) {
        pVal = String((p as any)[field]);
      } else {
        return !term.isNegated;
      }

      const pValLower = pVal.toLowerCase();
      if (term.operator === 'greater_than') {
        return Number(pVal) > Number(value);
      }
      if (term.operator === 'less_than') {
        return Number(pVal) < Number(value);
      }
      if (term.operator === 'not_equals') {
        return pValLower !== value;
      }
      return pValLower.includes(value);
    } else {
      const textToSearch = `${p.name} ${p.pid} ${p.username || ''} ${p.status}`.toLowerCase();
      const match = textToSearch.includes(value);
      return term.isNegated ? !match : match;
    }
  });
}

function matchConnection(c: NetworkConnection, terms: SearchTerm[]): boolean {
  if (terms.length === 0) return true;
  return terms.every(term => {
    if (term.category && term.category !== 'connection') return true;

    const field = term.field;
    const value = term.value.toLowerCase();

    if (field) {
      let cVal = '';
      if (field === 'country' && c.geo?.country) cVal = c.geo.country;
      else if (field === 'org' && c.geo?.org) cVal = c.geo.org;
      else if (field in c) {
        cVal = String((c as any)[field]);
      } else {
        return !term.isNegated;
      }

      const cValLower = cVal.toLowerCase();
      if (term.operator === 'greater_than') {
        return Number(cVal) > Number(value);
      }
      if (term.operator === 'less_than') {
        return Number(cVal) < Number(value);
      }
      if (term.operator === 'not_equals') {
        return cValLower !== value;
      }
      return cValLower.includes(value);
    } else {
      const geoText = c.geo ? `${c.geo.country} ${c.geo.city} ${c.geo.org}` : '';
      const textToSearch = `${c.local_ip} ${c.local_port} ${c.remote_ip} ${c.remote_port} ${c.status} ${c.process} ${c.protocol} ${geoText}`.toLowerCase();
      const match = textToSearch.includes(value);
      return term.isNegated ? !match : match;
    }
  });
}

function matchLog(l: LogEntry, terms: SearchTerm[]): boolean {
  if (terms.length === 0) return true;
  return terms.every(term => {
    if (term.category && term.category !== 'log') return true;

    const field = term.field;
    const value = term.value.toLowerCase();

    if (field) {
      let lVal = '';
      if (field in l) {
        lVal = String((l as any)[field]);
      } else {
        return !term.isNegated;
      }

      const lValLower = lVal.toLowerCase();
      if (term.operator === 'not_equals') {
        return lValLower !== value;
      }
      return lValLower.includes(value);
    } else {
      const textToSearch = `${l.process} ${l.message} ${l.level} ${l.category} ${l.source}`.toLowerCase();
      const match = textToSearch.includes(value);
      return term.isNegated ? !match : match;
    }
  });
}

function matchPort(pt: { port: number; ip: string; process: string; pid: number }, terms: SearchTerm[]): boolean {
  if (terms.length === 0) return true;
  return terms.every(term => {
    if (term.category && term.category !== 'port') return true;

    const field = term.field;
    const value = term.value.toLowerCase();

    if (field) {
      let pVal = '';
      if (field in pt) {
        pVal = String((pt as any)[field]);
      } else {
        return !term.isNegated;
      }

      const pValLower = pVal.toLowerCase();
      if (term.operator === 'greater_than') {
        return Number(pVal) > Number(value);
      }
      if (term.operator === 'less_than') {
        return Number(pVal) < Number(value);
      }
      if (term.operator === 'not_equals') {
        return pValLower !== value;
      }
      return pValLower.includes(value);
    } else {
      const textToSearch = `${pt.port} ${pt.ip} ${pt.process} ${pt.pid}`.toLowerCase();
      const match = textToSearch.includes(value);
      return term.isNegated ? !match : match;
    }
  });
}

// ── Component Definition ─────────────────────────────────────────────────────
export default function ThreatHuntingPage() {
  const { connections, processes, logs, metrics, listeningPorts, incidents } = useAppStore();

  const [searchQuery, setSearchQuery] = useState('');
  const [isHunting, setIsHunting] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const [activeQuery, setActiveQuery] = useState<string | null>(null);
  const [consoleLog, setConsoleLog] = useState<string[]>([]);
  const [mounted, setMounted] = useState(false);

  // MITRE & Graph state
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<{ id: string; type: string; label: string; risk: string; data: any } | null>(null);

  // ── Pan-only state ───────────────────────────────────────────────
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const dragStart = useRef({ mouseX: 0, mouseY: 0, panX: 0, panY: 0 });

  const handleMouseDown = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    if (e.button !== 0) return;
    dragStart.current = { mouseX: e.clientX, mouseY: e.clientY, panX: pan.x, panY: pan.y };
    setIsDragging(true);
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    if (!isDragging) return;
    const { mouseX, mouseY, panX, panY } = dragStart.current;
    const rect = e.currentTarget.getBoundingClientRect();
    // Convert screen pixel delta to viewBox units (700×400)
    const dx = ((e.clientX - mouseX) / rect.width)  * 700;
    const dy = ((e.clientY - mouseY) / rect.height) * 400;
    setPan({ x: panX + dx, y: panY + dy });
  }, [isDragging]);

  const handleMouseUp    = useCallback(() => setIsDragging(false), []);
  const handleMouseLeave = useCallback(() => setIsDragging(false), []);
  const handleResetPan   = useCallback(() => setPan({ x: 0, y: 0 }), []);

  // Query Builder UI States
  const [showBuilder, setShowBuilder] = useState(false);
  const [qbChannel, setQbChannel] = useState<'process' | 'connection' | 'log' | 'port'>('process');
  const [qbField, setQbField] = useState('name');
  const [qbOperator, setQbOperator] = useState('contains');
  const [qbValue, setQbValue] = useState('');
  const [queryConditions, setQueryConditions] = useState<QueryCondition[]>([]);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Update builder fields when channel changes
  useEffect(() => {
    if (FIELD_OPTIONS[qbChannel]) {
      setQbField(FIELD_OPTIONS[qbChannel][0].value);
    }
  }, [qbChannel]);

  // Sync builder conditions to searchQuery string
  const compileQueryString = (conditions: QueryCondition[]) => {
    if (conditions.length === 0) return '';
    return conditions
      .map(c => {
        const isNeg = c.operator === 'not_equals' ? '!' : '';
        const opSym = c.operator === 'greater_than' ? '>' : c.operator === 'less_than' ? '<' : ':';
        return `${c.channel}.${c.field}${opSym}${isNeg}${c.value}`;
      })
      .join(' ');
  };

  const handleAddCondition = () => {
    if (!qbValue.trim()) {
      toast.error('Please enter a query value');
      return;
    }
    const newCond: QueryCondition = {
      id: Math.random().toString(),
      channel: qbChannel,
      field: qbField,
      operator: qbOperator,
      value: qbValue.trim()
    };
    const updated = [...queryConditions, newCond];
    setQueryConditions(updated);
    const qStr = compileQueryString(updated);
    setSearchQuery(qStr);
    setQbValue('');
    toast.success('Condition added to query');
  };

  const handleRemoveCondition = (id: string) => {
    const updated = queryConditions.filter(c => c.id !== id);
    setQueryConditions(updated);
    const qStr = compileQueryString(updated);
    setSearchQuery(qStr);
  };

  const handleClearAllConditions = () => {
    setQueryConditions([]);
    setSearchQuery('');
    setSelectedTactic(null);
  };

  // Run the threat hunt logic
  const executeHunt = (queryText?: string) => {
    const queryStr = queryText !== undefined ? queryText : searchQuery;
    setIsHunting(true);
    setHasSearched(false);
    setConsoleLog([]);
    setSelectedNode(null);

    const hostname = metrics?.hostname || 'localhost';

    const outputLogs = [
      `[${new Date().toLocaleTimeString()}] Proactive hunt sequence initialized...`,
      `[${new Date().toLocaleTimeString()}] Searching active system memory processes (${processes.length} tracked)...`,
      `[${new Date().toLocaleTimeString()}] Querying socket connection matrix (${connections.length} established)...`,
      `[${new Date().toLocaleTimeString()}] Scanning telemetry syslog database (${logs.length} indexes)...`,
      `[${new Date().toLocaleTimeString()}] Cross-correlating with active listeners on (${listeningPorts.length} interfaces)...`,
      `[${new Date().toLocaleTimeString()}] Parsing query: "${queryStr || 'ALL telemetries'}"`,
      `[${new Date().toLocaleTimeString()}] Executing correlation filters...`
    ];

    outputLogs.forEach((log, i) => {
      setTimeout(() => {
        setConsoleLog((prev) => [...prev, log]);
      }, i * 250);
    });

    setTimeout(() => {
      setIsHunting(false);
      setHasSearched(true);
      setConsoleLog((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] Hunt completed. Visual correlation graph populated successfully.`
      ]);
      toast.success('Threat Hunt Complete', {
        description: 'Telemetry correlation maps are now active.'
      });
    }, 1800);
  };

  // ── Query Matching Computations ──────────────────────────────────────────────
  const parsedTerms = useMemo(() => parseQueryString(searchQuery), [searchQuery]);

  const matchedProcesses = useMemo(() => {
    // If no search has happened yet, we match everything to show live topology overview
    if (!hasSearched && searchQuery === '') return processes;
    return processes.filter(p => matchProcess(p, parsedTerms));
  }, [processes, parsedTerms, hasSearched, searchQuery]);

  const matchedConnections = useMemo(() => {
    if (!hasSearched && searchQuery === '') return connections;
    return connections.filter(c => matchConnection(c, parsedTerms));
  }, [connections, parsedTerms, hasSearched, searchQuery]);

  const matchedLogs = useMemo(() => {
    if (!hasSearched && searchQuery === '') return logs;
    return logs.filter(l => matchLog(l, parsedTerms));
  }, [logs, parsedTerms, hasSearched, searchQuery]);

  const matchedPorts = useMemo(() => {
    if (!hasSearched && searchQuery === '') return listeningPorts;
    return listeningPorts.filter(pt => matchPort(pt, parsedTerms));
  }, [listeningPorts, parsedTerms, hasSearched, searchQuery]);

  // Compute MITRE ATT&CK tactical classifications
  const mitreClassifications = useMemo(() => {
    const execution: { desc: string; node: any; type: string }[] = [];
    const privEsc: { desc: string; node: any; type: string }[] = [];
    const defenseEvasion: { desc: string; node: any; type: string }[] = [];
    const discovery: { desc: string; node: any; type: string }[] = [];
    const c2: { desc: string; node: any; type: string }[] = [];
    const impact: { desc: string; node: any; type: string }[] = [];

    matchedProcesses.forEach(p => {
      const nameLower = p.name.toLowerCase();
      if (['sh', 'bash', 'python', 'python3', 'node', 'perl', 'ruby', 'zsh', 'cmd', 'powershell'].some(shell => nameLower.includes(shell))) {
        execution.push({ desc: `Shell interpreter spawn: ${p.name} (PID: ${p.pid})`, node: p, type: 'process' });
      }
      if (p.username === 'root') {
        privEsc.push({ desc: `Process owned by UID 0 (root): ${p.name}`, node: p, type: 'process' });
      }
      if (p.suspicious) {
        defenseEvasion.push({ desc: `Rogue metadata flagged suspicious: ${p.name}`, node: p, type: 'process' });
      }
      if (['arp', 'nmap', 'ifconfig', 'netstat', 'ping', 'whoami', 'id'].some(cmd => nameLower.includes(cmd))) {
        discovery.push({ desc: `Network/ID utility run: ${p.name}`, node: p, type: 'process' });
      }
      if (p.high_resource || p.cpu_percent > 40) {
        impact.push({ desc: `High CPU exhaust: ${p.name} (${p.cpu_percent}%)`, node: p, type: 'process' });
      }
    });

    matchedConnections.forEach(c => {
      if (c.status === 'ESTABLISHED' && !isPrivateIp(c.remote_ip)) {
        c2.push({ desc: `Public C2 established socket to ${c.remote_ip}:${c.remote_port}`, node: c, type: 'connection' });
      }
      if (c.status === 'LISTEN') {
        discovery.push({ desc: `Port listener active: Port ${c.local_port} (${c.process})`, node: c, type: 'connection' });
      }
    });

    matchedLogs.forEach(l => {
      const msg = l.message.toLowerCase();
      if (l.level === 'error' || msg.includes('fail') || msg.includes('denied')) {
        impact.push({ desc: `Log failure flag: [${l.process}] ${l.message}`, node: l, type: 'log' });
      }
      if (msg.includes('sudo') || msg.includes('root') || msg.includes('admin') || msg.includes('privilege')) {
        privEsc.push({ desc: `Audit log auth upgrade event: ${l.message}`, node: l, type: 'log' });
      }
      if (msg.includes('clear') || msg.includes('delete') || msg.includes('kill') || msg.includes('remove')) {
        defenseEvasion.push({ desc: `History tamper warning log: ${l.message}`, node: l, type: 'log' });
      }
    });

    return { execution, privEsc, defenseEvasion, discovery, c2, impact };
  }, [matchedProcesses, matchedConnections, matchedLogs]);

  // MITRE Click Filtering logic
  const mitreFilteredData = useMemo(() => {
    if (!selectedTactic) return null;
    const records = mitreClassifications[selectedTactic as keyof typeof mitreClassifications] || [];
    
    const processesList = records.filter(r => r.type === 'process').map(r => r.node as RealProcess);
    const connectionsList = records.filter(r => r.type === 'connection').map(r => r.node as NetworkConnection);
    const logsList = records.filter(r => r.type === 'log').map(r => r.node as LogEntry);

    return {
      processes: processesList,
      connections: connectionsList,
      logs: logsList
    };
  }, [selectedTactic, mitreClassifications]);

  const activeProcesses = mitreFilteredData ? mitreFilteredData.processes : matchedProcesses;
  const activeConnections = mitreFilteredData ? mitreFilteredData.connections : matchedConnections;
  const activeLogs = mitreFilteredData ? mitreFilteredData.logs : matchedLogs;
  const activePorts = mitreFilteredData ? [] : matchedPorts; // ports aren't mitre mapped directly

  // Total match count
  const matchCount = activeProcesses.length + activeConnections.length + activeLogs.length + activePorts.length;

  // ── Dynamic SVG Layout Calculations ──────────────────────────────────────────
  const graphData = useMemo(() => {
    const nodes: any[] = [];
    const links: any[] = [];

    // Central Host Machine Node
    const cx = 350;
    const cy = 200;

    nodes.push({
      id: 'host',
      label: metrics?.hostname || 'ForenSys-Agent',
      type: 'host',
      x: cx,
      y: cy,
      risk: metrics?.threat_level === 'critical' ? 'critical' : 'low',
      data: metrics
    });

    // Sub-select nodes to prevent SVG cluttering (max 10 processes, 10 connections, 10 logs)
    const displayProcs = activeProcesses.slice(0, 8);
    const displayConns = activeConnections.slice(0, 8);
    const displayLogs = activeLogs.slice(0, 8);
    const displayPorts = activePorts.slice(0, 6);

    const procCount = displayProcs.length;

    // Layout processes circularly
    displayProcs.forEach((p, idx) => {
      const angle = (idx / (procCount || 1)) * 2 * Math.PI;
      const px = cx + 90 * Math.cos(angle);
      const py = cy + 90 * Math.sin(angle);
      const pId = `proc-${p.pid}`;

      const isSus = p.suspicious || p.username === 'root';

      nodes.push({
        id: pId,
        label: `${p.name} (PID: ${p.pid})`,
        type: 'process',
        x: px,
        y: py,
        risk: isSus ? 'high' : 'low',
        data: p
      });

      links.push({
        source: 'host',
        target: pId,
        type: 'host-process',
        animated: p.cpu_percent > 10,
        color: isSus ? '#f97316' : '#22d3ee'
      });

      // Find related sockets for this process
      const relConns = displayConns.filter(c => c.pid === p.pid || (c.process && c.process.toLowerCase() === p.name.toLowerCase()));
      relConns.forEach((c, cIdx) => {
        const cAngle = angle + (cIdx - (relConns.length - 1) / 2) * 0.25;
        const cxNode = cx + 180 * Math.cos(cAngle);
        const cyNode = cy + 180 * Math.sin(cAngle);
        const cId = `conn-${c.local_port}-${c.remote_port}-${cIdx}`;

        nodes.push({
          id: cId,
          label: `${c.remote_ip}:${c.remote_port}`,
          type: 'connection',
          x: cxNode,
          y: cyNode,
          risk: !isPrivateIp(c.remote_ip) ? 'medium' : 'low',
          data: c
        });

        links.push({
          source: pId,
          target: cId,
          type: 'process-connection',
          animated: c.status === 'ESTABLISHED',
          color: !isPrivateIp(c.remote_ip) ? '#ec4899' : '#6366f1'
        });
      });

      // Find related logs
      const relLogs = displayLogs.filter(l => l.process.toLowerCase() === p.name.toLowerCase());
      relLogs.forEach((l, lIdx) => {
        const lAngle = angle + Math.PI/2 + (lIdx - (relLogs.length - 1) / 2) * 0.25;
        const lxNode = cx + 180 * Math.cos(lAngle);
        const lyNode = cy + 180 * Math.sin(lAngle);
        const lId = `log-${l.id}`;

        if (!nodes.some(n => n.id === lId)) {
          nodes.push({
            id: lId,
            label: `Syslog [${l.level}]`,
            type: 'log',
            x: lxNode,
            y: lyNode,
            risk: l.level === 'error' ? 'critical' : 'medium',
            data: l
          });

          links.push({
            source: pId,
            target: lId,
            type: 'process-log',
            animated: l.level === 'error',
            color: l.level === 'error' ? '#ef4444' : '#10b981'
          });
        }
      });
    });

    // Unlinked connections (connect directly to host)
    const linkedConnIds = links.filter(l => l.type === 'process-connection').map(l => l.target);
    const unlinkedConns = displayConns.filter(c => !linkedConnIds.includes(`conn-${c.local_port}-${c.remote_port}-0`));
    unlinkedConns.forEach((c, idx) => {
      const angle = Math.PI * (1.2 + (idx / (unlinkedConns.length || 1)) * 0.6);
      const cxNode = cx + 170 * Math.cos(angle);
      const cyNode = cy + 170 * Math.sin(angle);
      const cId = `conn-unlinked-${idx}`;

      nodes.push({
        id: cId,
        label: `${c.remote_ip || 'LISTEN'}:${c.remote_port || c.local_port}`,
        type: 'connection',
        x: cxNode,
        y: cyNode,
        risk: c.status === 'ESTABLISHED' ? 'medium' : 'low',
        data: c
      });

      links.push({
        source: 'host',
        target: cId,
        type: 'host-connection',
        animated: c.status === 'ESTABLISHED',
        color: '#818cf8'
      });
    });

    // Unlinked logs
    const linkedLogIds = links.filter(l => l.type === 'process-log').map(l => l.target);
    const unlinkedLogs = displayLogs.filter(l => !linkedLogIds.includes(`log-${l.id}`));
    unlinkedLogs.forEach((l, idx) => {
      const angle = Math.PI * (0.2 + (idx / (unlinkedLogs.length || 1)) * 0.6);
      const lxNode = cx + 160 * Math.cos(angle);
      const lyNode = cy + 160 * Math.sin(angle);
      const lId = `log-unlinked-${l.id}`;

      nodes.push({
        id: lId,
        label: `Syslog: ${l.process}`,
        type: 'log',
        x: lxNode,
        y: lyNode,
        risk: l.level === 'error' ? 'critical' : 'low',
        data: l
      });

      links.push({
        source: 'host',
        target: lId,
        type: 'host-log',
        animated: l.level === 'error',
        color: l.level === 'error' ? '#ef4444' : '#10b981'
      });
    });

    return { nodes, links };
  }, [activeProcesses, activeConnections, activeLogs, activePorts, metrics]);

  // ── Incident Escalation Helper ──────────────────────────────────────────────
  const handleEscalateIncident = (hit: any, type: string) => {
    useAppStore.getState().raiseIncidentAndCaptureForensics(type as any, hit);
    toast.success('Escalated successfully', {
      description: `Created new open incident and captured forensic evidence.`
    });
  };

  // ── CSV Exporter ─────────────────────────────────────────────────────────────
  const handleExportCSV = () => {
    let csvContent = 'data:text/csv;charset=utf-8,';
    csvContent += 'Category,Identity/Detail,Risk Level,Host,Remediation Action\n';

    activeProcesses.forEach(p => {
      csvContent += `Process,"${p.name} (PID: ${p.pid}, USER: ${p.username})",${p.suspicious ? 'high' : 'low'},${metrics?.hostname || 'localhost'},"Terminate PID ${p.pid}"\n`;
    });

    activeConnections.forEach(c => {
      csvContent += `Connection,"${c.process} (${c.local_ip}:${c.local_port} -> ${c.remote_ip}:${c.remote_port})",${!isPrivateIp(c.remote_ip) ? 'high' : 'low'},${metrics?.hostname || 'localhost'},"Block IP ${c.remote_ip} in firewall"\n`;
    });

    activeLogs.forEach(l => {
      csvContent += `Log,"[${l.process}] ${l.message.replace(/"/g, '""')}",${l.level === 'error' ? 'high' : 'medium'},${metrics?.hostname || 'localhost'},"Review logs and keys"\n`;
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `threat_hunt_report_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success('Hunt Report Exported', { description: 'CSV file downloaded successfully.' });
  };

  if (!mounted) return null;

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5 bg-background cyber-grid relative">
      <div className="absolute inset-0 bg-linear-to-b from-transparent via-cyan-950/5 to-transparent pointer-events-none" />

      {/* Header Panel */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 rounded-full blur-2xl pointer-events-none" />
        <div className="z-10">
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Target className="w-6 h-6 text-accent animate-pulse-slow" />
            Threat Hunting Workspace
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Build multi-attribute filters, cross-reference IOC traces, and generate visual telemetry graphs.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleExportCSV}
            disabled={matchCount === 0}
            className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <Download className="w-4 h-4 text-accent" /> Export Hunt
          </button>
          <div className={`flex items-center gap-1.5 font-mono text-xs ${metrics?.threat_level === 'critical' ? 'text-red-400' : 'text-cyan-400'}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
            SOC Live Stream Connected
          </div>
        </div>
      </div>

      {/* Analytics Counter Ticker */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="glass p-3 rounded-lg border border-border/50 flex flex-col justify-between">
          <span className="text-[10px] uppercase font-mono text-muted-foreground flex items-center gap-1">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Tracked Processes
          </span>
          <span className="text-xl font-bold text-foreground mt-1 font-mono">{processes.length}</span>
        </div>
        <div className="glass p-3 rounded-lg border border-border/50 flex flex-col justify-between">
          <span className="text-[10px] uppercase font-mono text-muted-foreground flex items-center gap-1">
            <Globe className="w-3.5 h-3.5 text-indigo-400" /> Active Sockets
          </span>
          <span className="text-xl font-bold text-foreground mt-1 font-mono">{connections.length}</span>
        </div>
        <div className="glass p-3 rounded-lg border border-border/50 flex flex-col justify-between">
          <span className="text-[10px] uppercase font-mono text-muted-foreground flex items-center gap-1">
            <ArrowUpRight className="w-3.5 h-3.5 text-purple-400" /> Open Ports
          </span>
          <span className="text-xl font-bold text-foreground mt-1 font-mono">{listeningPorts.length}</span>
        </div>
        <div className="glass p-3 rounded-lg border border-border/50 flex flex-col justify-between">
          <span className="text-[10px] uppercase font-mono text-muted-foreground flex items-center gap-1">
            <FileText className="w-3.5 h-3.5 text-emerald-400" /> Accumulated Logs
          </span>
          <span className="text-xl font-bold text-foreground mt-1 font-mono">{logs.length}</span>
        </div>
        <div className="glass p-3 rounded-lg border border-accent/30 bg-accent/5 flex flex-col justify-between col-span-2 md:col-span-1">
          <span className="text-[10px] uppercase font-mono text-accent font-semibold flex items-center gap-1">
            <Target className="w-3.5 h-3.5" /> Correlation Hits
          </span>
          <span className="text-xl font-bold text-accent mt-1 font-mono">{matchCount}</span>
        </div>
      </div>

      {/* Main Console & Query Inputs */}
      <div className="space-y-3">
        {/* Search Console */}
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row gap-3">
            {/* Search Input */}
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
              <Input
                placeholder="Query syntax: process.name:bash connection.remote_ip:127.0.0.1 log.level:error ..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && executeHunt()}
                className="pl-9 pr-10 bg-input border-border/50 text-sm h-9 font-mono text-accent focus:ring-1 focus:ring-accent"
              />
              {searchQuery && (
                <button
                  onClick={handleClearAllConditions}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button
                onClick={() => setShowBuilder(!showBuilder)}
                variant="outline"
                size="sm"
                className={`h-9 text-xs border-border/60 flex items-center gap-1.5 ${showBuilder ? 'bg-accent/10 border-accent text-accent' : ''}`}
              >
                <Sliders className="w-3.5 h-3.5" />
                <span>Builder</span>
              </Button>

              <Button
                onClick={() => executeHunt()}
                disabled={isHunting}
                className="bg-accent hover:bg-accent/90 text-accent-foreground h-9 px-4 text-xs font-mono font-semibold flex items-center gap-1.5"
              >
                {isHunting ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>RUN HUNT</span>
                  </>
                )}
              </Button>
            </div>
          </div>

          {/* Builder Panel Drawer */}
          <AnimatePresence>
            {showBuilder && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="border-t border-border/40 pt-4 overflow-hidden"
              >
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 bg-muted/40 p-4 rounded-lg border border-border/40">
                  <div className="space-y-1">
                    <label className="text-[10px] font-mono uppercase text-muted-foreground">Source Channel</label>
                    <Select value={qbChannel} onValueChange={(val: any) => setQbChannel(val)}>
                      <SelectTrigger className="w-full bg-input h-9 text-xs border-border/60 text-foreground">
                        <SelectValue placeholder="Channel" />
                      </SelectTrigger>
                      <SelectContent className="bg-popover border-border">
                        <SelectItem value="process">Processes ⚙️</SelectItem>
                        <SelectItem value="connection">Connections 🌐</SelectItem>
                        <SelectItem value="log">Logs 📄</SelectItem>
                        <SelectItem value="port">Ports 🔌</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[10px] font-mono uppercase text-muted-foreground">Attribute Field</label>
                    <Select value={qbField} onValueChange={setQbField}>
                      <SelectTrigger className="w-full bg-input h-9 text-xs border-border/60 text-foreground">
                        <SelectValue placeholder="Field" />
                      </SelectTrigger>
                      <SelectContent className="bg-popover border-border">
                        {FIELD_OPTIONS[qbChannel]?.map(opt => (
                          <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[10px] font-mono uppercase text-muted-foreground">Match Condition</label>
                    <Select value={qbOperator} onValueChange={setQbOperator}>
                      <SelectTrigger className="w-full bg-input h-9 text-xs border-border/60 text-foreground">
                        <SelectValue placeholder="Operator" />
                      </SelectTrigger>
                      <SelectContent className="bg-popover border-border">
                        {OPERATOR_OPTIONS.map(opt => (
                          <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[10px] font-mono uppercase text-muted-foreground">Value Target</label>
                    <div className="flex gap-2">
                      <Input
                        placeholder="Search term or limit..."
                        value={qbValue}
                        onChange={(e) => setQbValue(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleAddCondition()}
                        className="bg-input border-border/60 text-xs h-9"
                      />
                      <Button
                        size="sm"
                        onClick={handleAddCondition}
                        className="bg-accent hover:bg-accent/80 text-accent-foreground h-9 px-3 shrink-0"
                      >
                        <Plus className="w-4 h-4" /> Add
                      </Button>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Condition Badges and Filters */}
          {queryConditions.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-border/30">
              <span className="text-[10px] uppercase font-mono text-muted-foreground mr-1">Active Rules:</span>
              {queryConditions.map((cond) => (
                <Badge
                  key={cond.id}
                  variant="outline"
                  className="bg-muted/40 border-accent/40 text-accent font-mono text-xs py-1 px-2.5 flex items-center gap-1.5 rounded"
                >
                  {CHANNEL_ICONS[cond.channel]}
                  <span>
                    {cond.field} {cond.operator === 'contains' ? ':' : cond.operator === 'equals' ? '=' : cond.operator === 'not_equals' ? '!=' : cond.operator === 'greater_than' ? '>' : '<'} &quot;{cond.value}&quot;
                  </span>
                  <button
                    onClick={() => handleRemoveCondition(cond.id)}
                    className="hover:text-red-400 cursor-pointer"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </Badge>
              ))}
              <Button
                variant="ghost"
                size="sm"
                onClick={handleClearAllConditions}
                className="h-7 text-xs text-red-400 hover:text-red-300 ml-auto"
              >
                <Trash2 className="w-3 h-3 mr-1" /> Clear Query
              </Button>
            </div>
          )}
        </div>

        {/* Live Running Correlation Console Output */}
        {consoleLog.length > 0 && (
          <div className="bg-black/80 rounded-xl border border-border/70 p-3 shadow-inner">
            <div className="flex items-center gap-2 mb-2">
              <Terminal className="w-3.5 h-3.5 text-accent animate-pulse" />
              <span className="text-[10px] text-accent font-mono uppercase tracking-wider">Correlation Engine Syslog Audit</span>
              {isHunting && <div className="w-2.5 h-2.5 rounded-full bg-accent animate-ping ml-auto" />}
            </div>
            <div className="max-h-24 overflow-y-auto scrollbar-thin">
              {consoleLog.map((log, i) => (
                <motion.p
                  key={i}
                  initial={{ opacity: 0, x: -5 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="text-[11px] font-mono text-green-400/90 leading-relaxed"
                >
                  {log}
                </motion.p>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* MITRE ATT&CK Matrix panel */}
      <div className="glass rounded-xl border border-border/60 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs uppercase font-mono tracking-wider text-foreground flex items-center gap-1.5">
            <Layers className="w-4 h-4 text-purple-400" /> Interactive MITRE ATT&CK Matrix Cross-Reference
          </h2>
          {selectedTactic && (
            <Badge
              variant="outline"
              className="bg-purple-950/30 text-purple-300 border-purple-800 cursor-pointer text-[10px]"
              onClick={() => setSelectedTactic(null)}
            >
              Filtering by: {selectedTactic} <X className="w-3 h-3 ml-1" />
            </Badge>
          )}
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 text-xs">
          {/* Execution Column */}
          <div
            onClick={() => setSelectedTactic(selectedTactic === 'execution' ? null : 'execution')}
            className={`border rounded-lg p-2.5 transition-all cursor-pointer ${
              selectedTactic === 'execution'
                ? 'bg-purple-950/50 border-purple-500 ring-1 ring-purple-500'
                : mitreClassifications.execution.length > 0
                ? 'bg-purple-950/20 border-purple-900/60 hover:border-purple-800'
                : 'border-border/30 bg-muted/10 opacity-60'
            }`}
          >
            <div className="flex justify-between items-start">
              <span className="font-semibold text-foreground">Execution</span>
              {mitreClassifications.execution.length > 0 && (
                <Badge className="bg-purple-500/20 text-purple-300 border-purple-700 text-[10px] font-mono">
                  {mitreClassifications.execution.length}
                </Badge>
              )}
            </div>
            <p className="text-[10px] text-muted-foreground mt-1 leading-tight">Spawning interpreter engines, scripting, shells.</p>
          </div>

          {/* Privilege Escalation */}
          <div
            onClick={() => setSelectedTactic(selectedTactic === 'privEsc' ? null : 'privEsc')}
            className={`border rounded-lg p-2.5 transition-all cursor-pointer ${
              selectedTactic === 'privEsc'
                ? 'bg-purple-950/50 border-purple-500 ring-1 ring-purple-500'
                : mitreClassifications.privEsc.length > 0
                ? 'bg-purple-950/20 border-purple-900/60 hover:border-purple-800'
                : 'border-border/30 bg-muted/10 opacity-60'
            }`}
          >
            <div className="flex justify-between items-start">
              <span className="font-semibold text-foreground">Privilege Escalation</span>
              {mitreClassifications.privEsc.length > 0 && (
                <Badge className="bg-purple-500/20 text-purple-300 border-purple-700 text-[10px] font-mono">
                  {mitreClassifications.privEsc.length}
                </Badge>
              )}
            </div>
            <p className="text-[10px] text-muted-foreground mt-1 leading-tight">Root owner privilege upgrade, root sudo events.</p>
          </div>

          {/* Defense Evasion */}
          <div
            onClick={() => setSelectedTactic(selectedTactic === 'defenseEvasion' ? null : 'defenseEvasion')}
            className={`border rounded-lg p-2.5 transition-all cursor-pointer ${
              selectedTactic === 'defenseEvasion'
                ? 'bg-purple-950/50 border-purple-500 ring-1 ring-purple-500'
                : mitreClassifications.defenseEvasion.length > 0
                ? 'bg-purple-950/20 border-purple-900/60 hover:border-purple-800'
                : 'border-border/30 bg-muted/10 opacity-60'
            }`}
          >
            <div className="flex justify-between items-start">
              <span className="font-semibold text-foreground">Defense Evasion</span>
              {mitreClassifications.defenseEvasion.length > 0 && (
                <Badge className="bg-purple-500/20 text-purple-300 border-purple-700 text-[10px] font-mono">
                  {mitreClassifications.defenseEvasion.length}
                </Badge>
              )}
            </div>
            <p className="text-[10px] text-muted-foreground mt-1 leading-tight">Rogue elements, task kills, syslog logs deletion.</p>
          </div>

          {/* Discovery */}
          <div
            onClick={() => setSelectedTactic(selectedTactic === 'discovery' ? null : 'discovery')}
            className={`border rounded-lg p-2.5 transition-all cursor-pointer ${
              selectedTactic === 'discovery'
                ? 'bg-purple-950/50 border-purple-500 ring-1 ring-purple-500'
                : mitreClassifications.discovery.length > 0
                ? 'bg-purple-950/20 border-purple-900/60 hover:border-purple-800'
                : 'border-border/30 bg-muted/10 opacity-60'
            }`}
          >
            <div className="flex justify-between items-start">
              <span className="font-semibold text-foreground">Discovery</span>
              {mitreClassifications.discovery.length > 0 && (
                <Badge className="bg-purple-500/20 text-purple-300 border-purple-700 text-[10px] font-mono">
                  {mitreClassifications.discovery.length}
                </Badge>
              )}
            </div>
            <p className="text-[10px] text-muted-foreground mt-1 leading-tight">Port listening checks, network recon commands.</p>
          </div>

          {/* Command and Control */}
          <div
            onClick={() => setSelectedTactic(selectedTactic === 'c2' ? null : 'c2')}
            className={`border rounded-lg p-2.5 transition-all cursor-pointer ${
              selectedTactic === 'c2'
                ? 'bg-purple-950/50 border-purple-500 ring-1 ring-purple-500'
                : mitreClassifications.c2.length > 0
                ? 'bg-purple-950/20 border-purple-900/60 hover:border-purple-800'
                : 'border-border/30 bg-muted/10 opacity-60'
            }`}
          >
            <div className="flex justify-between items-start">
              <span className="font-semibold text-foreground">Command & Control</span>
              {mitreClassifications.c2.length > 0 && (
                <Badge className="bg-purple-500/20 text-purple-300 border-purple-700 text-[10px] font-mono">
                  {mitreClassifications.c2.length}
                </Badge>
              )}
            </div>
            <p className="text-[10px] text-muted-foreground mt-1 leading-tight">External Established connections, non-local IPs.</p>
          </div>

          {/* Impact */}
          <div
            onClick={() => setSelectedTactic(selectedTactic === 'impact' ? null : 'impact')}
            className={`border rounded-lg p-2.5 transition-all cursor-pointer ${
              selectedTactic === 'impact'
                ? 'bg-purple-950/50 border-purple-500 ring-1 ring-purple-500'
                : mitreClassifications.impact.length > 0
                ? 'bg-purple-950/20 border-purple-900/60 hover:border-purple-800'
                : 'border-border/30 bg-muted/10 opacity-60'
            }`}
          >
            <div className="flex justify-between items-start">
              <span className="font-semibold text-foreground">Impact</span>
              {mitreClassifications.impact.length > 0 && (
                <Badge className="bg-purple-500/20 text-purple-300 border-purple-700 text-[10px] font-mono">
                  {mitreClassifications.impact.length}
                </Badge>
              )}
            </div>
            <p className="text-[10px] text-muted-foreground mt-1 leading-tight">Rogue hardware exhaust, error logs, fatal process loops.</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-stretch">
        {/* Playbook Templates list */}
        <div className="lg:col-span-1 flex flex-col">
          <div className="glass rounded-xl border border-border/60 p-4 flex flex-col h-full flex-1">
            <h2 className="text-sm font-semibold text-foreground flex items-center gap-1.5 mb-3 shrink-0">
              <Activity className="w-4 h-4 text-accent" /> Pre-built Hunt Templates
            </h2>
            <div className="space-y-2 flex-1 overflow-y-auto pr-1 scrollbar-thin">
              {PRE_BUILT_QUERIES.map((query) => (
                <motion.div
                  key={query.id}
                  whileHover={{ scale: 1.01 }}
                  onClick={() => {
                    setSearchQuery(query.query);
                    setActiveQuery(query.id);
                    setQueryConditions(query.conditions.map(c => ({
                      id: Math.random().toString(),
                      channel: c.channel as any,
                      field: c.field,
                      operator: c.operator,
                      value: c.value
                    })));
                    executeHunt(query.query);
                  }}
                  className={`rounded-lg p-3.5 border cursor-pointer transition-all ${
                    activeQuery === query.id
                      ? 'border-accent bg-accent/10 shadow-[0_0_15px_rgba(34,211,238,0.1)]'
                      : 'border-border/40 bg-black/45 hover:bg-black/60 hover:border-border/80'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <p className="text-xs font-semibold text-foreground leading-tight">{query.name}</p>
                    <Badge
                      className={`text-[10px] shrink-0 border uppercase font-mono ${
                        query.risk === 'Critical'
                          ? 'bg-red-950/40 text-red-400 border-red-900'
                          : query.risk === 'High'
                          ? 'bg-orange-950/40 text-orange-400 border-orange-900'
                          : 'bg-yellow-950/40 text-yellow-400 border-yellow-900'
                      }`}
                    >
                      {query.risk}
                    </Badge>
                  </div>
                  <p className="text-[11px] text-muted-foreground mb-3">{query.description}</p>
                  <div className="flex items-center justify-between border-t border-border/30 pt-2">
                    <Badge variant="outline" className="text-[10px] border-border/60 font-mono text-muted-foreground">{query.type}</Badge>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 text-xs text-accent hover:text-accent/80 hover:bg-accent/10 p-1 px-2 font-mono"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSearchQuery(query.query);
                        setActiveQuery(query.id);
                        executeHunt(query.query);
                      }}
                    >
                      <Play className="w-3 h-3 mr-1 fill-current" /> RUN PLAY
                    </Button>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>

        {/* Results Visualizer Tab panel */}
        <div className="lg:col-span-2 space-y-3 flex flex-col">
          <Tabs defaultValue="graph" className="w-full">
            <div className="flex items-center justify-between border-b border-border/50 pb-2">
              <TabsList className="bg-muted/30 border border-border/50 h-9 p-0.5 rounded-lg">
                <TabsTrigger value="graph" className="text-xs h-8 data-[state=open]:bg-accent data-[state=open]:text-accent-foreground font-mono">
                  Visual Map
                </TabsTrigger>
                <TabsTrigger value="processes" className="text-xs h-8 data-[state=open]:bg-accent data-[state=open]:text-accent-foreground font-mono">
                  Processes ({activeProcesses.length})
                </TabsTrigger>
                <TabsTrigger value="connections" className="text-xs h-8 data-[state=open]:bg-accent data-[state=open]:text-accent-foreground font-mono">
                  Sockets ({activeConnections.length})
                </TabsTrigger>
                <TabsTrigger value="logs" className="text-xs h-8 data-[state=open]:bg-accent data-[state=open]:text-accent-foreground font-mono">
                  Syslogs ({activeLogs.length})
                </TabsTrigger>
                <TabsTrigger value="ports" className="text-xs h-8 data-[state=open]:bg-accent data-[state=open]:text-accent-foreground font-mono">
                  Ports ({activePorts.length})
                </TabsTrigger>
              </TabsList>

              <Badge className={matchCount > 0 ? 'bg-red-950/40 text-red-400 border border-red-800' : 'bg-green-950/40 text-green-400 border border-green-800'}>
                {matchCount} Matches Discovered
              </Badge>
            </div>

            {/* TAB: Graph Correlation */}
            <TabsContent value="graph" className="mt-3">
              <div className="glass rounded-xl border border-border/60 overflow-hidden relative bg-black/40">
                <div className="absolute top-3 left-3 bg-black/60 border border-border/60 rounded p-2 z-10 text-[10px] font-mono space-y-1">
                  <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> Host Node</div>
                  <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded bg-cyan-500" /> Process Node</div>
                  <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded bg-indigo-500" /> Socket Node</div>
                  <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded bg-emerald-500" /> Log Node</div>
                </div>

                <div className="absolute top-3 right-3 z-10 text-[10px] font-mono">
                  {selectedNode ? (
                    <Badge variant="outline" className="bg-accent/15 text-accent border-accent/40 flex items-center gap-1">
                      Focused: {selectedNode.label}
                      <button onClick={() => setSelectedNode(null)} className="hover:text-red-400"><X className="w-3 h-3" /></button>
                    </Badge>
                  ) : (
                    <span className="text-muted-foreground bg-black/40 p-1 px-2 border border-border/40 rounded">Click nodes to inspect</span>
                  )}
                </div>

                {isHunting ? (
                  <div className="h-[400px] flex flex-col items-center justify-center space-y-4">
                    <Loader2 className="w-10 h-10 text-accent animate-spin" />
                    <p className="text-xs font-mono text-accent animate-pulse">Running telemetry scanning loops...</p>
                  </div>
                ) : graphData.nodes.length <= 1 ? (
                  <div className="h-[400px] flex flex-col items-center justify-center p-6 text-center">
                    <Target className="w-10 h-10 text-muted-foreground mb-3 animate-pulse" />
                    <p className="text-sm font-semibold text-foreground">No Correlation Hits Visualized</p>
                    <p className="text-xs text-muted-foreground mt-1 max-w-sm">
                      Select a Playbook template or refine your active filter string to populate matches.
                    </p>
                  </div>
                ) : (
                  <svg
                    className={`w-full h-[400px] select-none ${isDragging ? 'cursor-grabbing' : 'cursor-grab'}`}
                    viewBox="0 0 700 400"
                    onMouseDown={handleMouseDown}
                    onMouseMove={handleMouseMove}
                    onMouseUp={handleMouseUp}
                    onMouseLeave={handleMouseLeave}
                  >
                    <defs>
                      <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#4b5563" />
                      </marker>
                    </defs>

                    {/* Pan-only group: translate content so drag feels 1:1 with cursor */}
                    <g transform={`translate(${pan.x}, ${pan.y})`}>
                      {/* SVG Connections Lines */}
                      {graphData.links.map((link, idx) => {
                        const sourceNode = graphData.nodes.find(n => n.id === link.source);
                        const targetNode = graphData.nodes.find(n => n.id === link.target);
                        if (!sourceNode || !targetNode) return null;

                        return (
                          <g key={`link-${idx}`}>
                            {/* Main line path */}
                            <line
                              x1={sourceNode.x}
                              y1={sourceNode.y}
                              x2={targetNode.x}
                              y2={targetNode.y}
                              stroke={link.color}
                              strokeWidth={link.animated ? 1.5 : 1}
                              strokeDasharray={link.type.includes('log') ? '4 4' : 'none'}
                              className="opacity-60"
                            />
                            {/* Flow animation dots along line */}
                            {link.animated && (
                              <circle r="2.5" fill={link.color}>
                                <animateMotion
                                  dur={link.color === '#ef4444' ? '1.8s' : '3.5s'}
                                  repeatCount="indefinite"
                                  path={`M ${sourceNode.x} ${sourceNode.y} L ${targetNode.x} ${targetNode.y}`}
                                />
                              </circle>
                            )}
                          </g>
                        );
                      })}

                      {/* Nodes drawing */}
                      {graphData.nodes.map((node) => {
                        const isSelected = selectedNode?.id === node.id;
                        const size = node.type === 'host' ? 24 : node.type === 'process' ? 14 : 12;

                        let nodeColor = 'bg-cyan-500';
                        if (node.type === 'host') nodeColor = 'bg-cyan-400';
                        else if (node.type === 'connection') nodeColor = 'bg-indigo-500';
                        else if (node.type === 'log') nodeColor = 'bg-emerald-500';
                        else if (node.type === 'port') nodeColor = 'bg-purple-500';

                        let riskOutline = 'stroke-border/40';
                        if (node.risk === 'critical') riskOutline = 'stroke-red-500 animate-pulse';
                        else if (node.risk === 'high') riskOutline = 'stroke-orange-500 animate-pulse';
                        else if (node.risk === 'medium') riskOutline = 'stroke-yellow-500';

                        return (
                          <g
                            key={node.id}
                            transform={`translate(${node.x}, ${node.y})`}
                            onClick={() => setSelectedNode(node)}
                            className="cursor-pointer"
                          >
                            {/* Pulsing ring indicator for matches */}
                            {node.risk !== 'low' && (
                              <circle
                                r={size + 6}
                                className={`fill-none stroke-2 opacity-55 ${riskOutline}`}
                              />
                            )}

                            {/* Central node boundary circle */}
                            <circle
                              r={size}
                              className={`stroke-2 ${
                                isSelected ? 'stroke-accent fill-accent/20' : 'stroke-border fill-card'
                              } transition-colors`}
                            />

                            {/* Mini icon representations */}
                            {node.type === 'host' && (
                              <text y="5" textAnchor="middle" className="text-[12px] font-sans font-semibold fill-cyan-400">💻</text>
                            )}
                            {node.type === 'process' && (
                              <text y="4" textAnchor="middle" className="text-[9px] fill-cyan-300">⚙️</text>
                            )}
                            {node.type === 'connection' && (
                              <text y="4" textAnchor="middle" className="text-[8px] fill-indigo-300">🌐</text>
                            )}
                            {node.type === 'log' && (
                              <text y="4" textAnchor="middle" className="text-[8px] fill-emerald-300">📄</text>
                            )}

                            {/* Node Text labels */}
                            <text
                              y={size + 14}
                              textAnchor="middle"
                              className={`text-[8.5px] font-mono ${
                                isSelected ? 'fill-accent font-bold' : 'fill-muted-foreground'
                              }`}
                            >
                              {node.label.length > 20 ? `${node.label.substring(0, 18)}...` : node.label}
                            </text>
                          </g>
                        );
                      })}
                    </g>
                  </svg>
                )}

                {/* Reset Pan button */}
                {!isHunting && graphData.nodes.length > 1 && (
                  <div className="absolute bottom-3 right-3 z-10">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={handleResetPan}
                      className="h-7 px-2 text-[10px] font-mono text-muted-foreground hover:text-foreground hover:bg-muted/80 bg-black/60 border border-border/60 rounded-lg flex items-center gap-1 shadow-[0_4px_12px_rgba(0,0,0,0.5)]"
                      title="Reset Pan"
                    >
                      <RefreshCw className="w-3 h-3" />
                      <span>RESET</span>
                    </Button>
                  </div>
                )}
              </div>
            </TabsContent>

            {/* TAB: Processes Matches Table */}
            <TabsContent value="processes" className="mt-3 space-y-2">
              <div className="glass rounded-xl border border-border/50 overflow-hidden">
                <div className="grid grid-cols-12 gap-2 px-4 py-3 border-b border-border/60 text-xs text-muted-foreground font-mono uppercase bg-muted/20">
                  <div className="col-span-3">Process Name</div>
                  <div className="col-span-2">PID</div>
                  <div className="col-span-2">User</div>
                  <div className="col-span-2 text-right">CPU %</div>
                  <div className="col-span-1 text-center">Status</div>
                  <div className="col-span-2 text-center">Actions</div>
                </div>

                <ScrollArea className="h-96">
                  {activeProcesses.length === 0 ? (
                    <div className="p-8 text-center text-xs font-mono text-muted-foreground">No matching processes found</div>
                  ) : (
                    <div className="divide-y divide-border/30">
                      {activeProcesses.map((p, idx) => (
                        <div key={`${p.pid}-${idx}`} className="grid grid-cols-12 gap-2 px-4 py-3 hover:bg-card/50 transition-colors items-center font-mono text-xs">
                          <div className="col-span-3 font-semibold text-cyan-400 flex items-center gap-1.5 truncate">
                            {p.suspicious && <ShieldAlert className="w-3.5 h-3.5 text-orange-500 shrink-0" />}
                            {p.name}
                          </div>
                          <div className="col-span-2 text-muted-foreground">{p.pid}</div>
                          <div className="col-span-2 truncate">{p.username || 'n/a'}</div>
                          <div className="col-span-2 text-right text-foreground">{p.cpu_percent}%</div>
                          <div className="col-span-1 text-center">
                            <Badge variant="outline" className={`text-[10px] capitalize py-0 ${p.status === 'running' ? 'border-cyan-800 text-cyan-400 bg-cyan-950/20' : 'border-border/80 text-muted-foreground'}`}>{p.status}</Badge>
                          </div>
                          <div className="col-span-2 flex items-center justify-center gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setSelectedNode({ id: `proc-${p.pid}`, type: 'process', label: p.name, risk: p.suspicious ? 'high' : 'low', data: p })}
                              className="h-7 px-2 text-[10px] border-border/80 text-foreground hover:bg-muted"
                            >
                              Inspect
                            </Button>
                            <Button
                              size="sm"
                              onClick={() => handleEscalateIncident(p, 'process')}
                              className="h-7 px-2 text-[10px] bg-red-950/20 border border-red-800 text-red-400 hover:bg-red-950/40"
                            >
                              Escalate
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>

            {/* TAB: Sockets Matches Table */}
            <TabsContent value="connections" className="mt-3 space-y-2">
              <div className="glass rounded-xl border border-border/50 overflow-hidden">
                <div className="grid grid-cols-12 gap-2 px-4 py-3 border-b border-border/60 text-xs text-muted-foreground font-mono uppercase bg-muted/20">
                  <div className="col-span-3">Process</div>
                  <div className="col-span-4">Socket Direction</div>
                  <div className="col-span-1">Proto</div>
                  <div className="col-span-2">Geo / Org</div>
                  <div className="col-span-2 text-center">Actions</div>
                </div>

                <ScrollArea className="h-96">
                  {activeConnections.length === 0 ? (
                    <div className="p-8 text-center text-xs font-mono text-muted-foreground">No matching sockets found</div>
                  ) : (
                    <div className="divide-y divide-border/30">
                      {activeConnections.map((c, idx) => {
                        const isExt = !isPrivateIp(c.remote_ip);
                        return (
                          <div key={`${c.id}-${idx}`} className="grid grid-cols-12 gap-2 px-4 py-3 hover:bg-card/50 transition-colors items-center font-mono text-xs">
                            <div className="col-span-3 font-semibold text-indigo-400 truncate">{c.process || `PID: ${c.pid}`}</div>
                            <div className="col-span-4 truncate text-muted-foreground">
                              {c.local_ip}:{c.local_port} <span className="text-accent">&rarr;</span> {c.remote_ip || 'LISTEN'}:{c.remote_port || ''}
                            </div>
                            <div className="col-span-1 uppercase text-muted-foreground">{c.protocol}</div>
                            <div className="col-span-2 truncate flex items-center gap-1">
                              {isExt ? (
                                <Badge variant="outline" className="border-pink-900 text-pink-400 bg-pink-950/20 text-[9px] py-0 truncate max-w-full">
                                  {c.geo?.country_code || 'EXT'} - {c.geo?.org || 'Public'}
                                </Badge>
                              ) : (
                                <span className="text-muted-foreground text-[10px]">LAN</span>
                              )}
                            </div>
                            <div className="col-span-2 flex items-center justify-center gap-2">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => setSelectedNode({ id: `conn-${c.id || idx}`, type: 'connection', label: c.remote_ip, risk: isExt ? 'high' : 'low', data: c })}
                                className="h-7 px-2 text-[10px] border-border/80 text-foreground hover:bg-muted"
                              >
                                Inspect
                              </Button>
                              <Button
                                size="sm"
                                onClick={() => handleEscalateIncident(c, 'connection')}
                                className="h-7 px-2 text-[10px] bg-red-950/20 border border-red-800 text-red-400 hover:bg-red-950/40"
                              >
                                Escalate
                              </Button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>

            {/* TAB: Logs Matches Table */}
            <TabsContent value="logs" className="mt-3 space-y-2">
              <div className="glass rounded-xl border border-border/50 overflow-hidden">
                <div className="grid grid-cols-12 gap-2 px-4 py-3 border-b border-border/60 text-xs text-muted-foreground font-mono uppercase bg-muted/20">
                  <div className="col-span-1">Lvl</div>
                  <div className="col-span-2">Process</div>
                  <div className="col-span-6">Log Message</div>
                  <div className="col-span-1">Source</div>
                  <div className="col-span-2 text-center font-sans">Actions</div>
                </div>

                <ScrollArea className="h-96">
                  {activeLogs.length === 0 ? (
                    <div className="p-8 text-center text-xs font-mono text-muted-foreground">No matching system logs found</div>
                  ) : (
                    <div className="divide-y divide-border/30">
                      {activeLogs.map((l, idx) => (
                        <div key={`${l.id}-${idx}`} className="grid grid-cols-12 gap-2 px-4 py-3 hover:bg-card/50 transition-colors items-center font-mono text-xs">
                          <div className="col-span-1">
                            <Badge className={`text-[9px] uppercase px-1 py-0 ${l.level === 'error' ? 'bg-red-950/40 text-red-400 border border-red-950' : l.level === 'warn' ? 'bg-yellow-950/40 text-yellow-400 border border-yellow-950' : 'bg-muted text-muted-foreground border border-transparent'}`}>
                              {l.level}
                            </Badge>
                          </div>
                          <div className="col-span-2 font-semibold text-emerald-400 truncate">{l.process}</div>
                          <div className="col-span-6 text-foreground/90 truncate pr-2">{l.message}</div>
                          <div className="col-span-1 text-[10px] text-muted-foreground truncate">{l.source}</div>
                          <div className="col-span-2 flex items-center justify-center gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setSelectedNode({ id: `log-${l.id}`, type: 'log', label: `Log ${l.id}`, risk: l.level === 'error' ? 'high' : 'low', data: l })}
                              className="h-7 px-2 text-[10px] border-border/80 text-foreground hover:bg-muted"
                            >
                              Inspect
                            </Button>
                            <Button
                              size="sm"
                              onClick={() => handleEscalateIncident(l, 'log')}
                              className="h-7 px-2 text-[10px] bg-red-950/20 border border-red-800 text-red-400 hover:bg-red-950/40"
                            >
                              Escalate
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>

            {/* TAB: Listening Ports matches */}
            <TabsContent value="ports" className="mt-3 space-y-2">
              <div className="glass rounded-xl border border-border/50 overflow-hidden">
                <div className="grid grid-cols-12 gap-2 px-4 py-3 border-b border-border/60 text-xs text-muted-foreground font-mono uppercase bg-muted/20">
                  <div className="col-span-2">Port</div>
                  <div className="col-span-3">Interface Address</div>
                  <div className="col-span-4">Associated Process</div>
                  <div className="col-span-3">PID</div>
                </div>

                <ScrollArea className="h-96">
                  {activePorts.length === 0 ? (
                    <div className="p-8 text-center text-xs font-mono text-muted-foreground">No matching listening ports found</div>
                  ) : (
                    <div className="divide-y divide-border/30">
                      {activePorts.map((pt, idx) => (
                        <div key={`${pt.port}-${idx}`} className="grid grid-cols-12 gap-2 px-4 py-3 hover:bg-card/50 transition-colors items-center font-mono text-xs">
                          <div className="col-span-2 font-semibold text-purple-400">Port {pt.port}</div>
                          <div className="col-span-3 text-muted-foreground">{pt.ip}</div>
                          <div className="col-span-4 text-foreground">{pt.process}</div>
                          <div className="col-span-3 text-muted-foreground">{pt.pid || 'n/a'}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>
          </Tabs>

          {/* Focused Node Detail Inspection Card */}
          {selectedNode && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-xl border border-border/60 p-4 relative"
            >
              <button
                onClick={() => setSelectedNode(null)}
                className="absolute top-3 right-3 text-muted-foreground hover:text-foreground"
              >
                <X className="w-4 h-4" />
              </button>

              <div className="flex items-center gap-2 mb-3">
                <ShieldCheck className="w-5 h-5 text-accent animate-glow" />
                <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide">
                  Active Asset Details: <span className="font-mono text-accent">{selectedNode.label}</span>
                </h3>
                <Badge variant="outline" className={`text-[10px] font-mono capitalize ${RISK_COLORS[selectedNode.risk]}`}>
                  Risk: {selectedNode.risk}
                </Badge>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                {/* Meta details */}
                <div className="space-y-2 bg-black/35 p-3 rounded border border-border/30">
                  <p className="text-[10px] text-muted-foreground uppercase">Raw Metadata JSON</p>
                  <pre className="max-h-36 overflow-y-auto text-[10px] text-green-300 leading-normal scrollbar-thin">
                    {JSON.stringify(selectedNode.data, null, 2)}
                  </pre>
                </div>

                {/* Remediation Checklists */}
                <div className="space-y-2.5">
                  <p className="text-[10px] text-muted-foreground uppercase flex items-center gap-1">
                    <Info className="w-3.5 h-3.5 text-accent" /> Forensic Remediations Playbook
                  </p>
                  <div className="space-y-2 text-[11px] leading-tight">
                    {selectedNode.type === 'process' && (
                      <>
                        <div className="flex items-start gap-1.5 text-foreground/90">
                          <span className="text-red-500">&#9656;</span>
                          <span>Kill PID <strong className="text-accent">{selectedNode.data.pid}</strong> immediately if confirmed rogue.</span>
                        </div>
                        <div className="flex items-start gap-1.5 text-foreground/90">
                          <span className="text-orange-500">&#9656;</span>
                          <span>Audit binary file path hashes against Virustotal database.</span>
                        </div>
                      </>
                    )}
                    {selectedNode.type === 'connection' && (
                      <>
                        <div className="flex items-start gap-1.5 text-foreground/90">
                          <span className="text-red-500">&#9656;</span>
                          <span>Block Remote IP <strong className="text-accent">{selectedNode.data.remote_ip}</strong> in host rules/firewall.</span>
                        </div>
                        <div className="flex items-start gap-1.5 text-foreground/90">
                          <span className="text-orange-500">&#9656;</span>
                          <span>Verify the source binary owning PID {selectedNode.data.pid}.</span>
                        </div>
                      </>
                    )}
                    {selectedNode.type === 'log' && (
                      <>
                        <div className="flex items-start gap-1.5 text-foreground/90">
                          <span className="text-red-500">&#9656;</span>
                          <span>Verify authentication keys or secrets matching this entry.</span>
                        </div>
                        <div className="flex items-start gap-1.5 text-foreground/90">
                          <span className="text-orange-500">&#9656;</span>
                          <span>Ensure auditd/syslog processes are not tampered or disabled.</span>
                        </div>
                      </>
                    )}
                    {selectedNode.type === 'host' && (
                      <>
                        <div className="flex items-start gap-1.5 text-foreground/90">
                          <span className="text-green-500">&#9656;</span>
                          <span>Host endpoint status is active. Check overall CPU resources.</span>
                        </div>
                      </>
                    )}

                    <div className="pt-2 border-t border-border/30 flex gap-2">
                      <Button
                        size="sm"
                        onClick={() => handleEscalateIncident(selectedNode.data, selectedNode.type)}
                        className="bg-red-950/40 hover:bg-red-900/40 border border-red-800 text-red-400 font-semibold h-7 text-[10px]"
                      >
                        Escalate Open Incident
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          toast.success('Asset marked nominal', { description: `${selectedNode.label} marked safe in session.` });
                          setSelectedNode(null);
                        }}
                        className="border-border/60 hover:bg-muted text-foreground h-7 text-[10px]"
                      >
                        Flag Safe
                      </Button>
                    </div>
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
