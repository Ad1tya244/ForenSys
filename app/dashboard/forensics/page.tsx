'use client';

import { useState, useEffect } from 'react';
import { Lock, Hash, Calendar, User, FileCode, Copy, Cpu, Globe, Database, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppStore, EvidenceItem } from '@/lib/app-store';
import { toast } from 'sonner';
import { AccessDenied } from '@/components/rbac/access-denied';

const renderStructuredPayload = (item: EvidenceItem) => {
  if (!item.payload) {
    return <p className="text-xs text-muted-foreground italic">No detailed payload metadata captured for this evidence.</p>;
  }

  const p = item.payload;

  switch (item.type) {
    case 'Log File':
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Process Name</span>
              <span className="text-foreground font-semibold text-sm flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-accent" />
                {p.process || 'syslog'}
              </span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Process PID</span>
              <span className="text-accent font-semibold text-sm">{p.pid ?? 'N/A'}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Source Stream</span>
              <span className="text-foreground text-xs truncate block">{p.source || 'system.log'}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Severity Level</span>
              <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold uppercase mt-0.5 ${
                p.level === 'error' ? 'bg-red-950/40 text-red-400 border border-red-800/30' :
                p.level === 'warn' ? 'bg-yellow-950/40 text-yellow-400 border border-yellow-800/30' :
                'bg-blue-950/40 text-blue-400 border border-blue-800/30'
              }`}>
                {p.level || 'info'}
              </span>
            </div>
          </div>
          <div className="p-3 bg-red-950/10 border border-red-900/20 rounded font-mono text-xs text-foreground/90 space-y-1 text-left">
            <span className="text-[10px] text-muted-foreground uppercase block">Captured Log Entry Payload</span>
            <p className="whitespace-pre-wrap leading-relaxed select-all">{p.message}</p>
          </div>
        </div>
      );

    case 'Memory Dump':
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-2.5 bg-card/45 rounded border border-border/20 col-span-2 md:col-span-1">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Process Name</span>
              <span className="text-foreground font-semibold text-sm truncate block">{p.name || 'unknown'}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Process PID</span>
              <span className="text-accent font-semibold text-sm">{p.pid ?? 'N/A'}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">User Context</span>
              <span className="text-foreground text-sm">{p.username || 'unknown'}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">CPU Load</span>
              <span className="text-foreground text-sm flex items-center gap-1">
                <Cpu className="w-3.5 h-3.5 text-accent" />
                {p.cpu_percent ?? 0}%
              </span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Memory Usage</span>
              <span className="text-foreground text-sm">{p.memory_percent ?? 0}%</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Audit Status</span>
              <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold uppercase mt-0.5 ${
                p.suspicious ? 'bg-red-950/40 text-red-400 border border-red-800/30' : 'bg-green-950/40 text-green-400 border border-green-800/30'
              }`}>
                {p.suspicious ? 'SUSPICIOUS' : 'VERIFIED CLEAN'}
              </span>
            </div>
          </div>
          {p.status && (
            <div className="p-2.5 bg-card/45 rounded border border-border/20 font-mono text-xs text-left">
              <span className="text-muted-foreground block text-[10px] uppercase mb-1">Process Run State</span>
              <span className="text-foreground">{p.status}</span>
            </div>
          )}
        </div>
      );

    case 'Network Capture':
    case 'Security Artifact':
    case 'Telemetry Package':
      const packets = p.packets || [];
      const logs = p.logs || [];
      
      const targetAsset = p.affected_assets?.[0];
      const isIcmpIncident = p.incident_title?.includes('ICMP');

      const icmpOrAttackerPkts = packets.filter((pkt: any) => 
        pkt.protocol === 'ICMP' ||
        (targetAsset && (pkt.src_ip === targetAsset || pkt.dst_ip === targetAsset))
      );
      const displayPackets = (isIcmpIncident && icmpOrAttackerPkts.length > 0) ? icmpOrAttackerPkts : (icmpOrAttackerPkts.length > 0 ? icmpOrAttackerPkts : packets);

      const firstPkt = displayPackets[0] || packets[0] || {};
      const srcIp = p.attacker_ip || firstPkt.src_ip || 'Remote IP';
      
      let dstIp = p.affected_assets?.[0] || firstPkt.dst_ip || 'Local Host';
      if ((!dstIp || dstIp === '0.0.0.0' || dstIp === 'localhost') && firstPkt.dst_ip) {
        dstIp = firstPkt.dst_ip;
      }
      
      const proto = isIcmpIncident ? 'ICMP' : (firstPkt.protocol || p.protocol || 'TCP');

      return (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Attacker IP (Source)</span>
              <span className="text-accent font-semibold text-sm truncate block">{srcIp}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Affected System (Target)</span>
              <span className="text-foreground text-xs truncate block">{dstIp}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Protocol</span>
              <span className="text-foreground font-semibold text-sm">{proto}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Captured Telemetry</span>
              <span className="text-foreground text-xs">{displayPackets.length} packets, {logs.length} logs</span>
            </div>
          </div>

          {displayPackets.length > 0 && (
            <div className="p-3 bg-card/30 border border-border/40 rounded space-y-2 text-left">
              <div className="flex items-center justify-between text-[11px] font-semibold text-muted-foreground uppercase tracking-wider border-b border-border/20 pb-1.5 font-mono">
                <span>Captured Packet Telemetry ({displayPackets.length} items)</span>
                <span className="font-mono text-accent">{proto} TELEMETRY</span>
              </div>
              <ScrollArea className="max-h-55">
                <div className="space-y-1 font-mono text-[11px]">
                  {displayPackets.map((pkt: any, idx: number) => (
                    <div key={idx} className="p-1.5 rounded bg-background/50 border border-border/20 flex items-center justify-between gap-2">
                      <span className="text-muted-foreground text-[10px] w-6 shrink-0">#{idx + 1}</span>
                      <Badge variant="outline" className="text-[9px] py-0 px-1 border-accent/40 text-accent shrink-0">{pkt.protocol || 'ICMP'}</Badge>
                      <span className="text-foreground font-medium truncate flex-1">{pkt.src_ip || 'N/A'} &rarr; {pkt.dst_ip || 'N/A'}</span>
                      <span className="text-muted-foreground text-[10px] shrink-0 truncate max-w-55">{pkt.info || `${pkt.length || 64} bytes`}</span>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          )}

          {p.indicators && p.indicators.length > 0 && (
            <div className="p-2.5 bg-card/45 rounded border border-border/20 font-mono text-xs text-left">
              <span className="text-muted-foreground block text-[10px] uppercase mb-1">Security Flags / Threat Indicators</span>
              <div className="flex gap-1.5 flex-wrap mt-1">
                {p.indicators.map((ind: string, idx: number) => (
                  <Badge key={idx} variant="outline" className="bg-red-950/20 text-red-400 border-red-900/40 text-[10px] py-0">
                    {ind}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      );

    case 'File': // Alert
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Alert Rule Category</span>
              <span className="text-foreground font-semibold text-sm">{p.category || 'unknown'}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Escalated Severity</span>
              <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold uppercase mt-0.5 ${
                p.severity === 'critical' ? 'bg-red-900/40 text-red-400 border border-red-700/50' :
                p.severity === 'high' ? 'bg-orange-900/40 text-orange-400 border border-orange-700/50' :
                p.severity === 'medium' ? 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/50' :
                'bg-blue-900/40 text-blue-400 border border-blue-700/50'
              }`}>
                {p.severity || 'high'}
              </span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Target Assets</span>
              <span className="text-foreground text-xs truncate block">{(p.affectedAssets && p.affectedAssets.join(', ')) || 'localhost'}</span>
            </div>
            <div className="p-2.5 bg-card/45 rounded border border-border/20">
              <span className="text-muted-foreground block text-[10px] uppercase tracking-wider mb-1">Sensor Source</span>
              <span className="text-foreground text-xs truncate block">{p.source || 'endpoint-agent'}</span>
            </div>
          </div>
          <div className="p-3 bg-red-950/10 border border-red-900/20 rounded font-mono text-xs text-foreground/90 space-y-1 text-left">
            <span className="text-[10px] text-muted-foreground uppercase block">Security Detection Context</span>
            <p className="whitespace-pre-wrap leading-relaxed select-all">{p.description}</p>
          </div>
        </div>
      );

    default:
      return (
        <div className="p-3 bg-card/45 rounded border border-border/20 font-mono text-xs text-foreground select-all whitespace-pre-wrap text-left">
          {JSON.stringify(p, null, 2)}
        </div>
      );
  }
};

export default function ForensicsPage() {
  const { evidenceItems, authenticateEvidenceItem, deleteEvidenceItemAction, currentUser, hasPermission } = useAppStore();
  const isAdmin = currentUser?.role === 'admin';
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceItem | null>(null);
  const [filter, setFilter] = useState('all');
  const [detailsTab, setDetailsTab] = useState<'structured' | 'raw'>('structured');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Keep selectedEvidence in sync when evidenceItems change or first load
  useEffect(() => {
    if (evidenceItems.length > 0 && !selectedEvidence) {
      setSelectedEvidence(evidenceItems[0]);
    }
  }, [evidenceItems, selectedEvidence]);

  useEffect(() => {
    setDetailsTab('structured');
  }, [selectedEvidence?.id]);

  const filteredItems = evidenceItems.filter((item) => {
    if (filter === 'all') return true;
    return item.type.toLowerCase() === filter.toLowerCase();
  });

  // Handle selected item falling out of filtered list
  useEffect(() => {
    if (selectedEvidence && !filteredItems.some(item => item.id === selectedEvidence.id)) {
      setSelectedEvidence(filteredItems[0] || null);
    }
  }, [filter, filteredItems, selectedEvidence]);

  if (!mounted) return null;

  if (!hasPermission('view_forensics')) {
    return <AccessDenied permission="view_forensics" />;
  }

  const handleDownloadJSON = (item: EvidenceItem) => {
    try {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(item, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `forensys_evidence_${item.id}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      toast.success('Evidence Downloaded', { description: `Saved as forensys_evidence_${item.id}.json` });
    } catch (e) {
      toast.error('Download Failed', { description: 'Could not export raw json.' });
    }
  };

  const handleExportReport = (item: EvidenceItem) => {
    try {
      const reportText = `FORENSYS SECURITY REPORT - EVIDENCE VAULT
==================================================
Evidence ID: ${item.id}
Incident ID: ${item.incidentId}
Evidence Type: ${item.type}
Collection Timestamp: ${new Date(item.collectedAt).toLocaleString()}
Collected By: ${item.collectedBy}
Validation Status: ${item.status}
SHA256 Integrity Hash: ${item.hash}

RAW PAYLOAD DATA
--------------------------------------------------
${JSON.stringify(item.payload || {}, null, 2)}
`;
      const dataStr = "data:text/plain;charset=utf-8," + encodeURIComponent(reportText);
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `forensys_report_${item.id}.txt`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      toast.success('Report Exported', { description: `Saved as forensys_report_${item.id}.txt` });
    } catch (e) {
      toast.error('Export Failed', { description: 'Could not write text report.' });
    }
  };

  // Handled inside initial useEffects to preserve execution order

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <Lock className="w-6 h-6 text-accent" />
          Forensic Evidence Vault
        </h1>
        <p className="text-muted-foreground">Chain of custody preservation and evidence authentication</p>
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap font-sans items-center">
        {['all', 'File', 'Memory Dump', 'Network Capture', 'Registry Export', 'Log File'].map((type) => {
          const count = type === 'all'
            ? evidenceItems.length
            : evidenceItems.filter(item => item.type === type).length;
          return (
            <button
              key={type}
              onClick={() => setFilter(type)}
              className={`h-7 px-3 rounded-full text-xs font-medium border transition-all duration-200 hover:scale-[1.01] active:scale-[0.97] ${
                filter === type
                  ? 'bg-accent/20 text-accent border-accent/50'
                  : 'bg-transparent border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              {type}
              <span className="ml-1 opacity-60 font-mono text-[10px]">{count}</span>
            </button>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Evidence List */}
        <div className="glass rounded-lg border border-border/50 overflow-hidden flex flex-col">
          <div className="p-4 border-b border-border/50">
            <h2 className="text-lg font-semibold text-foreground">Evidence Items ({filteredItems.length})</h2>
          </div>
          <ScrollArea className="flex-1 max-h-150 min-h-75">
            <div className="space-y-2 p-4">
              <AnimatePresence mode="popLayout">
                {filteredItems.map((item, idx) => (
                  <motion.div
                    key={item.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ delay: idx * 0.05 }}
                    onClick={() => setSelectedEvidence(item)}
                    className={`p-3 rounded border cursor-pointer transition-all ${
                      selectedEvidence?.id === item.id
                        ? 'border-accent bg-accent/10'
                        : 'border-border/50 hover:border-border'
                    }`}
                  >
                    <div className="flex items-start gap-2">
                      <div className="w-8 h-8 rounded bg-accent/20 flex items-center justify-center shrink-0 text-accent text-xs font-bold font-mono">
                        {(item.type || 'F')[0].toUpperCase()}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="font-semibold text-sm text-foreground">{item.id}</p>
                        <p className="text-xs text-muted-foreground line-clamp-2">{item.description}</p>
                        <Badge variant="outline" className={`text-xs mt-1 border-0 ${
                          item.status === 'Authenticated' 
                            ? 'bg-green-900/30 text-green-300'
                            : 'bg-blue-900/30 text-blue-300'
                        }`}>
                          {item.status}
                        </Badge>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
              {filteredItems.length === 0 && (
                <div className="py-12 text-center text-xs text-muted-foreground font-mono">
                  [NO EVIDENCE CONFIGURED]
                </div>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* Evidence Details */}
        <div className="lg:col-span-2 glass rounded-lg border border-border/50 p-6 flex flex-col min-h-87.5 justify-between">
          {selectedEvidence ? (
            <AnimatePresence mode="wait">
              <motion.div
                key={selectedEvidence.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="flex flex-col flex-1 min-h-0 space-y-4 w-full text-left"
              >
                {/* Header */}
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <Badge className="bg-accent/20 text-accent border-accent/50">{selectedEvidence.type}</Badge>
                    <Badge
                      className={
                        selectedEvidence.status === 'Authenticated'
                          ? 'bg-green-900/30 text-green-300 border-green-700/50'
                          : 'bg-blue-900/30 text-blue-300 border-blue-700/50'
                      }
                    >
                      {selectedEvidence.status}
                    </Badge>
                  </div>
                  <h2 className="text-xl font-bold text-foreground">{selectedEvidence.id}</h2>
                  <p className="text-muted-foreground mt-2">{selectedEvidence.description}</p>
                </div>

                {/* Metadata */}
                <div className="border-t border-border/50 pt-4 space-y-3">
                  <h3 className="font-semibold text-foreground">Evidence Metadata</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center justify-between p-2 bg-card/50 rounded border border-border/20">
                      <span className="text-muted-foreground flex items-center gap-2">
                        <Hash className="w-4 h-4 text-accent" />
                        Hash (SHA256)
                      </span>
                      <code className="text-accent font-mono text-xs truncate max-w-50 sm:max-w-xs">{selectedEvidence.hash}</code>
                    </div>
                    <div className="flex items-center justify-between p-2 bg-card/50 rounded border border-border/20">
                      <span className="text-muted-foreground flex items-center gap-2">
                        <User className="w-4 h-4 text-accent" />
                        Collected By
                      </span>
                      <span className="text-foreground font-mono text-xs">{selectedEvidence.collectedBy}</span>
                    </div>
                    <div className="flex items-center justify-between p-2 bg-card/50 rounded border border-border/20">
                      <span className="text-muted-foreground flex items-center gap-2">
                        <Calendar className="w-4 h-4 text-accent" />
                        Collection Time
                      </span>
                      <span className="text-foreground font-mono text-xs">{new Date(selectedEvidence.collectedAt).toLocaleString()}</span>
                    </div>
                  </div>
                </div>

                {/* Captured Forensic Payload */}
                {selectedEvidence.payload && (
                  <div className="border-t border-border/50 pt-4 space-y-3 flex-1 min-h-0 flex flex-col">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold text-foreground flex items-center gap-2">
                        <FileCode className="w-4 h-4 text-accent" />
                        Captured Forensic Payload
                      </h3>
                      <div className="flex bg-card/85 border border-border/50 rounded p-0.5 text-xs font-mono">
                        <button
                          onClick={() => setDetailsTab('structured')}
                          className={`px-2 py-1 rounded transition-all ${
                            detailsTab === 'structured'
                              ? 'bg-accent/20 text-accent font-semibold'
                              : 'text-muted-foreground hover:text-foreground'
                          }`}
                        >
                          Structured
                        </button>
                        <button
                          onClick={() => setDetailsTab('raw')}
                          className={`px-2 py-1 rounded transition-all ${
                            detailsTab === 'raw'
                              ? 'bg-accent/20 text-accent font-semibold'
                              : 'text-muted-foreground hover:text-foreground'
                          }`}
                        >
                          Raw JSON
                        </button>
                      </div>
                    </div>

                    <div className="glass rounded border border-border/50 p-4 bg-card/25 max-h-75 overflow-y-auto">
                      <AnimatePresence mode="wait">
                        <motion.div
                          key={detailsTab}
                          initial={{ opacity: 0, y: 10 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -10 }}
                          className="w-full text-left"
                        >
                          {detailsTab === 'structured' ? (
                            renderStructuredPayload(selectedEvidence)
                          ) : (
                            <div className="relative font-mono text-xs bg-black/40 border border-border/20 rounded p-3 text-emerald-400 overflow-auto max-h-60 select-all">
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText(JSON.stringify(selectedEvidence.payload, null, 2));
                                  toast.success('Copied Payload', { description: 'JSON copied to clipboard' });
                                }}
                                className="absolute right-2 top-2 p-1.5 rounded bg-card/85 hover:bg-card border border-border/30 text-muted-foreground hover:text-foreground transition-all"
                                title="Copy JSON"
                              >
                                <Copy className="w-3.5 h-3.5" />
                              </button>
                              <pre className="whitespace-pre-wrap leading-relaxed">{JSON.stringify(selectedEvidence.payload, null, 2)}</pre>
                            </div>
                          )}
                        </motion.div>
                      </AnimatePresence>
                    </div>
                  </div>
                )}

                {/* Actions Footer */}
                <div className="border-t border-border/50 pt-4 mt-auto grid grid-cols-2 sm:grid-cols-4 gap-2 shrink-0">
                  <Button
                    onClick={() => {
                      authenticateEvidenceItem(selectedEvidence.id);
                      toast.success('Evidence Authenticated', { description: 'Added verified checksum to chain of custody.' });
                    }}
                    className="w-full bg-accent hover:bg-accent/90 text-accent-foreground flex items-center justify-center gap-1.5 text-xs truncate"
                    size="sm"
                    disabled={selectedEvidence.status === 'Authenticated' || !hasPermission('manage_incidents')}
                  >
                    Authenticate
                  </Button>
                  <Button
                    onClick={() => handleDownloadJSON(selectedEvidence)}
                    variant="outline"
                    className="w-full border-border/50 flex items-center justify-center gap-1.5 text-xs truncate"
                    size="sm"
                    disabled={!hasPermission('export_forensics')}
                  >
                    Download JSON
                  </Button>
                  <Button
                    onClick={() => handleExportReport(selectedEvidence)}
                    variant="outline"
                    className="w-full border-border/50 flex items-center justify-center gap-1.5 text-xs truncate"
                    size="sm"
                    disabled={!hasPermission('export_forensics')}
                  >
                    Export Report
                  </Button>
                  {isAdmin ? (
                    <Button
                      onClick={async () => {
                        try {
                          await deleteEvidenceItemAction(selectedEvidence.id);
                          toast.success('Evidence Bundle Deleted', { description: `Forensic package ${selectedEvidence.id} removed.` });
                          setSelectedEvidence(null);
                        } catch (err: any) {
                          toast.error('Deletion Failed', { description: err.message || 'Only Admin users can delete forensic evidence bundles.' });
                        }
                      }}
                      variant="destructive"
                      className="w-full bg-red-600 hover:bg-red-500 text-white font-semibold flex items-center justify-center gap-1.5 text-xs truncate shadow-md shadow-red-950/50 border-0"
                      size="sm"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Delete Bundle
                    </Button>
                  ) : (
                    <div />
                  )}
                </div>
              </motion.div>
            </AnimatePresence>
          ) : (
            <div className="flex flex-col items-center justify-center text-center p-8">
              <Lock className="w-12 h-12 text-muted-foreground/40 mb-3 animate-pulse" />
              <p className="text-sm text-muted-foreground font-mono">[NO EVIDENCE IN VAULT]</p>
              <p className="text-xs text-muted-foreground/80 mt-1 max-w-md">
                Raise an event as an incident from host logs, network connections, or security alerts to capture forensic evidence.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
