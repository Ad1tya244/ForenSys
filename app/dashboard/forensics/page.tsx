'use client';

import { useState, useEffect } from 'react';
import { Lock, Hash, Calendar, User } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppStore, EvidenceItem } from '@/lib/app-store';

export default function ForensicsPage() {
  const { evidenceItems } = useAppStore();
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceItem | null>(null);
  const [filter, setFilter] = useState('all');

  // Keep selectedEvidence in sync when evidenceItems change or first load
  useEffect(() => {
    if (evidenceItems.length > 0 && !selectedEvidence) {
      setSelectedEvidence(evidenceItems[0]);
    }
  }, [evidenceItems, selectedEvidence]);

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

  return (
    <div className="flex-1 overflow-auto p-6 space-y-6">
      {/* Header */}
      <div className="space-y-2">
        <h1 className="text-3xl font-bold text-foreground flex items-center gap-2">
          <Lock className="w-8 h-8 text-accent" />
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
          <ScrollArea className="flex-1 max-h-[600px] min-h-[300px]">
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
        <div className="lg:col-span-2 glass rounded-lg border border-border/50 p-6 space-y-4 overflow-auto min-h-[350px] flex flex-col justify-center">
          {selectedEvidence ? (
            <AnimatePresence mode="wait">
              <motion.div
                key={selectedEvidence.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-4 w-full h-full text-left"
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
                      <code className="text-accent font-mono text-xs truncate max-w-[200px] sm:max-w-xs">{selectedEvidence.hash}</code>
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

                {/* Chain of Custody */}
                <div className="border-t border-border/50 pt-4">
                  <h3 className="font-semibold text-foreground mb-3">Chain of Custody</h3>
                  <div className="space-y-2">
                    {selectedEvidence.chain.map((step, idx) => (
                      <div key={idx} className="flex items-center gap-3">
                        <div className="w-6 h-6 rounded-full bg-accent/20 text-accent flex items-center justify-center text-xs font-bold font-mono">
                          ✓
                        </div>
                        <span className="text-foreground text-sm font-mono">{step}</span>
                        {idx < selectedEvidence.chain.length - 1 && (
                          <div className="flex-1 h-0.5 bg-border/50" />
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div className="border-t border-border/50 pt-4 flex gap-2">
                  <Button className="flex-1 bg-accent hover:bg-accent/90 text-accent-foreground" size="sm">
                    Verify Hash
                  </Button>
                  <Button variant="outline" className="flex-1 border-border/50" size="sm">
                    Download
                  </Button>
                  <Button variant="outline" className="flex-1 border-border/50" size="sm">
                    Export
                  </Button>
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
