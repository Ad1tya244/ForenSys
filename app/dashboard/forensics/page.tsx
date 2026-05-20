'use client';

import { useState } from 'react';
import { Lock, FileText, Hash, Calendar, User } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { motion, AnimatePresence } from 'framer-motion';

const evidenceItems = [
  {
    id: 'EVD-001',
    type: 'File',
    description: 'Suspicious PowerShell script from user temp folder',
    hash: 'SHA256: a4f3c8e9...',
    collectedBy: 'Sarah Johnson',
    collectedAt: '2024-01-15T14:32:45Z',
    chain: ['Collected', 'Analyzed', 'Reported'],
    status: 'Authenticated',
  },
  {
    id: 'EVD-002',
    type: 'Memory Dump',
    description: 'Process memory capture from suspicious svchost.exe',
    hash: 'SHA256: b5f4d9f0...',
    collectedBy: 'Michael Chen',
    collectedAt: '2024-01-15T14:30:12Z',
    chain: ['Collected', 'Analyzed'],
    status: 'Authenticated',
  },
  {
    id: 'EVD-003',
    type: 'Network Capture',
    description: 'PCAP file of C2 communication attempt',
    hash: 'SHA256: c6f5e0a1...',
    collectedBy: 'Lisa Anderson',
    collectedAt: '2024-01-15T14:28:33Z',
    chain: ['Collected'],
    status: 'Sealed',
  },
  {
    id: 'EVD-004',
    type: 'Registry Export',
    description: 'Windows registry hives from compromised system',
    hash: 'SHA256: d7f6f1b2...',
    collectedBy: 'John Smith',
    collectedAt: '2024-01-15T14:25:18Z',
    chain: ['Collected', 'Analyzed', 'Reported'],
    status: 'Authenticated',
  },
  {
    id: 'EVD-005',
    type: 'Log File',
    description: 'Event logs from affected server spanning 48 hours',
    hash: 'SHA256: e8f7f2c3...',
    collectedBy: 'Emily Brown',
    collectedAt: '2024-01-15T14:22:47Z',
    chain: ['Collected'],
    status: 'Sealed',
  },
];

export default function ForensicsPage() {
  const [selectedEvidence, setSelectedEvidence] = useState(evidenceItems[0]);
  const [filter, setFilter] = useState('all');

  const filteredItems = evidenceItems.filter((item) => {
    if (filter === 'all') return true;
    return item.type.toLowerCase() === filter.toLowerCase();
  });

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
          <ScrollArea className="flex-1">
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
                      selectedEvidence.id === item.id
                        ? 'border-accent bg-accent/10'
                        : 'border-border/50 hover:border-border'
                    }`}
                  >
                    <div className="flex items-start gap-2">
                      <div className="w-8 h-8 rounded bg-accent/20 flex items-center justify-center flex-shrink-0 text-accent text-xs font-bold">
                        {item.type[0]}
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
            </div>
          </ScrollArea>
        </div>

        {/* Evidence Details */}
        <div className="lg:col-span-2 glass rounded-lg border border-border/50 p-6 space-y-4 overflow-auto">
          <motion.div
            key={selectedEvidence.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-4"
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
                <div className="flex items-center justify-between p-2 bg-card/50 rounded">
                  <span className="text-muted-foreground flex items-center gap-2">
                    <Hash className="w-4 h-4" />
                    Hash (SHA256)
                  </span>
                  <code className="text-accent font-mono text-xs">{selectedEvidence.hash}</code>
                </div>
                <div className="flex items-center justify-between p-2 bg-card/50 rounded">
                  <span className="text-muted-foreground flex items-center gap-2">
                    <User className="w-4 h-4" />
                    Collected By
                  </span>
                  <span className="text-foreground">{selectedEvidence.collectedBy}</span>
                </div>
                <div className="flex items-center justify-between p-2 bg-card/50 rounded">
                  <span className="text-muted-foreground flex items-center gap-2">
                    <Calendar className="w-4 h-4" />
                    Collection Time
                  </span>
                  <span className="text-foreground">{new Date(selectedEvidence.collectedAt).toLocaleString()}</span>
                </div>
              </div>
            </div>

            {/* Chain of Custody */}
            <div className="border-t border-border/50 pt-4">
              <h3 className="font-semibold text-foreground mb-3">Chain of Custody</h3>
              <div className="space-y-2">
                {selectedEvidence.chain.map((step, idx) => (
                  <div key={idx} className="flex items-center gap-3">
                    <div className="w-6 h-6 rounded-full bg-accent/20 text-accent flex items-center justify-center text-xs font-bold">
                      ✓
                    </div>
                    <span className="text-foreground text-sm">{step}</span>
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
        </div>
      </div>
    </div>
  );
}
