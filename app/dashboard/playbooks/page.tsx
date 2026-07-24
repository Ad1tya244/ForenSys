'use client';

import { useState, useEffect } from 'react';
import { Shield, Lock, RotateCcw, CheckCircle, Search, Filter } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useAppStore } from '@/lib/app-store';

export default function FirewallRulesPage() {
  const { blockedIps, blockedIpDetails, blockIpAction, unblockIpAction, ruleCatalog } = useAppStore();
  const [mounted, setMounted] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [manualIpInput, setManualIpInput] = useState('');

  useEffect(() => {
    setMounted(true);
  }, []);

  const filteredBlocklist = blockedIpDetails.filter((item) =>
    item.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
    item.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
    item.incident_id.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Shield className="w-6 h-6 text-accent" />
            Firewall Rules & IP Blocklist
          </h1>
          <p className="text-muted-foreground text-sm">
            Active macOS PF firewall rules, active perimeter blocklists, and defense configurations
          </p>
        </div>
        <Badge className="bg-accent/15 text-accent border-accent/30 px-3 py-1 font-mono text-xs">
          Perimeter Engine Active ({blockedIps.length} IPs Blocked)
        </Badge>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass p-4 rounded-lg border border-accent/30">
          <p className="text-xs text-accent">Active Blocked Source IPs</p>
          <p className="text-2xl font-bold text-foreground mt-1 font-mono">{blockedIps.length}</p>
        </div>
        <div className="glass p-4 rounded-lg border border-border/50">
          <p className="text-xs text-muted-foreground">Registered Detection Rules</p>
          <p className="text-2xl font-bold text-foreground mt-1 font-mono">{ruleCatalog.length || 10}</p>
        </div>
        <div className="glass p-4 rounded-lg border border-green-500/30">
          <p className="text-xs text-green-400">Firewall Engine Status</p>
          <p className="text-2xl font-bold text-green-300 mt-1 font-mono">ENFORCING</p>
        </div>
      </div>

      {/* Active IP Blocklist Table */}
      <div className="glass rounded-lg border border-border/50 overflow-hidden space-y-3 p-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Lock className="w-4 h-4 text-accent" />
            Active Perimeter IP Blocklist
          </h2>
          <div className="flex flex-col sm:flex-row items-center gap-2 w-full md:w-auto">
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Input
                placeholder="Enter IP to block (e.g. 192.168.1.5)..."
                value={manualIpInput}
                onChange={(e) => setManualIpInput(e.target.value)}
                className="bg-black/40 border-border/50 text-xs w-full sm:w-56"
              />
              <Button
                size="sm"
                onClick={async () => {
                  if (!manualIpInput.trim()) return;
                  await blockIpAction(manualIpInput.trim());
                  setManualIpInput('');
                }}
                className="bg-red-600 hover:bg-red-500 text-white font-semibold text-xs shrink-0"
              >
                Block IP
              </Button>
            </div>
            <div className="relative w-full sm:w-60">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-muted-foreground" />
              <Input
                placeholder="Search blocked IP, reason..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 bg-black/40 border-border/50 text-xs"
              />
            </div>
          </div>
        </div>

        <ScrollArea className="h-90 w-full border border-border/30 rounded-lg">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-border/50 bg-black/40 text-[11px] text-muted-foreground uppercase tracking-wider">
                <th className="p-3">Blocked IP</th>
                <th className="p-3">Status</th>
                <th className="p-3">Block Reason</th>
                <th className="p-3">Incident ID</th>
                <th className="p-3">Timestamp</th>
                <th className="p-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/20">
              {filteredBlocklist.map((item, idx) => {
                const isBlocked = blockedIps.includes(item.ip) || item.status === 'active' || item.status === 'success';
                return (
                  <tr key={`${item.ip}-${idx}`} className="hover:bg-white/5 transition-colors">
                    <td className="p-3 font-bold text-accent">{item.ip}</td>
                    <td className="p-3">
                      <Badge className={isBlocked ? 'bg-red-950/40 text-red-400 border-red-800/50 text-[10px]' : 'bg-emerald-950/40 text-emerald-400 border-emerald-800/50 text-[10px]'}>
                        {isBlocked ? 'BLOCKED' : 'UNBLOCKED'}
                      </Badge>
                    </td>
                    <td className="p-3 text-foreground">{item.reason}</td>
                    <td className="p-3 text-muted-foreground">{item.incident_id || 'N/A'}</td>
                    <td className="p-3 text-muted-foreground">{item.blocked_at}</td>
                    <td className="p-3 text-right">
                      {isBlocked ? (
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-6 text-[10px] border-yellow-500/40 text-yellow-400 hover:bg-yellow-500/20 gap-1 cursor-pointer"
                          onClick={() => unblockIpAction(item.ip)}
                        >
                          <RotateCcw className="w-3 h-3" /> Unblock IP
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          className="h-6 text-[10px] bg-red-600 hover:bg-red-500 text-white font-semibold gap-1 cursor-pointer"
                          onClick={() => blockIpAction(item.ip)}
                        >
                          Block IP
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
              {filteredBlocklist.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-xs text-muted-foreground font-mono">
                    [NO ACTIVE PERIMETER IP BLOCKS FOUND]
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </ScrollArea>
      </div>
    </div>
  );
}
