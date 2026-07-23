'use client';

import { useState, useEffect } from 'react';
import { Shield, Lock, RotateCcw, CheckCircle, Search, Filter } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useAppStore } from '@/lib/app-store';

export default function FirewallRulesPage() {
  const { blockedIps, blockedIpDetails, unblockIpAction, ruleCatalog } = useAppStore();
  const [mounted, setMounted] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

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
            <Shield className="w-6 h-6 text-purple-400" />
            Firewall Rules & IP Blocklist
          </h1>
          <p className="text-muted-foreground text-sm">
            Active macOS PF firewall rules, active perimeter blocklists, and defense configurations
          </p>
        </div>
        <Badge className="bg-purple-950/60 text-purple-300 border-purple-700/50 px-3 py-1 font-mono text-xs">
          Perimeter Engine Active ({blockedIps.length} IPs Blocked)
        </Badge>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass p-4 rounded-lg border border-purple-500/30">
          <p className="text-xs text-purple-300">Active Blocked Source IPs</p>
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
      <div className="glass rounded-lg border border-purple-500/30 overflow-hidden space-y-3 p-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Lock className="w-4 h-4 text-purple-400" />
            Active Perimeter IP Blocklist
          </h2>
          <div className="relative w-full md:w-72">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-muted-foreground" />
            <Input
              placeholder="Search blocked IP, reason, incident..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 bg-black/40 border-border/50 text-xs"
            />
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
              {filteredBlocklist.map((item, idx) => (
                <tr key={`${item.ip}-${idx}`} className="hover:bg-white/5 transition-colors">
                  <td className="p-3 font-bold text-purple-300">{item.ip}</td>
                  <td className="p-3">
                    <Badge className={item.status === 'active' ? 'bg-red-900/30 text-red-300 border-red-700/50 text-[10px]' : 'bg-green-900/30 text-green-300 border-green-700/50 text-[10px]'}>
                      {item.status.toUpperCase()}
                    </Badge>
                  </td>
                  <td className="p-3 text-foreground">{item.reason}</td>
                  <td className="p-3 text-muted-foreground">{item.incident_id || 'N/A'}</td>
                  <td className="p-3 text-muted-foreground">{item.blocked_at}</td>
                  <td className="p-3 text-right">
                    {item.status === 'active' && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-6 text-[10px] border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/20 gap-1"
                        onClick={() => unblockIpAction(item.ip)}
                      >
                        <RotateCcw className="w-3 h-3" /> Unblock / Rollback IP
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
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

      {/* Detection Rule Catalog */}
      <div className="glass rounded-lg border border-border/50 p-4 space-y-3">
        <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Shield className="w-4 h-4 text-accent" />
          Active EDR Detection Rule Catalog
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {ruleCatalog.map((rule, idx) => (
            <div key={rule.id || idx} className="p-3 bg-black/40 rounded border border-border/30 space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-foreground">{rule.name}</span>
                <Badge className="bg-accent/15 text-accent border-accent/30 text-[10px]">
                  {rule.severity.toUpperCase()}
                </Badge>
              </div>
              <p className="text-[11px] text-muted-foreground">{rule.description}</p>
              <div className="flex items-center justify-between text-[10px] text-muted-foreground pt-1 border-t border-border/20 font-mono">
                <span>Window: {rule.window}</span>
                <span>Remediation: {rule.remediation}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
