'use client';

import { useState, useEffect } from 'react';
import { Zap, Plus, Play, Pause, Trash2, Check, AlertCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import { useAppStore, AutomationRule } from '@/lib/app-store';

const CATEGORY_COLORS: Record<string, string> = {
  containment: 'bg-red-900/30 text-red-300 border-red-700/50',
  notification: 'bg-blue-900/30 text-blue-300 border-blue-700/50',
  enrichment: 'bg-purple-900/30 text-purple-300 border-purple-700/50',
  ticketing: 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-900/30 text-red-300 border-red-700/50',
  high: 'bg-orange-900/30 text-orange-300 border-orange-700/50',
  medium: 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50',
  any: 'bg-gray-900/30 text-gray-300 border-gray-700/50',
};

export default function AutomationPage() {
  const rules = useAppStore((state) => state.rules);
  const fetchRules = useAppStore((state) => state.fetchRules);
  const saveRule = useAppStore((state) => state.saveRule);
  const deleteRule = useAppStore((state) => state.deleteRule);
  const triggerRule = useAppStore((state) => state.triggerRule);

  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [newRule, setNewRule] = useState({
    name: '',
    description: '',
    trigger: '',
    action: '',
    severity: 'any' as AutomationRule['severity'],
    category: 'notification' as AutomationRule['category']
  });
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    fetchRules();
  }, [fetchRules]);

  const selectedRule = rules.find((r) => r.id === selectedRuleId) || null;
  const filtered = rules.filter((r) => categoryFilter === 'all' || r.category === categoryFilter);

  const toggleRule = async (id: string) => {
    const rule = rules.find((r) => r.id === id);
    if (!rule) return;
    try {
      const updated = { ...rule, enabled: !rule.enabled };
      await saveRule(updated);
      toast.info(`Rule "${rule.name}" ${updated.enabled ? 'enabled' : 'disabled'}`);
    } catch (e) {
      toast.error('Failed to toggle rule');
    }
  };

  const removeRule = async (id: string) => {
    try {
      await deleteRule(id);
      if (selectedRuleId === id) setSelectedRuleId(null);
      toast.success('Rule deleted');
    } catch (e) {
      toast.error('Failed to delete rule');
    }
  };

  const triggerRuleManually = async (rule: AutomationRule) => {
    try {
      await triggerRule(rule.id);
      toast.success(`Rule triggered: ${rule.name}`, { description: rule.action });
    } catch (e) {
      toast.error('Failed to trigger rule');
    }
  };

  const addRule = async () => {
    if (!newRule.name || !newRule.trigger || !newRule.action) {
      toast.error('Please fill in required fields');
      return;
    }
    const rule: AutomationRule = {
      id: Date.now().toString(),
      ...newRule,
      enabled: true,
      lastFired: null,
      firedCount: 0,
    };
    try {
      await saveRule(rule);
      setShowAddModal(false);
      setNewRule({ name: '', description: '', trigger: '', action: '', severity: 'any', category: 'notification' });
      toast.success('Automation rule created');
    } catch (e) {
      toast.error('Failed to create automation rule');
    }
  };

  const stats = {
    total: rules.length,
    enabled: rules.filter((r) => r.enabled).length,
    totalFired: rules.reduce((acc, r) => acc + r.firedCount, 0),
  };

  if (!mounted) return null;

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Zap className="w-6 h-6 text-accent" />
            Automation Rules
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">SOAR-style automated response rule engine</p>
        </div>
        <Button
          onClick={() => setShowAddModal(true)}
          className="bg-accent hover:bg-accent/90 text-accent-foreground gap-2 text-sm"
        >
          <Plus className="w-4 h-4" /> New Rule
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Total Rules', value: stats.total, color: 'text-foreground' },
          { label: 'Active Rules', value: stats.enabled, color: 'text-green-400' },
          { label: 'Total Executions', value: stats.totalFired.toLocaleString(), color: 'text-accent' },
        ].map((stat) => (
          <div key={stat.label} className="glass rounded-lg p-3 border border-border/50">
            <div className="text-xs text-muted-foreground mb-1">{stat.label}</div>
            <div className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
          </div>
        ))}
      </div>

      {/* Category Filter */}
      <div className="flex gap-2 flex-wrap">
        {(['all', 'containment', 'notification', 'enrichment', 'ticketing'] as const).map((cat) => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className={`px-3 py-1 rounded-full text-xs font-medium border transition-all duration-200 hover:scale-[1.01] active:scale-[0.97] capitalize ${
              categoryFilter === cat
                ? 'bg-accent/20 text-accent border-accent/50'
                : 'border border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Rules List */}
        <div className="lg:col-span-3 space-y-2">
          <AnimatePresence>
            {filtered.map((rule, i) => (
              <motion.div
                key={rule.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ delay: i * 0.04 }}
                onClick={() => setSelectedRuleId(selectedRuleId === rule.id ? null : rule.id)}
                className={`glass rounded-lg p-4 border cursor-pointer transition-all ${
                  selectedRuleId === rule.id
                    ? 'border-accent bg-accent/5'
                    : 'border-border/50 hover:border-border'
                } ${!rule.enabled ? 'opacity-60' : ''}`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                      <h3 className="text-sm font-semibold text-foreground">{rule.name}</h3>
                      <Badge className={`text-xs ${CATEGORY_COLORS[rule.category]}`}>{rule.category}</Badge>
                      <Badge className={`text-xs ${SEVERITY_COLORS[rule.severity]}`}>{rule.severity}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mb-2">{rule.description}</p>
                    <div className="space-y-1 text-xs">
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <span className="text-accent font-medium">IF</span>
                        <span className="font-mono">{rule.trigger}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <span className="text-green-400 font-medium">THEN</span>
                        <span className="font-mono">{rule.action}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                      <span>Fired: <span className="text-foreground font-mono">{rule.firedCount}×</span></span>
                      {rule.lastFired && (
                        <span>Last: <span className="text-foreground">{new Date(rule.lastFired).toLocaleDateString()}</span></span>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-2 shrink-0">
                    <button
                      onClick={(e) => { e.stopPropagation(); toggleRule(rule.id); }}
                      className={`relative w-10 h-5 rounded-full transition-colors ${rule.enabled ? 'bg-accent' : 'bg-muted'}`}
                    >
                      <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${rule.enabled ? 'translate-x-5' : 'translate-x-0.5'}`} />
                    </button>
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>

        {/* Rule Detail */}
        <div className="lg:col-span-2">
          {!selectedRule ? (
            <div className="glass rounded-lg border border-border/50 p-8 text-center">
              <Zap className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">Select a rule to view details</p>
            </div>
          ) : (
            <AnimatePresence mode="wait">
              <motion.div
                key={selectedRule.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="glass rounded-lg border border-border/50 p-5 space-y-4"
              >
                <div className="flex items-start justify-between">
                  <h3 className="text-sm font-bold text-foreground">{selectedRule.name}</h3>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs text-red-400 hover:text-red-300 hover:bg-red-900/20 p-1.5"
                    onClick={() => removeRule(selectedRule.id)}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Badge className={CATEGORY_COLORS[selectedRule.category]}>{selectedRule.category}</Badge>
                  <Badge className={SEVERITY_COLORS[selectedRule.severity]}>{selectedRule.severity}</Badge>
                  <Badge className={selectedRule.enabled ? 'bg-green-900/30 text-green-300 border-green-700/50' : 'bg-muted/30 text-muted-foreground border-border/50'}>
                    {selectedRule.enabled ? 'Active' : 'Disabled'}
                  </Badge>
                </div>

                <p className="text-xs text-muted-foreground">{selectedRule.description}</p>

                <div className="space-y-2">
                  <div className="p-3 bg-accent/5 border border-accent/20 rounded">
                    <p className="text-xs text-accent font-semibold mb-1">TRIGGER</p>
                    <p className="text-xs font-mono text-foreground">{selectedRule.trigger}</p>
                  </div>
                  <div className="p-3 bg-green-900/10 border border-green-700/30 rounded">
                    <p className="text-xs text-green-400 font-semibold mb-1">ACTION</p>
                    <p className="text-xs font-mono text-foreground">{selectedRule.action}</p>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-2 bg-card/50 rounded border border-border/50">
                    <div className="text-muted-foreground mb-0.5">Total Executions</div>
                    <div className="font-bold font-mono text-accent">{selectedRule.firedCount}</div>
                  </div>
                  <div className="p-2 bg-card/50 rounded border border-border/50">
                    <div className="text-muted-foreground mb-0.5">Last Fired</div>
                    <div className="font-bold text-foreground">
                      {selectedRule.lastFired ? new Date(selectedRule.lastFired).toLocaleDateString() : 'Never'}
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <Button
                    onClick={() => triggerRuleManually(selectedRule)}
                    disabled={!selectedRule.enabled}
                    className="w-full bg-accent hover:bg-accent/90 text-accent-foreground gap-2 text-xs"
                    size="sm"
                  >
                    <Play className="w-3.5 h-3.5" /> Trigger Manually
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => toggleRule(selectedRule.id)}
                    className="w-full border-border/50 gap-2 text-xs"
                    size="sm"
                  >
                    {selectedRule.enabled ? <><Pause className="w-3.5 h-3.5" /> Disable</> : <><Play className="w-3.5 h-3.5" /> Enable</>}
                  </Button>
                </div>
              </motion.div>
            </AnimatePresence>
          )}
        </div>
      </div>

      {/* Add Rule Modal */}
      <Dialog open={showAddModal} onOpenChange={setShowAddModal}>
        <DialogContent className="bg-card border-border/50" aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle className="text-foreground">Create Automation Rule</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 mt-2">
            {[
              { label: 'Rule Name *', key: 'name' as const, placeholder: 'e.g. Block Suspicious IP' },
              { label: 'Description', key: 'description' as const, placeholder: 'What this rule does...' },
              { label: 'Trigger Condition *', key: 'trigger' as const, placeholder: 'e.g. Alert severity == CRITICAL' },
              { label: 'Action *', key: 'action' as const, placeholder: 'e.g. POST to Slack webhook' },
            ].map((field) => (
              <div key={field.key}>
                <label className="text-xs text-muted-foreground block mb-1">{field.label}</label>
                <input
                  type="text"
                  value={newRule[field.key]}
                  onChange={(e) => setNewRule((n) => ({ ...n, [field.key]: e.target.value }))}
                  placeholder={field.placeholder}
                  className="w-full bg-input border border-border/50 rounded-md px-3 py-2 text-sm text-foreground outline-none focus:border-accent/50"
                />
              </div>
            ))}
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Severity</label>
                <select value={newRule.severity} onChange={(e) => setNewRule((n) => ({ ...n, severity: e.target.value as AutomationRule['severity'] }))}
                  className="w-full bg-input border border-border/50 rounded-md px-2 py-2 text-sm text-foreground">
                  {['any', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Category</label>
                <select value={newRule.category} onChange={(e) => setNewRule((n) => ({ ...n, category: e.target.value as AutomationRule['category'] }))}
                  className="w-full bg-input border border-border/50 rounded-md px-2 py-2 text-sm text-foreground">
                  {['notification', 'containment', 'enrichment', 'ticketing'].map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            </div>
            <Button onClick={addRule} className="w-full bg-accent hover:bg-accent/90 text-accent-foreground">
              Create Rule
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
