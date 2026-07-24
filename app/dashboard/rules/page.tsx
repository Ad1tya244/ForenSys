'use client';

import { useState, useEffect } from 'react';
import { BookOpen, Search, Filter, Settings2, Check, Lock } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useAppStore } from '@/lib/app-store';
import { saveRule } from '@/lib/api-client';
import { toast } from 'sonner';

export default function EDRRulesPage() {
  const { ruleCatalog = [], currentUser, updateRuleInCatalog, fetchRules } = useAppStore();
  const [mounted, setMounted] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  const isAdmin = currentUser?.role === 'admin';

  // Config state for selected rule
  const [thresholdInput, setThresholdInput] = useState<string>('20');
  const [windowInput, setWindowInput] = useState<string>('10s');

  useEffect(() => {
    setMounted(true);
    if (fetchRules) {
      fetchRules();
    }
  }, []);

  const filteredRules = (ruleCatalog || []).filter((rule: any) => {
    const nameStr = rule.name || '';
    const descStr = rule.description || '';
    const idStr = rule.id || '';
    const matchesSearch =
      nameStr.toLowerCase().includes(searchQuery.toLowerCase()) ||
      descStr.toLowerCase().includes(searchQuery.toLowerCase()) ||
      idStr.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || rule.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  // Default to first rule if none selected
  useEffect(() => {
    if (filteredRules.length > 0 && !selectedRuleId) {
      const firstId = filteredRules[0].id || 'RULE-01';
      setSelectedRuleId(firstId);
    }
  }, [filteredRules, selectedRuleId]);

  const selectedRule = filteredRules.find((r: any, i: number) => (r.id || `RULE-0${i + 1}`) === selectedRuleId) || filteredRules[0];

  useEffect(() => {
    if (selectedRule) {
      setWindowInput(selectedRule.time_window || selectedRule.window || '10s');
      if (selectedRule.threshold !== undefined && selectedRule.threshold !== null) {
        setThresholdInput(String(selectedRule.threshold));
      }
    }
  }, [selectedRule?.id, selectedRule?.threshold, selectedRule?.time_window]);

  const totalRules = (ruleCatalog || []).length;
  const criticalHighCount = (ruleCatalog || []).filter((r: any) => r.severity === 'critical' || r.severity === 'high').length;
  const mediumCount = (ruleCatalog || []).filter((r: any) => r.severity === 'medium').length;
  const lowCount = Math.max(0, totalRules - (criticalHighCount + mediumCount));

  const handleSaveConfig = async () => {
    if (!isAdmin) {
      toast.error('Permission Denied', { description: 'Only Administrator role can edit EDR rule configurations.' });
      return;
    }
    if (!selectedRule) return;

    setIsSaving(true);
    try {
      const updatedRule = {
        ...selectedRule,
        time_window: windowInput,
        threshold: parseInt(thresholdInput, 10) || 20,
      };
      await saveRule(updatedRule as any);
      if (updateRuleInCatalog) {
        updateRuleInCatalog(updatedRule);
      }
      if (fetchRules) {
        await fetchRules();
      }
      toast.success('EDR Rule Configuration Persisted', {
        description: `Successfully updated ${selectedRule.name} backend thresholds to ${thresholdInput} events over ${windowInput}.`
      });
    } catch (err) {
      toast.error('Error saving rule configuration', { description: String(err) });
    } finally {
      setIsSaving(false);
    }
  };

  if (!mounted) return null;

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <BookOpen className="w-6 h-6 text-accent" />
            EDR Rules Catalog
          </h1>
          <p className="text-muted-foreground text-sm">
            Active behavioral threat detection rules, sliding windows, and response orchestrations
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!isAdmin && (
            <Badge className="bg-yellow-950/40 text-yellow-400 border-yellow-800/50 px-2.5 py-1 text-xs gap-1">
              <Lock className="w-3 h-3" /> Read Only (Analyst View)
            </Badge>
          )}
          <Badge className="bg-accent/15 text-accent border-accent/30 px-3 py-1 font-mono text-xs">
            {totalRules} Rules Registered
          </Badge>
        </div>
      </div>

      {/* Overview Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass p-4 rounded-lg border border-border/50">
          <p className="text-xs text-muted-foreground">Total Active EDR Rules</p>
          <p className="text-2xl font-bold text-foreground mt-1 font-mono">{totalRules}</p>
        </div>
        <div className="glass p-4 rounded-lg border border-red-500/30">
          <p className="text-xs text-red-400">Critical / High Severity</p>
          <p className="text-2xl font-bold text-red-300 mt-1 font-mono">{criticalHighCount}</p>
        </div>
        <div className="glass p-4 rounded-lg border border-yellow-500/30">
          <p className="text-xs text-yellow-400">Medium Severity</p>
          <p className="text-2xl font-bold text-yellow-300 mt-1 font-mono">{mediumCount}</p>
        </div>
        <div className="glass p-4 rounded-lg border border-green-500/30">
          <p className="text-xs text-green-400">Low / Informational</p>
          <p className="text-2xl font-bold text-green-300 mt-1 font-mono">{lowCount}</p>
        </div>
      </div>

      {/* Controls Bar */}
      <div className="glass p-4 rounded-lg border border-border/50 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-muted-foreground" />
          <Input
            placeholder="Search rules by name, ID, or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 bg-black/40 border-border/50 text-xs"
          />
        </div>
        <div className="flex items-center gap-2 w-full md:w-auto">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-black/60 border border-border/50 rounded px-3 py-1.5 text-xs text-foreground focus:outline-none focus:border-accent"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Master-Detail 2-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 min-h-125">
        {/* Left Column: Rules Master List */}
        <div className="lg:col-span-5 glass rounded-lg border border-border/50 p-4 space-y-3">
          <h2 className="text-sm font-semibold text-foreground flex items-center justify-between border-b border-border/30 pb-2">
            <span>Detection Rules ({filteredRules.length})</span>
            <span className="text-xs text-muted-foreground">Select to view & edit</span>
          </h2>

          <ScrollArea className="h-120 pr-2">
            <div className="space-y-2">
              {filteredRules.map((rule: any, idx: number) => {
                const ruleId = rule.id || `RULE-0${idx + 1}`;
                const isSelected = selectedRuleId === ruleId;
                const timeWindow = rule.time_window || rule.window || '10s';

                return (
                  <div
                    key={ruleId}
                    onClick={() => setSelectedRuleId(ruleId)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-accent/15 border-accent/60 shadow-md ring-1 ring-accent/40'
                        : 'bg-card/40 border-border/30 hover:border-accent/30 hover:bg-card/60'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-accent font-bold text-xs">{ruleId}</span>
                      <Badge
                        className={
                          rule.severity === 'critical' || rule.severity === 'high'
                            ? 'bg-red-950/40 text-red-400 border-red-800/50 text-[10px]'
                            : rule.severity === 'medium'
                            ? 'bg-yellow-950/40 text-yellow-400 border-yellow-800/50 text-[10px]'
                            : 'bg-green-950/40 text-green-400 border-green-800/50 text-[10px]'
                        }
                      >
                        {rule.severity ? rule.severity.toUpperCase() : 'HIGH'}
                      </Badge>
                    </div>
                    <h3 className="font-bold text-foreground text-sm mt-1 truncate">{rule.name}</h3>
                    <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{rule.description}</p>
                    <div className="mt-2 text-xs text-accent/80 flex items-center justify-between border-t border-border/20 pt-1.5 font-mono">
                      <span>Window: {timeWindow}</span>
                      <span>Configure →</span>
                    </div>
                  </div>
                );
              })}

              {filteredRules.length === 0 && (
                <div className="py-16 text-center text-xs text-muted-foreground font-mono">
                  [NO EDR RULES FOUND]
                </div>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* Right Column: Selected Rule Detail & Threshold Configuration Panel */}
        <div className="lg:col-span-7 glass rounded-lg border border-border/50 p-5 space-y-4">
          {selectedRule ? (
            <div className="space-y-5">
              {/* Header */}
              <div className="border-b border-border/30 pb-3 flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <Badge className="bg-accent/20 text-accent border-accent/40 text-xs font-bold font-mono">
                      {selectedRule.id || 'RULE-01'}
                    </Badge>
                    <h2 className="text-lg font-bold text-foreground">{selectedRule.name}</h2>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                    {selectedRule.description}
                  </p>
                </div>
                <Badge
                  className={
                    selectedRule.severity === 'critical' || selectedRule.severity === 'high'
                      ? 'bg-red-950/40 text-red-400 border-red-800/50 text-xs px-2.5 py-1'
                      : selectedRule.severity === 'medium'
                      ? 'bg-yellow-950/40 text-yellow-400 border-yellow-800/50 text-xs px-2.5 py-1'
                      : 'bg-green-950/40 text-green-400 border-green-800/50 text-xs px-2.5 py-1'
                  }
                >
                  {selectedRule.severity ? selectedRule.severity.toUpperCase() : 'HIGH'}
                </Badge>
              </div>

              {/* Detailed Breakdown */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded bg-card/40 border border-border/30 space-y-1">
                  <span className="text-muted-foreground text-[10px] uppercase block">Telemetry Source</span>
                  <span className="text-foreground font-semibold capitalize">{selectedRule.datasource || 'network'} Telemetry Engine</span>
                </div>
                <div className="p-3 rounded bg-card/40 border border-border/30 space-y-1">
                  <span className="text-muted-foreground text-[10px] uppercase block">MITRE ATT&CK Mapping</span>
                  <span className="text-purple-300 font-semibold">{selectedRule.mitre_tactics ? selectedRule.mitre_tactics.join(', ') : 'Impact'}</span>
                </div>
                <div className="p-3 rounded bg-card/40 border border-border/30 space-y-1">
                  <span className="text-muted-foreground text-[10px] uppercase block">Detection Confidence</span>
                  <span className="text-emerald-400 font-semibold font-mono">{selectedRule.confidence ? `${Math.round(selectedRule.confidence * 100)}%` : '90%'}</span>
                </div>
                <div className="p-3 rounded bg-card/40 border border-border/30 space-y-1">
                  <span className="text-muted-foreground text-[10px] uppercase block">Automated SOAR Action</span>
                  <span className="text-accent font-semibold truncate block">{selectedRule.recommended_remediation || 'Perimeter Block (PF)'}</span>
                </div>
              </div>

              {/* Threshold & Parameters Configuration Section */}
              <div className="p-4 rounded-lg bg-black/40 border border-accent/30 space-y-4">
                <div className="flex items-center justify-between border-b border-accent/20 pb-2">
                  <div className="flex items-center gap-2 text-accent">
                    <Settings2 className="w-4 h-4" />
                    <h3 className="text-xs font-bold uppercase tracking-wider">Configure Rule Thresholds & Parameters</h3>
                  </div>
                  {!isAdmin && (
                    <span className="text-[10px] text-yellow-400 font-mono">Requires Admin Role to Save</span>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-xs text-muted-foreground block">
                      Detection Threshold Limit (Packets / Events):
                    </label>
                    <Input
                      type="number"
                      disabled={!isAdmin}
                      value={thresholdInput}
                      onChange={(e) => setThresholdInput(e.target.value)}
                      className="bg-black/60 border-border/50 text-xs font-mono"
                    />
                    <span className="text-[10px] text-muted-foreground block">Trigger alert when event count exceeds this threshold.</span>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-xs text-muted-foreground block">
                      Sliding Evaluation Window (Seconds):
                    </label>
                    <Input
                      disabled={!isAdmin}
                      value={windowInput}
                      onChange={(e) => setWindowInput(e.target.value)}
                      className="bg-black/60 border-border/50 text-xs font-mono"
                    />
                    <span className="text-[10px] text-muted-foreground block">Rolling timeframe for accumulating telemetry events.</span>
                  </div>
                </div>

                <div className="pt-2 flex justify-end">
                  <Button
                    size="sm"
                    disabled={!isAdmin || isSaving}
                    onClick={handleSaveConfig}
                    className="bg-accent hover:bg-accent/80 text-accent-foreground font-semibold text-xs gap-1.5 cursor-pointer"
                  >
                    <Check className="w-3.5 h-3.5" /> {isSaving ? 'Persisting to Backend...' : 'Save Rule Configuration'}
                  </Button>
                </div>
              </div>
            </div>
          ) : (
            <div className="py-24 text-center text-xs text-muted-foreground font-mono">
              [SELECT A RULE FROM THE LEFT PANEL TO VIEW DETAILS & CONFIGURE THRESHOLDS]
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
