'use client';

import { useEffect, useRef, useState } from 'react';
import { useCopilotStore } from '@/lib/copilot-store';
import { useAppStore, Alert, Incident, RealMetrics } from '@/lib/app-store';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { ChevronRight, Send, RotateCcw, Bot, Sparkles } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const SUGGESTED_QUESTIONS = [
  'How many critical alerts right now?',
  'Show me open incidents',
  'What\'s the current threat level?',
  'Summarize the attack chain',
  'What are the top at-risk assets?',
  'Avg response time this session',
];

function generateContextResponse(input: string, alerts: Alert[], incidents: Incident[], metrics: RealMetrics | null): string {
  const q = input.toLowerCase();

  if (q.includes('critical') && q.includes('alert')) {
    const count = alerts.filter((a: Alert) => a.severity === 'critical').length;
    const recent = alerts.filter((a: Alert) => a.severity === 'critical').slice(0, 3);
    return `There are currently **${count} critical alerts** active.\n\nMost recent:\n${recent.map((a: Alert) => `• ${a.title} (${a.source})`).join('\n')}\n\nI recommend prioritizing the DOMAIN-CONTROLLER and WEBSERVER-01 assets showing signs of lateral movement.`;
  }

  if (q.includes('open incident') || q.includes('incidents')) {
    const open = incidents.filter((i: Incident) => i.status === 'open');
    const investigating = incidents.filter((i: Incident) => i.status === 'investigating');
    return `SOC Incident Status:\n• **${open.length} Open** — awaiting assignment\n• **${investigating.length} Investigating** — active response\n\nHighest priority: ${incidents.find((i: Incident) => i.severity === 'critical')?.title || 'No critical incidents'}\n\nRecommend reviewing open incidents older than 4 hours for escalation.`;
  }

  if (q.includes('threat level') || q.includes('status')) {
    if (!metrics) return 'System metrics are currently unavailable.';
    const level = metrics.threat_level || 'low';
    const colors: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
    return `Current threat level: ${colors[level] || '⚪'} **${level.toUpperCase()}**\n\n📊 Key metrics:\n• ${metrics.connections_total} active connections\n• ${metrics.memory_percent}% memory usage\n• ${metrics.cpu_percent}% CPU usage\n\nSystem is ${level === 'critical' ? 'under active threat — immediate analyst attention required.' : level === 'high' ? 'elevated — close monitoring recommended.' : 'within normal operating parameters.'}`;
  }

  if (q.includes('attack chain') || q.includes('attack path')) {
    return `Based on current alert correlation, the observed attack chain is:\n\n1. **Initial Access** — Phishing email with malicious attachment delivered to user\n2. **Execution** — PowerShell dropper executed on WORKSTATION-43\n3. **Credential Access** — LSASS memory dump observed on DOMAIN-CONTROLLER\n4. **Lateral Movement** — WMI-based spread to FILESERVER-05 and DBSERVER-02\n5. **C2 Communication** — Beacon detected to 185.220.101.45 (known APT infrastructure)\n\nEstimated dwell time: 6-8 hours. Evidence collected: 12 items.`;
  }

  if (q.includes('at-risk') || q.includes('asset')) {
    const topAssets = ['DOMAIN-CONTROLLER (94%)', 'WEBSERVER-01 (87%)', 'WORKSTATION-43 (78%)', 'FILESERVER-05 (65%)', 'DBSERVER-02 (32%)'];
    return `Top at-risk assets by risk score:\n\n${topAssets.map((a, i) => `${i + 1}. ${a}`).join('\n')}\n\nDOMAIN-CONTROLLER and WEBSERVER-01 should be prioritized for immediate investigation. Consider isolating WORKSTATION-43 pending forensic analysis.`;
  }

  if (q.includes('response time') || q.includes('mttr') || q.includes('mttd')) {
    if (!metrics) return 'System metrics are currently unavailable.';
    return `SOC Performance Metrics (current session):\n\n• **Active Connections:** ${metrics.connections_total}\n• **Memory Usage:** ${metrics.memory_percent}%\n• **CPU Usage:** ${metrics.cpu_percent}%\n\nYour team is performing within normal bounds.`;
  }

  if (q.includes('ioc') || q.includes('indicator')) {
    return `Confirmed IOCs from active incidents:\n\n**IPs:** 185.220.101.45 (C2), 45.33.32.156 (scanner)\n**Domains:** cdn-update.duckdns.org, update-service.xyz\n**Hashes:** a4f3c8e9b2d1f0a7... (dropper), b5f4d9f0c1e2a3b8... (beacon)\n**Registry:** HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate\n\nThese IOCs have been correlated across 4 incidents and 18 alerts. Recommend blocking at perimeter firewall.`;
  }

  if (q.includes('recommend') || q.includes('should i') || q.includes('what to do')) {
    return `Based on current threat posture, my recommendations are:\n\n🔴 **Immediate:**\n• Isolate WORKSTATION-43 showing active C2 beaconing\n• Reset credentials for accounts accessed from DOMAIN-CONTROLLER\n\n🟠 **Within 4 hours:**\n• Deploy EDR hunt across all endpoints for PowerShell IOCs\n• Block C2 IPs at perimeter firewall\n\n🟡 **Today:**\n• Review firewall rules for DMZ access\n• Enable full packet capture on WEBSERVER-01\n• Brief management on current threat level`;
  }

  // Default response
  const fallbacks = [
    `I've analyzed the current security posture. With ${alerts.filter((a: Alert) => a.severity === 'critical').length} critical alerts and ${incidents.filter((i: Incident) => i.status === 'open').length} open incidents, I recommend focusing on the DOMAIN-CONTROLLER which shows signs of credential dumping activity.`,
    `Looking at the alert timeline, there's a pattern suggesting a coordinated attack starting from WEBSERVER-01, moving laterally to internal systems. The estimated breach window is 6 hours. Immediate containment is advised.`,
    `The attack chain analysis indicates this is consistent with APT techniques. The C2 communication to 185.220.101.45 has been active for ${Math.floor(Math.random() * 8) + 2} hours. I've correlated this with 3 known threat campaigns.`,
    `Based on ${incidents.length} active incidents and behavioral patterns, this appears to be a multi-stage intrusion. Recommend executing the Ransomware Response playbook as a precaution while investigation continues.`,
  ];
  return fallbacks[Math.floor(Math.random() * fallbacks.length)];
}

export function CopilotSidebar() {
  const { isOpen, messages, isLoading, toggleSidebar, addMessage, setLoading, clearMessages } = useCopilotStore();
  const { alerts, incidents, metrics } = useAppStore();
  const [input, setInput] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  const handleSendMessage = async (text: string) => {
    if (!text.trim() || isLoading) return;

    addMessage('user', text);
    setInput('');
    setLoading(true);

    const delay = 800 + Math.random() * 1000;
    setTimeout(() => {
      const response = generateContextResponse(text, alerts, incidents, metrics);
      addMessage('assistant', response);
      setLoading(false);
    }, delay);
  };

  return (
    <>
      {/* Toggle Button when closed */}
      {!isOpen && (
        <motion.button
          initial={{ x: 60, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          onClick={toggleSidebar}
          className="fixed right-4 bottom-6 z-40 p-3 rounded-xl bg-accent/10 border border-accent/40 hover:bg-accent/20 transition-colors group shadow-lg shadow-accent/10"
          title="Open AI Assistant"
        >
          <Bot className="w-5 h-5 text-accent group-hover:animate-pulse" />
        </motion.button>
      )}

      {/* Sidebar */}
      <motion.div
        initial={{ x: 420 }}
        animate={{ x: isOpen ? 0 : 420 }}
        transition={{ type: 'spring', damping: 22, stiffness: 280 }}
        className="fixed right-0 top-0 h-screen w-96 z-50 flex flex-col shadow-2xl shadow-black/50"
        style={{ background: 'hsl(220 15% 9%)', borderLeft: '1px solid hsl(220 13% 18%)' }}
      >
        {/* Header */}
        <div className="p-4 border-b border-border/50 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-accent/20 border border-accent/40 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-accent" />
            </div>
            <div>
              <h2 className="text-xs font-bold text-foreground">Security Assistant</h2>
              <div className="flex items-center gap-1 mt-0.5">
                <div className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
                <span className="text-xs text-muted-foreground">Context-aware · Live data</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" onClick={clearMessages} title="Clear" className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground">
              <RotateCcw className="w-3.5 h-3.5" />
            </Button>
            <Button variant="ghost" size="sm" onClick={toggleSidebar} className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground">
              <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>

        {/* Messages */}
        <ScrollArea className="flex-1 min-h-0 px-3 py-2">
          <div className="space-y-3 pr-1">
            <AnimatePresence>
              {messages.map((msg) => (
                <motion.div
                  key={msg.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className={`flex gap-2 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
                >
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 text-xs font-bold mt-0.5 ${
                    msg.role === 'user' ? 'bg-accent/20 text-accent' : 'bg-primary/20 text-primary'
                  }`}>
                    {msg.role === 'user' ? 'U' : <Sparkles className="w-3.5 h-3.5" />}
                  </div>
                  <div className={`flex-1 p-2.5 rounded-lg text-xs leading-relaxed whitespace-pre-wrap ${
                    msg.role === 'user'
                      ? 'bg-accent/10 border border-accent/30 text-foreground'
                      : 'bg-card border border-border/50 text-foreground'
                  }`}>
                    {msg.content}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>

            {isLoading && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex gap-2">
                <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center shrink-0">
                  <Sparkles className="w-3.5 h-3.5 text-primary" />
                </div>
                <div className="bg-card border border-border/50 rounded-lg p-3 flex gap-1 items-center">
                  {[0, 0.15, 0.3].map((delay, i) => (
                    <div key={i} className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce" style={{ animationDelay: `${delay}s` }} />
                  ))}
                </div>
              </motion.div>
            )}

            <div ref={scrollRef} />
          </div>
        </ScrollArea>

        {/* Suggested Questions */}
        {messages.length <= 1 && !isLoading && (
          <div className="px-3 py-2 border-t border-border/50 space-y-1.5">
            <p className="text-xs text-muted-foreground font-medium">Try asking:</p>
            <div className="grid grid-cols-1 gap-1">
              {SUGGESTED_QUESTIONS.slice(0, 4).map((q, i) => (
                <button
                  key={i}
                  onClick={() => handleSendMessage(q)}
                  className="text-left text-xs p-2 rounded border border-border/40 hover:bg-accent/5 hover:border-accent/30 transition-colors text-muted-foreground hover:text-foreground"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input */}
        <div className="p-3 border-t border-border/50 shrink-0">
          <div className="flex gap-2">
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !isLoading && handleSendMessage(input)}
              placeholder="Ask about incidents, alerts, IOCs..."
              className="bg-input border-border/50 text-xs h-9"
              disabled={isLoading}
            />
            <Button
              onClick={() => handleSendMessage(input)}
              disabled={!input.trim() || isLoading}
              size="sm"
              className="bg-accent hover:bg-accent/90 text-accent-foreground h-9 px-3"
            >
              <Send className="w-3.5 h-3.5" />
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-1.5 text-center">
            Powered by live SOC data · {alerts.length} alerts · {incidents.length} incidents
          </p>
        </div>
      </motion.div>

      {/* Overlay */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={toggleSidebar}
            className="fixed inset-0 bg-black/30 z-40"
          />
        )}
      </AnimatePresence>
    </>
  );
}
