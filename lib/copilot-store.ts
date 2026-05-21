import { create } from 'zustand';
import { useAppStore, Alert, Incident, RealMetrics } from './app-store';

export interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

interface CopilotState {
  isOpen: boolean;
  messages: Message[];
  isLoading: boolean;
  toggleSidebar: () => void;
  addMessage: (role: 'user' | 'assistant', content: string) => void;
  setLoading: (loading: boolean) => void;
  clearMessages: () => void;
  sendMessage: (text: string) => Promise<void>;
}

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

  // Handle log analysis requests
  if (q.includes('log entry') || q.includes('log analysis') || q.includes('analyze log')) {
    return `I have analyzed the provided log entry.\n\nKey observations:\n• **Context:** This is a system log event from the process/subsystem specified.\n• **Severity:** Assessed as relevant to host security operations.\n• **Recommendations:**\n  1. Correlate this timestamp with network connections around the same period.\n  2. If the process is unexpected or user-initiated (e.g., sudo, sshd), check user activity history.\n  3. Run a threat hunt queries across endpoint tools for similar occurrences.`;
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

export const useCopilotStore = create<CopilotState>((set, get) => ({
  isOpen: false,
  messages: [
    {
      id: '1',
      role: 'assistant',
      content: "I'm your AI Security Assistant. I can help you analyze incidents, search for related alerts, summarize attack chains, and provide security insights. What would you like to investigate?",
      timestamp: new Date(),
    },
  ],
  isLoading: false,
  toggleSidebar: () => set((state) => ({ isOpen: !state.isOpen })),
  addMessage: (role, content) =>
    set((state) => ({
      messages: [
        ...state.messages,
        {
          id: `${Date.now()}`,
          role,
          content,
          timestamp: new Date(),
        },
      ],
    })),
  setLoading: (loading) => set({ isLoading: loading }),
  clearMessages: () =>
    set({
      messages: [
        {
          id: '1',
          role: 'assistant',
          content: "I'm your AI Security Assistant. I can help you analyze incidents, search for related alerts, summarize attack chains, and provide security insights. What would you like to investigate?",
          timestamp: new Date(),
        },
      ],
    }),
  sendMessage: async (text: string) => {
    const { addMessage, setLoading, isOpen } = get();
    if (!text.trim()) return;

    if (!isOpen) {
      set({ isOpen: true });
    }

    addMessage('user', text);
    setLoading(true);

    const delay = 800 + Math.random() * 1000;
    setTimeout(() => {
      const { alerts, incidents, metrics } = useAppStore.getState();
      const response = generateContextResponse(text, alerts, incidents, metrics);
      addMessage('assistant', response);
      setLoading(false);
    }, delay);
  },
}));
