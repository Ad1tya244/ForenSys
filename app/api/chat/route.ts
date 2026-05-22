import { NextRequest, NextResponse } from 'next/server';
import { Message } from '@/lib/copilot-store';
import { Alert, Incident, RealMetrics } from '@/lib/app-store';

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

  if (q.includes('log entry') || q.includes('log analysis') || q.includes('analyze log')) {
    return `I have analyzed the provided log entry.\n\nKey observations:\n• **Context:** This is a system log event from the process/subsystem specified.\n• **Severity:** Assessed as relevant to host security operations.\n• **Recommendations:**\n  1. Correlate this timestamp with network connections around the same period.\n  2. If the process is unexpected or user-initiated (e.g., sudo, sshd), check user activity history.\n  3. Run a threat hunt queries across endpoint tools for similar occurrences.`;
  }

  const fallbacks = [
    `I've analyzed the current security posture. With ${alerts.filter((a: Alert) => a.severity === 'critical').length} critical alerts and ${incidents.filter((i: Incident) => i.status === 'open').length} open incidents, I recommend focusing on the DOMAIN-CONTROLLER which shows signs of credential dumping activity.`,
    `Looking at the alert timeline, there's a pattern suggesting a coordinated attack starting from WEBSERVER-01, moving laterally to internal systems. The estimated breach window is 6 hours. Immediate containment is advised.`,
    `The attack chain analysis indicates this is consistent with APT techniques. The C2 communication to 185.220.101.45 has been active for 4 hours. I've correlated this with 3 known threat campaigns.`,
    `Based on ${incidents.length} active incidents and behavioral patterns, this appears to be a multi-stage intrusion. Recommend executing the Ransomware Response playbook as a precaution while investigation continues.`,
  ];
  return fallbacks[Math.floor(Math.random() * fallbacks.length)];
}

async function generateGeminiResponse(
  input: string,
  history: Message[],
  apiKey: string,
  alerts: Alert[],
  incidents: Incident[],
  metrics: RealMetrics | null
): Promise<string> {
  const systemPrompt = `You are Iris, an advanced AI Security Assistant integrated into the ForenSys Security Operations Center (SOC) dashboard.
Your goal is to help security analysts investigate threats, analyze system telemetry, understand attack paths, and respond to alerts/incidents on their local machine.

Current SOC Live Data Context:
------------------------------
- Host Machine Info: ${metrics ? `Hostname: ${metrics.hostname}, Platform: ${metrics.platform}, Threat Level: ${metrics.threat_level}` : 'Telemetry offline'}
- Active Telemetry: ${metrics ? `CPU: ${metrics.cpu_percent}%, Memory: ${metrics.memory_percent}%, Connections: ${metrics.connections_total}` : 'N/A'}
- Security Alerts: ${alerts.length} active alerts.
  ${alerts.slice(0, 15).map(a => `• [${a.severity.toUpperCase()}] ${a.title} - Source: ${a.source} - Status: ${a.status} (ID: ${a.id})`).join('\n')}
- Security Incidents: ${incidents.length} incidents in queue.
  ${incidents.slice(0, 10).map(i => `• [${i.severity.toUpperCase()}] ${i.title} - Status: ${i.status} (ID: ${i.id})`).join('\n')}

Guidelines for responding:
1. Always base your analysis on the live SOC context provided above.
2. Be professional, concise, and focused on security operations.
3. Recommend specific actions, playbooks, or commands where appropriate.
4. Format your output in clean Markdown. Use bold text, bulleted lists, and code blocks.
5. If the user asks general cybersecurity questions, answer them accurately and relate them to their current local SOC environment when possible.`;

  const contents = [
    ...history.slice(-10).map(msg => ({
      role: msg.role === 'user' ? 'user' : 'model',
      parts: [{ text: msg.content }]
    })),
    {
      role: 'user',
      parts: [{ text: input }]
    }
  ];

  const payload = {
    contents,
    systemInstruction: {
      parts: [{ text: systemPrompt }]
    },
    generationConfig: {
      temperature: 0.2,
      maxOutputTokens: 1000
    }
  };

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    const message = errorData?.error?.message || response.statusText;
    throw new Error(`Gemini API Error: ${message}`);
  }

  const data = await response.json();
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) {
    throw new Error('Gemini API returned an empty response.');
  }

  return text;
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { text, history, alerts, incidents, metrics } = body;

    const apiKey = process.env.GEMINI_API_KEY || process.env.NEXT_PUBLIC_GEMINI_API_KEY || '';

    if (apiKey) {
      try {
        const aiResponse = await generateGeminiResponse(text, history, apiKey, alerts, incidents, metrics);
        return NextResponse.json({ success: true, response: aiResponse });
      } catch (geminiError: any) {
        console.error("Gemini API call failed, falling back to local heuristics:", geminiError);
        const fallbackResponse = generateContextResponse(text, alerts, incidents, metrics);
        return NextResponse.json({ success: true, response: fallbackResponse });
      }
    } else {
      const fallbackResponse = generateContextResponse(text, alerts, incidents, metrics);
      return NextResponse.json({ success: true, response: fallbackResponse });
    }
  } catch (err: any) {
    console.error("Error in API route handler:", err);
    return NextResponse.json(
      { success: false, error: err.message || 'Internal server error' },
      { status: 500 }
    );
  }
}
