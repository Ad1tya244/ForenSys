import { NextRequest, NextResponse } from 'next/server';
import type { SocContext } from '@/lib/copilot-context';

interface ChatMessage { role: 'user' | 'assistant'; content: string }

const fmtDur = (sec: number | null | undefined) => {
  if (sec === null || sec === undefined) return 'n/a';
  if (sec < 1) return `${Math.round(sec * 1000)} ms`;
  if (sec < 60) return `${sec.toFixed(1)} s`;
  return `${Math.floor(sec / 60)} m ${Math.round(sec % 60)} s`;
};
const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);

/** Answers from the live snapshot only. Used when no Gemini key is configured or the API call fails. */
function localAnswer(input: string, c: SocContext): string {
  const q = input.toLowerCase();
  const has = (...w: string[]) => w.some((x) => q.includes(x));
  const open = c.alerts.items.filter((a) => a.status !== 'resolved');

  if (has('critical', 'high severity', 'severity')) {
    const sev = has('critical') ? 'critical' : has('high') ? 'high' : null;
    const list = open.filter((a) => (sev ? a.severity === sev : a.severity === 'critical' || a.severity === 'high')).slice(0, 5);
    const count = sev ? c.alerts.bySeverity[sev] || 0 : (c.alerts.bySeverity.critical || 0) + (c.alerts.bySeverity.high || 0);
    if (!list.length) return `No open ${sev ?? 'critical or high'} alerts right now.`;
    return `**${count} open ${sev ?? 'critical/high'} alert${count === 1 ? '' : 's'}.** Most recent:\n${list.map((a) => `• [${a.severity.toUpperCase()}] ${a.title} (${a.source})`).join('\n')}`;
  }

  if (has('mttd', 'mttr', 'response time', 'detection time')) {
    const mttd = c.incidents.map((i) => i.mttdSec).filter((x): x is number => x !== null);
    const mttr = c.incidents.map((i) => i.mttrSec).filter((x): x is number => x !== null);
    if (!c.incidents.length) return 'No incidents have been detected yet, so there is no MTTD/MTTR to report.';
    return `Across the ${c.incidents.length} most recent incident${c.incidents.length === 1 ? '' : 's'}:\n• **Avg MTTD** (first attacker activity → detection): ${fmtDur(avg(mttd))}\n• **Avg MTTR** (detection → containment): ${fmtDur(avg(mttr))}${mttr.length < c.incidents.length ? `\n• ${c.incidents.length - mttr.length} incident(s) uncontained, excluded from MTTR` : ''}\n\nThe Analytics page has the full distribution.`;
  }

  if (has('blocked', 'blocklist', 'block list', 'perimeter', 'contained', 'remediat')) {
    const active = c.blocklist.filter((b) => b.status === 'active');
    const lines = [
      `**${active.length} IP${active.length === 1 ? '' : 's'} on the perimeter blocklist** (logical block; the sniffer ignores their traffic until you unblock them):`,
      ...(active.length ? active.slice(0, 8).map((b) => `• \`${b.ip}\` — ${b.reason || 'no reason recorded'}${b.incidentId ? ` (${b.incidentId})` : ''}`) : ['• none']),
    ];
    if (c.remediation.length) lines.push('', 'Latest remediation actions:', ...c.remediation.slice(0, 5).map((r) => `• ${r.action} → ${r.target} [${r.status}] for ${r.incidentId}`));
    return lines.join('\n');
  }

  if (has('evidence', 'forensic', 'seal')) {
    return `The vault holds **${c.evidence.packages} evidence package${c.evidence.packages === 1 ? '' : 's'}**, ${c.evidence.sealed} sealed with a SHA-256 hash. Open the Forensics page to verify or export one.`;
  }

  if (has('ioc', 'indicator', 'attacker')) {
    const ips = [...new Set(c.incidents.map((i) => i.attackerIp).filter((x): x is string => !!x))];
    if (!ips.length) return 'No attacker IPs have been identified in current incidents.';
    return `Attacker IPs from current incidents:\n${ips.map((ip) => `• \`${ip}\`${c.blocklist.find((b) => b.ip === ip && b.status === 'active') ? ' (blocked)' : ''}`).join('\n')}`;
  }

  if (has('incident')) {
    if (!c.incidents.length) return 'No incidents have been raised yet.';
    const byStatus = (st: string) => c.incidents.filter((i) => i.status === st).length;
    return `**${c.incidents.length} incident${c.incidents.length === 1 ? '' : 's'}**: ${byStatus('open')} open, ${byStatus('investigating')} investigating, ${byStatus('contained')} contained, ${byStatus('resolved')} resolved.\n\nLatest:\n${c.incidents.slice(0, 5).map((i) => `• [${i.severity.toUpperCase()}] ${i.title} — ${i.status}${i.attackerIp ? `, source \`${i.attackerIp}\`` : ''}`).join('\n')}`;
  }

  if (has('threat level', 'status', 'posture', 'summary', 'summarize', 'overview', 'how are we')) {
    const h = c.host;
    return `${h ? `Host **${h.hostname}** (${h.platform}) — threat level **${h.threatLevel.toUpperCase()}**, CPU ${h.cpu}%, memory ${h.memory}%, ${h.connections} connections.` : 'Host telemetry is offline.'}\n• ${c.alerts.open} open alert${c.alerts.open === 1 ? '' : 's'} (${c.alerts.bySeverity.critical || 0} critical, ${c.alerts.bySeverity.high || 0} high)\n• ${c.incidents.length} incident${c.incidents.length === 1 ? '' : 's'}\n• ${c.blocklist.filter((b) => b.status === 'active').length} IP(s) blocked\n• ${c.evidence.packages} evidence package${c.evidence.packages === 1 ? '' : 's'}`;
  }

  if (has('recommend', 'should i', 'what to do', 'next step')) {
    if (!open.length && !c.incidents.length) return 'Nothing needs action right now: no open alerts or incidents.';
    const steps: string[] = [];
    const uncontained = c.incidents.filter((i) => i.status !== 'contained' && i.status !== 'resolved');
    if (uncontained.length) steps.push(`Review ${uncontained.length} incident(s) that are not yet contained, starting with "${uncontained[0].title}".`);
    if (open.length) steps.push(`Triage ${open.length} open alert(s); acknowledge or resolve each from the Alerts page.`);
    steps.push('Confirm the sealed evidence for each incident, then export the incident PDF from Reports.');
    steps.push('Release blocked IPs only after you have confirmed the source is no longer a threat.');
    return `Suggested next steps based on live data:\n${steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`;
  }

  if (has('alert')) {
    if (!c.alerts.total) return 'There are no alerts.';
    return `**${c.alerts.open} open alert${c.alerts.open === 1 ? '' : 's'}** of ${c.alerts.total} total.\n${open.slice(0, 5).map((a) => `• [${a.severity.toUpperCase()}] ${a.title} — ${a.status}`).join('\n') || '• none open'}`;
  }

  return `I can answer from live ForenSys data: alerts, incidents, MTTD/MTTR, the perimeter blocklist and remediation actions, forensic evidence, and next steps. Try “summarize current status” or “which IPs are blocked?”.\n\n_Local mode: set \`GEMINI_API_KEY\` for open-ended analysis._`;
}

function systemPrompt(c: SocContext): string {
  return `You are Iris, the AI assistant inside the ForenSys single-host EDR/SOC dashboard.

Rules:
- Answer ONLY from the live data below. If something is not in the data, say you don't have it; never invent hosts, IPs, hashes, attack chains or numbers.
- ForenSys remediation is logical only: "block IP" adds the address to a perimeter blocklist that the packet sniffer honours until an analyst unblocks it. No real firewall rules or processes are changed, so never describe it as a firewall change and never tell the user to run pfctl/iptables/kill.
- MTTD = first attacker activity → detection. MTTR = detection → last containment action (evidence sealing excluded). Uncontained incidents have no MTTR.
- Be concise and professional. Use Markdown bullets and \`code\` for IPs/IDs. Cite alert/incident IDs when relevant.

LIVE DATA (JSON, newest first):
${JSON.stringify(c)}`;
}

async function gemini(input: string, history: ChatMessage[], apiKey: string, c: SocContext): Promise<string> {
  // Gemini wants the conversation to start with a user turn; drop the assistant greeting.
  const prior = history.slice(-10);
  while (prior.length && prior[0].role !== 'user') prior.shift();
  const contents = [
    ...prior.map((m) => ({ role: m.role === 'user' ? 'user' : 'model', parts: [{ text: m.content }] })),
    { role: 'user', parts: [{ text: input }] },
  ];

  const res = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
    body: JSON.stringify({
      contents,
      systemInstruction: { parts: [{ text: systemPrompt(c) }] },
      generationConfig: { temperature: 0.2, maxOutputTokens: 1500 },
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Gemini API error: ${err?.error?.message || res.statusText}`);
  }
  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts?.map((p: any) => p.text).filter(Boolean).join('');
  if (!text) throw new Error('Gemini returned an empty response.');
  return text;
}

export async function POST(req: NextRequest) {
  try {
    const { text, history, context } = (await req.json()) as { text?: string; history?: ChatMessage[]; context?: SocContext };
    if (!text || !context) return NextResponse.json({ success: false, error: 'Missing text or context' }, { status: 400 });

    const apiKey = process.env.GEMINI_API_KEY || '';
    if (apiKey) {
      try {
        return NextResponse.json({ success: true, response: await gemini(text, history || [], apiKey, context), mode: 'gemini' });
      } catch (e: any) {
        console.error('Gemini call failed, answering locally:', e?.message || e);
      }
    }
    return NextResponse.json({ success: true, response: localAnswer(text, context), mode: 'local' });
  } catch (err: any) {
    console.error('Chat route error:', err);
    return NextResponse.json({ success: false, error: err?.message || 'Internal server error' }, { status: 500 });
  }
}
