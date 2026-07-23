'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield, Lock, Mail, User, ArrowRight, Loader2,
  Eye, EyeOff, Terminal, Activity, AlertTriangle,
  CheckCircle2, Wifi, Database, Cpu, Globe
} from 'lucide-react';
import { useAppStore } from '@/lib/app-store';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';

/* ─── Telemetry log data ─────────────────────────────────────────── */
type LogTag = 'OK' | 'INFO' | 'WARN';
interface LogEntry { time: string; tag: LogTag; msg: string }

const LOG_POOL: { tag: LogTag; msg: string }[] = [
  { tag: 'OK',   msg: 'TLS 1.3 handshake completed — port 443' },
  { tag: 'INFO', msg: 'IP blocklist sync — 1650 threat entries loaded' },
  { tag: 'OK',   msg: 'Threat intelligence feed: ONLINE' },
  { tag: 'INFO', msg: 'Entropy validation: score 0.97 — PASS' },
  { tag: 'OK',   msg: 'SIEM connector pool initialised (12 nodes)' },
  { tag: 'INFO', msg: 'Kernel telemetry hooks: ACTIVE' },
  { tag: 'WARN', msg: 'Anomalous probe — 192.168.0.14 quarantined' },
  { tag: 'OK',   msg: 'Host IDS baseline snapshot stored' },
  { tag: 'INFO', msg: 'Memory sanitiser sweep: CLEAN' },
  { tag: 'OK',   msg: 'Iris AI engine v3.2: LOADED' },
  { tag: 'INFO', msg: 'ACL ruleset: 2048 port filters applied' },
  { tag: 'OK',   msg: 'Certificate chain verified — root CA trusted' },
  { tag: 'INFO', msg: 'WebSocket uplink latency: 4 ms' },
  { tag: 'OK',   msg: 'Log rotation complete — 14-day retention active' },
  { tag: 'INFO', msg: 'System health check: HTTP 200 OK' },
  { tag: 'OK',   msg: 'Firewall policy reload: SUCCESS' },
  { tag: 'INFO', msg: 'Database cluster integrity: VERIFIED' },
  { tag: 'OK',   msg: 'Session token rotation complete' },
];

const TAG_STYLE: Record<LogTag, string> = {
  OK:   'text-accent',
  INFO: 'text-blue-400',
  WARN: 'text-yellow-400',
};

/* ─── Animated radar rings ───────────────────────────────────────── */
function RadarHUD() {
  const rings = [240, 190, 140, 96, 56, 24];
  const blips = [
    { top: '23%', left: '27%', color: 'bg-red-500',   shadow: '0 0 8px rgba(239,68,68,0.9)',   delay: 0 },
    { top: '58%', right: '24%', color: 'bg-yellow-400', shadow: '0 0 8px rgba(251,191,36,0.9)', delay: 0.7 },
    { bottom: '30%', left: '40%', color: 'bg-accent',  shadow: '0 0 8px rgba(0,200,180,0.9)', delay: 1.2 },
  ];

  return (
    <div className="relative flex items-center justify-center select-none" style={{ width: 250, height: 250 }}>
      {/* Ambient glow */}
      <div className="absolute inset-0 rounded-full" style={{ background: 'radial-gradient(circle, rgba(0,200,180,0.06) 0%, transparent 70%)' }} />

      {/* Rings */}
      {rings.map((r, i) => (
        <div key={r} className="absolute rounded-full border" style={{
          width: r, height: r,
          borderColor: i % 2 === 0 ? 'rgba(0,200,180,0.12)' : 'rgba(0,200,180,0.06)',
          borderStyle: i === 1 ? 'dashed' : 'solid',
        }} />
      ))}

      {/* Cross-hairs */}
      <div className="absolute" style={{ width: 240, height: 1, background: 'rgba(0,200,180,0.06)' }} />
      <div className="absolute" style={{ width: 1, height: 240, background: 'rgba(0,200,180,0.06)' }} />

      {/* Cardinal ticks */}
      {[0, 90, 180, 270].map(deg => (
        <div key={deg} className="absolute" style={{ width: 240, height: 240, transform: `rotate(${deg}deg)` }}>
          <div className="absolute" style={{ top: 0, left: '50%', transform: 'translateX(-50%)', width: 1, height: 10, background: 'rgba(0,200,180,0.35)' }} />
        </div>
      ))}

      {/* Sweep */}
      <motion.div
        className="absolute origin-center"
        style={{
          width: 120, height: 120,
          bottom: '50%', right: '50%',
          background: 'conic-gradient(from 0deg, transparent 75%, rgba(0,200,180,0.16) 100%)',
          borderRadius: '100% 0 0 0',
          transformOrigin: 'bottom right',
        }}
        animate={{ rotate: 360 }}
        transition={{ duration: 3.5, ease: 'linear', repeat: Infinity }}
      />

      {/* Blips */}
      {blips.map((b, i) => (
        <motion.div
          key={i}
          className={`absolute w-2 h-2 rounded-full ${b.color}`}
          style={{ ...b as any, boxShadow: b.shadow }}
          animate={{ opacity: [1, 0.2, 1], scale: [1, 1.4, 1] }}
          transition={{ duration: 2, repeat: Infinity, delay: b.delay }}
        />
      ))}

      {/* Degree labels */}
      {(['N', 'E', 'S', 'W'] as const).map((label, i) => {
        const pos = [
          { top: -2, left: '50%', transform: 'translateX(-50%)' },
          { top: '50%', right: -16, transform: 'translateY(-50%)' },
          { bottom: -2, left: '50%', transform: 'translateX(-50%)' },
          { top: '50%', left: -16, transform: 'translateY(-50%)' },
        ];
        return (
          <span key={label} className="absolute text-[9px] font-mono text-accent/30" style={pos[i] as React.CSSProperties}>
            {label}
          </span>
        );
      })}

      {/* Core */}
      <div className="absolute w-9 h-9 rounded-full flex items-center justify-center"
        style={{ background: 'hsl(220 15% 8%)', border: '1px solid rgba(0,200,180,0.3)', boxShadow: '0 0 20px rgba(0,200,180,0.2)' }}>
        <Activity className="w-4 h-4 text-accent" />
      </div>
    </div>
  );
}

/* ─── Page ───────────────────────────────────────────────────────── */
export default function LoginPage() {
  const router = useRouter();
  const { currentUser, setupRequired, bootstrapAdmin, login, connectBackend } = useAppStore();

  const [loading, setLoading]             = useState(false);
  const [name, setName]                   = useState('');
  const [email, setEmail]                 = useState('');
  const [password, setPassword]           = useState('');
  const [showPassword, setShowPassword]   = useState(false);
  const [logs, setLogs]                   = useState<LogEntry[]>([]);
  const logsEndRef                        = useRef<HTMLDivElement>(null);

  useEffect(() => { connectBackend(); }, [connectBackend]);
  useEffect(() => { if (currentUser) router.push('/dashboard'); }, [currentUser, router]);

  // Seed & stream logs
  useEffect(() => {
    const now = () => new Date().toLocaleTimeString('en-GB', { hour12: false });
    setLogs(LOG_POOL.slice(0, 4).map(l => ({ time: now(), ...l })));

    const id = setInterval(() => {
      const pick = LOG_POOL[Math.floor(Math.random() * LOG_POOL.length)];
      setLogs(prev => [...prev.slice(-20), { time: now(), ...pick }]);
    }, 1800);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password || (setupRequired && !name)) {
      toast.error('Missing fields', { description: 'Please fill in all required fields.' });
      return;
    }
    setLoading(true);
    try {
      if (setupRequired) {
        await bootstrapAdmin(name, email, password);
        toast.success('Admin Created', { description: 'Administrator initialised successfully.' });
      } else {
        await login(email, password);
        toast.success('Access Granted', { description: 'Welcome back.' });
      }
      router.push('/dashboard');
    } catch (err: any) {
      toast.error(setupRequired ? 'Setup Failed' : 'Authentication Failed', {
        description: err.message || 'Check your credentials and try again.',
      });
    } finally {
      setLoading(false);
    }
  };

  /* Stat tiles shown in left panel */
  const stats = [
    { icon: Shield,   label: 'Firewall Rules', value: '1,650',    color: 'text-accent' },
    { icon: Globe,    label: 'Threats',         value: '0 Active', color: 'text-green-400' },
    { icon: Cpu,      label: 'Encryption',      value: 'AES-256', color: 'text-blue-400' },
    { icon: Database, label: 'Uplink',           value: '4 ms',    color: 'text-accent' },
  ];

  return (
    <div className="h-screen w-full flex overflow-hidden" style={{ background: 'hsl(220 15% 6%)' }}>

      {/* ─── Cyber-grid background (same as dashboard) ─── */}
      <div className="pointer-events-none absolute inset-0 cyber-grid opacity-60" />

      {/* ─── Ambient glows ─── */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-175 h-175 rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(0,200,180,0.04) 0%, transparent 65%)' }} />
        <div className="absolute -bottom-40 -right-40 w-150 h-150 rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.04) 0%, transparent 65%)' }} />
      </div>

      {/* ════════════════════════ LEFT PANEL ════════════════════════ */}
      <div className="relative z-10 hidden lg:flex flex-col flex-1 h-screen border-r border-border/40 overflow-hidden">

        {/* Top navigation bar — mirrors dashboard header style */}
        <div className="h-12 flex items-center justify-between px-6 border-b border-border/40 shrink-0"
          style={{ background: '#000000' }}>
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-md flex items-center justify-center bg-accent/20 border border-accent/40">
              <Shield className="w-4 h-4 text-accent" />
            </div>
            <span className="text-sm font-bold tracking-widest text-white">
              FOREN<span className="text-accent">SYS</span>
            </span>
            <span className="text-[9px] font-mono text-muted-foreground border border-border/50 px-1.5 py-0.5 rounded">
              SOC PLATFORM
            </span>
          </div>

          {/* Live indicator */}
          <div className="flex items-center gap-1.5">
            <motion.div
              className="w-1.5 h-1.5 rounded-full bg-accent"
              animate={{ opacity: [1, 0.3, 1] }}
              transition={{ duration: 1.5, repeat: Infinity }}
            />
            <span className="text-[10px] font-mono text-accent tracking-widest">LIVE FEED</span>
          </div>
        </div>

        {/* Content area */}
        <div className="flex-1 flex flex-col p-5 gap-4 overflow-hidden bg-black">

          {/* Hero text */}
          <div className="space-y-0.5">
            <h2 className="text-xl font-bold text-foreground leading-tight">
              Threat Situational <span className="text-accent">Awareness Console</span>
            </h2>
            <p className="text-[10px] text-muted-foreground font-mono tracking-wider">
              REAL-TIME · MULTI-VECTOR · FORENSIC-GRADE DETECTION
            </p>
          </div>

          {/* Radar centered */}
          <div className="flex-1 flex items-center justify-center min-h-0">
            <div className="flex flex-col items-center gap-3">
              <RadarHUD />

              {/* Stat cards — same glass style as dashboard KPI cards */}
              <div className="grid grid-cols-4 gap-3 w-full max-w-130">
                {stats.map(s => {
                  const Icon = s.icon;
                  return (
                    <div key={s.label} className="bg-black rounded-lg p-3 border border-border/50 flex flex-col gap-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] font-mono text-muted-foreground uppercase tracking-wider">{s.label}</span>
                        <Icon className={`w-3 h-3 ${s.color}`} />
                      </div>
                      <span className={`text-sm font-bold font-mono ${s.color}`}>{s.value}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Terminal log — same card style as dashboard panels */}
          <div className="bg-black rounded-lg border border-border/50 overflow-hidden shrink-0">
            <div className="flex items-center justify-between px-4 py-2 border-b border-border/50"
              style={{ background: '#050505' }}>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
                <Terminal className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-[10px] font-mono text-muted-foreground tracking-wider uppercase">
                  Live Host Telemetry
                </span>
              </div>
              <div className="flex gap-1.5">
                <div className="w-2 h-2 rounded-full bg-red-500/50" />
                <div className="w-2 h-2 rounded-full bg-yellow-400/50" />
                <div className="w-2 h-2 rounded-full bg-green-400/50" />
              </div>
            </div>
            <div className="h-32 overflow-y-auto p-3 space-y-0.5" style={{ background: '#000000' }}>
              {logs.map((log, i) => (
                <div key={i} className="flex items-start gap-2.5 font-mono text-[10px] leading-5">
                  <span className="text-muted-foreground/50 shrink-0 w-16">{log.time}</span>
                  <span className={`shrink-0 font-bold w-8 ${TAG_STYLE[log.tag]}`}>{log.tag}</span>
                  <span className="text-muted-foreground">{log.msg}</span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          </div>

          {/* Footer meta — same as dashboard breadcrumb style */}
          <div className="flex items-center justify-between text-[9px] font-mono text-muted-foreground/40 tracking-widest uppercase shrink-0">
            <span>NODE: SOC-PRIMARY-01</span>
            <span>CLUSTER: FORENSYS-PROD</span>
            <span>SHIELD v2.1 · AES-256-GCM</span>
          </div>
        </div>
      </div>

      {/* Vertical divider gradient */}
      <div className="hidden lg:block w-px shrink-0"
        style={{ background: 'linear-gradient(to bottom, transparent, hsl(185 100% 48% / 0.2) 30%, hsl(185 100% 48% / 0.2) 70%, transparent)' }} />

      {/* ════════════════════════ RIGHT PANEL ════════════════════════ */}
      <div className="relative z-10 w-full lg:w-110 xl:w-120 shrink-0 flex items-center justify-center p-6 h-screen overflow-y-auto bg-black">

        <motion.div
          className="w-full max-w-sm"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
        >
          {/* ── Card — solid deep black ── */}
          <div className="bg-black rounded-xl border border-border/60 overflow-hidden"
            style={{ boxShadow: '0 24px 60px rgba(0,0,0,0.8)' }}>

            {/* Accent top line */}
            <div className="h-px w-full" style={{ background: 'linear-gradient(90deg, transparent, hsl(185 100% 48% / 0.7), transparent)' }} />

            <div className="p-7">
              {/* Logo block */}
              <div className="flex flex-col items-center mb-7">
                <motion.div
                  className="relative mb-5"
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: 0.1, duration: 0.4 }}
                >
                  {/* Glow behind icon */}
                  <div className="absolute inset-0 rounded-xl blur-xl scale-150"
                    style={{ background: 'hsl(185 100% 48% / 0.15)' }} />
                  <div className="relative w-14 h-14 rounded-xl flex items-center justify-center border border-accent/30 bg-black">
                    <Shield className="w-7 h-7 text-accent" />
                  </div>
                </motion.div>

                {/* Brand name — all caps, FOREN white, SYS accent */}
                <h1 className="text-2xl font-bold tracking-[0.15em] leading-none">
                  <span className="text-foreground">FOREN</span><span className="text-accent">SYS</span>
                </h1>
                <p className="mt-1.5 text-[10px] font-mono tracking-[0.2em] text-muted-foreground uppercase">
                  {setupRequired ? 'Administrator Bootstrap' : 'Security Operations Portal'}
                </p>

                {/* Status badge — same pill style used in dashboard header */}
                <div className="mt-3 flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-border/50 bg-black">
                  <motion.div
                    className="w-1.5 h-1.5 rounded-full bg-green-400"
                    animate={{ opacity: [1, 0.4, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />
                  <span className="text-[9px] font-mono text-green-400 tracking-widest uppercase">
                    Secure Uplink Active
                  </span>
                </div>
              </div>

              {/* Notice banner — same card/border style */}
              <div className="mb-6 flex gap-2.5 items-start rounded-lg border border-yellow-400/20 bg-black px-3 py-2.5">
                <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 shrink-0 mt-px" />
                <p className="text-[10px] font-mono text-muted-foreground leading-relaxed">
                  {setupRequired
                    ? 'First-time setup: this account will hold full administrative privileges over all platform nodes and RBAC records.'
                    : 'Authorised personnel only. All activity is logged, monitored, and subject to audit under corporate security policy.'}
                </p>
              </div>

              {/* Form */}
              <form onSubmit={handleSubmit} className="space-y-4">
                <AnimatePresence mode="popLayout">
                  {setupRequired && (
                    <motion.div
                      key="name"
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.25 }}
                    >
                      <InputField
                        label="Display Name"
                        icon={<User className="w-4 h-4" />}
                      >
                        <input
                          type="text"
                          placeholder="Full name"
                          value={name}
                          onChange={e => setName(e.target.value)}
                          required={setupRequired}
                          className="soc-input"
                        />
                      </InputField>
                    </motion.div>
                  )}
                </AnimatePresence>

                <InputField label="Email Address" icon={<Mail className="w-4 h-4" />}>
                  <input
                    type="email"
                    placeholder={setupRequired ? 'admin@forensys.local' : 'operator@forensys.io'}
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    required
                    className="soc-input"
                  />
                </InputField>

                <InputField
                  label="Password"
                  icon={<Lock className="w-4 h-4" />}
                  suffix={
                    <button type="button" tabIndex={-1}
                      onClick={() => setShowPassword(v => !v)}
                      className="text-muted-foreground hover:text-foreground transition-colors">
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  }
                >
                  <input
                    type={showPassword ? 'text' : 'password'}
                    placeholder="••••••••"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    required
                    className="soc-input pr-10"
                  />
                </InputField>

                {/* Submit button — matches dashboard accent button style */}
                <motion.button
                  type="submit"
                  disabled={loading}
                  whileHover={{ scale: loading ? 1 : 1.01 }}
                  whileTap={{ scale: loading ? 1 : 0.99 }}
                  className="relative w-full h-10 rounded-lg font-bold text-xs uppercase tracking-widest font-mono flex items-center justify-center gap-2 mt-2 overflow-hidden transition-opacity disabled:opacity-60 text-black bg-accent"
                >
                  {/* Shine on hover */}
                  <div className="absolute inset-0 opacity-0 hover:opacity-100 transition-opacity"
                    style={{ background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.08), transparent)' }} />
                  {loading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <>
                      {setupRequired ? 'Initialise Administrator' : 'Authenticate Access'}
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </motion.button>
              </form>

              {/* Footer — 3-col grid matching dashboard bottom bars */}
              <div className="mt-6 pt-5 border-t border-border/40 grid grid-cols-3 gap-3">
                {[
                  { icon: <Wifi className="w-3.5 h-3.5" />,       label: 'TLS 1.3',     color: 'text-accent' },
                  { icon: <CheckCircle2 className="w-3.5 h-3.5" />, label: 'Monitored',   color: 'text-green-400' },
                  { icon: <Activity className="w-3.5 h-3.5" />,    label: 'Live Audit',  color: 'text-accent' },
                ].map(f => (
                  <div key={f.label} className="flex flex-col items-center gap-1 text-center">
                    <span className={f.color}>{f.icon}</span>
                    <span className="text-[8px] font-mono text-muted-foreground uppercase tracking-widest">{f.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <p className="mt-4 text-center text-[9px] font-mono text-muted-foreground/30 tracking-widest uppercase">
            Forensys v2.1 · Enterprise SOC Platform
          </p>
        </motion.div>

        {/* Inline CSS for shared input class — uses dashboard color tokens */}
        <style jsx global>{`
          .soc-input {
            width: 100%;
            background: #000000;
            border: 1px solid hsl(0 0% 16%);
            border-radius: 8px;
            padding: 9px 12px 9px 38px;
            font-size: 13px;
            font-family: var(--font-mono, monospace);
            color: hsl(0 0% 98%);
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
          }
          .soc-input::placeholder {
            color: hsl(0 0% 40%);
          }
          .soc-input:focus {
            border-color: hsl(185 100% 48% / 0.5);
            box-shadow: 0 0 0 3px hsl(185 100% 48% / 0.08);
          }
        `}</style>
      </div>
    </div>
  );
}

/* ─── Reusable input wrapper ─────────────────────────────────────── */
function InputField({
  label, icon, suffix, children,
}: {
  label: string;
  icon: React.ReactNode;
  suffix?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <label className="text-[10px] font-bold font-mono text-muted-foreground uppercase tracking-widest">
        {label}
      </label>
      <div className="relative flex items-center">
        <span className="absolute left-3 text-muted-foreground pointer-events-none">{icon}</span>
        {children}
        {suffix && <span className="absolute right-3">{suffix}</span>}
      </div>
    </div>
  );
}
