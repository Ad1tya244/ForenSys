'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { CopilotSidebar } from '@/components/copilot/copilot-sidebar';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useAppStore } from '@/lib/app-store';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  BarChart3,
  AlertTriangle,
  Shield,
  Zap,
  FileText,
  Settings,
  Activity,
  Network,
  BookOpen,
  Users,
  GitBranch,
  Target,
  Lock,
  Menu,
  X,
  Bell,
  ChevronRight,
  LogOut,
  User,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: Activity },
  { href: '/dashboard/alerts', label: 'Alerts', icon: AlertTriangle },
  { href: '/dashboard/threat-intelligence', label: 'Network Intel', icon: Shield },
  { href: '/dashboard/incidents', label: 'Incidents', icon: FileText },
  { href: '/dashboard/forensics', label: 'Forensics', icon: Lock },
  { href: '/dashboard/automation', label: 'Automation', icon: Zap },
  { href: '/dashboard/playbooks', label: 'Playbooks', icon: BookOpen },
  { href: '/dashboard/logs', label: 'Logs', icon: GitBranch },
  { href: '/dashboard/threat-hunting', label: 'Threat Hunt', icon: Target },
  { href: '/dashboard/architecture', label: 'Architecture', icon: Network },
  { href: '/dashboard/rbac', label: 'RBAC', icon: Users },
  { href: '/dashboard/analytics', label: 'Analytics', icon: BarChart3 },
  { href: '/dashboard/reports', label: 'Reports', icon: FileText },
  { href: '/dashboard/settings', label: 'Settings', icon: Settings },
];

const threatLevelColors: Record<string, string> = {
  low: 'bg-green-500',
  medium: 'bg-yellow-500',
  high: 'bg-orange-500',
  critical: 'bg-red-500',
};

const threatLevelText: Record<string, string> = {
  low: 'text-green-400',
  medium: 'text-yellow-400',
  high: 'text-orange-400',
  critical: 'text-red-400',
};

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mounted, setMounted] = useState(false);
  const {
    metrics,
    notifications,
    unreadCount,
    markAllRead,
    connectBackend,
    backendConnected,
    currentUser,
    hasPermission,
    logout,
  } = useAppStore();

  useEffect(() => {
    setMounted(true);
    connectBackend();
  }, [connectBackend]);

  // Protect dashboard routes
  useEffect(() => {
    if (mounted && !currentUser) {
      router.push('/login');
    }
  }, [mounted, currentUser, router]);

  // Sidebar navigation permissions mapping
  const navItemPermissions: Record<string, string> = {
    '/dashboard/alerts': 'view_alerts',
    '/dashboard/threat-intelligence': 'view_alerts',
    '/dashboard/incidents': 'view_incidents',
    '/dashboard/forensics': 'view_forensics',
    '/dashboard/automation': 'manage_playbooks',
    '/dashboard/playbooks': 'manage_playbooks',
    '/dashboard/logs': 'view_logs',
    '/dashboard/threat-hunting': 'run_hunt',
    '/dashboard/rbac': 'manage_users',
    '/dashboard/analytics': 'view_analytics',
    '/dashboard/settings': 'manage_settings',
  };

  const visibleNavItems = navItems.filter((item) => {
    const perm = navItemPermissions[item.href];
    return !perm || hasPermission(perm);
  });

  const currentPage = navItems.find(
    (item) =>
      pathname === item.href ||
      (pathname.startsWith(item.href) && item.href !== '/dashboard')
  );

  const breadcrumbs = [
    { label: 'FORENSYS', href: '/dashboard' },
    ...(currentPage && currentPage.href !== '/dashboard'
      ? [{ label: currentPage.label, href: currentPage.href }]
      : []),
  ];

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      {/* Sidebar */}
      <aside
        className={`${
          sidebarOpen ? 'w-56' : 'w-16'
        } bg-sidebar border-r border-sidebar-border transition-all duration-300 flex flex-col overflow-hidden shrink-0`}
        style={{ background: 'hsl(220 15% 8%)' }}
      >
        {/* Logo */}
        <div className="p-3 border-b border-sidebar-border">
          <div className="flex items-center gap-2">
            <div className="w-9 h-9 bg-sidebar-primary rounded-lg flex items-center justify-center shrink-0">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <AnimatePresence>
              {sidebarOpen && (
                <motion.div
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -10 }}
                  className="flex flex-col min-w-0"
                >
                  <span className="text-sm font-bold text-white tracking-widest">FORENSYS</span>
                  <span className="text-xs text-accent">SOC Platform</span>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
          {visibleNavItems.map((item) => {
            const Icon = item.icon;
            const isActive =
              pathname === item.href ||
              (pathname.startsWith(item.href) && item.href !== '/dashboard');
            return (
              <Link key={item.href} href={item.href}>
                <div
                  className={`flex items-center gap-2.5 px-2.5 py-2 rounded-md cursor-pointer transition-all duration-150 group ${
                    isActive
                      ? 'bg-accent/15 text-accent border border-accent/30'
                      : 'text-sidebar-foreground hover:bg-white/5 border border-transparent'
                  }`}
                  title={!sidebarOpen ? item.label : undefined}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-accent' : 'text-sidebar-foreground/70 group-hover:text-sidebar-foreground'}`} />
                  <AnimatePresence>
                    {sidebarOpen && (
                      <motion.span
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="text-xs font-medium truncate"
                      >
                        {item.label}
                      </motion.span>
                    )}
                  </AnimatePresence>
                  {isActive && sidebarOpen && (
                    <div className="ml-auto w-1.5 h-1.5 rounded-full bg-accent" />
                  )}
                </div>
              </Link>
            );
          })}
        </nav>

        {/* Toggle */}
        <div className="p-2 border-t border-sidebar-border">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="w-full flex items-center justify-center p-2 rounded-md text-sidebar-foreground/60 hover:text-sidebar-foreground hover:bg-white/5 transition-colors"
          >
            {sidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </aside>

      {/* Right column */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header */}
        <header className="h-12 border-b border-border/50 flex items-center justify-between px-4 shrink-0"
          style={{ background: 'hsl(220 13% 9%)' }}>
          {/* Breadcrumb */}
          <div className="flex items-center gap-1 text-xs">
            {breadcrumbs.map((crumb, i) => (
              <span key={crumb.href} className="flex items-center gap-1">
                {i > 0 && <ChevronRight className="w-3 h-3 text-muted-foreground" />}
                <Link
                  href={crumb.href}
                  className={`${
                    i === breadcrumbs.length - 1
                      ? 'text-foreground font-medium'
                      : 'text-muted-foreground hover:text-foreground'
                  } transition-colors`}
                >
                  {crumb.label}
                </Link>
              </span>
            ))}
          </div>

          {/* Right side controls */}
          <div className="flex items-center gap-3">
            {/* Backend Connection Status */}
            {mounted && (
              <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-card/50 border border-border/50">
                <div className={`w-1.5 h-1.5 rounded-full ${backendConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                <span className={`text-[10px] font-semibold font-mono ${backendConnected ? 'text-green-400' : 'text-red-400'}`}>
                  {backendConnected ? 'API: ONLINE' : 'API: OFFLINE'}
                </span>
              </div>
            )}

            {/* Threat Level */}
            {mounted && metrics && (
              <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-card/50 border border-border/50">
                <div className={`w-1.5 h-1.5 rounded-full animate-pulse ${threatLevelColors[metrics.threat_level] ?? 'bg-gray-500'}`} />
                <span className={`text-xs font-semibold ${threatLevelText[metrics.threat_level] ?? 'text-gray-400'}`}>
                  {(metrics.threat_level || 'low').toUpperCase()}
                </span>
              </div>
            )}

            {/* Notification Bell */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="relative p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-white/5 transition-colors">
                  <Bell className="w-4 h-4" />
                  {mounted && unreadCount() > 0 && (
                    <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-red-500 rounded-full text-white text-[10px] font-bold flex items-center justify-center">
                      {unreadCount() > 9 ? '9+' : unreadCount()}
                    </span>
                  )}
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-80 bg-card border-border/50">
                <div className="flex items-center justify-between px-3 py-2 border-b border-border/50">
                  <span className="text-sm font-semibold text-foreground">Notifications</span>
                  <button
                    onClick={markAllRead}
                    className="text-xs text-accent hover:text-accent/80 transition-colors"
                  >
                    Mark all read
                  </button>
                </div>
                <div className="max-h-64 overflow-y-auto">
                  {notifications.slice(0, 8).map((n) => (
                    <div
                      key={n.id}
                      className={`px-3 py-2.5 border-b border-border/30 hover:bg-card/80 transition-colors ${
                        !n.read ? 'bg-accent/5' : ''
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        <div
                          className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${
                            n.severity === 'critical'
                              ? 'bg-red-500'
                              : n.severity === 'high'
                              ? 'bg-orange-500'
                              : 'bg-yellow-500'
                          }`}
                        />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs text-foreground font-medium truncate">{n.title}</p>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {n.timestamp.toLocaleTimeString()}
                          </p>
                        </div>
                        {!n.read && <div className="w-1.5 h-1.5 rounded-full bg-accent shrink-0 mt-1.5" />}
                      </div>
                    </div>
                  ))}
                </div>
                {notifications.length === 0 && (
                  <div className="px-3 py-6 text-center text-xs text-muted-foreground">
                    No notifications
                  </div>
                )}
              </DropdownMenuContent>
            </DropdownMenu>

            {/* User Menu */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="flex items-center gap-2 p-1.5 rounded-md hover:bg-white/5 transition-colors">
                  <div className="w-6 h-6 rounded-full bg-accent/20 border border-accent/40 flex items-center justify-center">
                    <User className="w-3.5 h-3.5 text-accent" />
                  </div>
                  <AnimatePresence>
                    {sidebarOpen && (
                      <span className="text-xs text-foreground font-medium hidden sm:block">
                        {mounted ? (currentUser?.name || 'Analyst') : 'Analyst'}
                      </span>
                    )}
                  </AnimatePresence>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-64 bg-card border-border/50 shadow-xl rounded-xl overflow-hidden p-0">
                {/* User identity header */}
                <div className="px-4 py-3.5 border-b border-border/40" style={{ background: 'hsl(220 13% 10%)' }}>
                  <div className="flex items-start gap-3">
                    {/* Avatar */}
                    <div className="w-9 h-9 rounded-lg bg-accent/15 border border-accent/30 flex items-center justify-center shrink-0">
                      <User className="w-4.5 h-4.5 text-accent" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-semibold text-foreground truncate">
                        {mounted ? (currentUser?.name || 'SOC Analyst') : 'SOC Analyst'}
                      </p>
                      <p className="text-[10px] text-muted-foreground font-mono truncate mt-0.5">
                        {mounted ? (currentUser?.email || 'analyst@forensys.io') : 'analyst@forensys.io'}
                      </p>
                      {/* Role + status row */}
                      <div className="flex items-center gap-1.5 mt-1.5">
                        <span className="text-[9px] font-bold font-mono uppercase tracking-widest px-1.5 py-0.5 rounded bg-accent/15 text-accent border border-accent/25">
                          {mounted ? (currentUser?.role || 'analyst') : 'analyst'}
                        </span>
                        {mounted && currentUser?.department && (
                          <span className="text-[9px] font-mono text-muted-foreground truncate">
                            {currentUser.department}
                          </span>
                        )}
                        <div className="ml-auto flex items-center gap-1">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-400" />
                          <span className="text-[8px] font-mono text-green-400 uppercase tracking-wider">Active</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Menu items */}
                <div className="py-1.5 px-1.5">
                  <DropdownMenuItem
                    onClick={() => router.push('/dashboard/settings')}
                    className="flex items-center gap-2.5 px-2.5 py-2 rounded-md text-muted-foreground cursor-pointer text-xs transition-colors focus:bg-white/5 focus:text-foreground data-[highlighted]:bg-white/5 data-[highlighted]:text-foreground hover:bg-white/5 hover:text-foreground"
                  >
                    <div className="w-6 h-6 rounded-md bg-white/5 flex items-center justify-center shrink-0">
                      <User className="w-3.5 h-3.5" />
                    </div>
                    <div>
                      <div className="font-medium">Profile</div>
                      <div className="text-[9px] text-muted-foreground/60 font-mono">Manage your account settings</div>
                    </div>
                  </DropdownMenuItem>
                </div>

                <div className="px-1.5 pb-1.5 border-t border-border/40 pt-1.5">
                  <DropdownMenuItem
                    onClick={logout}
                    className="flex items-center gap-2.5 px-2.5 py-2 rounded-md text-red-400 cursor-pointer text-xs transition-colors focus:bg-red-500/10 focus:text-red-300 data-[highlighted]:bg-red-500/10 data-[highlighted]:text-red-300 hover:bg-red-500/10 hover:text-red-300"
                  >
                    <div className="w-6 h-6 rounded-md bg-red-500/10 flex items-center justify-center shrink-0">
                      <LogOut className="w-3.5 h-3.5" />
                    </div>
                    <div>
                      <div className="font-medium">Sign out</div>
                      <div className="text-[9px] text-red-400/60 font-mono">End your current session</div>
                    </div>
                  </DropdownMenuItem>
                </div>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        {/* Main content */}
        <main className="flex-1 overflow-auto flex flex-col">
          {children}
        </main>
      </div>

      {/* AI Copilot */}
      <CopilotSidebar />
    </div>
  );
}
