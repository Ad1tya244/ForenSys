'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
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
  { href: '/dashboard/threat-intelligence', label: 'Threat Intel', icon: Shield },
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
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mounted, setMounted] = useState(false);
  const { metrics, notifications, unreadCount, markAllRead, connectBackend, backendConnected } = useAppStore();

  useEffect(() => {
    setMounted(true);
    connectBackend();
  }, [connectBackend]);


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
          {navItems.map((item) => {
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
                        Analyst
                      </span>
                    )}
                  </AnimatePresence>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="bg-card border-border/50">
                <div className="px-3 py-2 border-b border-border/50">
                  <p className="text-sm font-medium text-foreground">SOC Analyst</p>
                  <p className="text-xs text-muted-foreground">analyst@forensys.io</p>
                </div>
                <DropdownMenuItem className="text-muted-foreground hover:text-foreground cursor-pointer">
                  <User className="w-4 h-4 mr-2" /> Profile
                </DropdownMenuItem>
                <DropdownMenuSeparator className="bg-border/50" />
                <DropdownMenuItem className="text-red-400 hover:text-red-300 cursor-pointer">
                  <LogOut className="w-4 h-4 mr-2" /> Sign out
                </DropdownMenuItem>
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
