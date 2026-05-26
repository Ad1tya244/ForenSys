'use client';

import { useState, useEffect } from 'react';
import { 
  Users, Plus, Search, Shield, ShieldAlert, Trash2, Check, X, Eye, EyeOff, 
  UserCheck, UserX, Activity, Terminal, Key, Info, ShieldCheck, Database
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import { useAppStore } from '@/lib/app-store';
import { AccessDenied } from '@/components/rbac/access-denied';
import { RbacUser, ALL_PERMISSIONS, DEFAULT_PERMISSIONS } from '@/lib/api-client';

const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-red-500/10 text-red-400 border border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.05)]',
  analyst: 'bg-accent/10 text-accent border border-accent/20 shadow-[0_0_10px_rgba(0,200,255,0.05)]',
  responder: 'bg-orange-500/10 text-orange-400 border border-orange-500/20 shadow-[0_0_10px_rgba(249,115,22,0.05)]',
  viewer: 'bg-zinc-500/10 text-zinc-400 border border-zinc-500/20',
};

const ROLE_LEFT_BORDERS: Record<string, string> = {
  admin: 'border-l-red-500/50',
  analyst: 'border-l-accent/50',
  responder: 'border-l-orange-500/50',
  viewer: 'border-l-zinc-500/50'
};

const ROLE_META: Record<string, { icon: React.ReactNode; label: string; desc: string; gradient: string }> = {
  admin: {
    icon: <ShieldAlert className="w-5 h-5 text-red-400" />,
    label: 'Administrators',
    desc: 'Full system permission access',
    gradient: 'from-red-950/20 to-red-900/5 border-red-900/30 hover:border-red-600/50 shadow-red-950/20'
  },
  analyst: {
    icon: <Terminal className="w-5 h-5 text-accent" />,
    label: 'Analysts',
    desc: 'Threat monitoring & analysis controls',
    gradient: 'from-cyan-950/20 to-cyan-900/5 border-accent/30 hover:border-accent/60 shadow-cyan-950/20'
  },
  responder: {
    icon: <Activity className="w-5 h-5 text-orange-400" />,
    label: 'Responders',
    desc: 'Alert triaging & playbook triage',
    gradient: 'from-orange-950/20 to-orange-900/5 border-orange-900/30 hover:border-orange-600/50 shadow-orange-950/20'
  },
  viewer: {
    icon: <Eye className="w-5 h-5 text-zinc-400" />,
    label: 'Viewers',
    desc: 'Read-only log & incident analysis',
    gradient: 'from-zinc-950/20 to-zinc-900/5 border-zinc-800/30 hover:border-zinc-650/50 shadow-zinc-950/20'
  }
};

const PERMISSION_DETAILS: Record<string, { label: string; desc: string; category: string }> = {
  view_alerts: { label: 'View Alerts', desc: 'Read-only access to active alert feeds', category: 'Monitoring' },
  view_incidents: { label: 'View Incidents', desc: 'Access active and archived incidents logs', category: 'Monitoring' },
  view_analytics: { label: 'View Analytics', desc: 'Read dashboards containing MTTD, MTTR, and trends', category: 'Monitoring' },
  view_logs: { label: 'View Logs', desc: 'Query and explore system logs in Log Explorer', category: 'Monitoring' },
  
  manage_alerts: { label: 'Manage Alerts', desc: 'Acknowledge, prioritize, and resolve security alerts', category: 'Response Operations' },
  manage_incidents: { label: 'Manage Incidents', desc: 'Assign incidents, log mitigation steps, and update status', category: 'Response Operations' },
  run_hunt: { label: 'Run Threat Hunts', desc: 'Trigger endpoint scans and filesystem IOC lookups', category: 'Response Operations' },
  export_forensics: { label: 'Export Reports', desc: 'Download CSV/JSON reports containing platform data', category: 'Response Operations' },
  
  view_forensics: { label: 'View Forensic Map', desc: 'Access network map topology and trace nodes', category: 'Platform Settings' },
  manage_playbooks: { label: 'Manage Playbooks', desc: 'Configure automation containment rules (SOAR)', category: 'Platform Settings' },
  manage_settings: { label: 'Manage Settings', desc: 'Modify system preferences, thresholds, and triggers', category: 'Platform Settings' },
  manage_users: { label: 'Manage Operators', desc: 'Provision user profiles, alter roles, and reset keys', category: 'Platform Settings' },
};

const CATEGORIES = ['Monitoring', 'Response Operations', 'Platform Settings'];

export default function RBACPage() {
  const { users, fetchUsers, saveUser, deleteUser, hasPermission, backendConnected, currentUser } = useAppStore();
  const [search, setSearch] = useState('');
  const [selectedUser, setSelectedUser] = useState<RbacUser | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newUser, setNewUser] = useState({ name: '', email: '', role: 'viewer' as RbacUser['role'], department: '', password: '' });
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [showCreatePassword, setShowCreatePassword] = useState(false);
  const [showResetPassword, setShowResetPassword] = useState(false);

  useEffect(() => {
    if (backendConnected) {
      fetchUsers();
    }
  }, [fetchUsers, backendConnected]);

  // View enforcement check
  const isAuthorized = hasPermission('manage_users');
  if (!isAuthorized) {
    return <AccessDenied permission="manage_users" />;
  }

  const filtered = users.filter(
    (u) =>
      u.name.toLowerCase().includes(search.toLowerCase()) ||
      u.email.toLowerCase().includes(search.toLowerCase()) ||
      u.department.toLowerCase().includes(search.toLowerCase())
  );

  const togglePermission = async (userId: string, perm: string) => {
    const user = users.find((u) => u.id === userId);
    if (!user || userId === currentUser?.id) return; // Prevent self-modification of permissions

    try {
      const perms = user.permissions.includes(perm)
        ? user.permissions.filter((p) => p !== perm)
        : [...user.permissions, perm];
      const updatedUser = { ...user, permissions: perms };
      
      await saveUser(updatedUser);
      
      if (selectedUser?.id === userId) {
        setSelectedUser(updatedUser);
      }
      toast.success(`Permission updated`);
    } catch (err) {
      toast.error('Failed to update permission');
    }
  };

  const toggleUserStatus = async (userId: string) => {
    const user = users.find((u) => u.id === userId);
    if (!user || userId === currentUser?.id) return; // Prevent self-deactivation

    try {
      const updatedUser = { 
        ...user, 
        status: (user.status === 'active' ? 'inactive' : 'active') as RbacUser['status'] 
      };
      
      await saveUser(updatedUser);
      
      if (selectedUser?.id === userId) {
        setSelectedUser(updatedUser);
      }
      toast.info('User status updated');
    } catch (err) {
      toast.error('Failed to update status');
    }
  };

  const addUser = async () => {
    if (!newUser.name || !newUser.email || !newUser.password) {
      toast.error('Please fill in all required fields (including password)');
      return;
    }
    
    setLoading(true);
    try {
      const user: Omit<RbacUser, 'id'> = {
        ...newUser,
        status: 'active',
        permissions: DEFAULT_PERMISSIONS[newUser.role] || [],
      };
      
      await saveUser(user);
      setShowAddModal(false);
      setNewUser({ name: '', email: '', role: 'viewer', department: '', password: '' });
      toast.success('User added successfully');
    } catch (err) {
      toast.error('Failed to add user');
    } finally {
      setLoading(false);
    }
  };

  const removeUser = async (userId: string) => {
    if (userId === currentUser?.id) {
      toast.error('You cannot delete your own account');
      return;
    }
    try {
      await deleteUser(userId);
      if (selectedUser?.id === userId) setSelectedUser(null);
      toast.success('User removed');
    } catch (err) {
      toast.error('Failed to remove user');
    }
  };

  const roleCounts = {
    admin: users.filter((u) => u.role === 'admin').length,
    analyst: users.filter((u) => u.role === 'analyst').length,
    responder: users.filter((u) => u.role === 'responder').length,
    viewer: users.filter((u) => u.role === 'viewer').length,
  };

  const isSelfSelected = selectedUser?.id === currentUser?.id;

  return (
    <div className="flex-1 overflow-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2.5">
            <Users className="w-6 h-6 text-accent" />
            Operator Access Control
          </h1>
          <p className="text-xs text-muted-foreground mt-1">Configure role assignments, system containment triggers, and operator credentials</p>
        </div>
        <Button
          onClick={() => setShowAddModal(true)}
          className="bg-accent hover:bg-accent/90 text-accent-foreground gap-2 text-xs h-9 px-4 font-semibold shrink-0 shadow-[0_0_15px_rgba(0,200,255,0.2)] transition-all duration-300"
        >
          <Plus className="w-4 h-4" /> Add Operator
        </Button>
      </div>

      {/* Role Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Object.entries(roleCounts).map(([role, count]) => {
          const meta = ROLE_META[role];
          return (
            <div 
              key={role} 
              className={`rounded-lg p-4 border bg-linear-to-br ${meta.gradient} transition-all duration-300 hover:scale-[1.02] flex items-center justify-between shadow-[0_4px_12px_rgba(0,0,0,0.15)]`}
            >
              <div className="space-y-1">
                <span className="text-[9px] uppercase font-bold tracking-widest text-muted-foreground block">{meta.label}</span>
                <span className="text-3xl font-extrabold font-mono text-foreground tracking-tight block">{count}</span>
                <span className="text-[9px] text-muted-foreground block leading-tight">{meta.desc}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 shadow-inner shrink-0">
                {meta.icon}
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* User List Panel */}
        <div className="lg:col-span-2 glass rounded-xl border border-border/50 overflow-hidden flex flex-col shadow-lg">
          <div className="p-4 border-b border-border/50 bg-card/20 space-y-2 flex items-center justify-between gap-4">
            <h2 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-accent" />
              Operators List ({filtered.length})
            </h2>
          </div>
          
          <div className="p-3 border-b border-border/50 bg-card/10">
            <div className="relative">
              <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
              <Input
                placeholder="Search by name, email, department..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 bg-input border-border/50 text-xs h-9 focus:border-accent/40"
              />
            </div>
          </div>
          
          <ScrollArea className="flex-1 max-h-[550px]">
            <div className="space-y-2 p-3">
              <AnimatePresence>
                {filtered.length === 0 ? (
                  <div className="py-12 text-center flex flex-col items-center justify-center">
                    <Users className="w-8 h-8 text-muted-foreground/30 mb-2" />
                    <p className="text-xs text-muted-foreground">No operators found matching query</p>
                  </div>
                ) : (
                  filtered.map((user) => {
                    const isSelfItem = user.id === currentUser?.id;
                    return (
                      <motion.div
                        key={user.id}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 10 }}
                        onClick={() => setSelectedUser(user)}
                        className={`p-3.5 rounded-lg border-l-4 border cursor-pointer transition-all duration-300 hover:scale-[1.01] ${
                          selectedUser?.id === user.id
                            ? 'border-accent bg-accent/10 shadow-[0_0_15px_rgba(0,200,255,0.08)]'
                            : `border-border/40 ${ROLE_LEFT_BORDERS[user.role]} hover:border-border hover:bg-card/50`
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className="w-8 h-8 rounded-lg bg-accent/15 border border-accent/20 flex items-center justify-center text-accent text-xs font-extrabold shrink-0 shadow-inner">
                            {user.name.charAt(0)}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-0.5">
                              <p className="text-xs font-bold text-foreground truncate">
                                {user.name} {isSelfItem && <span className="text-[10px] text-accent font-mono ml-1">(You)</span>}
                              </p>
                              {user.status === 'active' ? (
                                <span className="relative flex h-2 w-2 shrink-0">
                                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                                  <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                                </span>
                              ) : (
                                <span className="inline-flex rounded-full h-2 w-2 bg-zinc-650 shrink-0" title="Inactive operator" />
                              )}
                            </div>
                            <p className="text-[10px] text-muted-foreground truncate font-mono">{user.email}</p>
                            <div className="flex items-center justify-between gap-1.5 mt-2">
                              <Badge className={`text-[9px] uppercase font-bold py-0.5 px-2 tracking-wider ${ROLE_COLORS[user.role]}`}>{user.role}</Badge>
                              <span className="text-[10px] text-muted-foreground font-medium">{user.department}</span>
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    );
                  })
                )}
              </AnimatePresence>
            </div>
          </ScrollArea>
        </div>

        {/* Permissions Panel */}
        <div className="lg:col-span-3 glass rounded-xl border border-border/50 overflow-hidden shadow-lg flex flex-col min-h-[500px]">
          {!selectedUser ? (
            <div className="p-12 text-center h-full flex flex-col items-center justify-center flex-1">
              <div className="p-4 rounded-full bg-accent/10 border border-accent/20 mb-4 animate-pulse">
                <Shield className="w-8 h-8 text-accent/80" />
              </div>
              <p className="text-sm font-semibold text-foreground">Select an Operator Profile</p>
              <p className="text-xs text-muted-foreground mt-1 max-w-[280px]">Select an active profile from the left list to modify user roles, reset passwords, or tweak granular SOC console permissions.</p>
            </div>
          ) : (
            <AnimatePresence mode="wait">
              <motion.div
                key={selectedUser.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="p-5 space-y-6"
              >
                {/* User Header */}
                <div className="bg-card/40 p-5 rounded-xl border border-border/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-[0_4px_20px_rgba(0,0,0,0.2)] relative overflow-hidden">
                  {/* Subtle backglow gradient based on user role */}
                  <div className={`absolute top-0 right-0 w-24 h-24 rounded-full filter blur-2xl opacity-10 bg-current ${
                    selectedUser.role === 'admin' ? 'text-red-500' : selectedUser.role === 'analyst' ? 'text-accent' : selectedUser.role === 'responder' ? 'text-orange-500' : 'text-zinc-500'
                  }`} />
                  
                  <div className="flex items-center gap-4 relative z-10">
                    <div className="w-12 h-12 rounded-xl bg-accent/15 border border-accent/35 flex items-center justify-center text-accent text-lg font-bold shadow-[0_0_15px_rgba(0,200,255,0.1)] shrink-0">
                      {selectedUser.name.charAt(0)}
                    </div>
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <p className="text-base font-extrabold text-foreground tracking-tight leading-tight">{selectedUser.name}</p>
                        {selectedUser.status === 'active' ? (
                          <Badge className="bg-green-500/10 text-green-400 border border-green-500/20 text-[9px] py-0 px-1.5 font-bold uppercase tracking-wider">Active</Badge>
                        ) : (
                          <Badge className="bg-zinc-500/10 text-zinc-400 border border-zinc-500/20 text-[9px] py-0 px-1.5 font-bold uppercase tracking-wider">Inactive</Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground font-mono">{selectedUser.email}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge className={`text-[9px] uppercase font-bold py-0.5 px-2 tracking-wider ${ROLE_COLORS[selectedUser.role]}`}>{selectedUser.role}</Badge>
                        <span className="text-[11px] text-muted-foreground font-medium">{selectedUser.department}</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2 relative z-10 shrink-0">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={isSelfSelected}
                      className={`h-9 text-xs border-border/50 px-3 font-semibold transition-colors ${
                        isSelfSelected 
                          ? 'opacity-40 cursor-not-allowed text-muted-foreground bg-zinc-900/10'
                          : selectedUser.status === 'active' 
                            ? 'hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/30' 
                            : 'hover:bg-green-500/10 hover:text-green-400 hover:border-green-500/30'
                      }`}
                      onClick={() => toggleUserStatus(selectedUser.id)}
                      title={isSelfSelected ? "Cannot deactivate yourself" : ""}
                    >
                      {selectedUser.status === 'active' ? (
                        <><UserX className="w-3.5 h-3.5 mr-1.5" /> Deactivate</>
                      ) : (
                        <><UserCheck className="w-3.5 h-3.5 mr-1.5" /> Activate</>
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      disabled={isSelfSelected}
                      className={`h-9 w-9 text-red-400 hover:text-red-300 hover:bg-red-900/30 border border-transparent hover:border-red-500/20 rounded-lg transition-colors ${
                        isSelfSelected ? 'opacity-30 cursor-not-allowed' : ''
                      }`}
                      onClick={() => removeUser(selectedUser.id)}
                      title={isSelfSelected ? "Cannot delete yourself" : "Delete User"}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>

                {/* Self-Modification Warning Alert */}
                {isSelfSelected && (
                  <div className="flex items-start gap-3 bg-red-500/10 border border-red-500/20 p-3.5 rounded-xl shadow-[0_0_15px_rgba(239,68,68,0.05)]">
                    <Info className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <div className="space-y-0.5">
                      <p className="text-xs font-bold text-red-400">Self-Modification Protection Active</p>
                      <p className="text-[10px] text-muted-foreground leading-normal">
                        To prevent accidental administrator lockout, you cannot modify your own role, alter your own permissions, or deactivate your account. If changes are required, please have another administrator execute them.
                      </p>
                    </div>
                  </div>
                )}

                {/* Role Assignment */}
                <div className="bg-card/20 p-4 rounded-xl border border-border/40 space-y-3">
                  <div>
                    <h3 className="text-xs font-bold text-accent uppercase tracking-widest block">Role Assignment</h3>
                    <p className="text-[10px] text-muted-foreground mt-0.5">Changing role template resets permissions to default templates automatically</p>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {(['admin', 'analyst', 'responder', 'viewer'] as RbacUser['role'][]).map((role) => (
                      <button
                        key={role}
                        disabled={isSelfSelected}
                        onClick={async () => {
                          try {
                            const updated = { 
                              ...selectedUser, 
                              role, 
                              permissions: DEFAULT_PERMISSIONS[role] || [] 
                            };
                            await saveUser(updated);
                            setSelectedUser(updated);
                            toast.success(`Role updated to ${role}`);
                          } catch (err) {
                            toast.error('Failed to update role');
                          }
                        }}
                        className={`px-3 py-2 rounded-lg border text-xs capitalize font-semibold transition-all duration-200 text-center ${
                          isSelfSelected
                            ? selectedUser.role === role 
                              ? ROLE_COLORS[role] + ' border-current opacity-70 cursor-not-allowed shadow-none'
                              : 'border-border/40 text-muted-foreground bg-card/10 opacity-30 cursor-not-allowed'
                            : selectedUser.role === role 
                              ? ROLE_COLORS[role] + ' border-current scale-[1.02] cursor-pointer' 
                              : 'border-border/40 text-muted-foreground bg-card/10 hover:text-foreground hover:bg-card/25 cursor-pointer'
                        }`}
                      >
                        {role}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Reset Password */}
                <div className="bg-card/20 p-4 rounded-xl border border-border/40 space-y-3">
                  <div>
                    <h3 className="text-xs font-bold text-accent uppercase tracking-widest block">Security Credentials</h3>
                    <p className="text-[10px] text-muted-foreground mt-0.5">Reset operator access password. Credentials are hashed using bcrypt.</p>
                  </div>
                  <div className="flex gap-2 max-w-md">
                    <div className="relative flex-1">
                      <Input
                        type={showResetPassword ? 'text' : 'password'}
                        placeholder="Enter new password (min. 8 chars)"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        className="bg-input border-border/50 text-xs h-9 pr-9 focus:border-accent/40"
                      />
                      <button
                        type="button"
                        onClick={() => setShowResetPassword(!showResetPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors cursor-pointer"
                        tabIndex={-1}
                      >
                        {showResetPassword ? (
                          <EyeOff className="w-3.5 h-3.5" />
                        ) : (
                          <Eye className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                    <Button
                      size="sm"
                      onClick={async () => {
                        if (!newPassword) {
                          toast.error('Please enter a new password');
                          return;
                        }
                        if (newPassword.length < 8) {
                          toast.error('Password must be at least 8 characters long');
                          return;
                        }
                        try {
                          const updated = { 
                            ...selectedUser, 
                            password: newPassword 
                          };
                          await saveUser(updated);
                          setNewPassword('');
                          toast.success('Password updated successfully');
                        } catch (err) {
                          toast.error('Failed to update password');
                        }
                      }}
                      className="bg-accent hover:bg-accent/90 text-accent-foreground text-xs h-9 shrink-0 px-4 font-semibold"
                    >
                      Update Password
                    </Button>
                  </div>
                </div>

                {/* Permissions Grid */}
                <div className="space-y-4">
                  <div className="flex items-center gap-1.5 border-b border-border/40 pb-2">
                    <Shield className="w-4 h-4 text-accent" />
                    <h3 className="text-xs font-bold text-foreground uppercase tracking-widest">Granular Control Permissions</h3>
                  </div>
                  
                  <div className="space-y-5">
                    {CATEGORIES.map((cat) => {
                      const catPerms = ALL_PERMISSIONS.filter((p) => PERMISSION_DETAILS[p]?.category === cat);
                      return (
                        <div key={cat} className="space-y-2.5">
                          <h4 className="text-[10px] font-extrabold text-accent uppercase tracking-wider pl-0.5">{cat}</h4>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                            {catPerms.map((perm) => {
                              const hasIt = selectedUser.permissions.includes(perm);
                              const details = PERMISSION_DETAILS[perm];
                              return (
                                <button
                                  key={perm}
                                  disabled={isSelfSelected}
                                  onClick={() => togglePermission(selectedUser.id, perm)}
                                  className={`group flex items-start gap-3 p-3 rounded-lg border text-left transition-all duration-200 ${
                                    isSelfSelected
                                      ? hasIt
                                        ? 'border-accent/20 bg-accent/5 text-foreground/75 cursor-not-allowed opacity-75'
                                        : 'border-border/20 text-muted-foreground bg-card/5 cursor-not-allowed opacity-50'
                                      : hasIt
                                        ? 'border-accent/40 bg-accent/5 text-foreground hover:border-accent cursor-pointer'
                                        : 'border-border/40 text-muted-foreground bg-card/10 hover:text-foreground hover:border-border cursor-pointer'
                                  }`}
                                >
                                  <div className={`mt-0.5 w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${
                                    hasIt 
                                      ? isSelfSelected
                                        ? 'bg-accent/45 border-accent/30 text-accent-foreground/60'
                                        : 'bg-accent border-accent text-accent-foreground shadow-[0_0_8px_rgba(0,200,255,0.25)]' 
                                      : 'border-border/60 group-hover:border-border'
                                  }`}>
                                    {hasIt && <Check className="w-2.5 h-2.5 stroke-[3px]" />}
                                  </div>
                                  <div className="space-y-0.5">
                                    <span className="text-xs font-bold block transition-colors group-hover:text-foreground">
                                      {details?.label || perm.replace(/_/g, ' ')}
                                    </span>
                                    <span className="text-[9px] text-muted-foreground block leading-tight">
                                      {details?.desc || 'Modify access for this module.'}
                                    </span>
                                  </div>
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </motion.div>
            </AnimatePresence>
          )}
        </div>
      </div>

      {/* Add User Modal */}
      <Dialog open={showAddModal} onOpenChange={setShowAddModal}>
        <DialogContent className="border border-accent/20 backdrop-blur-md bg-zinc-950/95 max-w-md shadow-2xl" aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle className="text-foreground flex items-center gap-2">
              <Users className="w-5 h-5 text-accent" />
              Add New Operator
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 mt-2">
            {[
              { label: 'Name *', key: 'name' as const, placeholder: 'John Smith' },
              { label: 'Email *', key: 'email' as const, placeholder: 'john@company.com' },
              { label: 'Department', key: 'department' as const, placeholder: 'Security Operations' },
            ].map((field) => (
              <div key={field.key} className="space-y-1">
                <label className="text-xs font-bold text-muted-foreground block">{field.label}</label>
                <Input
                  value={newUser[field.key]}
                  onChange={(e) => setNewUser((n) => ({ ...n, [field.key]: e.target.value }))}
                  placeholder={field.placeholder}
                  className="bg-input border-border/50 text-xs h-9 focus:border-accent/40"
                />
              </div>
            ))}
            <div className="space-y-1">
              <label className="text-xs font-bold text-muted-foreground block">Password *</label>
              <div className="relative">
                <Input
                  type={showCreatePassword ? 'text' : 'password'}
                  value={newUser.password}
                  onChange={(e) => setNewUser((n) => ({ ...n, password: e.target.value }))}
                  placeholder="••••••••"
                  className="bg-input border-border/50 text-xs h-9 pr-9 focus:border-accent/40"
                />
                <button
                  type="button"
                  onClick={() => setShowCreatePassword(!showCreatePassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors cursor-pointer"
                  tabIndex={-1}
                >
                  {showCreatePassword ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-bold text-muted-foreground block">Role</label>
              <select
                value={newUser.role}
                onChange={(e) => setNewUser((n) => ({ ...n, role: e.target.value as RbacUser['role'] }))}
                className="w-full bg-zinc-950 border border-border/50 rounded-md px-3 py-2 text-xs text-foreground focus:outline-none focus:border-accent/50 focus:ring-1 focus:ring-accent/30 cursor-pointer"
              >
                {['admin', 'analyst', 'responder', 'viewer'].map((r) => (
                  <option key={r} value={r} className="bg-zinc-950 text-foreground">{r}</option>
                ))}
              </select>
            </div>
            
            <div className="flex items-start gap-2 bg-accent/5 border border-accent/20 p-3 rounded-lg mt-2">
              <Info className="w-4 h-4 text-accent shrink-0 mt-0.5" />
              <p className="text-[10px] text-muted-foreground leading-snug">
                Creating an operator establishes an profile with the default template permissions for their chosen role. You can customize permissions individually later.
              </p>
            </div>

            <Button 
              onClick={addUser} 
              disabled={loading}
              className="w-full bg-accent hover:bg-accent/90 text-accent-foreground mt-2 font-semibold h-10 shadow-[0_0_15px_rgba(0,200,255,0.15)]"
            >
              {loading ? 'Registering Operator...' : 'Register Operator'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
