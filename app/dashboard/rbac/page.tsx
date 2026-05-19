'use client';

import { useState } from 'react';
import { Users, Plus, Search, Shield, Edit2, Trash2, Check, X } from 'lucide-react';
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

interface RbacUser {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer' | 'responder';
  department: string;
  status: 'active' | 'inactive';
  permissions: string[];
}

const ALL_PERMISSIONS = [
  'view_alerts',
  'manage_alerts',
  'view_incidents',
  'manage_incidents',
  'view_forensics',
  'export_forensics',
  'view_analytics',
  'run_hunt',
  'manage_playbooks',
  'view_logs',
  'manage_settings',
  'manage_users',
];

const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-red-900/30 text-red-300 border-red-700/50',
  analyst: 'bg-accent/20 text-accent border-accent/50',
  responder: 'bg-orange-900/30 text-orange-300 border-orange-700/50',
  viewer: 'bg-gray-900/30 text-gray-300 border-gray-700/50',
};

const DEFAULT_PERMISSIONS: Record<string, string[]> = {
  admin: ALL_PERMISSIONS,
  analyst: ['view_alerts', 'manage_alerts', 'view_incidents', 'manage_incidents', 'view_forensics', 'view_analytics', 'run_hunt', 'view_logs'],
  responder: ['view_alerts', 'manage_alerts', 'view_incidents', 'manage_incidents', 'manage_playbooks', 'view_logs'],
  viewer: ['view_alerts', 'view_incidents', 'view_analytics', 'view_logs'],
};

const INITIAL_USERS: RbacUser[] = [
  { id: '1', name: 'Sarah Johnson', email: 'sarah.j@company.com', role: 'admin', department: 'Security', status: 'active', permissions: DEFAULT_PERMISSIONS.admin },
  { id: '2', name: 'Michael Chen', email: 'm.chen@company.com', role: 'analyst', department: 'SOC', status: 'active', permissions: DEFAULT_PERMISSIONS.analyst },
  { id: '3', name: 'Emily Brown', email: 'emily.brown@company.com', role: 'analyst', department: 'Threat Intel', status: 'active', permissions: DEFAULT_PERMISSIONS.analyst },
  { id: '4', name: 'David Rodriguez', email: 'd.rodriguez@company.com', role: 'responder', department: 'IR Team', status: 'active', permissions: DEFAULT_PERMISSIONS.responder },
  { id: '5', name: 'Lisa Anderson', email: 'l.anderson@company.com', role: 'viewer', department: 'Compliance', status: 'active', permissions: DEFAULT_PERMISSIONS.viewer },
  { id: '6', name: 'James Wilson', email: 'j.wilson@company.com', role: 'viewer', department: 'Management', status: 'inactive', permissions: DEFAULT_PERMISSIONS.viewer },
];

export default function RBACPage() {
  const [users, setUsers] = useState<RbacUser[]>(INITIAL_USERS);
  const [search, setSearch] = useState('');
  const [selectedUser, setSelectedUser] = useState<RbacUser | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newUser, setNewUser] = useState({ name: '', email: '', role: 'viewer' as RbacUser['role'], department: '' });

  const filtered = users.filter(
    (u) =>
      u.name.toLowerCase().includes(search.toLowerCase()) ||
      u.email.toLowerCase().includes(search.toLowerCase()) ||
      u.department.toLowerCase().includes(search.toLowerCase())
  );

  const togglePermission = (userId: string, perm: string) => {
    setUsers((prev) =>
      prev.map((u) => {
        if (u.id !== userId) return u;
        const perms = u.permissions.includes(perm)
          ? u.permissions.filter((p) => p !== perm)
          : [...u.permissions, perm];
        return { ...u, permissions: perms };
      })
    );
    if (selectedUser?.id === userId) {
      setSelectedUser((prev) =>
        prev
          ? {
              ...prev,
              permissions: prev.permissions.includes(perm)
                ? prev.permissions.filter((p) => p !== perm)
                : [...prev.permissions, perm],
            }
          : null
      );
    }
    toast.success(`Permission updated`);
  };

  const toggleUserStatus = (userId: string) => {
    setUsers((prev) =>
      prev.map((u) =>
        u.id === userId ? { ...u, status: u.status === 'active' ? 'inactive' : 'active' } : u
      )
    );
    toast.info('User status updated');
  };

  const addUser = () => {
    if (!newUser.name || !newUser.email) {
      toast.error('Please fill in all required fields');
      return;
    }
    const user: RbacUser = {
      id: Date.now().toString(),
      ...newUser,
      status: 'active',
      permissions: DEFAULT_PERMISSIONS[newUser.role],
    };
    setUsers((prev) => [user, ...prev]);
    setShowAddModal(false);
    setNewUser({ name: '', email: '', role: 'viewer', department: '' });
    toast.success('User added successfully');
  };

  const removeUser = (userId: string) => {
    setUsers((prev) => prev.filter((u) => u.id !== userId));
    if (selectedUser?.id === userId) setSelectedUser(null);
    toast.success('User removed');
  };

  const roleCounts = {
    admin: users.filter((u) => u.role === 'admin').length,
    analyst: users.filter((u) => u.role === 'analyst').length,
    responder: users.filter((u) => u.role === 'responder').length,
    viewer: users.filter((u) => u.role === 'viewer').length,
  };

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Users className="w-6 h-6 text-accent" />
            Role-Based Access Control
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Manage user permissions and access levels</p>
        </div>
        <Button
          onClick={() => setShowAddModal(true)}
          className="bg-accent hover:bg-accent/90 text-accent-foreground gap-2 text-sm"
        >
          <Plus className="w-4 h-4" /> Add User
        </Button>
      </div>

      {/* Role Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {Object.entries(roleCounts).map(([role, count]) => (
          <div key={role} className={`rounded-lg p-3 border ${ROLE_COLORS[role]}`}>
            <div className="text-xs font-medium mb-1 capitalize">{role}</div>
            <div className="text-2xl font-bold font-mono">{count}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* User List */}
        <div className="lg:col-span-2 glass rounded-lg border border-border/50 overflow-hidden flex flex-col">
          <div className="p-3 border-b border-border/50 space-y-2">
            <div className="relative">
              <Search className="w-4 h-4 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
              <Input
                placeholder="Search users..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8 bg-input border-border/50 text-xs h-8"
              />
            </div>
          </div>
          <ScrollArea className="flex-1 max-h-[500px]">
            <div className="space-y-1.5 p-3">
              <AnimatePresence>
                {filtered.map((user) => (
                  <motion.div
                    key={user.id}
                    initial={{ opacity: 0, x: -15 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 15 }}
                    onClick={() => setSelectedUser(user)}
                    className={`p-3 rounded border cursor-pointer transition-all ${
                      selectedUser?.id === user.id
                        ? 'border-accent bg-accent/10'
                        : 'border-border/50 hover:border-border hover:bg-card/60'
                    }`}
                  >
                    <div className="flex items-start gap-2.5">
                      <div className="w-8 h-8 rounded-full bg-accent/20 border border-accent/30 flex items-center justify-center text-accent text-xs font-bold flex-shrink-0">
                        {user.name.charAt(0)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <p className="text-xs font-semibold text-foreground truncate">{user.name}</p>
                          {user.status === 'inactive' && (
                            <div className="w-1.5 h-1.5 rounded-full bg-muted-foreground flex-shrink-0" />
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground truncate">{user.email}</p>
                        <div className="flex items-center gap-1.5 mt-1">
                          <Badge className={`text-xs ${ROLE_COLORS[user.role]}`}>{user.role}</Badge>
                          <span className="text-xs text-muted-foreground">{user.department}</span>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </ScrollArea>
        </div>

        {/* Permission Panel */}
        <div className="lg:col-span-3 glass rounded-lg border border-border/50 overflow-hidden">
          {!selectedUser ? (
            <div className="p-12 text-center h-full flex flex-col items-center justify-center">
              <Shield className="w-8 h-8 text-muted-foreground mb-3" />
              <p className="text-sm text-muted-foreground">Select a user to manage permissions</p>
            </div>
          ) : (
            <AnimatePresence mode="wait">
              <motion.div
                key={selectedUser.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="p-5 space-y-5"
              >
                {/* User Header */}
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-accent/20 border border-accent/30 flex items-center justify-center text-accent font-bold">
                      {selectedUser.name.charAt(0)}
                    </div>
                    <div>
                      <p className="text-sm font-bold text-foreground">{selectedUser.name}</p>
                      <p className="text-xs text-muted-foreground">{selectedUser.email}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge className={`text-xs ${ROLE_COLORS[selectedUser.role]}`}>{selectedUser.role}</Badge>
                        <span className="text-xs text-muted-foreground">{selectedUser.department}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs border-border/50"
                      onClick={() => toggleUserStatus(selectedUser.id)}
                    >
                      {selectedUser.status === 'active' ? (
                        <><X className="w-3.5 h-3.5 mr-1" /> Deactivate</>
                      ) : (
                        <><Check className="w-3.5 h-3.5 mr-1" /> Activate</>
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs text-red-400 hover:text-red-300 hover:bg-red-900/20"
                      onClick={() => removeUser(selectedUser.id)}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>

                {/* Role Selector */}
                <div>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Role</h3>
                  <div className="flex gap-2 flex-wrap">
                    {(['admin', 'analyst', 'responder', 'viewer'] as RbacUser['role'][]).map((role) => (
                      <button
                        key={role}
                        onClick={() => {
                          setUsers((prev) => prev.map((u) => u.id === selectedUser.id ? { ...u, role, permissions: DEFAULT_PERMISSIONS[role] } : u));
                          setSelectedUser({ ...selectedUser, role, permissions: DEFAULT_PERMISSIONS[role] });
                          toast.success(`Role updated to ${role}`);
                        }}
                        className={`px-3 py-1 rounded border text-xs capitalize transition-all ${
                          selectedUser.role === role ? ROLE_COLORS[role] : 'border-border/50 text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        {role}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Permissions Grid */}
                <div>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Permissions</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    {ALL_PERMISSIONS.map((perm) => {
                      const hasIt = selectedUser.permissions.includes(perm);
                      return (
                        <button
                          key={perm}
                          onClick={() => togglePermission(selectedUser.id, perm)}
                          className={`flex items-center gap-2 p-2 rounded border text-xs transition-all text-left ${
                            hasIt
                              ? 'border-accent/50 bg-accent/10 text-accent'
                              : 'border-border/50 text-muted-foreground hover:text-foreground hover:border-border'
                          }`}
                        >
                          <div className={`w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 ${
                            hasIt ? 'bg-accent border-accent text-accent-foreground' : 'border-border/60'
                          }`}>
                            {hasIt && <Check className="w-2.5 h-2.5" />}
                          </div>
                          {perm.replace(/_/g, ' ')}
                        </button>
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
        <DialogContent className="bg-card border-border/50" aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle className="text-foreground">Add New User</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 mt-2">
            {[
              { label: 'Name *', key: 'name' as const, placeholder: 'John Smith' },
              { label: 'Email *', key: 'email' as const, placeholder: 'john@company.com' },
              { label: 'Department', key: 'department' as const, placeholder: 'Security Operations' },
            ].map((field) => (
              <div key={field.key}>
                <label className="text-xs text-muted-foreground block mb-1">{field.label}</label>
                <Input
                  value={newUser[field.key]}
                  onChange={(e) => setNewUser((n) => ({ ...n, [field.key]: e.target.value }))}
                  placeholder={field.placeholder}
                  className="bg-input border-border/50 text-sm"
                />
              </div>
            ))}
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Role</label>
              <select
                value={newUser.role}
                onChange={(e) => setNewUser((n) => ({ ...n, role: e.target.value as RbacUser['role'] }))}
                className="w-full bg-input border border-border/50 rounded-md px-3 py-2 text-sm text-foreground"
              >
                {['admin', 'analyst', 'responder', 'viewer'].map((r) => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
            </div>
            <Button onClick={addUser} className="w-full bg-accent hover:bg-accent/90 text-accent-foreground mt-2">
              Add User
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
