'use client';

import { useState, useEffect } from 'react';
import { Users, Plus, Search, Shield, Trash2, Check, X, Eye, EyeOff } from 'lucide-react';
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
  admin: 'bg-red-900/30 text-red-300 border-red-700/50',
  analyst: 'bg-accent/20 text-accent border-accent/50',
  responder: 'bg-orange-900/30 text-orange-300 border-orange-700/50',
  viewer: 'bg-gray-900/30 text-gray-300 border-gray-700/50',
};

export default function RBACPage() {
  const { users, fetchUsers, saveUser, deleteUser, hasPermission, backendConnected } = useAppStore();
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
    if (!user) return;

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
    if (!user) return;

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
                      <div className="w-8 h-8 rounded-full bg-accent/20 border border-accent/30 flex items-center justify-center text-accent text-xs font-bold shrink-0">
                        {user.name.charAt(0)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <p className="text-xs font-semibold text-foreground truncate">{user.name}</p>
                          {user.status === 'inactive' && (
                            <div className="w-1.5 h-1.5 rounded-full bg-muted-foreground shrink-0" />
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
                        className={`px-3 py-1 rounded border text-xs capitalize transition-all ${
                          selectedUser.role === role ? ROLE_COLORS[role] : 'border-border/50 text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        {role}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Reset Password */}
                <div>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Reset Password</h3>
                  <div className="flex gap-2 max-w-sm">
                    <div className="relative flex-1">
                      <Input
                        type={showResetPassword ? 'text' : 'password'}
                        placeholder="Enter new password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        className="bg-input border-border/50 text-xs h-9 pr-9"
                      />
                      <button
                        type="button"
                        onClick={() => setShowResetPassword(!showResetPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
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
                      className="bg-accent hover:bg-accent/90 text-accent-foreground text-xs h-9 shrink-0"
                    >
                      Update
                    </Button>
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
                          <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 ${
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
              <label className="text-xs text-muted-foreground block mb-1">Password *</label>
              <div className="relative">
                <Input
                  type={showCreatePassword ? 'text' : 'password'}
                  value={newUser.password}
                  onChange={(e) => setNewUser((n) => ({ ...n, password: e.target.value }))}
                  placeholder="••••••••"
                  className="bg-input border-border/50 text-sm pr-9"
                />
                <button
                  type="button"
                  onClick={() => setShowCreatePassword(!showCreatePassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
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
            <Button 
              onClick={addUser} 
              disabled={loading}
              className="w-full bg-accent hover:bg-accent/90 text-accent-foreground mt-2"
            >
              {loading ? 'Adding...' : 'Add User'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
