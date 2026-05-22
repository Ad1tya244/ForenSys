'use client';

import { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Save, Bell, Shield, Link2, Sliders } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useAppStore } from '@/lib/app-store';
import { motion } from 'framer-motion';
import { toast } from 'sonner';

export default function SettingsPage() {
  const { settings, updateSettings } = useAppStore();
  const [localSettings, setLocalSettings] = useState({ ...settings });
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (!dirty) {
      setLocalSettings({ ...settings });
    }
  }, [settings, dirty]);

  const update = (patch: Partial<typeof localSettings>) => {
    setLocalSettings((s) => ({ ...s, ...patch }));
    setDirty(true);
  };

  const updateProfile = (field: 'name' | 'email' | 'role', value: string) => {
    setLocalSettings((s) => ({
      ...s,
      profile: {
        ...(s.profile || { name: '', email: '', role: '' }),
        [field]: value,
      },
    }));
    setDirty(true);
  };

  const save = () => {
    updateSettings(localSettings);
    setDirty(false);
    toast.success('Settings saved', { description: 'Your configuration has been updated.' });
  };

  const toggleIntegration = (name: string) => {
    const integrations = localSettings.integrations || [];
    const updated = integrations.map((i) =>
      i.name === name ? { ...i, connected: !i.connected } : i
    );
    update({ integrations: updated });
    const isCurrentlyConnected = integrations.find((i) => i.name === name)?.connected;
    toast.info(`${name} ${!isCurrentlyConnected ? 'connected' : 'disconnected'}`);
  };

  const profile = localSettings.profile || { name: '', email: '', role: '' };

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <SettingsIcon className="w-6 h-6 text-accent" />
            Settings
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Configure platform preferences and integrations</p>
        </div>
        {dirty && (
          <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}>
            <Button onClick={save} className="bg-accent hover:bg-accent/90 text-accent-foreground gap-2">
              <Save className="w-4 h-4" /> Save Changes
            </Button>
          </motion.div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Profile */}
        <Card className="bg-card border-border/50 p-5 space-y-4">
          <div className="flex items-center gap-2 mb-1">
            <Shield className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold text-foreground">Profile</h2>
          </div>
          <div className="space-y-3">
            {[
              { label: 'Display Name', key: 'name' as const },
              { label: 'Email', key: 'email' as const },
              { label: 'Role', key: 'role' as const },
            ].map((field) => (
              <div key={field.key}>
                <label className="text-xs text-muted-foreground block mb-1">{field.label}</label>
                <input
                  type="text"
                  value={profile[field.key]}
                  onChange={(e) => updateProfile(field.key, e.target.value)}
                  className="w-full bg-input border border-border/50 rounded-md px-3 py-2 text-sm text-foreground outline-none focus:border-accent/50 transition-colors"
                />
              </div>
            ))}
          </div>
        </Card>

        {/* Notifications */}
        <Card className="bg-card border-border/50 p-5 space-y-4">
          <div className="flex items-center gap-2 mb-1">
            <Bell className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold text-foreground">Notifications</h2>
          </div>
          <div className="space-y-2">
            {[
              { key: 'notifyOnCritical' as const, label: 'Critical Alert Notifications', desc: 'Immediate push for severity: critical' },
              { key: 'notifyOnHigh' as const, label: 'High Alert Notifications', desc: 'Push notifications for high severity' },
              { key: 'dailySummary' as const, label: 'Daily Digest Email', desc: 'Receive daily SOC summary at 08:00' },
            ].map((notif) => {
              const checked = !!localSettings[notif.key];
              return (
                <div key={notif.key} className="flex items-center justify-between p-3 bg-card/50 rounded border border-border/50">
                  <div>
                    <p className="text-xs font-medium text-foreground">{notif.label}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{notif.desc}</p>
                  </div>
                  <button
                    onClick={() => update({ [notif.key]: !checked })}
                    className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${
                      checked ? 'bg-accent' : 'bg-muted'
                    }`}
                  >
                    <div
                      className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ${
                        checked ? 'translate-x-5' : 'translate-x-0.5'
                      }`}
                    />
                  </button>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Alert Thresholds */}
        <Card className="bg-card border-border/50 p-5 space-y-4">
          <div className="flex items-center gap-2 mb-1">
            <Sliders className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold text-foreground">Alert Thresholds</h2>
          </div>
          <div className="space-y-4">
            {[
              { key: 'criticalThreshold' as const, label: 'Critical Threshold', color: 'bg-red-500', textColor: 'text-red-400', glowColor: 'rgba(239, 68, 68, 0.4)' },
              { key: 'highThreshold' as const, label: 'High Threshold', color: 'bg-orange-500', textColor: 'text-orange-400', glowColor: 'rgba(249, 115, 22, 0.4)' },
              { key: 'mediumThreshold' as const, label: 'Medium Threshold', color: 'bg-yellow-500', textColor: 'text-yellow-400', glowColor: 'rgba(234, 179, 8, 0.4)' },
            ].map((threshold) => {
              const value = localSettings[threshold.key] ?? 50;
              return (
                <div key={threshold.key} className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs text-muted-foreground">{threshold.label}</label>
                    <span className={`text-xs font-bold font-mono ${threshold.textColor}`}>
                      {value}%
                    </span>
                  </div>

                  <div className="relative w-full h-6 flex items-center">
                    {/* Custom Track Background */}
                    <div className="w-full h-2 bg-muted/30 rounded-full overflow-hidden border border-border/10">
                      <div
                        className={`h-full ${threshold.color} rounded-full`}
                        style={{ width: `${value}%` }}
                      />
                    </div>

                    {/* Custom Thumb */}
                    <div
                      className="absolute w-4 h-4 rounded-full border-2 border-background shadow-lg transition-all pointer-events-none -ml-2"
                      style={{
                        left: `${value}%`,
                        backgroundColor: threshold.key === 'criticalThreshold' ? '#ef4444' : threshold.key === 'highThreshold' ? '#f97316' : '#eab308',
                        boxShadow: `0 0 10px ${threshold.glowColor}, 0 2px 4px rgba(0, 0, 0, 0.5)`
                      }}
                    />

                    {/* Invisible Slider Input Overlaid on Top */}
                    <input
                      type="range"
                      min={0}
                      max={100}
                      value={value}
                      onChange={(e) => update({ [threshold.key]: parseInt(e.target.value) })}
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Integrations */}
        <Card className="bg-card border-border/50 p-5 space-y-4">
          <div className="flex items-center gap-2 mb-1">
            <Link2 className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold text-foreground">Integrations</h2>
          </div>
          <div className="space-y-2">
            {(localSettings.integrations || []).map((integration) => (
              <div key={integration.name} className="flex items-center justify-between p-3 bg-card/50 rounded border border-border/50">
                <div className="flex items-center gap-2.5">
                  <div className={`w-2 h-2 rounded-full ${integration.connected ? 'bg-green-500' : 'bg-muted-foreground'}`} />
                  <span className="text-sm text-foreground">{integration.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge
                    className={integration.connected
                      ? 'bg-green-900/30 text-green-300 border-green-700/50'
                      : 'bg-muted/30 text-muted-foreground border-border/50'
                    }
                  >
                    {integration.connected ? 'Connected' : 'Disconnected'}
                  </Badge>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs border border-border/50"
                    onClick={() => toggleIntegration(integration.name)}
                  >
                    {integration.connected ? 'Disconnect' : 'Connect'}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Save footer */}
      <div className="flex justify-end pt-2">
        <Button onClick={save} className="bg-accent hover:bg-accent/90 text-accent-foreground gap-2">
          <Save className="w-4 h-4" /> Save All Settings
        </Button>
      </div>
    </div>
  );
}
