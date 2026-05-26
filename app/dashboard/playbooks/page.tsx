'use client';

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { BookOpen, Play, Zap } from 'lucide-react';
import { motion } from 'framer-motion';

// Playbooks array cleared of all pre-existing fake data.
const playbooks: {
  id: string;
  name: string;
  description: string;
  stages: string[];
  successRate: number;
  triggers: string[];
}[] = [];

export default function PlaybooksPage() {
  const [selectedPlaybook, setSelectedPlaybook] = useState<typeof playbooks[0] | null>(playbooks[0] || null);
  const [activeStage, setActiveStage] = useState(0);

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      {/* Header */}
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <BookOpen className="w-6 h-6 text-accent" />
          Attack Playbooks
        </h1>
        <p className="text-muted-foreground">Automated response workflows for common attack patterns</p>
      </div>

      {/* Playbooks Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {playbooks.length === 0 ? (
          <div className="md:col-span-2 glass rounded-lg p-8 border border-border/50 text-center flex flex-col items-center justify-center min-h-[160px]">
            <BookOpen className="w-8 h-8 text-muted-foreground/35 mb-2 animate-pulse" />
            <p className="text-sm font-semibold text-foreground">No Playbooks Configured</p>
            <p className="text-xs text-muted-foreground mt-1">
              There are currently no response playbooks loaded. Define orchestration playbooks to automate responses.
            </p>
          </div>
        ) : (
          playbooks.map((pb, idx) => (
            <motion.div
              key={pb.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.1 }}
              onClick={() => {
                setSelectedPlaybook(pb);
                setActiveStage(0);
              }}
              className={`glass rounded-lg p-4 border cursor-pointer transition-all ${
                selectedPlaybook?.id === pb.id
                  ? 'border-accent bg-accent/10'
                  : 'border-border/50 hover:border-border'
              }`}
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between">
                  <h3 className="font-semibold text-foreground">{pb.name}</h3>
                  <Badge className="bg-accent/20 text-accent border-accent/50">{pb.successRate}%</Badge>
                </div>
                <p className="text-sm text-muted-foreground">{pb.description}</p>
                <div className="flex flex-wrap gap-1">
                  {pb.triggers.map((trigger) => (
                    <Badge key={trigger} variant="outline" className="border-border/50 text-xs">
                      {trigger}
                    </Badge>
                  ))}
                </div>
              </div>
            </motion.div>
          ))
        )}
      </div>

      {/* Playbook Details */}
      {selectedPlaybook && (
        <motion.div
          key={selectedPlaybook.id}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass rounded-lg border border-border/50 p-6 space-y-6"
        >
          <div>
            <h2 className="text-2xl font-bold text-foreground mb-2">{selectedPlaybook.name}</h2>
            <p className="text-muted-foreground">{selectedPlaybook.description}</p>
          </div>

          {/* Stages */}
          <div className="space-y-4">
            <h3 className="font-semibold text-foreground">Execution Stages</h3>
            <div className="space-y-2">
              {selectedPlaybook.stages.map((stage, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.1 }}
                  onClick={() => setActiveStage(idx)}
                  className={`p-4 rounded border cursor-pointer transition-all flex items-center gap-3 ${
                    activeStage === idx
                      ? 'border-accent bg-accent/10'
                      : 'border-border/50 hover:border-border'
                  }`}
                >
                  <div className="w-8 h-8 rounded-full bg-accent/20 text-accent flex items-center justify-center font-semibold text-sm">
                    {idx + 1}
                  </div>
                  <span className="font-semibold text-foreground">{stage}</span>
                  {idx < selectedPlaybook.stages.length - 1 && (
                    <Zap className="w-4 h-4 text-muted-foreground ml-auto" />
                  )}
                </motion.div>
              ))}
            </div>
          </div>

          {/* Stage Details */}
          {selectedPlaybook.stages[activeStage] && (
            <motion.div
              key={activeStage}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="border-t border-border/50 pt-4 space-y-3"
            >
              <h3 className="font-semibold text-foreground">Stage: {selectedPlaybook.stages[activeStage]}</h3>
              <div className="bg-card/50 rounded border border-border/50 p-4 space-y-2">
                <p className="text-sm text-muted-foreground">
                  This stage involves automated actions and analyst approval checkpoints. Manual overrides are available throughout execution.
                </p>
                <div className="flex gap-2">
                  <Button className="flex-1 bg-accent hover:bg-accent/90 text-accent-foreground" size="sm">
                    <Play className="w-4 h-4 mr-2" />
                    Execute
                  </Button>
                  <Button variant="outline" className="flex-1 border-border/50" size="sm">
                    Test Run
                  </Button>
                </div>
              </div>
            </motion.div>
          )}

          {/* Success Rate */}
          <div className="border-t border-border/50 pt-4">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Success Rate</span>
              <div className="flex items-center gap-2">
                <div className="w-32 h-2 bg-card rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${selectedPlaybook.successRate}%` }}
                    transition={{ delay: 0.5, duration: 1 }}
                    className="h-full bg-linear-to-r from-accent to-accent/50"
                  />
                </div>
                <span className="font-semibold text-accent">{selectedPlaybook.successRate}%</span>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
