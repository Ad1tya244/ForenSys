'use client';

import { useEffect, useRef, useState } from 'react';
import { useCopilotStore } from '@/lib/copilot-store';
import { useAppStore } from '@/lib/app-store';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { ChevronRight, Send, RotateCcw, Bot, Sparkles } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const SUGGESTED_QUESTIONS = [
  'How many critical alerts right now?',
  'Show me open incidents',
  'What\'s the current threat level?',
  'Summarize the attack chain',
  'What are the top at-risk assets?',
  'Avg response time this session',
];

export function CopilotSidebar() {
  const { isOpen, messages, isLoading, toggleSidebar, clearMessages, sendMessage } = useCopilotStore();
  const { alerts, incidents } = useAppStore();
  const [input, setInput] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  const handleSendMessage = async (text: string) => {
    if (!text.trim() || isLoading) return;
    setInput('');
    await sendMessage(text);
  };

  return (
    <>
      {/* Toggle Button when closed */}
      {!isOpen && (
        <motion.button
          initial={{ x: 60, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          onClick={toggleSidebar}
          className="fixed right-4 bottom-6 z-40 p-3 rounded-xl bg-accent/10 border border-accent/40 hover:bg-accent/20 transition-colors group shadow-lg shadow-accent/10"
          title="Open AI Assistant"
        >
          <Bot className="w-5 h-5 text-accent group-hover:animate-pulse" />
        </motion.button>
      )}

      {/* Sidebar */}
      <motion.div
        initial={{ x: 420 }}
        animate={{ x: isOpen ? 0 : 420 }}
        transition={{ type: 'spring', damping: 22, stiffness: 280 }}
        className="fixed right-0 top-0 h-screen w-96 z-50 flex flex-col shadow-2xl shadow-black/50"
        style={{ background: 'hsl(220 15% 9%)', borderLeft: '1px solid hsl(220 13% 18%)' }}
      >
        {/* Header */}
        <div className="p-4 border-b border-border/50 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-accent/20 border border-accent/40 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-accent" />
            </div>
            <div>
              <h2 className="text-xs font-bold text-foreground">Security Assistant</h2>
              <div className="flex items-center gap-1 mt-0.5">
                <div className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
                <span className="text-xs text-muted-foreground">Context-aware · Live data</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" onClick={clearMessages} title="Clear" className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground">
              <RotateCcw className="w-3.5 h-3.5" />
            </Button>
            <Button variant="ghost" size="sm" onClick={toggleSidebar} className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground">
              <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>

        {/* Messages */}
        <ScrollArea className="flex-1 min-h-0 px-3 py-2">
          <div className="space-y-3 pr-1">
            <AnimatePresence>
              {messages.map((msg) => (
                <motion.div
                  key={msg.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className={`flex gap-2 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
                >
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 text-xs font-bold mt-0.5 ${
                    msg.role === 'user' ? 'bg-accent/20 text-accent' : 'bg-primary/20 text-primary'
                  }`}>
                    {msg.role === 'user' ? 'U' : <Sparkles className="w-3.5 h-3.5" />}
                  </div>
                  <div className={`flex-1 p-2.5 rounded-lg text-xs leading-relaxed whitespace-pre-wrap ${
                    msg.role === 'user'
                      ? 'bg-accent/10 border border-accent/30 text-foreground'
                      : 'bg-card border border-border/50 text-foreground'
                  }`}>
                    {msg.content}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>

            {isLoading && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex gap-2">
                <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center shrink-0">
                  <Sparkles className="w-3.5 h-3.5 text-primary" />
                </div>
                <div className="bg-card border border-border/50 rounded-lg p-3 flex gap-1 items-center">
                  {[0, 0.15, 0.3].map((delay, i) => (
                    <div key={i} className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce" style={{ animationDelay: `${delay}s` }} />
                  ))}
                </div>
              </motion.div>
            )}

            <div ref={scrollRef} />
          </div>
        </ScrollArea>

        {/* Suggested Questions */}
        {messages.length <= 1 && !isLoading && (
          <div className="px-3 py-2 border-t border-border/50 space-y-1.5">
            <p className="text-xs text-muted-foreground font-medium">Try asking:</p>
            <div className="grid grid-cols-1 gap-1">
              {SUGGESTED_QUESTIONS.slice(0, 4).map((q, i) => (
                <button
                  key={i}
                  onClick={() => handleSendMessage(q)}
                  className="text-left text-xs p-2 rounded border border-border/40 hover:bg-accent/5 hover:border-accent/30 transition-colors text-muted-foreground hover:text-foreground"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input */}
        <div className="p-3 border-t border-border/50 shrink-0">
          <div className="flex gap-2">
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !isLoading && handleSendMessage(input)}
              placeholder="Ask about incidents, alerts, IOCs..."
              className="bg-input border-border/50 text-xs h-9"
              disabled={isLoading}
            />
            <Button
              onClick={() => handleSendMessage(input)}
              disabled={!input.trim() || isLoading}
              size="sm"
              className="bg-accent hover:bg-accent/90 text-accent-foreground h-9 px-3"
            >
              <Send className="w-3.5 h-3.5" />
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-1.5 text-center">
            Powered by live SOC data · {alerts.length} alerts · {incidents.length} incidents
          </p>
        </div>
      </motion.div>

      {/* Overlay */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={toggleSidebar}
            className="fixed inset-0 bg-black/30 z-40"
          />
        )}
      </AnimatePresence>
    </>
  );
}
