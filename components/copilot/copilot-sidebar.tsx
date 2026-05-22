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

function parseInlineMarkdown(text: string): React.ReactNode[] {
  const regex = /(\*\*.*?\*\*|`.*?`)/g;
  const parts = text.split(regex);
  
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="font-semibold text-accent">{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} className="px-1 py-0.5 rounded bg-zinc-950/80 font-mono text-[10px] text-accent border border-zinc-800/40">{part.slice(1, -1)}</code>;
    }
    return part;
  });
}

function renderMessageContent(content: string) {
  const parts = content.split(/(```\w*\n[\s\S]*?```)/g);

  return parts.map((part, index) => {
    if (part.startsWith('```')) {
      const match = part.match(/```(\w*)\n([\s\S]*?)```/);
      const language = match ? match[1] : '';
      const code = match ? match[2].trim() : part.replace(/```/g, '').trim();
      return (
        <div key={index} className="my-2 p-2.5 rounded bg-zinc-950 font-mono text-[10px] text-zinc-200 overflow-x-auto border border-zinc-800/80">
          {language && <div className="text-[9px] uppercase text-zinc-500 mb-1 border-b border-zinc-800/50 pb-0.5">{language}</div>}
          <pre className="whitespace-pre">{code}</pre>
        </div>
      );
    } else {
      const lines = part.split('\n');
      return lines.map((line, lineIndex) => {
        const trimmed = line.trim();
        if (!trimmed) {
          return <div key={`${index}-${lineIndex}`} className="h-1.5" />;
        }

        const listMatch = line.match(/^(\s*)(•|\*|-|\d+\.)\s+(.*)/);
        
        if (listMatch) {
          const indent = listMatch[1].length;
          const textContent = listMatch[3];
          const children = parseInlineMarkdown(textContent);
          
          return (
            <div key={`${index}-${lineIndex}`} className="flex items-start gap-1.5 my-1" style={{ paddingLeft: `${indent * 8}px` }}>
              <span className="text-accent/80 select-none font-bold mt-0.5">•</span>
              <span className="flex-1 text-[11px] leading-relaxed">{children}</span>
            </div>
          );
        }

        const children = parseInlineMarkdown(line);
        return (
          <p key={`${index}-${lineIndex}`} className="mb-1 text-[11px] leading-relaxed">
            {children}
          </p>
        );
      });
    }
  });
}

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
          title="Open Iris"
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
              <h2 className="text-xs font-bold text-foreground">Iris</h2>
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
        <ScrollArea className="flex-1 min-h-0 px-3 py-2 [&_[data-slot=scroll-area-viewport]>div]:block!">
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
                  <div className={`flex-1 min-w-0 p-2.5 rounded-lg text-xs leading-relaxed ${
                    msg.role === 'user'
                      ? 'bg-accent/10 border border-accent/30 text-foreground whitespace-pre-wrap'
                      : 'bg-card border border-border/50 text-foreground'
                  }`}>
                    {msg.role === 'user' ? msg.content : renderMessageContent(msg.content)}
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

