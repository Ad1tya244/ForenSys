'use client';

import Link from 'next/link';
import { ShieldAlert, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';

interface AccessDeniedProps {
  permission?: string;
  message?: string;
}

export function AccessDenied({ permission, message }: AccessDeniedProps) {
  const displayMessage = message || (permission 
    ? `You do not have the required permission (${permission}) to view this resource.`
    : "You do not have permission to access this resource.");

  return (
    <div className="flex-1 flex flex-col items-center justify-center p-6 min-h-[70vh]">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.4 }}
        className="max-w-md w-full glass border border-red-500/20 rounded-xl p-8 text-center flex flex-col items-center shadow-[0_0_50px_rgba(239,68,68,0.05)] relative overflow-hidden"
      >
        {/* Glow effect */}
        <div className="absolute -top-12 -left-12 w-24 h-24 bg-red-500/10 rounded-full blur-2xl" />
        <div className="absolute -bottom-12 -right-12 w-24 h-24 bg-red-500/10 rounded-full blur-2xl" />

        {/* Pulsing red ShieldAlert icon */}
        <motion.div
          animate={{ 
            boxShadow: [
              "0 0 0 0 rgba(239, 68, 68, 0.4)",
              "0 0 0 12px rgba(239, 68, 68, 0)",
            ]
          }}
          transition={{
            repeat: Infinity,
            duration: 2,
            ease: "easeInOut"
          }}
          className="w-16 h-16 rounded-full bg-red-950/40 border border-red-500/50 flex items-center justify-center text-red-500 mb-6 shrink-0"
        >
          <ShieldAlert className="w-8 h-8" />
        </motion.div>

        {/* Title */}
        <h2 className="text-xl font-bold text-foreground tracking-wide uppercase mb-2">
          Access Denied
        </h2>

        {/* Description */}
        <p className="text-sm text-muted-foreground mb-6 leading-relaxed">
          {displayMessage}
        </p>

        {/* Action Button */}
        <Link href="/dashboard" passHref>
          <Button variant="outline" className="border-border/50 hover:bg-white/5 text-xs gap-2">
            <ArrowLeft className="w-3.5 h-3.5" /> Return to Dashboard
          </Button>
        </Link>
      </motion.div>
    </div>
  );
}
