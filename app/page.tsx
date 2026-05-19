'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    router.push('/dashboard');
  }, [router]);

  return (
    <div className="w-full h-screen flex items-center justify-center bg-background">
      <div className="text-center space-y-4">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-accent/20 rounded-full">
          <div className="w-2 h-2 bg-accent rounded-full animate-pulse" />
        </div>
        <p className="text-foreground">Initializing FORENSYS...</p>
      </div>
    </div>
  );
}
