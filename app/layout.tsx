import type { Metadata } from 'next'
import { Geist, Geist_Mono } from 'next/font/google'
import { Analytics } from '@vercel/analytics/next'
import { Toaster } from 'sonner'
import './globals.css'

const _geist = Geist({ subsets: ["latin"] });
const _geistMono = Geist_Mono({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: 'FORENSYS - Forensic-Safe Endpoint Detection & Automated SOC Response Platform',
  description: 'Forensic-safe endpoint detection and automated SOC response: real-time detection, logical containment and preserved forensic evidence',
  keywords: ['SOC', 'SIEM', 'cybersecurity', 'forensics', 'threat intelligence', 'incident response'],
  icons: {
    icon: [
      {
        url: '/icon.svg',
        type: 'image/svg+xml',
      },
    ],
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body className="font-sans antialiased bg-background text-foreground">
        {children}
        <Toaster
          theme="dark"
          position="bottom-right"
          toastOptions={{
            style: {
              background: 'hsl(220 13% 12%)',
              border: '1px solid hsl(220 13% 18%)',
              color: 'hsl(0 0% 98%)',
            },
          }}
        />
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
