import type { Metadata } from 'next'
import { InteractiveBackground } from '@/components/ui/InteractiveBackground'
import './globals.css'

export const metadata: Metadata = {
  title: 'Correlic — Know What Your AI Agent Actually Does',
  description:
    'Cursor, Claude Code, and Copilot run with full access to your machine. Correlic monitors every file read, network call, and command at the kernel level — so nothing goes unnoticed.',
  keywords: [
    'AI agent security',
    'AI agent monitoring',
    'AI coding assistant security',
    'Cursor security',
    'Claude Code security',
    'Copilot security monitoring',
    'eBPF observability',
    'kernel telemetry',
    'vibe coding security',
    'AI agent security risks',
  ],
  openGraph: {
    title: 'Correlic — Know What Your AI Agent Actually Does',
    description:
      'Your AI agent reads files, makes network calls, and runs commands with full access. Correlic sees everything — at the kernel level.',
    type: 'website',
    siteName: 'Correlic',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Correlic — Know What Your AI Agent Actually Does',
    description: 'Your AI agent has full access to your machine. Do you know what it\'s doing?',
  },
  robots: { index: true, follow: true },
  icons: {
    icon: '/favicon.png',
    apple: '/favicon.png',
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <meta name="theme-color" content="#0a0612" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <InteractiveBackground />
        {children}
      </body>
    </html>
  )
}
