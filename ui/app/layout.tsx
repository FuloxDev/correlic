import './globals.css'
import { Providers } from './providers'
import { AppShell } from '@/component/AppShell'

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
        <script dangerouslySetInnerHTML={{ __html: `
          (function(){
            try {
              var t = localStorage.getItem('correlix-theme') || 'correlic-purple';
              document.documentElement.setAttribute('data-theme', t);
              var f = localStorage.getItem('correlix-font') || 'Space Grotesk';
              document.documentElement.style.setProperty('--active-font', f);
            } catch(e){}
          })();
        `}} />
      </head>
      <body className="bg-background text-foreground">
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  )
}
