import type { Metadata } from 'next'
import { IBM_Plex_Sans, Inter, JetBrains_Mono, Space_Grotesk } from 'next/font/google'
import './globals.css'
import { Providers } from './providers'
import { DEFAULT_FONT, DEFAULT_THEME, appearanceBootScript, fontSlug } from '@/lib/appearance'

// Self-hosted at build time by next/font: no runtime request to Google.
const inter = Inter({ subsets: ['latin'], variable: '--font-inter', display: 'swap' })
const spaceGrotesk = Space_Grotesk({ subsets: ['latin'], variable: '--font-space-grotesk', display: 'swap' })
const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jetbrains-mono', display: 'swap' })
const ibmPlexSans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['300', '400', '500', '600', '700'],
  variable: '--font-ibm-plex-sans',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'Correlic',
  description: 'Correlic security dashboard',
}

const fontClasses = [inter.variable, spaceGrotesk.variable, jetbrainsMono.variable, ibmPlexSans.variable].join(' ')

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html
      lang="en"
      className={`dark ${fontClasses}`}
      data-theme={DEFAULT_THEME}
      data-font={fontSlug(DEFAULT_FONT)}
      suppressHydrationWarning
    >
      <head>
        {/* Applies the stored theme/font before first paint; same tables as the picker. */}
        <script dangerouslySetInnerHTML={{ __html: appearanceBootScript() }} />
      </head>
      <body className="bg-background text-foreground">
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
