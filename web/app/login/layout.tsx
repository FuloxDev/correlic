import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Sign In — Correlic',
  description: 'Sign in to your Correlic account to access your security dashboard.',
}

export default function LoginLayout({ children }: { children: React.ReactNode }) {
  return children
}
