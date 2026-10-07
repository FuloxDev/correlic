import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Get Early Access — Correlic',
  description: 'Join the waitlist for Correlic — AI agent security monitoring built on eBPF.',
}

export default function RegisterLayout({ children }: { children: React.ReactNode }) {
  return children
}
