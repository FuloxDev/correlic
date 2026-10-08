'use client'

import { ToastProvider } from '@/component/ToastProvider'

export function Providers({ children }: { children: React.ReactNode }) {
  return <ToastProvider>{children}</ToastProvider>
}
