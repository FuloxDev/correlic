'use client'

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastProvider } from '@/component/ToastProvider'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 60_000, // 60 seconds - data stays fresh for 1 minute
      refetchOnMount: false, // Don't refetch on component mount if data is fresh
      refetchOnReconnect: false, // Don't refetch on reconnect if data is fresh
    },
  },
})

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>
  )
}
