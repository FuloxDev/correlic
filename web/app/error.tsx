'use client'

import { Button } from '@/components/ui/Button'

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4 text-center">
      <div className="glass-card p-10 max-w-md space-y-5">
        <div className="w-14 h-14 mx-auto rounded-full bg-[rgba(255,59,92,0.1)] border border-[rgba(255,59,92,0.2)] flex items-center justify-center">
          <span className="text-2xl text-[#ff3b5c]">!</span>
        </div>
        <h2
          className="text-xl font-bold text-[#e8dff5]"
          style={{ fontFamily: "'Space Grotesk', sans-serif" }}
        >
          Something went wrong
        </h2>
        <p className="text-sm text-[#c4b5d9]">
          {error.message || 'An unexpected error occurred.'}
        </p>
        <Button variant="outline" size="sm" onClick={reset}>
          Try again
        </Button>
      </div>
    </div>
  )
}
