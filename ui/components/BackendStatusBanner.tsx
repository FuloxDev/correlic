'use client'

import { WifiOff } from 'lucide-react'
import { useBackendUnreachable } from '@/lib/backend-status'

/** Shown whenever an API call fails with a network error or 502/503/504; clears on the next success. */
export default function BackendStatusBanner() {
  const unreachable = useBackendUnreachable()
  if (!unreachable) return null

  return (
    <div
      role="alert"
      className="sticky top-0 z-30 flex items-center gap-2 px-4 py-2 text-sm backdrop-blur-md"
      style={{
        background: 'var(--critical-bg)',
        color: 'var(--critical)',
        borderBottom: '1px solid var(--critical)',
      }}
    >
      <WifiOff className="w-4 h-4 shrink-0" aria-hidden="true" />
      <span>
        <strong>Backend unreachable.</strong> Requests are failing and the data shown may be stale. Retrying automatically.
      </span>
    </div>
  )
}
