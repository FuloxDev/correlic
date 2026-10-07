'use client'

import { useState } from 'react'
import type { IdentityRecord } from '@/lib/types'

interface IdentityGroupProps {
  kind: string
  records: IdentityRecord[]
}

export function IdentityGroup({ kind, records }: IdentityGroupProps) {
  const [expanded, setExpanded] = useState(true)

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div 
      className="rounded-lg overflow-hidden"
      style={{ border: '1px solid var(--border)' }}
    >
      <button
        className="w-full flex items-center justify-between p-4 transition-colors"
        style={{ background: 'var(--background-tertiary)' }}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <svg 
            className="w-4 h-4 transition-transform" 
            fill="none" 
            viewBox="0 0 24 24" 
            stroke="currentColor"
            style={{ 
              color: 'var(--foreground-muted)',
              transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)' 
            }}
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <span 
            className="font-medium"
            style={{ color: 'var(--foreground)' }}
          >
            {kind}
          </span>
          <span 
            className="text-xs px-2 py-0.5 rounded"
            style={{ background: 'var(--accent-muted)', color: 'var(--accent)' }}
          >
            {records.length}
          </span>
        </div>
      </button>

      {expanded && (
        <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
          {records.map((record, idx) => (
            <div 
              key={idx} 
              className="p-4 transition-colors hover:bg-[var(--background-tertiary)]"
              style={{ background: 'var(--background-secondary)' }}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span 
                      className="font-mono text-sm break-all"
                      style={{ color: 'var(--foreground)' }}
                    >
                      {record.value}
                    </span>
                    <button
                      className="p-1 rounded transition-colors flex-shrink-0"
                      style={{ color: 'var(--foreground-muted)' }}
                      onClick={() => copyToClipboard(record.value)}
                      title="Copy to clipboard"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
                      </svg>
                    </button>
                  </div>
                  <div className="flex items-center gap-4 mt-2 text-xs" style={{ color: 'var(--foreground-muted)' }}>
                    <span>
                      First seen: {new Date(record.first_seen_at).toLocaleString()}
                    </span>
                    <span>
                      Last seen: {new Date(record.last_seen_at).toLocaleString()}
                    </span>
                    <span 
                      className="px-1.5 py-0.5 rounded"
                      style={{ background: 'var(--background-tertiary)' }}
                    >
                      {record.seen_count} events
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
