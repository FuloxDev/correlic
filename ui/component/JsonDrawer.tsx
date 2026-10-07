'use client'

import { useState } from 'react'

interface JsonDrawerProps {
  data: unknown
  defaultExpanded?: boolean
}

export function JsonDrawer({ data, defaultExpanded = false }: JsonDrawerProps) {
  const [expanded, setExpanded] = useState(defaultExpanded)

  if (data === null || data === undefined) {
    return (
      <span 
        className="text-sm italic"
        style={{ color: 'var(--foreground-subtle)' }}
      >
        null
      </span>
    )
  }

  const formatted = JSON.stringify(data, null, 2)
  const isLong = formatted.length > 200 || formatted.includes('\n')

  if (!isLong) {
    return (
      <pre 
        className="text-xs font-mono p-3 rounded-lg overflow-auto"
        style={{ 
          background: 'var(--background-tertiary)',
          color: 'var(--foreground-muted)',
          maxHeight: '200px'
        }}
      >
        {formatted}
      </pre>
    )
  }

  return (
    <div>
      <button
        className="flex items-center gap-2 text-xs font-medium mb-2 transition-colors"
        style={{ color: 'var(--accent)' }}
        onClick={() => setExpanded(!expanded)}
      >
        <svg 
          className="w-4 h-4 transition-transform" 
          fill="none" 
          viewBox="0 0 24 24" 
          stroke="currentColor"
          style={{ transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)' }}
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        {expanded ? 'Collapse' : 'Expand'} JSON
      </button>
      {expanded && (
        <div className="relative">
          <pre 
            className="text-xs font-mono p-3 rounded-lg overflow-auto animate-fade-in"
            style={{ 
              background: 'var(--background-tertiary)',
              color: 'var(--foreground-muted)',
              maxHeight: '400px'
            }}
          >
            {formatted}
          </pre>
          <button
            className="absolute top-2 right-2 p-1.5 rounded transition-colors"
            style={{ 
              background: 'var(--background-secondary)',
              color: 'var(--foreground-muted)'
            }}
            onClick={() => navigator.clipboard.writeText(formatted)}
            title="Copy to clipboard"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
            </svg>
          </button>
        </div>
      )}
    </div>
  )
}
