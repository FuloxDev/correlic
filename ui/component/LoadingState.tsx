'use client'

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div 
      className="flex flex-col items-center justify-center py-20"
      style={{ color: 'var(--foreground-muted)' }}
    >
      <div className="relative">
        {/* Outer ring */}
        <div 
          className="w-12 h-12 rounded-full border-2 opacity-20"
          style={{ borderColor: 'var(--accent)' }}
        />
        {/* Spinning arc */}
        <div 
          className="absolute inset-0 w-12 h-12 rounded-full border-2 border-transparent animate-spin"
          style={{ 
            borderTopColor: 'var(--accent)',
            borderRightColor: 'var(--accent)'
          }}
        />
        {/* Inner glow */}
        <div 
          className="absolute inset-2 rounded-full animate-pulse-glow"
          style={{ background: 'var(--accent-muted)' }}
        />
      </div>
      <p className="mt-4 text-sm font-medium">{label}</p>
    </div>
  )
}
