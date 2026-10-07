import { cn } from '@/lib/utils'

interface GlowCardProps extends React.HTMLAttributes<HTMLDivElement> {
  glow?: boolean
  gradient?: boolean
}

export function GlowCard({ className, glow = false, gradient = false, children, ...props }: GlowCardProps) {
  return (
    <div
      className={cn(
        'glass-card p-6 relative overflow-hidden',
        glow && 'animate-pulse-glow',
        gradient && 'border-gradient',
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
}
