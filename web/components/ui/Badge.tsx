import { cn } from '@/lib/utils'
import { cva, type VariantProps } from 'class-variance-authority'

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold tracking-wide border',
  {
    variants: {
      variant: {
        critical: 'bg-[rgba(255,59,92,0.12)] border-[rgba(255,59,92,0.3)] text-[#ff3b5c]',
        high:     'bg-[rgba(255,122,47,0.12)] border-[rgba(255,122,47,0.3)] text-[#ff7a2f]',
        medium:   'bg-[rgba(240,200,0,0.12)] border-[rgba(240,200,0,0.3)] text-[#f0c800]',
        low:      'bg-[rgba(0,230,118,0.12)] border-[rgba(0,230,118,0.3)] text-[#00e676]',
        accent:   'bg-[rgba(147,51,234,0.12)] border-[rgba(147,51,234,0.25)] text-[#9333ea]',
        muted:    'bg-[rgba(107,90,128,0.12)] border-[rgba(107,90,128,0.3)] text-[#6b5a80]',
        new:      'bg-[rgba(147,51,234,0.2)] border-[#9333ea] text-[#9333ea]',
      },
    },
    defaultVariants: { variant: 'accent' },
  }
)

interface BadgeProps extends React.HTMLAttributes<'span'>, VariantProps<typeof badgeVariants> {
  dot?: boolean
}

export function Badge({ className, variant, dot = false, children, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...(props as React.HTMLAttributes<HTMLSpanElement>)}>
      {dot && (
        <span
          className="w-1.5 h-1.5 rounded-full bg-current"
          style={{ animation: variant === 'critical' ? 'pulse-glow 2s infinite' : undefined }}
        />
      )}
      {children}
    </span>
  )
}
