import Image from 'next/image'
import { cn } from '@/lib/utils'

const sizeMap = {
  sm:   { w: 32,  h: 33,  text: 'text-xl',  gap: 'gap-2' },
  md:   { w: 48,  h: 49,  text: 'text-[1.7rem]', gap: 'gap-3' },
  lg:   { w: 80,  h: 82,  text: 'text-4xl', gap: 'gap-4' },
  hero: { w: 250, h: 256, text: 'text-5xl', gap: 'gap-5' },
} as const

interface LogoProps {
  className?: string
  iconOnly?: boolean
  size?: keyof typeof sizeMap
}

export function Logo({ className, iconOnly = false, size = 'md' }: LogoProps) {
  const s = sizeMap[size]

  return (
    <div className={cn('flex items-center', s.gap, className)}>
      <Image
        src="/logo.png"
        alt="Correlic"
        width={s.w}
        height={s.h}
        className="shrink-0"
        priority={size === 'hero'}
      />

      {!iconOnly && (
        <span
          style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          className={cn(s.text, 'font-bold tracking-wide text-[#e8dff5]')}
        >
          CORRE
          <span className="text-[#f59e0b]">LIC</span>
        </span>
      )}
    </div>
  )
}
