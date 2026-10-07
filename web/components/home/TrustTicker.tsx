'use client'

import { ShieldCheck, Gift, MessageSquareText, Zap } from 'lucide-react'

const messages = [
  { icon: ShieldCheck,       text: 'Agent not working? Tell us — we fix it within 24 hours, guaranteed.', accent: '#00e676' },
  { icon: Gift,              text: 'Founding members get up to 90% off all future plans. Locked for life.', accent: '#f59e0b' },
  { icon: MessageSquareText, text: 'Every feedback report is read and tracked. Fixes ship fast.', accent: '#a855f7' },
  { icon: Zap,               text: 'Free during early access. No credit card. No catch.', accent: '#9333ea' },
]

function TickerItem({ icon: Icon, text, accent }: { icon: typeof ShieldCheck; text: string; accent: string }) {
  return (
    <div className="trust-ticker-item flex items-center gap-3 px-6 sm:px-8 shrink-0 select-none group cursor-default">
      {/* Icon pill */}
      <div
        className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0 transition-all duration-300 group-hover:scale-110"
        style={{
          background: `${accent}12`,
          border: `1px solid ${accent}30`,
          boxShadow: `0 0 12px ${accent}15`,
        }}
      >
        <Icon className="w-3.5 h-3.5" style={{ color: accent }} />
      </div>
      {/* Text */}
      <span className="text-sm sm:text-base text-[#c4b5d9] whitespace-nowrap transition-colors duration-300 group-hover:text-[#e8dff5]">
        {text}
      </span>
      {/* Separator dot */}
      <div className="flex items-center gap-1 mx-4 shrink-0">
        <span
          className="w-1 h-1 rounded-full"
          style={{ background: accent, opacity: 0.4 }}
        />
      </div>
    </div>
  )
}

export function TrustTicker() {
  return (
    <div
      className="relative overflow-hidden"
      style={{ marginTop: '5rem' }}
    >
      {/* Top glow line */}
      <div
        className="absolute top-0 left-0 right-0 h-[1px]"
        style={{
          background: 'linear-gradient(90deg, transparent, rgba(147,51,234,0.3), rgba(0,230,118,0.2), rgba(245,158,11,0.2), rgba(147,51,234,0.3), transparent)',
        }}
      />
      {/* Bottom glow line */}
      <div
        className="absolute bottom-0 left-0 right-0 h-[1px]"
        style={{
          background: 'linear-gradient(90deg, transparent, rgba(147,51,234,0.15), transparent)',
        }}
      />

      {/* Background with subtle gradient */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: 'linear-gradient(90deg, rgba(147,51,234,0.03), rgba(0,230,118,0.02), rgba(245,158,11,0.02), rgba(147,51,234,0.03))',
        }}
      />

      {/* Flowing particle on top border */}
      <div
        className="absolute top-[-1px] h-[2px] w-20 rounded-full pointer-events-none z-10"
        style={{
          background: 'linear-gradient(90deg, transparent, #9333ea, transparent)',
          boxShadow: '0 0 12px #9333ea, 0 0 24px rgba(147,51,234,0.4)',
          animation: 'ticker-particle 8s linear infinite',
        }}
      />

      <div className="py-3.5">
        {/* Gradient fades */}
        <div
          className="absolute left-0 top-0 bottom-0 w-20 sm:w-40 z-10 pointer-events-none"
          style={{ background: 'linear-gradient(90deg, rgba(10,6,18,1) 0%, transparent 100%)' }}
        />
        <div
          className="absolute right-0 top-0 bottom-0 w-20 sm:w-40 z-10 pointer-events-none"
          style={{ background: 'linear-gradient(270deg, rgba(10,6,18,1) 0%, transparent 100%)' }}
        />

        {/* Scrolling track */}
        <div className="trust-ticker-track flex items-center">
          {messages.map((m, i) => (
            <TickerItem key={`a-${i}`} icon={m.icon} text={m.text} accent={m.accent} />
          ))}
          {messages.map((m, i) => (
            <TickerItem key={`b-${i}`} icon={m.icon} text={m.text} accent={m.accent} />
          ))}
        </div>
      </div>
    </div>
  )
}
