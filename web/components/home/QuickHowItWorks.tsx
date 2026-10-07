'use client'

import { motion } from 'framer-motion'
import { Terminal, Eye, Shield } from 'lucide-react'

const steps = [
  {
    icon: Terminal,
    color: '#9333ea',
    step: '1',
    title: 'Install the agent',
    desc: 'One command. 30 seconds. Runs silently in the background — no config needed.',
  },
  {
    icon: Eye,
    color: '#00e676',
    step: '2',
    title: 'Use your AI tools normally',
    desc: 'Cursor, Claude Code, Copilot — keep working exactly as you do. Nothing changes.',
  },
  {
    icon: Shield,
    color: '#f59e0b',
    step: '3',
    title: 'See everything your agent did',
    desc: 'Every file read, network call, and command — with real-time threat detection and alerts.',
  },
]

export function QuickHowItWorks() {
  return (
    <section id="how-it-works-summary" className="py-28 relative">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse 60% 40% at 50% 50%, rgba(147,51,234,0.05) 0%, transparent 70%)',
        }}
      />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          className="text-center mb-16"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <span className="text-xs font-semibold text-[#9333ea] uppercase tracking-widest">
            Get Started
          </span>
          <h2
            className="mt-3 text-3xl sm:text-4xl font-bold text-[#e8dff5]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            Up and Running in 3 Steps
          </h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {steps.map((s, i) => {
            const Icon = s.icon
            return (
              <motion.div
                key={s.step}
                className="relative p-7 rounded-xl text-center group hover:translate-y-[-4px] transition-all duration-300"
                style={{
                  background: 'rgba(18, 10, 36, 0.7)',
                  border: `1px solid ${s.color}20`,
                  boxShadow: `0 0 20px ${s.color}08`,
                  backdropFilter: 'blur(12px)',
                }}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.12 }}
              >
                {/* Top accent */}
                <div
                  className="absolute top-0 left-0 right-0 h-[2px]"
                  style={{
                    background: `linear-gradient(90deg, transparent, ${s.color}60, transparent)`,
                  }}
                />

                {/* Step number */}
                <div
                  className="w-10 h-10 rounded-full flex items-center justify-center mx-auto mb-5 text-sm font-bold"
                  style={{
                    background: `${s.color}15`,
                    border: `1.5px solid ${s.color}40`,
                    color: s.color,
                    boxShadow: `0 0 16px ${s.color}20`,
                  }}
                >
                  {s.step}
                </div>

                <div
                  className="w-14 h-14 rounded-xl flex items-center justify-center mx-auto mb-5"
                  style={{
                    background: `linear-gradient(135deg, ${s.color}15, ${s.color}05)`,
                    border: `1px solid ${s.color}30`,
                    boxShadow: `0 0 20px ${s.color}15`,
                  }}
                >
                  <Icon
                    className="w-7 h-7"
                    style={{
                      color: s.color,
                      filter: `drop-shadow(0 0 8px ${s.color}50)`,
                    }}
                  />
                </div>

                <h3
                  className="text-lg font-bold text-[#e8dff5] mb-3"
                  style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                >
                  {s.title}
                </h3>
                <p className="text-sm text-[#c4b5d9] leading-relaxed">{s.desc}</p>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
