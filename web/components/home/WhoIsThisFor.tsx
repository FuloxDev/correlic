'use client'

import { motion } from 'framer-motion'
import { Code2, Users, ShieldCheck } from 'lucide-react'

const audiences = [
  {
    icon: Code2,
    color: '#f59e0b',
    title: 'For Individual Developers',
    desc: 'See what your AI agent does on your machine. Every file it reads, every connection it makes. Free forever for personal use.',
    cta: 'Know what your agent is doing',
  },
  {
    icon: Users,
    color: '#9333ea',
    title: 'For Engineering Teams',
    desc: 'Monitor AI agent activity across your team. Shared dashboard, detection policies, and behavioral baselines. Ship fast with AI — safely.',
    cta: 'Visibility across your team',
  },
  {
    icon: ShieldCheck,
    color: '#00e676',
    title: 'For Security & Compliance',
    desc: 'Full audit trail of every AI agent action. Incident investigation, MITRE ATT&CK mapping, and compliance-ready reporting.',
    cta: 'Audit trail for AI agents',
  },
]

export function WhoIsThisFor() {
  return (
    <section className="py-28 relative">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse 50% 40% at 80% 50%, rgba(147,51,234,0.04) 0%, transparent 60%), radial-gradient(ellipse 40% 30% at 20% 50%, rgba(0,230,118,0.03) 0%, transparent 60%)',
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
            Built For You
          </span>
          <h2
            className="mt-3 text-3xl sm:text-4xl font-bold text-[#e8dff5]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            Whether You Code Solo or Lead a Team
          </h2>
          <p className="mt-4 text-[#c4b5d9] max-w-xl mx-auto">
            Correlic adapts to how you work — from individual vibe-coders to enterprise security teams.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {audiences.map((a, i) => {
            const Icon = a.icon
            return (
              <motion.div
                key={a.title}
                className="relative p-7 rounded-xl group hover:translate-y-[-4px] transition-all duration-300 overflow-hidden"
                style={{
                  background: 'rgba(18, 10, 36, 0.7)',
                  border: `1px solid ${a.color}20`,
                  boxShadow: `0 0 20px ${a.color}08`,
                  backdropFilter: 'blur(12px)',
                }}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
              >
                {/* Top accent */}
                <div
                  className="absolute top-0 left-0 right-0 h-[2px]"
                  style={{
                    background: `linear-gradient(90deg, transparent, ${a.color}70, transparent)`,
                  }}
                />
                {/* Corner glow */}
                <div
                  className="absolute top-0 left-0 w-32 h-32 pointer-events-none opacity-60 group-hover:opacity-100 transition-opacity duration-500"
                  style={{
                    background: `radial-gradient(circle at 0% 0%, ${a.color}10, transparent 70%)`,
                  }}
                />

                <div
                  className="w-14 h-14 rounded-xl flex items-center justify-center mb-5 relative"
                  style={{
                    background: `linear-gradient(135deg, ${a.color}18, ${a.color}05)`,
                    border: `1px solid ${a.color}35`,
                    boxShadow: `0 0 20px ${a.color}18`,
                  }}
                >
                  <Icon
                    className="w-7 h-7"
                    style={{
                      color: a.color,
                      filter: `drop-shadow(0 0 8px ${a.color}50)`,
                    }}
                  />
                </div>

                <h3
                  className="text-lg font-bold text-[#e8dff5] mb-3 relative"
                  style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                >
                  {a.title}
                </h3>
                <p className="text-sm text-[#c4b5d9] leading-relaxed relative mb-4">
                  {a.desc}
                </p>
                <p
                  className="text-xs font-semibold relative"
                  style={{ color: a.color }}
                >
                  {a.cta} →
                </p>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
