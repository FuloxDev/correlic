'use client'

import { motion } from 'framer-motion'
import { ShieldCheck, Network, Activity, Key, Clock, Shield, GitBranch } from 'lucide-react'
import Link from 'next/link'
import { Button } from '@/components/ui/Button'

const stats = [
  { value: '<100ms', label: 'Kernel to finding', color: '#9333ea' },
  { value: '~90%',   label: 'Noise reduction',   color: '#00e676' },
  { value: '3',      label: 'Platforms',          color: '#f0c800' },
  { value: 'BYOK',   label: 'Your LLM keys',     color: '#a855f7' },
]

const principles = [
  {
    icon: ShieldCheck,
    color: '#9333ea',
    title: 'Security-First Sampling',
    description:
      'AI agent events bypass sampling entirely. Suspicious patterns are always kept. Security is never sacrificed for performance — every meaningful event reaches your detection engine.',
  },
  {
    icon: Network,
    color: '#00e676',
    title: 'Correlation at Core',
    description:
      'Dual-database architecture: PostgreSQL for time-series events, Neo4j for process relationship graphs. Every event is mapped by agent session and process ID — this is what Correlic is named for.',
  },
  {
    icon: Activity,
    color: '#f0c800',
    title: 'Behavioral Learning',
    description:
      'The system learns what\'s normal for each AI agent and adapts over time. Manually baseline expected behavior or let auto-learning handle it. Noise decreases continuously while threat visibility stays complete.',
  },
  {
    icon: Key,
    color: '#a855f7',
    title: 'BYOK Privacy',
    description:
      'Bring your own LLM API key for AI-powered analysis. Your data never leaves your infrastructure. Keys encrypted with AES-256-GCM — we never see them.',
  },
]

const whyItems = [
  {
    icon: Clock,
    color: '#a855f7',
    title: 'Catches Slow Attacks Other Tools Miss',
    description:
      'Most tools only see the last few minutes. Correlic tracks agent behavior from 1-minute snapshots to yearly trends — catching threats that unfold over days or weeks, not just fast bursts.',
  },
  {
    icon: Shield,
    color: '#ff7a2f',
    title: 'Zero Noise From Background Processes',
    description:
      'Detection rules only fire on AI agent activity. System daemons and human actions never trigger alerts — so every finding is worth your attention. No tuning required.',
  },
  {
    icon: GitBranch,
    color: '#ff3b5c',
    title: 'Connects the Dots Across Attacks',
    description:
      'A single file read is a data point. Credential theft followed by exfiltration is a threat. Correlic links individual events into multi-step attack patterns automatically — so you see the full picture, not isolated alerts.',
  },
]

const containerVariants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.1 } },
}

const itemVariants = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: 'easeOut' as const } },
}

export function AboutSection() {
  return (
    <section id="about" className="py-32 relative">
      {/* Background accents */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse 50% 40% at 15% 30%, rgba(147,51,234,0.05) 0%, transparent 60%), radial-gradient(ellipse 40% 30% at 85% 70%, rgba(168,85,247,0.04) 0%, transparent 60%)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        {/* ── Top: Mission + Stats ──────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 lg:gap-20 items-start">
          {/* Left — mission */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="space-y-10"
          >
            <div>
              <span className="text-xs font-semibold text-[#9333ea] uppercase tracking-widest">
                Mission
              </span>
              <h2
                className="mt-4 text-3xl sm:text-4xl lg:text-5xl font-bold text-[#e8dff5] leading-[1.15]"
                style={{ fontFamily: "'Space Grotesk', sans-serif" }}
              >
                AI Agents Are Powerful.
                <br />
                <span className="text-gradient">That&apos;s the Problem.</span>
              </h2>
              <p className="mt-6 text-base sm:text-lg text-[#c4b5d9] leading-relaxed">
                AI agents like Cursor, Claude Code, and Copilot run on your machine with
                shell access, network access, and file access. They can read your SSH keys,
                hit unexpected endpoints, modify CI configs, and escalate privileges — often
                in ways that look completely benign to traditional security tools.
              </p>
              <p className="mt-4 text-base sm:text-lg text-[#c4b5d9] leading-relaxed">
                Correlic was built to close that gap. We hook directly into your OS kernel —
                eBPF on Linux, ETW on Windows, kqueue on macOS — and understand what AI agents
                are <span className="text-[#e8dff5] font-medium">actually doing</span>, not just what they claim to be doing.
              </p>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {stats.map((s) => (
                <div
                  key={s.label}
                  className="relative px-4 py-5 rounded-xl text-center overflow-hidden transition-all duration-300 group hover:scale-[1.03]"
                  style={{
                    background: 'rgba(18, 10, 36, 0.7)',
                    border: `1px solid ${s.color}25`,
                    boxShadow: `0 0 20px ${s.color}08`,
                  }}
                >
                  {/* Top accent */}
                  <div
                    className="absolute top-0 left-0 right-0 h-[2px]"
                    style={{ background: `linear-gradient(90deg, transparent, ${s.color}60, transparent)` }}
                  />
                  <div
                    className="text-xl sm:text-2xl font-bold mb-1.5 truncate"
                    style={{
                      fontFamily: "'Space Grotesk', sans-serif",
                      color: s.color,
                      filter: `drop-shadow(0 0 10px ${s.color}40)`,
                    }}
                  >
                    {s.value}
                  </div>
                  <div className="text-[11px] text-[#6b5a80] group-hover:text-[#c4b5d9] transition-colors">{s.label}</div>
                </div>
              ))}
            </div>

            <div className="flex gap-4 flex-wrap">
              <Link href="/register">
                <Button variant="primary" size="lg">Claim Your Spot</Button>
              </Link>
              <Link href="/feedback">
                <Button variant="outline" size="lg">Send Feedback</Button>
              </Link>
            </div>
          </motion.div>

          {/* Right — principles */}
          <motion.div
            variants={containerVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            className="space-y-5"
          >
            <h3 className="text-sm font-semibold text-[#6b5a80] uppercase tracking-widest mb-8">
              Design Principles
            </h3>
            {principles.map((p) => {
              const Icon = p.icon
              return (
                <motion.div
                  key={p.title}
                  variants={itemVariants}
                  className="p-5 lg:p-6 flex gap-5 relative overflow-hidden rounded-xl transition-all duration-300 group hover:translate-y-[-2px]"
                  style={{
                    background: 'rgba(18, 10, 36, 0.7)',
                    border: `1px solid ${p.color}20`,
                    boxShadow: `0 0 15px ${p.color}06`,
                    backdropFilter: 'blur(12px)',
                  }}
                >
                  {/* Left accent bar with gradient */}
                  <div
                    className="absolute left-0 top-0 bottom-0 w-[3px] transition-all duration-300"
                    style={{ background: `linear-gradient(180deg, transparent, ${p.color}, transparent)` }}
                  />
                  {/* Hover glow */}
                  <div
                    className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
                    style={{ background: `radial-gradient(ellipse 60% 80% at 0% 50%, ${p.color}08, transparent 70%)` }}
                  />

                  <div
                    className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0 relative"
                    style={{
                      background: `linear-gradient(135deg, ${p.color}15, ${p.color}05)`,
                      border: `1px solid ${p.color}30`,
                      boxShadow: `0 0 16px ${p.color}15`,
                    }}
                  >
                    <Icon className="w-6 h-6" style={{ color: p.color, filter: `drop-shadow(0 0 6px ${p.color}50)` }} />
                  </div>
                  <div className="relative">
                    <h4
                      className="text-base font-semibold text-[#e8dff5] mb-1.5"
                      style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                    >
                      {p.title}
                    </h4>
                    <p className="text-sm text-[#c4b5d9] leading-relaxed">{p.description}</p>
                  </div>
                </motion.div>
              )
            })}
          </motion.div>
        </div>

        {/* ── Divider ──────────────────────────────────── */}
        <div className="mt-28 mb-28 mx-auto max-w-md h-px bg-gradient-to-r from-transparent via-[rgba(147,51,234,0.25)] to-transparent" />

        {/* ── Bottom: Why Correlic ──────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
        >
          <div className="text-center mb-14">
            <span className="text-xs font-semibold text-[#9333ea] uppercase tracking-widest">
              What Sets Us Apart
            </span>
            <h2
              className="mt-4 text-3xl sm:text-4xl lg:text-5xl font-bold text-[#e8dff5]"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              Why Correlic
            </h2>
          </div>

          <motion.div
            className="grid grid-cols-1 md:grid-cols-3 gap-6"
            variants={containerVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            {whyItems.map((item) => {
              const Icon = item.icon
              return (
                <motion.div
                  key={item.title}
                  variants={itemVariants}
                  className="p-7 relative overflow-hidden rounded-xl transition-all duration-300 group hover:translate-y-[-4px]"
                  style={{
                    background: 'rgba(18, 10, 36, 0.7)',
                    border: `1px solid ${item.color}20`,
                    boxShadow: `0 0 20px ${item.color}08`,
                    backdropFilter: 'blur(12px)',
                  }}
                >
                  {/* Top gradient accent */}
                  <div
                    className="absolute top-0 left-0 right-0 h-[2px]"
                    style={{ background: `linear-gradient(90deg, transparent, ${item.color}70, transparent)` }}
                  />
                  {/* Corner glow */}
                  <div
                    className="absolute top-0 left-0 w-32 h-32 pointer-events-none opacity-60 group-hover:opacity-100 transition-opacity duration-500"
                    style={{ background: `radial-gradient(circle at 0% 0%, ${item.color}10, transparent 70%)` }}
                  />
                  {/* Hover border glow */}
                  <div
                    className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
                    style={{ boxShadow: `inset 0 0 30px ${item.color}08, 0 0 30px ${item.color}10` }}
                  />

                  <div
                    className="w-14 h-14 rounded-xl flex items-center justify-center mb-5 relative"
                    style={{
                      background: `linear-gradient(135deg, ${item.color}18, ${item.color}05)`,
                      border: `1px solid ${item.color}35`,
                      boxShadow: `0 0 20px ${item.color}18`,
                    }}
                  >
                    <Icon className="w-7 h-7" style={{ color: item.color, filter: `drop-shadow(0 0 8px ${item.color}50)` }} />
                  </div>
                  <h3
                    className="text-lg font-bold text-[#e8dff5] mb-3 relative"
                    style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                  >
                    {item.title}
                  </h3>
                  <p className="text-sm text-[#c4b5d9] leading-relaxed relative">{item.description}</p>
                </motion.div>
              )
            })}
          </motion.div>
        </motion.div>
      </div>
    </section>
  )
}
