'use client'

import Link from 'next/link'
import Image from 'next/image'
import { Shield, Cpu, Activity, Lock } from 'lucide-react'
import { motion } from 'framer-motion'
import { Button } from '@/components/ui/Button'
const stats = [
  { icon: Lock,     value: 'On-Prem', label: 'Your data stays yours' },
  { icon: Cpu,      value: '< 1ms',   label: 'Detection latency' },
  { icon: Activity, value: '~90%',    label: 'Noise reduction' },
  { icon: Shield,   value: 'AI-Gated',label: 'Detection' },
]

const brandLetters = [
  { char: 'C', color: '#e8dff5' },
  { char: 'O', color: '#e8dff5' },
  { char: 'R', color: '#e8dff5' },
  { char: 'R', color: '#e8dff5' },
  { char: 'E', color: '#e8dff5' },
  { char: 'L', color: '#f59e0b' },
  { char: 'I', color: '#f59e0b' },
  { char: 'C', color: '#f59e0b' },
]

export function Hero() {
  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden">
      {/* Background radial glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse 80% 60% at 50% 20%, rgba(147,51,234,0.08) 0%, transparent 70%)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 lg:py-20 w-full">

        {/* ── Centered hero block: logo + brand + headline + CTAs ── */}
        <div className="flex flex-col items-center text-center">

          {/* Logo + CORRELIC brand */}
          <motion.div
            className="flex items-center gap-6 sm:gap-8 mb-14 lg:mb-16"
            initial={{ opacity: 0, scale: 0.85 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.7, ease: 'easeOut' }}
          >
            {/* Logo */}
            <div className="relative logo-shimmer">
              <Image
                src="/logo.png"
                alt="Correlic"
                width={180}
                height={184}
                className=""
                priority
              />
            </div>

            {/* Animated CORRELIC text */}
            <div className="flex flex-col items-start">
              {/* Brand name */}
              <div className="flex">
                {brandLetters.map((letter, i) => (
                  <motion.span
                    key={i}
                    className={`text-5xl sm:text-6xl lg:text-7xl font-bold tracking-wider ${
                      letter.color === '#f59e0b' ? 'brand-shimmer-gold' : 'brand-shimmer'
                    }`}
                    style={{
                      fontFamily: "'Space Grotesk', sans-serif",
                      color: letter.color,
                      filter: letter.color === '#f59e0b'
                        ? 'drop-shadow(0 0 20px rgba(245,158,11,0.3))'
                        : 'drop-shadow(0 0 20px rgba(147,51,234,0.15))',
                    }}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{
                      duration: 0.4,
                      delay: 0.5 + i * 0.08,
                      ease: 'easeOut',
                    }}
                  >
                    {letter.char}
                  </motion.span>
                ))}
              </div>

              {/* Tagline + Secure pill on same row */}
              <div className="flex items-center gap-4 mt-2 ml-0.5">
                <motion.span
                  className="text-xs sm:text-sm tracking-[0.35em] uppercase text-[#6b5a80]"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 1.3, duration: 0.6 }}
                >
                  CORRELATE
                  <span className="mx-2 text-[#9333ea]">·</span>
                  DETECT
                  <span className="mx-2 text-[#9333ea]">·</span>
                  PROTECT
                </motion.span>

                {/* Secure pill */}
                <motion.div
                  className="secure-pill flex items-center gap-2 px-3 py-1 rounded-full border border-[rgba(0,230,118,0.2)] bg-[rgba(0,230,118,0.05)]"
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 1.5, duration: 0.5 }}
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full bg-[#00e676]"
                    style={{ boxShadow: '0 0 6px rgba(0,230,118,0.6)', animation: 'pulse-glow 2s infinite' }}
                  />
                  <span className="text-xs font-semibold text-[#00e676] tracking-wide">Secure</span>
                </motion.div>
              </div>
            </div>
          </motion.div>

          {/* Headline — single line */}
          <motion.h1
            className="text-3xl sm:text-4xl lg:text-5xl xl:text-[3.5rem] font-bold leading-[1.15] tracking-tight"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.4 }}
          >
            <span className="text-[#e8dff5]">Know What Your AI Agent </span>
            <span className="text-gradient">Actually Does</span>
          </motion.h1>

          {/* Description */}
          <motion.p
            className="mt-6 lg:mt-8 text-base sm:text-lg text-[#c4b5d9] leading-relaxed max-w-3xl"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.55 }}
          >
            Cursor, Claude Code, and Copilot run with full access to your machine — files, network, credentials, everything.
            Correlic monitors every action at the kernel level so nothing goes unnoticed.
            100% on-prem. Your data never leaves your device.
          </motion.p>

          {/* CTAs */}
          <motion.div
            className="flex flex-wrap justify-center gap-4 mt-10 lg:mt-12"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.7 }}
          >
            <Link href="/register">
              <Button variant="primary" size="lg">
                <Shield className="w-4 h-4" />
                Claim Your Spot
              </Button>
            </Link>
            <Link href="#how-it-works-summary">
              <Button variant="outline" size="lg">
                How It Works
              </Button>
            </Link>
          </motion.div>

          {/* Stats row */}
          <motion.div
            className="flex flex-wrap justify-center gap-8 sm:gap-10 mt-14 lg:mt-16"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.85 }}
          >
            {stats.map(({ icon: Icon, value, label }) => (
              <div key={label} className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-[rgba(147,51,234,0.08)] border border-[rgba(147,51,234,0.15)] flex items-center justify-center">
                  <Icon className="w-4 h-4 text-[#9333ea]" />
                </div>
                <div className="text-left">
                  <div className="text-sm font-bold text-[#e8dff5]">{value}</div>
                  <div className="text-xs text-[#6b5a80]">{label}</div>
                </div>
              </div>
            ))}
          </motion.div>

          {/* Platform support */}
          <motion.div
            className="flex items-center justify-center gap-5 text-xs text-[#6b5a80] mt-8"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 1.0 }}
          >
            <span className="flex items-center gap-1.5">
              <span className="text-[#00e676]">●</span> Linux (eBPF)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="text-[#c4b5d9]">●</span> Windows (ETW)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="text-[#f0c800]">●</span> macOS (Beta)
            </span>
          </motion.div>
        </div>

      </div>

      {/* Scroll hint */}
      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-1.5 text-[#6b5a80] text-xs">
        <div className="w-px h-8 bg-gradient-to-b from-[rgba(147,51,234,0.3)] to-transparent" />
      </div>
    </section>
  )
}
