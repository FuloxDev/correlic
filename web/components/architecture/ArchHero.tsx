'use client'

import { motion } from 'framer-motion'
import { ChevronDown } from 'lucide-react'

export function ArchHero() {
  return (
    <section className="pt-32 pb-20 relative overflow-hidden">
      {/* Multi-layered background glows */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse 60% 50% at 50% 20%, rgba(147,51,234,0.08) 0%, transparent 70%), radial-gradient(ellipse 40% 30% at 80% 80%, rgba(168,85,247,0.04) 0%, transparent 60%)',
        }}
      />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center relative">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: 'easeOut' }}
        >
          <motion.span
            className="inline-block text-xs font-semibold text-[#9333ea] uppercase tracking-widest px-4 py-1.5 rounded-full mb-6"
            style={{ background: 'rgba(147,51,234,0.08)', border: '1px solid rgba(147,51,234,0.2)' }}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 }}
          >
            Architecture Deep Dive
          </motion.span>

          <h1
            className="text-4xl sm:text-5xl lg:text-6xl xl:text-7xl font-bold leading-[1.1]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            <span className="text-[#e8dff5]">What Happens When Your</span>
            <br />
            <span className="text-gradient">AI Agent Goes Rogue</span>
          </h1>

          <motion.p
            className="mt-7 text-lg sm:text-xl text-[#c4b5d9] max-w-2xl mx-auto leading-relaxed"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
          >
            See how Correlic monitors AI agent activity from the kernel up — capturing
            every process, file access, and network connection, then surfacing threats
            with autonomous AI investigation.
          </motion.p>

          <motion.div
            className="mt-8 inline-flex items-center gap-2.5 px-5 py-2.5 rounded-full text-sm text-[#00e676] font-medium"
            style={{
              background: 'rgba(0,230,118,0.06)',
              border: '1px solid rgba(0,230,118,0.2)',
              boxShadow: '0 0 20px rgba(0,230,118,0.06)',
            }}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
          >
            <span className="w-2 h-2 rounded-full bg-[#00e676]" style={{ boxShadow: '0 0 8px #00e676' }} />
            100% on-prem — no data ever leaves your infrastructure
          </motion.div>
        </motion.div>

        {/* Scroll indicator */}
        <motion.div
          className="mt-16 flex flex-col items-center gap-2 text-[#6b5a80]"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.8 }}
        >
          <span className="text-xs tracking-widest uppercase">Scroll to explore</span>
          <motion.div
            animate={{ y: [0, 6, 0] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
          >
            <ChevronDown className="w-5 h-5" />
          </motion.div>
        </motion.div>
      </div>
    </section>
  )
}
