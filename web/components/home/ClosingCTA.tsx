'use client'

import Link from 'next/link'
import { motion } from 'framer-motion'
import { Shield, ArrowRight } from 'lucide-react'
import { Button } from '@/components/ui/Button'

export function ClosingCTA() {
  return (
    <section className="py-32 relative">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse 60% 50% at 50% 50%, rgba(147,51,234,0.07) 0%, transparent 70%)',
        }}
      />

      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 relative text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
        >
          <h2
            className="text-3xl sm:text-4xl lg:text-5xl font-bold text-[#e8dff5] leading-[1.15]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            AI Agents Are Powerful.
            <br />
            <span className="text-gradient">That&apos;s the Problem.</span>
          </h2>

          <p className="mt-6 text-base sm:text-lg text-[#c4b5d9] leading-relaxed max-w-2xl mx-auto">
            Your AI agent reads files, makes network calls, and runs commands with the same
            access you have. Correlic hooks into the kernel so you see everything it does —
            not just what it tells you.
          </p>

          <div className="flex flex-wrap justify-center gap-4 mt-10">
            <Link href="/register">
              <Button variant="primary" size="lg">
                <Shield className="w-4 h-4" />
                Claim Your Spot
              </Button>
            </Link>
            <Link href="/about">
              <Button variant="outline" size="lg">
                Learn More About Correlic
                <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
