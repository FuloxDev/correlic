'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Cpu, Radio, Filter, Network, Shield, Activity,
  FileSearch, GitBranch, Layers, BrainCircuit, Bell,
} from 'lucide-react'
import Link from 'next/link'
import { Button } from '@/components/ui/Button'

const stages = [
  { id: 'kernel', icon: Cpu, color: '#9333ea', title: 'See Everything. Miss Nothing.', tagline: 'Linux · Windows · macOS', desc: 'Platform-native kernel hooks capture every AI agent action. eBPF on Linux, ETW with Security Audit on Windows, kqueue and FSEvents on macOS. Synchronous capture with zero silent drops.' },
  { id: 'session', icon: Radio, color: '#c4b5d9', title: 'Know Which Agent Did What', tagline: 'AI lineage · session UUID', desc: 'Each AI agent root process gets a unique session UUID. All child processes — tools, shells, subprocesses — automatically inherit the session, building a complete lineage tree across PIDs.' },
  { id: 'sampling', icon: Filter, color: '#f0c800', title: '90% Less Noise. Zero Missed Threats.', tagline: 'AI bypass · security-first', desc: 'AI agent events bypass sampling entirely. Suspicious patterns like credential access and network anomalies are always kept. Benign noise is filtered with ~90% volume reduction.' },
  { id: 'correlation', icon: Network, color: '#00e676', title: 'Every Event, Connected', tagline: 'Neo4j · PostgreSQL', desc: 'Every event is correlated by agent session and process ID. Neo4j builds a live process relationship graph. PostgreSQL stores structured events for time-series queries. Dual storage, one unified view.' },
  { id: 'detection', icon: Shield, color: '#ff7a2f', title: '13 Detection Rules Built for AI Threats', tagline: 'AI-gated · MITRE mapped', desc: 'Detection rules gate on AI process attribution first — only agent-descended processes trigger alerts. Covers credential access, exfiltration, persistence, privilege escalation, code tampering, and more.' },
  { id: 'behavioral', icon: Activity, color: '#c4b5d9', title: 'Learns Your Normal. Alerts the Abnormal.', tagline: 'auto-learn · manual control', desc: 'Learns what\'s normal for each AI agent over time. Baseline any finding for a custom period or permanently. Sensitive resources like SSH keys and credential stores are never auto-baselined.' },
  { id: 'findings', icon: FileSearch, color: '#f0c800', title: 'Every Detection, Actionable', tagline: 'triage · suppress · act', desc: 'Each detection produces a structured finding with severity, confidence, and MITRE technique mapping. Allow, dismiss, or investigate — every decision feeds back into behavioral learning.' },
  { id: 'chains', icon: GitBranch, color: '#ff3b5c', title: 'Catches Multi-Step Attacks', tagline: 'multi-step attack patterns', desc: 'Links individual findings into attack sequences across time windows. Credential theft followed by exfiltration, privilege escalation into persistence. Chain findings amplify severity and bypass cooldowns.' },
  { id: 'incidents', icon: Layers, color: '#00e676', title: 'From Findings to Full Picture', tagline: 'dossier · lifecycle', desc: 'Findings grouped by host and agent session into incidents. A structured dossier is assembled automatically — process chain, timeline, network activity, sensitive files, behavioral context.' },
  { id: 'ai', icon: BrainCircuit, color: '#a855f7', title: 'Ask Your AI About Any Incident', tagline: 'BYOK · context windows', desc: 'Context windows from 1-minute to 1-year feed a BYOK LLM for evidence-based analysis. The AI queries process trees and event history autonomously — no assumptions, only evidence-backed conclusions.' },
  { id: 'alerts', icon: Bell, color: '#ff7a2f', title: 'The Right Alert, to the Right Place', tagline: 'Slack · webhook · in-app', desc: 'All findings generate in-app notifications. Incidents trigger Slack and HMAC-signed webhook delivery. Severity gating per endpoint — configure what reaches each channel without code changes.' },
]

export function FeatureGrid() {
  const [active, setActive] = useState<string | null>(null)

  return (
    <section id="features" className="py-28 relative">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{ background: 'radial-gradient(ellipse 70% 50% at 50% 30%, rgba(147,51,234,0.06) 0%, transparent 70%)' }}
      />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        {/* Heading */}
        <motion.div
          className="text-center mb-20"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <span className="text-xs font-semibold text-[#9333ea] uppercase tracking-widest">
            Under the Hood
          </span>
          <h2
            className="mt-3 text-3xl sm:text-4xl font-bold text-[#e8dff5]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            How Correlic Protects You
          </h2>
          <p className="mt-4 text-[#c4b5d9] max-w-xl mx-auto">
            An 11-stage pipeline purpose-built for monitoring AI agents — from kernel capture to incident response.
            Tap any stage to see the technical detail.
          </p>
        </motion.div>

        {/* Timeline */}
        <div className="relative">
          <div className="space-y-8 lg:space-y-14 relative">
            {/* Central glowing line — desktop */}
            <div className="hidden lg:block absolute left-1/2 top-[36px] bottom-[36px] -translate-x-1/2 w-[3px]" style={{ zIndex: 1 }}>
              <div
                className="w-full h-full rounded-full"
                style={{
                  background: 'linear-gradient(180deg, rgba(147,51,234,0.5), rgba(168,85,247,0.5), rgba(0,230,118,0.4), rgba(255,122,47,0.4))',
                  boxShadow: '0 0 12px rgba(147,51,234,0.25)',
                }}
              />
              {/* Flowing particle down */}
              <div
                className="flow-particle flow-particle-v absolute left-0"
                style={{
                  background: '#9333ea',
                  boxShadow: '0 0 12px #9333ea, 0 0 24px #9333ea50',
                  animationDuration: '4s',
                }}
              />
              {/* Flowing particle up */}
              <div
                className="flow-particle flow-particle-v absolute left-0"
                style={{
                  background: '#00e676',
                  boxShadow: '0 0 12px #00e676, 0 0 24px #00e67650',
                  animationDuration: '5s',
                  animationDirection: 'reverse',
                  animationDelay: '2s',
                }}
              />
            </div>

            {/* Mobile: left-aligned timeline line */}
            <div className="lg:hidden absolute left-7 top-[24px] bottom-[24px] w-[3px]" style={{ zIndex: 1 }}>
              <div
                className="w-full h-full rounded-full"
                style={{
                  background: 'linear-gradient(180deg, rgba(147,51,234,0.4), rgba(168,85,247,0.4), rgba(255,122,47,0.3))',
                  boxShadow: '0 0 8px rgba(147,51,234,0.15)',
                }}
              />
            </div>
            {stages.map((stage, i) => {
              const isLeft = i % 2 === 0
              const isActive = active === stage.id

              return (
                <motion.div
                  key={stage.id}
                  className="relative"
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, margin: '-40px' }}
                  transition={{ duration: 0.4 }}
                >
                  {/* Desktop layout */}
                  <div className="hidden lg:grid lg:grid-cols-[1fr_auto_1fr] lg:gap-8 lg:items-start">
                    {isLeft ? (
                      <TimelineCard
                        stage={stage}
                        isActive={isActive}
                        side="left"
                        onClick={() => setActive(isActive ? null : stage.id)}
                      />
                    ) : (
                      <div />
                    )}

                    <TimelineNode
                      stage={stage}
                      index={i}
                      isActive={isActive}
                      onClick={() => setActive(isActive ? null : stage.id)}
                    />

                    {!isLeft ? (
                      <TimelineCard
                        stage={stage}
                        isActive={isActive}
                        side="right"
                        onClick={() => setActive(isActive ? null : stage.id)}
                      />
                    ) : (
                      <div />
                    )}
                  </div>

                  {/* Mobile layout */}
                  <div className="lg:hidden flex items-start gap-4 pl-1">
                    <TimelineNode
                      stage={stage}
                      index={i}
                      isActive={isActive}
                      onClick={() => setActive(isActive ? null : stage.id)}
                      small
                    />
                    <div className="flex-1 pt-0.5">
                      <TimelineCard
                        stage={stage}
                        isActive={isActive}
                        side="right"
                        onClick={() => setActive(isActive ? null : stage.id)}
                      />
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </div>
        </div>

        {/* CTA */}
        <motion.div
          className="text-center mt-16"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ delay: 0.3 }}
        >
          <Link href="/how-it-works">
            <Button variant="outline" size="lg">
              Explore the Full Pipeline →
            </Button>
          </Link>
        </motion.div>
      </div>
    </section>
  )
}

/* ─── Timeline Node (icon on the line) ────────────────────────────────────── */

function TimelineNode({
  stage,
  index,
  isActive,
  onClick,
  small,
}: {
  stage: typeof stages[0]
  index: number
  isActive: boolean
  onClick: () => void
  small?: boolean
}) {
  const Icon = stage.icon
  const size = small ? 'w-12 h-12' : 'w-[72px] h-[72px]'
  const iconSize = small ? 'w-6 h-6' : 'w-9 h-9'

  return (
    <motion.button
      onClick={onClick}
      className="relative shrink-0"
      style={{ zIndex: 5 }}
      whileHover={{ scale: 1.12 }}
      transition={{ type: 'spring', damping: 12, stiffness: 200 }}
    >
      {/* Glow halo */}
      <div
        className="absolute inset-[-8px] rounded-2xl blur-xl transition-opacity duration-300"
        style={{ background: stage.color, opacity: isActive ? 0.55 : 0.2, zIndex: -1 }}
      />

      {/* Icon box */}
      <div
        className={`${size} rounded-2xl flex items-center justify-center relative transition-all duration-300`}
        style={{
          background: `linear-gradient(145deg, ${stage.color}12, #120a24 40%, ${stage.color}08)`,
          border: `1.5px solid ${isActive ? stage.color : `${stage.color}50`}`,
          boxShadow: `0 0 20px ${stage.color}${isActive ? '40' : '20'}, inset 0 1px 0 ${stage.color}15, inset 0 0 24px ${stage.color}10`,
        }}
      >
        <Icon className={iconSize} style={{ color: stage.color, filter: `drop-shadow(0 0 8px ${stage.color}60)` }} />

        {/* Number badge */}
        <div
          className="absolute -top-2 -right-2 w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold"
          style={{
            background: isActive ? stage.color : `linear-gradient(135deg, #1a0e35, #120a24)`,
            color: isActive ? '#0a0612' : stage.color,
            border: `1.5px solid ${isActive ? stage.color : `${stage.color}50`}`,
            boxShadow: `0 0 10px ${stage.color}${isActive ? '70' : '30'}`,
          }}
        >
          {index + 1}
        </div>
      </div>

      {/* Active pulse ring */}
      {isActive && (
        <motion.div
          className="absolute inset-[-6px] rounded-2xl pointer-events-none"
          style={{ border: `1.5px solid ${stage.color}50` }}
          animate={{ scale: [1, 1.18, 1], opacity: [0.6, 0, 0.6] }}
          transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
        />
      )}
    </motion.button>
  )
}

/* ─── Timeline Card ───────────────────────────────────────────────────────── */

function TimelineCard({
  stage,
  isActive,
  side,
  onClick,
}: {
  stage: typeof stages[0]
  isActive: boolean
  side: 'left' | 'right'
  onClick: () => void
}) {
  return (
    <motion.button
      onClick={onClick}
      className="w-full text-left p-5 lg:p-6 relative overflow-hidden transition-all duration-300 group rounded-xl"
      style={{
        background: 'rgba(18, 10, 36, 0.8)',
        border: `1px solid ${isActive ? `${stage.color}50` : `${stage.color}20`}`,
        boxShadow: isActive
          ? `0 0 30px ${stage.color}15, inset 0 0 30px ${stage.color}05`
          : `0 0 15px ${stage.color}08`,
        backdropFilter: 'blur(12px)',
      }}
      whileHover={{ y: -3, transition: { type: 'spring', damping: 20, stiffness: 300 } }}
    >
      {/* Top gradient accent line */}
      <div
        className="absolute top-0 left-0 right-0 h-[2px]"
        style={{
          background: `linear-gradient(90deg, transparent, ${stage.color}${isActive ? '80' : '40'}, transparent)`,
        }}
      />

      {/* Side accent bar with gradient */}
      <div
        className={`absolute ${side === 'left' ? 'right-0' : 'left-0'} top-0 bottom-0 w-[3px] transition-opacity duration-300`}
        style={{
          background: `linear-gradient(180deg, transparent, ${stage.color}${isActive ? '' : '80'}, transparent)`,
        }}
      />

      {/* Hover glow overlay */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
        style={{ background: `radial-gradient(ellipse 80% 60% at ${side === 'left' ? '100%' : '0%'} 50%, ${stage.color}10, transparent 70%)` }}
      />

      {/* Content */}
      <div className={`${side === 'left' ? 'text-right' : 'text-left'} relative`}>
        <h3
          className="text-base sm:text-lg font-bold text-[#e8dff5] transition-colors duration-200"
          style={{ fontFamily: "'Space Grotesk', sans-serif" }}
        >
          {stage.title}
        </h3>
        <p
          className="text-xs sm:text-sm mt-1 transition-colors duration-200 font-medium"
          style={{ color: isActive ? stage.color : '#6b5a80' }}
        >
          {stage.tagline}
        </p>

        {/* Expanded description */}
        <AnimatePresence>
          {isActive && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.25 }}
              className="overflow-hidden"
            >
              <p className="text-sm text-[#c4b5d9] leading-relaxed mt-3 pt-3 border-t border-[rgba(147,51,234,0.1)]">
                {stage.desc}
              </p>
              <Link
                href="/how-it-works"
                className="inline-flex items-center gap-1 text-xs font-semibold mt-3 hover:brightness-125 transition-all"
                style={{ color: stage.color }}
              >
                Deep dive →
              </Link>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.button>
  )
}
