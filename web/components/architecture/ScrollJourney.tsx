'use client'

import { useRef, useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { stages } from './stages'
import { StageContent } from './StageContent'
import { StageVisual } from './StageVisual'

/* ─── Progress Bar (fixed left edge) ──────────────────────────────────────── */

function ProgressBar({ activeIndex }: { activeIndex: number }) {
  return (
    <div className="fixed left-4 xl:left-8 top-1/2 -translate-y-1/2 z-40 hidden lg:flex flex-col items-center gap-0">
      {stages.map((stage, i) => (
        <div key={stage.id} className="flex flex-col items-center">
          {/* Dot */}
          <button
            onClick={() => {
              const el = document.getElementById(`stage-${stage.id}`)
              el?.scrollIntoView({ behavior: 'smooth', block: 'center' })
            }}
            className="group relative flex items-center"
          >
            <motion.div
              className="w-3 h-3 rounded-full border-2 transition-all duration-300"
              style={{
                borderColor: i <= activeIndex ? stage.color : '#6b5a8040',
                background: i === activeIndex ? stage.color : i < activeIndex ? `${stage.color}40` : 'transparent',
                boxShadow: i === activeIndex ? `0 0 12px ${stage.color}70` : 'none',
              }}
              animate={i === activeIndex ? { scale: [1, 1.3, 1] } : { scale: 1 }}
              transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
            />
            {/* Tooltip */}
            <span
              className="absolute left-7 text-xs font-medium whitespace-nowrap opacity-0 group-hover:opacity-100 transition-all duration-200 px-2.5 py-1 rounded-md pointer-events-none"
              style={{
                color: i <= activeIndex ? '#e8dff5' : '#6b5a80',
                background: i <= activeIndex ? `${stage.color}20` : 'rgba(18,10,36,0.8)',
                border: `1px solid ${i <= activeIndex ? `${stage.color}40` : '#6b5a8020'}`,
              }}
            >
              {stage.title}
            </span>
          </button>

          {/* Connector line */}
          {i < stages.length - 1 && (
            <div
              className="w-[2px] transition-all duration-500"
              style={{
                height: 18,
                background: i < activeIndex
                  ? `linear-gradient(180deg, ${stages[i].color}70, ${stages[i + 1].color}70)`
                  : '#6b5a8018',
                boxShadow: i < activeIndex ? `0 0 6px ${stages[i].color}30` : 'none',
              }}
            />
          )}
        </div>
      ))}
    </div>
  )
}

/* ─── Main Component ──────────────────────────────────────────────────────── */

export function ScrollJourney() {
  const containerRef = useRef<HTMLDivElement>(null)
  const stageRefs = useRef<(HTMLDivElement | null)[]>([])
  const [activeIndex, setActiveIndex] = useState(0)

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const idx = stageRefs.current.indexOf(entry.target as HTMLDivElement)
            if (idx !== -1) setActiveIndex(idx)
          }
        })
      },
      { rootMargin: '-40% 0px -40% 0px' }
    )

    stageRefs.current.forEach((ref) => {
      if (ref) observer.observe(ref)
    })

    return () => observer.disconnect()
  }, [])

  const activeStage = stages[activeIndex]

  return (
    <section ref={containerRef} className="relative">
      <ProgressBar activeIndex={activeIndex} />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section heading */}
        <motion.div
          className="text-center py-20"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
        >
          <span className="text-xs font-semibold text-[#9333ea] uppercase tracking-widest">
            The Journey
          </span>
          <h2
            className="mt-4 text-3xl sm:text-4xl lg:text-5xl font-bold text-[#e8dff5]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            How AI Agent Activity Is Monitored
          </h2>
          <p className="mt-5 text-lg text-[#c4b5d9] max-w-xl mx-auto">
            Scroll through each stage to see how Correlic captures, analyzes,
            and responds to everything your AI agents do.
          </p>
        </motion.div>

        {/* Desktop: sticky visual left + scrolling content right */}
        <div className="lg:flex lg:gap-12 xl:gap-16">
          {/* Sticky visual panel (desktop only) */}
          <div className="hidden lg:block lg:w-[42%] xl:w-[45%]">
            <div className="sticky top-24" style={{ height: 'calc(100vh - 8rem)' }}>
              <div className="h-full flex items-center">
                <motion.div
                  className="w-full p-7 relative overflow-hidden rounded-xl"
                  style={{
                    minHeight: 440,
                    background: 'rgba(18, 10, 36, 0.7)',
                    backdropFilter: 'blur(16px)',
                    border: `1px solid ${activeStage.color}25`,
                    boxShadow: `0 0 30px ${activeStage.color}08`,
                  }}
                  key="visual-panel"
                >
                  {/* Colored top accent */}
                  <motion.div
                    className="absolute top-0 left-0 right-0 h-[2px]"
                    animate={{
                      background: `linear-gradient(90deg, transparent, ${activeStage.color}80, transparent)`,
                    }}
                    transition={{ duration: 0.4 }}
                  />

                  {/* Corner glow */}
                  <motion.div
                    className="absolute top-0 right-0 w-40 h-40 pointer-events-none"
                    animate={{
                      background: `radial-gradient(circle at 100% 0%, ${activeStage.color}10, transparent 70%)`,
                    }}
                    transition={{ duration: 0.5 }}
                  />

                  {/* Stage indicator */}
                  <motion.div
                    className="flex items-center gap-3 mb-7"
                    key={activeStage.id + '-label'}
                    initial={{ opacity: 0, y: -8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                  >
                    <span
                      className="text-xs font-bold uppercase tracking-wider px-3 py-1 rounded-full"
                      style={{
                        color: activeStage.color,
                        background: `${activeStage.color}12`,
                        border: `1px solid ${activeStage.color}30`,
                      }}
                    >
                      Stage {activeIndex + 1} / {stages.length}
                    </span>
                    <span className="text-xs text-[#6b5a80]">{activeStage.title}</span>
                  </motion.div>

                  {/* Visual content */}
                  <StageVisual stageId={activeStage.id} color={activeStage.color} />

                  {/* Background glow */}
                  <motion.div
                    className="absolute inset-0 pointer-events-none rounded-xl"
                    animate={{
                      background: `radial-gradient(ellipse 80% 60% at 50% 50%, ${activeStage.color}06, transparent 70%)`,
                    }}
                    transition={{ duration: 0.5 }}
                  />
                </motion.div>
              </div>
            </div>
          </div>

          {/* Scrolling content */}
          <div className="lg:w-[58%] xl:w-[55%]">
            {stages.map((stage, i) => (
              <div
                key={stage.id}
                id={`stage-${stage.id}`}
                ref={(el) => { stageRefs.current[i] = el }}
                className="min-h-[80vh] flex items-center py-16 lg:py-24"
              >
                <div className="w-full">
                  {/* Mobile: show visual above content */}
                  <div className="lg:hidden mb-8">
                    <div
                      className="p-5 relative overflow-hidden rounded-xl"
                      style={{
                        minHeight: 280,
                        background: 'rgba(18, 10, 36, 0.7)',
                        border: `1px solid ${stage.color}25`,
                        boxShadow: `0 0 20px ${stage.color}08`,
                        backdropFilter: 'blur(12px)',
                      }}
                    >
                      <div
                        className="absolute top-0 left-0 right-0 h-[2px]"
                        style={{ background: `linear-gradient(90deg, transparent, ${stage.color}70, transparent)` }}
                      />
                      <div
                        className="text-xs font-bold uppercase tracking-wider mb-5 px-2.5 py-1 rounded-full inline-block"
                        style={{
                          color: stage.color,
                          background: `${stage.color}12`,
                          border: `1px solid ${stage.color}30`,
                        }}
                      >
                        Stage {i + 1} / {stages.length}
                      </div>
                      <StageVisual stageId={stage.id} color={stage.color} />
                    </div>
                  </div>
                  <StageContent stage={stage} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom summary — pipeline flow */}
        <motion.div
          className="py-20 text-center"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ delay: 0.3 }}
        >
          <div
            className="p-5 rounded-xl inline-flex flex-wrap items-center justify-center gap-3 text-xs"
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              background: 'rgba(18, 10, 36, 0.7)',
              border: '1px solid rgba(147,51,234,0.15)',
              boxShadow: '0 0 20px rgba(147,51,234,0.06)',
              backdropFilter: 'blur(12px)',
            }}
          >
            {stages.map((s, i) => (
              <span key={s.id} className="flex items-center gap-2.5">
                <span
                  className="font-semibold"
                  style={{ color: s.color, filter: `drop-shadow(0 0 4px ${s.color}40)` }}
                >
                  {s.title.split(' ')[0]}
                </span>
                {i < stages.length - 1 && (
                  <span className="text-[rgba(147,51,234,0.4)]">→</span>
                )}
              </span>
            ))}
          </div>
          <p className="text-sm text-[#6b5a80] mt-4">
            End-to-end latency under <span className="text-[#00e676] font-semibold">100ms</span> from kernel event to stored finding
          </p>
        </motion.div>
      </div>
    </section>
  )
}
