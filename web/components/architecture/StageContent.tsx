'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import type { Stage } from './stages'

const containerVariants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.1 } },
}

const itemVariants = {
  hidden: { opacity: 0, x: 20 },
  visible: { opacity: 1, x: 0, transition: { duration: 0.5, ease: 'easeOut' as const } },
}

export function StageContent({ stage }: { stage: Stage }) {
  const Icon = stage.icon
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null)

  return (
    <motion.div
      className="space-y-7"
      variants={containerVariants}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: '-15%' }}
    >
      {/* Stage label */}
      <motion.div variants={itemVariants} className="flex items-center gap-4">
        <div
          className="w-14 h-14 rounded-2xl flex items-center justify-center shrink-0"
          style={{
            background: `linear-gradient(135deg, ${stage.color}18, ${stage.color}05)`,
            border: `1.5px solid ${stage.color}35`,
            boxShadow: `0 0 20px ${stage.color}15`,
          }}
        >
          <Icon className="w-7 h-7" style={{ color: stage.color, filter: `drop-shadow(0 0 8px ${stage.color}50)` }} />
        </div>
        <div>
          <span
            className="text-xs font-bold uppercase tracking-wider"
            style={{ color: stage.color }}
          >
            Stage {stage.index + 1}
          </span>
          <p className="text-sm text-[#6b5a80] mt-0.5">{stage.subtitle}</p>
        </div>
      </motion.div>

      {/* Title */}
      <motion.h2
        variants={itemVariants}
        className="text-2xl sm:text-3xl lg:text-4xl font-bold text-[#e8dff5] leading-tight"
        style={{ fontFamily: "'Space Grotesk', sans-serif" }}
      >
        {stage.title}
      </motion.h2>

      {/* Description */}
      <motion.p variants={itemVariants} className="text-base sm:text-lg text-[#c4b5d9] leading-relaxed">
        {stage.description}
      </motion.p>

      {/* Detail points — interactive accordion */}
      <motion.div variants={itemVariants} className="space-y-3 pt-2">
        {stage.details.map((d, idx) => {
          const isOpen = expandedIdx === idx
          return (
            <motion.button
              key={d.label}
              onClick={() => setExpandedIdx(isOpen ? null : idx)}
              className="w-full text-left p-4 lg:p-5 rounded-xl relative overflow-hidden transition-all duration-300 group"
              style={{
                background: isOpen ? 'rgba(18, 10, 36, 0.9)' : 'rgba(18, 10, 36, 0.6)',
                border: `1px solid ${isOpen ? `${stage.color}40` : `${stage.color}15`}`,
                boxShadow: isOpen ? `0 0 25px ${stage.color}10` : 'none',
              }}
              whileHover={{ x: 4 }}
              transition={{ type: 'spring', damping: 20, stiffness: 300 }}
            >
              {/* Left accent */}
              <div
                className="absolute left-0 top-0 bottom-0 w-[3px] transition-all duration-300"
                style={{
                  background: isOpen
                    ? stage.color
                    : `linear-gradient(180deg, transparent, ${stage.color}40, transparent)`,
                  boxShadow: isOpen ? `0 0 8px ${stage.color}40` : 'none',
                }}
              />

              <div className="flex items-start gap-3 pl-2">
                <span
                  className="w-2 h-2 rounded-full shrink-0 mt-2 transition-all duration-300"
                  style={{
                    background: stage.color,
                    boxShadow: isOpen ? `0 0 8px ${stage.color}60` : 'none',
                  }}
                />
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-sm sm:text-base font-semibold text-[#e8dff5] group-hover:text-white transition-colors">
                      {d.label}
                    </span>
                    <motion.span
                      className="text-[#6b5a80] text-xs ml-2 shrink-0"
                      animate={{ rotate: isOpen ? 180 : 0 }}
                      transition={{ duration: 0.2 }}
                    >
                      ▾
                    </motion.span>
                  </div>
                  <AnimatePresence>
                    {isOpen && (
                      <motion.p
                        className="text-sm text-[#c4b5d9] leading-relaxed mt-2"
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ duration: 0.25 }}
                      >
                        {d.text}
                      </motion.p>
                    )}
                  </AnimatePresence>
                </div>
              </div>
            </motion.button>
          )
        })}
      </motion.div>
    </motion.div>
  )
}
