'use client'

import { motion } from 'framer-motion'
import Image from 'next/image'

const agents = [
  { name: 'Cursor',          subtitle: 'AI Code Editor',      icon: '/agents/cursor.svg',         color: '#9333ea' },
  { name: 'Claude Code',     subtitle: 'Anthropic CLI',       icon: '/agents/claude-code.svg',    color: '#f59e0b' },
  { name: 'GitHub Copilot',  subtitle: 'AI Pair Programmer',  icon: '/agents/github-copilot.svg', color: '#00e676' },
  { name: 'ChatGPT',         subtitle: 'OpenAI',              icon: '/agents/chatgpt.svg',        color: '#10b981' },
  { name: 'Gemini',          subtitle: 'Google AI',           icon: '/agents/gemini.svg',         color: '#3b82f6' },
  { name: 'Windsurf',        subtitle: 'Codeium AI IDE',      icon: '/agents/windsurf.svg',       color: '#06b6d4' },
  { name: 'Aider',           subtitle: 'AI Pair Programming', icon: '/agents/aider.svg',          color: '#f472b6' },
  { name: 'Amazon Q',        subtitle: 'AWS AI Assistant',    icon: '/agents/amazon-q.svg',       color: '#ff7a2f' },
  { name: 'Tabnine',         subtitle: 'AI Completion',       icon: '/agents/tabnine.svg',        color: '#a855f7' },
  { name: 'Cody',            subtitle: 'Sourcegraph AI',      icon: '/agents/cody.svg',           color: '#ef4444' },
]

function AgentCard({ agent }: { agent: typeof agents[0] }) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-5 rounded-2xl border border-[rgba(147,51,234,0.25)] bg-[rgba(18,10,36,0.5)] backdrop-blur-sm shadow-[0_0_15px_rgba(147,51,234,0.08),inset_0_0_15px_rgba(147,51,234,0.03)] hover:border-[rgba(147,51,234,0.45)] hover:bg-[rgba(18,10,36,0.8)] hover:shadow-[0_0_25px_rgba(147,51,234,0.18),inset_0_0_20px_rgba(147,51,234,0.06)] transition-all duration-300 shrink-0 cursor-default select-none min-w-[130px]">
      {/* Icon */}
      <div
        className="w-14 h-14 rounded-xl flex items-center justify-center overflow-hidden"
        style={{
          background: `${agent.color}10`,
          border: `1px solid ${agent.color}20`,
        }}
      >
        <Image
          src={agent.icon}
          alt={agent.name}
          width={48}
          height={48}
          className="w-12 h-12"
        />
      </div>
      {/* Label */}
      <div className="text-center">
        <div className="text-sm font-semibold text-[#e8dff5] whitespace-nowrap">{agent.name}</div>
      </div>
    </div>
  )
}

export function AgentMarquee() {
  return (
    <section className="py-20 lg:py-24 relative overflow-hidden">
      {/* Background glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: 'radial-gradient(ellipse 60% 40% at 50% 50%, rgba(147,51,234,0.04) 0%, transparent 70%)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        {/* Heading */}
        <motion.div
          className="text-center mb-14"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
        >
          <span className="text-xs font-semibold text-[#9333ea] uppercase tracking-widest">
            Universal Compatibility
          </span>
          <h2
            className="mt-3 text-3xl sm:text-4xl font-bold text-[#e8dff5]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            Works With Every AI Agent
          </h2>
          <p className="mt-4 text-[#c4b5d9] max-w-2xl mx-auto">
            Correlic monitors all major AI coding assistants and autonomous pipelines
            at the kernel level — no plugins, no SDKs, no code changes required.
          </p>
        </motion.div>
      </div>

      {/* Marquee container */}
      <div className="relative">
        {/* Gradient fade — left */}
        <div
          className="absolute left-0 top-0 bottom-0 w-24 sm:w-40 z-10 pointer-events-none"
          style={{ background: 'linear-gradient(90deg, #0a0612 0%, transparent 100%)' }}
        />
        {/* Gradient fade — right */}
        <div
          className="absolute right-0 top-0 bottom-0 w-24 sm:w-40 z-10 pointer-events-none"
          style={{ background: 'linear-gradient(270deg, #0a0612 0%, transparent 100%)' }}
        />

        {/* Scrolling track */}
        <div className="marquee-track flex gap-5 py-2 hover:[animation-play-state:paused]">
          {/* First set */}
          {agents.map((agent) => (
            <AgentCard key={`a-${agent.name}`} agent={agent} />
          ))}
          {/* Duplicate for seamless loop */}
          {agents.map((agent) => (
            <AgentCard key={`b-${agent.name}`} agent={agent} />
          ))}
        </div>
      </div>

      {/* Bottom text */}
      <motion.p
        className="text-center text-xs text-[#6b5a80] mt-8"
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ delay: 0.3 }}
      >
        Any process with shell, file, or network access is monitored — including custom agents and pipelines
      </motion.p>
    </section>
  )
}
