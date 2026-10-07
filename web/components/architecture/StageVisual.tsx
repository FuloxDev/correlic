'use client'

import { motion, AnimatePresence } from 'framer-motion'
import {
  Cpu, Monitor, Apple, Server, Radio, Filter,
  Network, Shield, Activity, FileSearch, GitBranch,
  Layers, BrainCircuit, Bell, Database, Lock,
  MessageSquare, AlertTriangle, CheckCircle, XCircle,
} from 'lucide-react'

/* ─── Shared animation wrappers ───────────────────────────────────────────── */

const fadeIn = {
  initial: { opacity: 0, y: 10 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -10 },
  transition: { duration: 0.4 },
}

function VisualWrap({ stageId, children }: { stageId: string; children: React.ReactNode }) {
  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={stageId}
        {...fadeIn}
        className="flex flex-col items-center justify-center"
        style={{ minHeight: 320 }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  )
}

function MiniCard({ color, icon: Icon, label, sub, delay = 0 }: {
  color: string; icon: React.ElementType; label: string; sub: string; delay?: number
}) {
  return (
    <motion.div
      className="glass-card p-3 flex items-center gap-2.5"
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay, duration: 0.3 }}
    >
      <div
        className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
        style={{ background: `${color}15`, border: `1px solid ${color}30` }}
      >
        <Icon className="w-4 h-4" style={{ color }} />
      </div>
      <div>
        <div className="text-xs font-semibold text-[#e8dff5]">{label}</div>
        <div className="text-[10px] text-[#6b5a80]">{sub}</div>
      </div>
    </motion.div>
  )
}

/* ─── Stage Visuals ───────────────────────────────────────────────────────── */

function KernelVisual({ color }: { color: string }) {
  const platforms = [
    { icon: Server, label: 'Linux', techs: ['eBPF Tracepoints', 'Kprobes', 'Ring Buffers'], color },
    { icon: Monitor, label: 'Windows', techs: ['ETW Providers', 'Security Audit', 'USN Journal'], color: '#c4b5d9' },
    { icon: Apple, label: 'macOS', techs: ['kqueue', 'FSEvents', 'lsof Polling'], color: '#f0c800' },
  ]

  return (
    <div className="w-full space-y-3">
      {platforms.map((p, i) => (
        <motion.div
          key={p.label}
          className="glass-card p-3 flex items-center gap-3"
          initial={{ opacity: 0, x: -15 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.12 }}
        >
          <div
            className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: `${p.color}15`, border: `1px solid ${p.color}30` }}
          >
            <p.icon className="w-4 h-4" style={{ color: p.color }} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-semibold text-[#e8dff5]">{p.label}</div>
            <div className="flex flex-wrap gap-1 mt-1">
              {p.techs.map((t) => (
                <span
                  key={t}
                  className="text-[8px] px-1.5 py-0.5 rounded"
                  style={{ color: p.color, background: `${p.color}10`, border: `1px solid ${p.color}18` }}
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        </motion.div>
      ))}
    </div>
  )
}

function TreeNode({ label, role, isRoot, color, roleColor, delay }: {
  label: string; role: string; isRoot: boolean; color: string; roleColor: string; delay: number
}) {
  return (
    <motion.div
      className="flex flex-col items-center"
      initial={{ opacity: 0, scale: 0.7, y: 8 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ delay, type: 'spring', damping: 18, stiffness: 200 }}
    >
      <div
        className="px-4 py-2 rounded-xl text-[11px] font-semibold relative"
        style={{
          background: isRoot ? `${color}18` : 'rgba(10,18,40,0.9)',
          border: `1.5px solid ${isRoot ? color : `${roleColor}40`}`,
          color: isRoot ? '#e8dff5' : '#c4b5d9',
          fontFamily: "'JetBrains Mono', monospace",
          boxShadow: isRoot
            ? `0 0 20px ${color}25, 0 0 40px ${color}10`
            : '0 2px 8px rgba(0,0,0,0.3)',
        }}
      >
        {isRoot && (
          <span
            className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full"
            style={{ background: color, boxShadow: `0 0 6px ${color}` }}
          />
        )}
        {label}
      </div>
      <span
        className="text-[7px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded mt-1"
        style={{ color: roleColor, background: `${roleColor}12`, border: `1px solid ${roleColor}20` }}
      >
        {role}
      </span>
    </motion.div>
  )
}

function TreeEdge({ color, delay }: { color: string; delay: number }) {
  return (
    <motion.div
      className="w-px mx-auto"
      style={{ height: 28, background: `linear-gradient(180deg, ${color}50, ${color}15)`, boxShadow: `0 0 4px ${color}20` }}
      initial={{ scaleY: 0, opacity: 0 }}
      animate={{ scaleY: 1, opacity: 1 }}
      transition={{ delay, duration: 0.3 }}
    />
  )
}

function SessionVisual({ color }: { color: string }) {
  const roleColor: Record<string, string> = {
    'AI Agent': color,
    Tool: '#f0c800',
    Shell: '#c4b5d9',
  }

  return (
    <div className="w-full">
      {/* Session banner */}
      <motion.div
        className="mx-auto w-fit px-3 py-1 rounded-full text-[8px] font-bold uppercase tracking-widest mb-3"
        style={{ background: `${color}15`, border: `1px solid ${color}30`, color }}
        initial={{ opacity: 0, y: -5 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        Session: sess-a1b2c3d4
      </motion.div>

      {/* Session boundary */}
      <motion.div
        className="rounded-2xl px-4 pt-4 pb-5 relative"
        style={{ border: `1px dashed ${color}18`, background: `${color}03` }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3, duration: 0.5 }}
      >
        {/* Row 1: Root */}
        <div className="flex justify-center">
          <TreeNode label="cursor" role="AI Agent" isRoot color={color} roleColor={roleColor['AI Agent']} delay={0} />
        </div>

        {/* Edge: root → children */}
        <div className="flex justify-center gap-[40%]">
          <TreeEdge color={color} delay={0.15} />
          <TreeEdge color={color} delay={0.2} />
        </div>

        {/* Row 2: Tools */}
        <div className="flex justify-around px-4">
          <TreeNode label="python3" role="Tool" isRoot={false} color={color} roleColor={roleColor.Tool} delay={0.2} />
          <TreeNode label="node" role="Tool" isRoot={false} color={color} roleColor={roleColor.Tool} delay={0.25} />
        </div>

        {/* Edge: tools → shells */}
        <div className="flex">
          <div className="flex-1 flex justify-around px-8">
            <TreeEdge color={color} delay={0.3} />
            <TreeEdge color={color} delay={0.35} />
          </div>
          <div className="flex-1 flex justify-center">
            <TreeEdge color={color} delay={0.4} />
          </div>
        </div>

        {/* Row 3: Shells */}
        <div className="flex justify-around px-2">
          <TreeNode label="curl" role="Shell" isRoot={false} color={color} roleColor={roleColor.Shell} delay={0.35} />
          <TreeNode label="git" role="Shell" isRoot={false} color={color} roleColor={roleColor.Shell} delay={0.4} />
          <TreeNode label="npm" role="Shell" isRoot={false} color={color} roleColor={roleColor.Shell} delay={0.45} />
        </div>

        {/* Legend */}
        <motion.div
          className="flex gap-4 justify-center mt-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.7 }}
        >
          {Object.entries(roleColor).map(([role, c]) => (
            <div key={role} className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: c }} />
              <span className="text-[8px] text-[#6b5a80]">{role}</span>
            </div>
          ))}
        </motion.div>
      </motion.div>
    </div>
  )
}

function SamplingVisual({ color }: { color: string }) {
  const rows = [
    { label: 'AI Agent Events', action: 'BYPASS', color: '#9333ea', icon: CheckCircle },
    { label: 'Suspicious Patterns', action: 'KEEP', color: '#00e676', icon: CheckCircle },
    { label: 'Benign System Activity', action: 'DROP', color: '#ff3b5c', icon: XCircle },
    { label: 'Remaining Events', action: 'SAMPLE', color: '#f0c800', icon: Filter },
  ]

  return (
    <div className="w-full space-y-2">
      <div className="text-center text-[10px] text-[#6b5a80] uppercase tracking-widest mb-3">Security-First Order</div>
      {rows.map((r, i) => (
        <motion.div
          key={r.label}
          className="flex items-center gap-3 glass-card p-2.5"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.12 }}
        >
          <r.icon className="w-4 h-4 shrink-0" style={{ color: r.color }} />
          <span className="text-xs text-[#c4b5d9] flex-1">{r.label}</span>
          <span
            className="text-[9px] font-bold px-2 py-0.5 rounded"
            style={{ color: r.color, background: `${r.color}12`, border: `1px solid ${r.color}20` }}
          >
            {r.action}
          </span>
        </motion.div>
      ))}
      <motion.div
        className="text-center text-xs text-[#6b5a80] pt-2"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
      >
        ~90% volume reduction · Zero AI blind spots
      </motion.div>
    </div>
  )
}

function CorrelationVisual({ color }: { color: string }) {
  return (
    <div className="w-full space-y-4">
      {/* Databases */}
      <div className="grid grid-cols-2 gap-3">
        <motion.div
          className="glass-card p-4 relative overflow-hidden"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="absolute top-0 left-0 right-0 h-[2px]" style={{ background: '#9333ea' }} />
          <Database className="w-6 h-6 mb-2" style={{ color: '#9333ea' }} />
          <div className="text-xs font-semibold text-[#e8dff5] mb-1.5">PostgreSQL</div>
          <div className="space-y-1">
            {['Events & findings', 'Baselines & incidents', 'AI context windows', 'Alert delivery queue'].map((item, i) => (
              <div key={item} className="flex items-center gap-1.5 text-[9px] text-[#c4b5d9]">
                <span className="w-1 h-1 rounded-full shrink-0 bg-[#9333ea]" />
                {item}
              </div>
            ))}
          </div>
        </motion.div>
        <motion.div
          className="glass-card p-4 relative overflow-hidden"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="absolute top-0 left-0 right-0 h-[2px]" style={{ background: color }} />
          <Network className="w-6 h-6 mb-2" style={{ color }} />
          <div className="text-xs font-semibold text-[#e8dff5] mb-1.5">Neo4j</div>
          <div className="space-y-1">
            {['Agent process trees', 'Parent-child edges', 'AI session propagation', 'Attack chain traversal'].map((item, i) => (
              <div key={item} className="flex items-center gap-1.5 text-[9px] text-[#c4b5d9]">
                <span className="w-1 h-1 rounded-full shrink-0" style={{ background: color }} />
                {item}
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Write strategy */}
      <motion.div
        className="space-y-2"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.35 }}
      >
        <div className="text-[9px] text-[#6b5a80] uppercase tracking-widest font-semibold text-center mb-1">
          Graph Write Strategy
        </div>
        <div className="glass-card p-3 flex items-start gap-3">
          <div
            className="w-2 h-2 rounded-full shrink-0 mt-1"
            style={{ background: '#ff7a2f', boxShadow: '0 0 6px #ff7a2f60' }}
          />
          <div>
            <div className="text-[10px] font-semibold text-[#ff7a2f]">Instant — Process Events</div>
            <div className="text-[9px] text-[#6b5a80]">Process tree edges written to Neo4j immediately so detection always has an up-to-date graph</div>
          </div>
        </div>
        <div className="glass-card p-3 flex items-start gap-3">
          <div
            className="w-2 h-2 rounded-full shrink-0 mt-1"
            style={{ background: '#c4b5d9', boxShadow: '0 0 6px #c4b5d940' }}
          />
          <div>
            <div className="text-[10px] font-semibold text-[#c4b5d9]">Batched — File, Network, DNS</div>
            <div className="text-[9px] text-[#6b5a80]">Buffered and flushed periodically for efficiency without sacrificing graph completeness</div>
          </div>
        </div>
      </motion.div>
    </div>
  )
}

function DetectionVisual({ color }: { color: string }) {
  /* Simulated live detection feed — shows the engine in action */
  const detections = [
    { event: 'python3 → /root/.ssh/id_rsa', rule: 'Credential Access', severity: 'CRITICAL', sevColor: '#ff3b5c', delay: 0.1 },
    { event: 'curl → 203.0.113.42:443', rule: 'Network Anomaly', severity: 'HIGH', sevColor: '#ff7a2f', delay: 0.3 },
    { event: 'agent → chmod 777 deploy.sh', rule: 'Code Tampering', severity: 'MEDIUM', sevColor: '#f0c800', delay: 0.5 },
  ]

  return (
    <div className="w-full space-y-4">
      {/* AI gate indicator */}
      <motion.div
        className="glass-card p-3 flex items-center gap-3"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0 }}
      >
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
          style={{ background: `${color}15`, border: `1px solid ${color}30` }}
        >
          <Shield className="w-4.5 h-4.5" style={{ color }} />
        </div>
        <div>
          <div className="text-[10px] font-semibold text-[#e8dff5]">AI Process Gate</div>
          <div className="text-[9px] text-[#6b5a80]">Only agent-descended processes trigger rules</div>
        </div>
        <div
          className="ml-auto px-2 py-0.5 rounded text-[8px] font-bold"
          style={{ color: '#00e676', background: '#00e67612', border: '1px solid #00e67620' }}
        >
          ACTIVE
        </div>
      </motion.div>

      {/* Live detection feed */}
      <div>
        <div className="text-[9px] text-[#6b5a80] uppercase tracking-widest font-semibold mb-2 text-center">
          Live Detection Feed
        </div>
        <div className="space-y-2">
          {detections.map((d, i) => (
            <motion.div
              key={d.rule}
              className="glass-card p-3 relative overflow-hidden"
              initial={{ opacity: 0, x: 15 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: d.delay }}
            >
              <div className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ background: d.sevColor }} />
              <div className="pl-2 flex items-center gap-2">
                <div className="flex-1 min-w-0">
                  <div
                    className="text-[10px] font-mono text-[#c4b5d9] truncate"
                    style={{ fontFamily: "'JetBrains Mono', monospace" }}
                  >
                    {d.event}
                  </div>
                  <div className="text-[9px] text-[#6b5a80] mt-0.5">{d.rule}</div>
                </div>
                <span
                  className="text-[8px] font-bold px-1.5 py-0.5 rounded shrink-0"
                  style={{ color: d.sevColor, background: `${d.sevColor}12`, border: `1px solid ${d.sevColor}20` }}
                >
                  {d.severity}
                </span>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Coverage note */}
      <motion.div
        className="text-center text-[9px] text-[#6b5a80] pt-1"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.7 }}
      >
        Full MITRE ATT&CK coverage · Continuously expanding
      </motion.div>
    </div>
  )
}

function BehavioralVisual({ color }: { color: string }) {
  return (
    <div className="w-full space-y-3">
      {/* How baselining works */}
      <div className="text-center text-[9px] text-[#6b5a80] uppercase tracking-widest font-semibold mb-1">
        Baseline Controls
      </div>

      {/* Manual baseline options */}
      <motion.div
        className="glass-card p-3 relative overflow-hidden"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <div className="absolute top-0 left-0 right-0 h-[2px]" style={{ background: '#9333ea' }} />
        <div className="text-[10px] font-semibold text-[#e8dff5] mb-2">Manual Baseline</div>
        <div className="flex flex-wrap gap-1.5">
          {['24 hours', '7 days', '30 days', 'Permanent'].map((dur, i) => (
            <motion.span
              key={dur}
              className="text-[9px] px-2 py-1 rounded-lg"
              style={{
                background: dur === 'Permanent' ? '#9333ea12' : 'rgba(10,18,40,0.8)',
                border: `1px solid ${dur === 'Permanent' ? '#9333ea30' : 'rgba(147,51,234,0.1)'}`,
                color: dur === 'Permanent' ? '#9333ea' : '#c4b5d9',
              }}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2 + i * 0.06 }}
            >
              {dur}
            </motion.span>
          ))}
        </div>
      </motion.div>

      {/* Auto-learning */}
      <motion.div
        className="glass-card p-3 relative overflow-hidden"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <div className="absolute top-0 left-0 right-0 h-[2px]" style={{ background: '#00e676' }} />
        <div className="text-[10px] font-semibold text-[#e8dff5] mb-1">Auto-Learning</div>
        <div className="text-[9px] text-[#6b5a80]">Strict safety rules · Manual baseline recommended for faster accuracy</div>
      </motion.div>

      {/* Protected */}
      <motion.div
        className="glass-card p-3 relative overflow-hidden"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.45 }}
      >
        <div className="absolute top-0 left-0 right-0 h-[2px]" style={{ background: '#ff3b5c' }} />
        <div className="text-[10px] font-semibold text-[#e8dff5] mb-1">Always Protected</div>
        <div className="text-[9px] text-[#6b5a80]">Credentials, privileged files, attack infrastructure — never suppressed</div>
      </motion.div>

      {/* Feedback loop */}
      <motion.div
        className="text-center text-[9px] text-[#6b5a80] pt-1"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
      >
        Every decision trains the system · Noise decreases over time
      </motion.div>
    </div>
  )
}

function FindingsVisual({ color }: { color: string }) {
  const findings = [
    { title: 'credential_access', severity: 'Critical', sevColor: '#ff3b5c' },
    { title: 'unexpected_network', severity: 'High', sevColor: '#ff7a2f' },
    { title: 'code_tampering', severity: 'Medium', sevColor: '#f0c800' },
  ]

  return (
    <div className="w-full space-y-2">
      {findings.map((f, i) => (
        <motion.div
          key={f.title}
          className="glass-card p-3 flex items-center gap-3 relative overflow-hidden"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.15 }}
        >
          <div className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ background: f.sevColor }} />
          <div className="pl-2 flex-1">
            <div className="text-xs font-mono font-semibold text-[#e8dff5]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              ai.{f.title}
            </div>
            <div className="text-[9px] text-[#6b5a80]">MITRE ATT&CK mapped · Confidence 0.92</div>
          </div>
          <span
            className="text-[9px] font-bold px-2 py-0.5 rounded shrink-0"
            style={{ color: f.sevColor, background: `${f.sevColor}12`, border: `1px solid ${f.sevColor}20` }}
          >
            {f.severity}
          </span>
        </motion.div>
      ))}
      <motion.div
        className="flex gap-2 justify-center pt-2"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
      >
        {['Allow', 'Dismiss', 'Investigate'].map((action) => (
          <span key={action} className="text-[9px] text-[#6b5a80] px-2 py-1 rounded border border-[rgba(147,51,234,0.1)]">
            {action}
          </span>
        ))}
      </motion.div>
    </div>
  )
}

function ChainsVisual({ color }: { color: string }) {
  const steps = [
    { label: 'credential_access', time: 'T+0s', color: '#ff3b5c' },
    { label: 'unauthorized_exec', time: 'T+45s', color: '#ff7a2f' },
    { label: 'data_exfiltration', time: 'T+3m', color: '#ff3b5c' },
  ]

  return (
    <div className="w-full">
      <motion.div
        className="text-center text-[10px] font-bold uppercase tracking-widest mb-4"
        style={{ color }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        Chain: Full Compromise
      </motion.div>
      <div className="space-y-1">
        {steps.map((step, i) => (
          <div key={step.label}>
            <motion.div
              className="glass-card p-2.5 flex items-center gap-3"
              initial={{ opacity: 0, x: -15 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.2 }}
            >
              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: step.color }} />
              <span className="text-[10px] font-mono text-[#c4b5d9] flex-1" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                {step.label}
              </span>
              <span className="text-[9px] text-[#6b5a80] font-mono" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                {step.time}
              </span>
            </motion.div>
            {i < steps.length - 1 && (
              <motion.div
                className="flex justify-center"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.2 + 0.1 }}
              >
                <div className="w-px h-4" style={{ background: `${color}40` }} />
              </motion.div>
            )}
          </div>
        ))}
      </div>
      <motion.div
        className="mt-3 text-center glass-card p-2"
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.7 }}
      >
        <span className="text-[9px] font-bold text-[#ff3b5c]">CRITICAL</span>
        <span className="text-[9px] text-[#6b5a80] ml-2">Severity amplified · Cooldown bypassed</span>
      </motion.div>
    </div>
  )
}

function IncidentVisual({ color }: { color: string }) {
  const findings = [
    { time: '14:32:01', rule: 'credential_access', detail: 'python3 → .ssh/id_rsa', severity: 'CRITICAL', sevColor: '#ff3b5c' },
    { time: '14:32:18', rule: 'unauthorized_exec', detail: 'curl spawned by agent', severity: 'HIGH', sevColor: '#ff7a2f' },
    { time: '14:32:44', rule: 'data_exfiltration', detail: 'curl → 203.0.113.42:443', severity: 'CRITICAL', sevColor: '#ff3b5c' },
  ]

  return (
    <div className="w-full">
      {/* Incident header */}
      <motion.div
        className="glass-card p-3 mb-3 relative overflow-hidden"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-[#ff3b5c]" />
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-[#ff3b5c]" />
            <span className="text-xs font-semibold text-[#e8dff5]">INC-0041</span>
            <span className="text-[8px] font-bold px-1.5 py-0.5 rounded bg-[#ff3b5c12] text-[#ff3b5c] border border-[#ff3b5c20]">CRITICAL</span>
          </div>
          <span
            className="text-[8px] font-bold px-1.5 py-0.5 rounded"
            style={{ color: '#ff7a2f', background: '#ff7a2f12', border: '1px solid #ff7a2f20' }}
          >
            OPEN
          </span>
        </div>
        <div className="text-[9px] text-[#6b5a80] mt-1.5">cursor session · 2 processes · chain detected</div>
      </motion.div>

      {/* Finding timeline */}
      <div className="relative pl-4">
        {/* Vertical timeline line */}
        <motion.div
          className="absolute left-[7px] top-2 bottom-2 w-px"
          style={{ background: `linear-gradient(180deg, #ff3b5c60, ${color}30)` }}
          initial={{ scaleY: 0 }}
          animate={{ scaleY: 1 }}
          transition={{ delay: 0.2, duration: 0.5 }}
        />

        <div className="space-y-2">
          {findings.map((f, i) => (
            <motion.div
              key={f.rule}
              className="relative"
              initial={{ opacity: 0, x: 10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 + i * 0.15 }}
            >
              {/* Timeline dot */}
              <div
                className="absolute left-[-13px] top-3 w-2.5 h-2.5 rounded-full border-2"
                style={{ borderColor: f.sevColor, background: '#0a0612', boxShadow: `0 0 6px ${f.sevColor}40` }}
              />

              <div className="glass-card p-2.5 ml-2">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[9px] font-mono text-[#6b5a80]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    {f.time}
                  </span>
                  <span
                    className="text-[8px] font-bold px-1.5 py-0.5 rounded"
                    style={{ color: f.sevColor, background: `${f.sevColor}12`, border: `1px solid ${f.sevColor}20` }}
                  >
                    {f.severity}
                  </span>
                </div>
                <div className="text-[10px] font-semibold text-[#e8dff5]">{f.rule}</div>
                <div className="text-[9px] text-[#6b5a80] mt-0.5 font-mono" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                  {f.detail}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Lifecycle states */}
      <motion.div
        className="flex gap-1.5 justify-center mt-3"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.7 }}
      >
        {[
          { label: 'open', active: true },
          { label: 'investigating', active: false },
          { label: 'resolved', active: false },
          { label: 'dismissed', active: false },
        ].map((s) => (
          <span
            key={s.label}
            className="text-[8px] px-1.5 py-0.5 rounded"
            style={{
              color: s.active ? '#ff7a2f' : '#6b5a80',
              background: s.active ? '#ff7a2f12' : 'transparent',
              border: `1px solid ${s.active ? '#ff7a2f20' : 'rgba(147,51,234,0.08)'}`,
              fontWeight: s.active ? 700 : 400,
            }}
          >
            {s.label}
          </span>
        ))}
      </motion.div>
    </div>
  )
}

function AIVisual({ color }: { color: string }) {
  const windows = [
    { label: '1 min', width: '30%', color: '#9333ea', delay: 0.05 },
    { label: '1 hour', width: '42%', color: '#c4b5d9', delay: 0.12 },
    { label: '1 day', width: '54%', color: '#f0c800', delay: 0.19 },
    { label: '1 week', width: '66%', color: '#ff7a2f', delay: 0.26 },
    { label: '1 month', width: '78%', color: '#ff3b5c', delay: 0.33 },
    { label: '1 year', width: '90%', color: '#a855f7', delay: 0.40 },
  ]

  return (
    <div className="w-full space-y-4">
      {/* Context window hierarchy — expanding bars */}
      <div className="text-center text-[9px] text-[#6b5a80] uppercase tracking-widest font-semibold mb-1">
        Context Window Hierarchy
      </div>
      <div className="space-y-1.5">
        {windows.map((w) => (
          <motion.div
            key={w.label}
            className="mx-auto flex items-center gap-2"
            style={{ width: w.width }}
            initial={{ opacity: 0, scaleX: 0.5 }}
            animate={{ opacity: 1, scaleX: 1 }}
            transition={{ delay: w.delay, duration: 0.35 }}
          >
            <div
              className="flex-1 h-7 rounded-lg flex items-center justify-between px-2.5"
              style={{ background: `${w.color}12`, border: `1px solid ${w.color}25` }}
            >
              <span className="text-[9px] font-semibold" style={{ color: w.color }}>{w.label}</span>
              <span className="text-[8px] text-[#6b5a80]">context</span>
            </div>
          </motion.div>
        ))}
      </div>

      {/* APT detection callout */}
      <motion.div
        className="glass-card p-3 relative overflow-hidden"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.55 }}
      >
        <div className="absolute top-0 left-0 right-0 h-[2px]" style={{ background: color }} />
        <div className="text-[10px] font-semibold text-[#e8dff5] mb-1">APT Detection</div>
        <div className="text-[9px] text-[#6b5a80]">
          Threats invisible at 1-minute scale become obvious at weekly or monthly granularity.
          Broader windows catch slow, persistent attacks.
        </div>
      </motion.div>

      {/* Ask anything */}
      <motion.div
        className="glass-card p-2.5 flex items-center gap-2"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.7 }}
      >
        <BrainCircuit className="w-3.5 h-3.5 shrink-0" style={{ color }} />
        <div className="text-[9px] text-[#c4b5d9] italic">
          &quot;What was this agent doing last Tuesday?&quot;
        </div>
      </motion.div>
    </div>
  )
}

function AlertsVisual({ color }: { color: string }) {
  return (
    <div className="w-full space-y-3">
      {/* Simulated notification feed */}
      <div className="text-center text-[9px] text-[#6b5a80] uppercase tracking-widest font-semibold mb-1">
        Live Alert Feed
      </div>

      {/* In-app notification */}
      <motion.div
        className="glass-card p-3 relative overflow-hidden"
        initial={{ opacity: 0, x: 15 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.1 }}
      >
        <div className="absolute left-0 top-0 bottom-0 w-[3px] bg-[#ff3b5c]" />
        <div className="pl-2 flex items-center gap-2">
          <Bell className="w-3.5 h-3.5 text-[#9333ea] shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-[10px] font-semibold text-[#e8dff5]">INC-0041 · credential_access</div>
            <div className="text-[8px] text-[#6b5a80]">cursor session · just now</div>
          </div>
          <span className="text-[8px] font-bold px-1.5 py-0.5 rounded bg-[#ff3b5c12] text-[#ff3b5c] border border-[#ff3b5c20]">CRITICAL</span>
        </div>
      </motion.div>

      {/* Slack message */}
      <motion.div
        className="glass-card p-3 relative overflow-hidden"
        initial={{ opacity: 0, x: 15 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.25 }}
      >
        <div className="absolute left-0 top-0 bottom-0 w-[3px] bg-[#00e676]" />
        <div className="pl-2 flex items-center gap-2">
          <MessageSquare className="w-3.5 h-3.5 text-[#00e676] shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-[10px] font-semibold text-[#e8dff5]">#security-alerts</div>
            <div className="text-[8px] text-[#6b5a80]">Incident escalated to CRITICAL · 3 findings</div>
          </div>
          <span className="text-[8px] text-[#00e676]">Sent</span>
        </div>
      </motion.div>

      {/* Webhook delivery */}
      <motion.div
        className="glass-card p-3 relative overflow-hidden"
        initial={{ opacity: 0, x: 15 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.4 }}
      >
        <div className="absolute left-0 top-0 bottom-0 w-[3px] bg-[#ff7a2f]" />
        <div className="pl-2 flex items-center gap-2">
          <Network className="w-3.5 h-3.5 text-[#ff7a2f] shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-[10px] font-semibold text-[#e8dff5]">POST → siem.internal/webhook</div>
            <div className="text-[8px] text-[#6b5a80]">HMAC-SHA256 signed · 200 OK</div>
          </div>
          <Lock className="w-3 h-3 text-[#f0c800] shrink-0" />
        </div>
      </motion.div>

      {/* Severity gate */}
      <motion.div
        className="flex items-center justify-center gap-2 pt-1"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.55 }}
      >
        {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((sev, i) => {
          const active = i >= 2
          const sevColors = ['#00e676', '#f0c800', '#ff7a2f', '#ff3b5c']
          return (
            <span
              key={sev}
              className="text-[7px] font-bold px-1.5 py-0.5 rounded"
              style={{
                color: active ? sevColors[i] : '#6b5a8040',
                background: active ? `${sevColors[i]}12` : 'transparent',
                border: `1px solid ${active ? `${sevColors[i]}25` : 'rgba(147,51,234,0.05)'}`,
              }}
            >
              {sev}
            </span>
          )
        })}
        <span className="text-[7px] text-[#6b5a80] ml-1">gate: HIGH+</span>
      </motion.div>
    </div>
  )
}

/* ─── Router ──────────────────────────────────────────────────────────────── */

export function StageVisual({ stageId, color }: { stageId: string; color: string }) {
  const visuals: Record<string, React.ReactNode> = {
    kernel: <KernelVisual color={color} />,
    session: <SessionVisual color={color} />,
    sampling: <SamplingVisual color={color} />,
    correlation: <CorrelationVisual color={color} />,
    detection: <DetectionVisual color={color} />,
    behavioral: <BehavioralVisual color={color} />,
    findings: <FindingsVisual color={color} />,
    chains: <ChainsVisual color={color} />,
    incidents: <IncidentVisual color={color} />,
    ai: <AIVisual color={color} />,
    alerts: <AlertsVisual color={color} />,
  }

  return (
    <VisualWrap stageId={stageId}>
      {visuals[stageId] ?? <div className="text-[#6b5a80] text-sm">Visual loading...</div>}
    </VisualWrap>
  )
}
