'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { Copy, Check, Server, Monitor, Apple, Shield, Terminal as TerminalIcon, Zap, Eye, Lock, Activity } from 'lucide-react'
import Link from 'next/link'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { TerminalBlock, type TerminalLine } from '@/components/ui/TerminalBlock'
import { cn } from '@/lib/utils'

const tabs = ['Linux', 'Windows', 'macOS'] as const
type OS = typeof tabs[number]
type LinuxMethodKey = 'quick' | 'package' | 'docker'
type WindowsMethodKey = 'quick' | 'docker'
type DockerSubMethodKey = 'compose' | 'allinone'

type MethodOption = {
  command: string
  note: string
  terminalLines: TerminalLine[]
}

const linuxMethods: Record<string, MethodOption> = {
  quick: {
    command: 'curl -sSL https://correlic.com/install.sh | sudo bash',
    note: 'One command installs everything · Requires root',
    terminalLines: [
      { text: 'curl -sSL https://correlic.com/install.sh | sudo bash', type: 'command', delay: 700 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic Installer v1.0.0', type: 'info', delay: 400 },
      { text: '', type: 'blank', delay: 200 },
      { text: 'Checking prerequisites...         ok', type: 'output', delay: 400 },
      { text: 'Detected: Ubuntu 24.04 LTS', type: 'success', delay: 350 },
      { text: 'Downloading Correlic bundle...    done', type: 'output', delay: 500 },
      { text: 'Setting up PostgreSQL...          done', type: 'output', delay: 400 },
      { text: 'Setting up Neo4j...               done', type: 'output', delay: 400 },
      { text: 'Generating mTLS certificates...  done', type: 'output', delay: 350 },
      { text: 'Running migrations...            done', type: 'output', delay: 350 },
      { text: 'Installing systemd services...   done', type: 'output', delay: 350 },
      { text: 'All 5 services running', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard → http://localhost:3001', type: 'success', delay: 500 },
    ],
  },
  package: {
    command: 'curl -fsSL https://correlic.com/downloads/linux/repo/correlic.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/correlic.gpg && echo "deb [signed-by=/usr/share/keyrings/correlic.gpg] https://correlic.com/downloads/linux/repo/apt stable main" | sudo tee /etc/apt/sources.list.d/correlic.list && sudo apt update && sudo apt install correlic',
    note: 'APT/YUM package manager · Enterprise deployments',
    terminalLines: [
      { text: '# Import GPG key and add repository', type: 'info', delay: 400 },
      { text: 'curl -fsSL https://correlic.com/downloads/linux/repo/correlic.gpg.key \\', type: 'command', delay: 500 },
      { text: '  | sudo gpg --dearmor -o /usr/share/keyrings/correlic.gpg', type: 'output', delay: 300 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'echo "deb [signed-by=...] https://correlic.com/.../apt stable main" \\', type: 'command', delay: 400 },
      { text: '  | sudo tee /etc/apt/sources.list.d/correlic.list', type: 'output', delay: 300 },
      { text: '', type: 'blank', delay: 300 },
      { text: '# Install', type: 'info', delay: 300 },
      { text: 'sudo apt update && sudo apt install correlic', type: 'command', delay: 600 },
      { text: 'Setting up correlic (1.0.0)...', type: 'output', delay: 400 },
      { text: 'Correlic installed successfully', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: '# Upgrade', type: 'info', delay: 300 },
      { text: 'sudo apt update && sudo apt upgrade correlic', type: 'command', delay: 500 },
    ],
  },
}

const linuxDockerMethods: Record<DockerSubMethodKey, MethodOption> = {
  compose: {
    command: 'export API_KEY=your-key && docker compose up -d',
    note: 'Docker & Docker Compose required · API key from correlic.com',
    terminalLines: [
      { text: 'curl -sSL https://correlic.com/docker-compose.yml -o docker-compose.yml', type: 'command', delay: 600 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'export API_KEY=your-key-from-correlic-com', type: 'command', delay: 500 },
      { text: 'docker compose up -d', type: 'command', delay: 600 },
      { text: '', type: 'blank', delay: 400 },
      { text: 'Generating mTLS certificates...  done', type: 'output', delay: 400 },
      { text: 'Running migrations...            done', type: 'output', delay: 400 },
      { text: 'Starting backend services...     done', type: 'output', delay: 350 },
      { text: 'Starting eBPF agent...           done', type: 'output', delay: 350 },
      { text: 'Starting dashboard...            done', type: 'output', delay: 350 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard ready → http://localhost:3001', type: 'success', delay: 500 },
    ],
  },
  allinone: {
    command: 'docker run -d -e API_KEY=your-key --privileged --pid=host -v /sys/kernel:/sys/kernel:ro -v correlic-data:/var/lib/correlic -p 3001:3001 ghcr.io/correlic/correlic:latest',
    note: 'Docker + sudo required · No Compose needed · API key from correlic.com',
    terminalLines: [
      { text: 'docker pull ghcr.io/correlic/correlic:latest', type: 'command', delay: 700 },
      { text: 'latest: Pulling from correlic/correlic', type: 'output', delay: 500 },
      { text: 'Status: Downloaded newer image', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 400 },
      { text: 'docker run -d --name correlic \\', type: 'command', delay: 500 },
      { text: '  -e API_KEY=your-key \\', type: 'output', delay: 200 },
      { text: '  --privileged --pid=host \\', type: 'output', delay: 200 },
      { text: '  -v /sys/kernel:/sys/kernel:ro \\', type: 'output', delay: 200 },
      { text: '  -v correlic-data:/var/lib/correlic \\', type: 'output', delay: 200 },
      { text: '  -p 3001:3001 \\', type: 'output', delay: 200 },
      { text: '  ghcr.io/correlic/correlic:latest', type: 'output', delay: 300 },
      { text: '', type: 'blank', delay: 500 },
      { text: 'Initializing PostgreSQL...       done', type: 'output', delay: 400 },
      { text: 'Running migrations...            done', type: 'output', delay: 400 },
      { text: 'Starting all services...         done', type: 'output', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard ready → http://localhost:3001', type: 'success', delay: 500 },
    ],
  },
}

const windowsMethods: Record<string, MethodOption> = {
  quick: {
    command: 'irm https://correlic.com/install/win | iex',
    note: 'Windows 10/11 or Server 2019+ · Administrator',
    terminalLines: [
      { text: 'irm https://correlic.com/install/win | iex', type: 'command', delay: 700 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic Installer v1.0.0', type: 'info', delay: 400 },
      { text: '', type: 'blank', delay: 200 },
      { text: 'Running as Administrator', type: 'success', delay: 350 },
      { text: 'Downloading Correlic bundle...    done', type: 'output', delay: 500 },
      { text: 'Extracting to C:\\Correlic...       done', type: 'output', delay: 400 },
      { text: 'Setting up PostgreSQL...          done', type: 'output', delay: 400 },
      { text: 'Setting up Neo4j...               done', type: 'output', delay: 400 },
      { text: 'Generating mTLS certificates...  done', type: 'output', delay: 350 },
      { text: 'Running migrations...            done', type: 'output', delay: 350 },
      { text: 'Installing Windows services...   done', type: 'output', delay: 350 },
      { text: 'All services started', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard → http://localhost:3001', type: 'success', delay: 500 },
    ],
  },
}

const windowsDockerMethods: Record<DockerSubMethodKey, MethodOption> = {
  compose: {
    command: 'docker compose up -d',
    note: 'Docker Desktop for Windows · Agent installed separately for ETW',
    terminalLines: [
      { text: 'curl -sSL https://correlic.com/docker-compose.yml -o docker-compose.yml', type: 'command', delay: 600 },
      { text: 'set API_KEY=your-key-from-correlic-com', type: 'command', delay: 500 },
      { text: 'docker compose up -d', type: 'command', delay: 600 },
      { text: '', type: 'blank', delay: 400 },
      { text: 'Starting backend services...     done', type: 'output', delay: 400 },
      { text: 'Starting dashboard...            done', type: 'output', delay: 350 },
      { text: '', type: 'blank', delay: 400 },
      { text: '# Install Windows agent (ETW telemetry)', type: 'info', delay: 400 },
      { text: 'irm https://correlic.com/install/win-agent | iex', type: 'command', delay: 600 },
      { text: 'CorrelixAgent service registered', type: 'success', delay: 400 },
      { text: 'Agent service started', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard → http://localhost:3001', type: 'success', delay: 500 },
    ],
  },
  allinone: {
    command: 'docker run -d -e API_KEY=your-key --name correlic -v correlic-data:/var/lib/correlic -p 3001:3001 ghcr.io/correlic/correlic:latest',
    note: 'Docker Desktop · No Compose needed · Agent installed separately',
    terminalLines: [
      { text: 'docker pull ghcr.io/correlic/correlic:latest', type: 'command', delay: 700 },
      { text: 'Status: Downloaded newer image', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 400 },
      { text: 'docker run -d --name correlic ^', type: 'command', delay: 500 },
      { text: '  -e API_KEY=your-key ^', type: 'output', delay: 200 },
      { text: '  -v correlic-data:/var/lib/correlic ^', type: 'output', delay: 200 },
      { text: '  -p 3001:3001 ghcr.io/correlic/correlic:latest', type: 'output', delay: 300 },
      { text: '', type: 'blank', delay: 400 },
      { text: 'Starting all services...         done', type: 'output', delay: 400 },
      { text: '', type: 'blank', delay: 400 },
      { text: '# Install Windows agent (ETW telemetry)', type: 'info', delay: 400 },
      { text: 'irm https://correlic.com/install/win-agent | iex', type: 'command', delay: 600 },
      { text: 'CorrelixAgent service registered', type: 'success', delay: 400 },
      { text: 'Agent service started', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard → http://localhost:3001', type: 'success', delay: 500 },
    ],
  },
}

const macOSData: MethodOption = {
  command: 'curl -sSL https://correlic.com/install/macos | sudo bash',
  note: 'macOS 13+ · Full Disk Access required',
  terminalLines: [
    { text: 'curl -sSL https://correlic.com/install/macos | sudo bash', type: 'command', delay: 700 },
    { text: '', type: 'blank', delay: 300 },
    { text: 'Correlic Installer v1.0.0 (macOS)', type: 'info', delay: 400 },
    { text: '', type: 'blank', delay: 200 },
    { text: 'macOS 14 Sonoma detected', type: 'success', delay: 350 },
    { text: 'Downloading Correlic bundle...    done', type: 'output', delay: 500 },
    { text: 'Setting up PostgreSQL...          done', type: 'output', delay: 400 },
    { text: 'Generating mTLS certificates...  done', type: 'output', delay: 350 },
    { text: 'Running migrations...            done', type: 'output', delay: 350 },
    { text: 'Starting services...             done', type: 'output', delay: 350 },
    { text: '', type: 'blank', delay: 300 },
    { text: 'Correlic is running!', type: 'success', delay: 400 },
    { text: 'Dashboard → http://localhost:3001', type: 'success', delay: 500 },
  ],
}

// Security-themed bright color palette
const osDisplay: Record<OS, { icon: typeof Server; color: string; glow: string; badge?: string }> = {
  Linux:   { icon: Server,  color: '#a855f7', glow: 'rgba(168, 85, 247, 0.5)' },
  Windows: { icon: Monitor, color: '#06b6d4', glow: 'rgba(6, 182, 212, 0.5)' },
  macOS:   { icon: Apple,   color: '#f59e0b', glow: 'rgba(245, 158, 11, 0.5)', badge: 'Coming Soon' },
}

function getActiveMethod(
  os: OS,
  linuxMethod: LinuxMethodKey,
  windowsMethod: WindowsMethodKey,
  dockerSubMethod: DockerSubMethodKey,
): MethodOption {
  if (os === 'Linux') {
    if (linuxMethod === 'docker') return linuxDockerMethods[dockerSubMethod]
    return linuxMethods[linuxMethod]
  }
  if (os === 'Windows') {
    if (windowsMethod === 'docker') return windowsDockerMethods[dockerSubMethod]
    return windowsMethods[windowsMethod]
  }
  return macOSData
}

function getTerminalTitle(os: OS, linuxMethod: LinuxMethodKey, windowsMethod: WindowsMethodKey, dockerSubMethod: DockerSubMethodKey): string {
  if (os === 'Linux') {
    if (linuxMethod === 'quick') return 'bash'
    if (linuxMethod === 'package') return 'apt / yum'
    return dockerSubMethod === 'compose' ? 'docker compose' : 'docker run'
  }
  if (os === 'Windows') {
    if (windowsMethod === 'quick') return 'PowerShell (Administrator)'
    return dockerSubMethod === 'compose' ? 'docker compose + PowerShell' : 'docker run + PowerShell'
  }
  return 'terminal'
}

const securityStats = [
  { icon: Shield,   value: '13',     label: 'Detection Rules',    color: '#06b6d4' },
  { icon: Eye,      value: 'Real-time', label: 'Process Monitor', color: '#a855f7' },
  { icon: Activity, value: 'Kernel', label: 'eBPF / ETW',         color: '#00e676' },
  { icon: Lock,     value: '100%',   label: 'Self-Hosted',        color: '#f59e0b' },
]

export function DownloadSection() {
  const [os, setOs] = useState<OS>('Linux')
  const [copied, setCopied] = useState(false)
  const [linuxMethod, setLinuxMethod] = useState<LinuxMethodKey>('quick')
  const [windowsMethod, setWindowsMethod] = useState<WindowsMethodKey>('quick')
  const [dockerSubMethod, setDockerSubMethod] = useState<DockerSubMethodKey>('compose')

  const display = osDisplay[os]
  const active = getActiveMethod(os, linuxMethod, windowsMethod, dockerSubMethod)
  const isDockerSelected = (os === 'Linux' && linuxMethod === 'docker') || (os === 'Windows' && windowsMethod === 'docker')

  function copy() {
    navigator.clipboard.writeText(active.command)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <section id="download" className="py-32 relative overflow-hidden">
      {/* ── Animated grid background ── */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.07]"
        style={{
          backgroundImage: `
            linear-gradient(rgba(168, 85, 247, 0.4) 1px, transparent 1px),
            linear-gradient(90deg, rgba(6, 182, 212, 0.4) 1px, transparent 1px)
          `,
          backgroundSize: '60px 60px',
          maskImage: 'radial-gradient(ellipse 80% 60% at 50% 50%, black 30%, transparent 80%)',
        }}
      />

      {/* ── Vibrant glow blobs ── */}
      <motion.div
        className="absolute top-1/4 left-1/4 w-[500px] h-[500px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(168,85,247,0.15) 0%, transparent 60%)' }}
        animate={{ scale: [1, 1.1, 1], opacity: [0.4, 0.6, 0.4] }}
        transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut' }}
      />
      <motion.div
        className="absolute top-1/2 right-1/4 w-[500px] h-[500px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.12) 0%, transparent 60%)' }}
        animate={{ scale: [1, 1.15, 1], opacity: [0.3, 0.5, 0.3] }}
        transition={{ duration: 10, repeat: Infinity, ease: 'easeInOut', delay: 2 }}
      />
      <motion.div
        className="absolute bottom-1/4 left-1/2 w-[400px] h-[400px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(0,230,118,0.1) 0%, transparent 60%)' }}
        animate={{ scale: [1, 1.2, 1], opacity: [0.3, 0.5, 0.3] }}
        transition={{ duration: 12, repeat: Infinity, ease: 'easeInOut', delay: 4 }}
      />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        {/* ── Header ── */}
        <motion.div
          className="text-center mb-14"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          {/* Badge with pulse */}
          <motion.div
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full mb-6 relative"
            style={{
              background: 'linear-gradient(135deg, rgba(168,85,247,0.15) 0%, rgba(6,182,212,0.15) 100%)',
              border: '1px solid rgba(168,85,247,0.3)',
              boxShadow: '0 0 30px rgba(168,85,247,0.15)',
            }}
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
          >
            <motion.span
              className="w-1.5 h-1.5 rounded-full"
              style={{ background: '#00e676', boxShadow: '0 0 8px #00e676' }}
              animate={{ opacity: [1, 0.3, 1] }}
              transition={{ duration: 1.5, repeat: Infinity }}
            />
            <span className="text-xs font-bold uppercase tracking-widest"
              style={{ background: 'linear-gradient(90deg, #a855f7, #06b6d4)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              Deploy Now
            </span>
          </motion.div>

          <h2
            className="text-4xl sm:text-5xl lg:text-6xl font-bold leading-[1.1]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            <span className="text-[#e8dff5]">One Command.</span>{' '}
            <span style={{
              background: 'linear-gradient(135deg, #a855f7 0%, #06b6d4 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}>
              Total Visibility.
            </span>
          </h2>
          <p className="mt-6 text-lg text-[#c4b5d9] max-w-xl mx-auto">
            Watch every file, network call, and system event your AI agents make.
            Kernel-level monitoring in under 60 seconds.
          </p>
        </motion.div>

        {/* ── Main install card ── */}
        <motion.div
          className="relative rounded-3xl overflow-hidden"
          style={{
            background: 'linear-gradient(135deg, rgba(20, 12, 40, 0.9) 0%, rgba(15, 8, 30, 0.95) 100%)',
            border: `1.5px solid ${display.color}40`,
            boxShadow: `0 0 60px ${display.color}15, 0 20px 80px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.04)`,
            backdropFilter: 'blur(20px)',
          }}
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.1 }}
        >
          {/* Animated gradient top border */}
          <motion.div
            className="absolute top-0 left-0 right-0 h-[2px]"
            style={{
              background: `linear-gradient(90deg, transparent 0%, ${display.color} 50%, transparent 100%)`,
            }}
            animate={{ backgroundPosition: ['0% 0%', '200% 0%'] }}
            transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
          />

          {/* Corner glow */}
          <motion.div
            className="absolute -top-20 -right-20 w-64 h-64 pointer-events-none rounded-full"
            style={{ background: `radial-gradient(circle, ${display.color}25 0%, transparent 70%)` }}
            animate={{ scale: [1, 1.1, 1] }}
            transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
          />

          <div className="p-8 lg:p-10 space-y-7">

            {/* ── OS Tabs (large + glowy) ── */}
            <div className="grid grid-cols-3 gap-3">
              {tabs.map((t) => {
                const d = osDisplay[t]
                const Icon = d.icon
                const isActive = os === t
                const disabled = d.badge === 'Coming Soon'
                return (
                  <motion.button
                    key={t}
                    onClick={() => !disabled && setOs(t)}
                    disabled={disabled}
                    whileHover={!disabled && !isActive ? { y: -2 } : {}}
                    whileTap={!disabled ? { scale: 0.98 } : {}}
                    className={cn(
                      'relative px-4 py-4 rounded-2xl font-semibold transition-all duration-300 border overflow-hidden group',
                      disabled && 'cursor-not-allowed'
                    )}
                    style={{
                      background: disabled
                        ? 'linear-gradient(135deg, rgba(245,158,11,0.08) 0%, rgba(245,158,11,0.03) 100%)'
                        : isActive
                          ? `linear-gradient(135deg, ${d.color}25 0%, ${d.color}10 100%)`
                          : 'rgba(10, 6, 18, 0.5)',
                      borderColor: disabled
                        ? 'rgba(245,158,11,0.35)'
                        : isActive
                          ? `${d.color}80`
                          : 'rgba(147,51,234,0.1)',
                      boxShadow: disabled
                        ? '0 0 25px rgba(245,158,11,0.12), inset 0 0 18px rgba(245,158,11,0.05)'
                        : isActive
                          ? `0 0 30px ${d.glow}, inset 0 0 20px ${d.color}10`
                          : 'none',
                    }}
                  >
                    {/* Active glow */}
                    {isActive && !disabled && (
                      <motion.div
                        className="absolute inset-0 pointer-events-none"
                        style={{
                          background: `radial-gradient(circle at 50% 100%, ${d.color}30, transparent 70%)`,
                        }}
                        animate={{ opacity: [0.5, 0.8, 0.5] }}
                        transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
                      />
                    )}

                    {/* Coming Soon ribbon (macOS) */}
                    {disabled && (
                      <motion.div
                        className="absolute -top-[1px] -right-[1px] px-2 py-0.5 rounded-bl-lg rounded-tr-2xl text-[8px] font-bold uppercase tracking-wider"
                        style={{
                          background: 'linear-gradient(135deg, #f59e0b 0%, #f0c800 100%)',
                          color: '#0a0612',
                          boxShadow: '0 0 12px rgba(245,158,11,0.5)',
                        }}
                        animate={{ boxShadow: ['0 0 12px rgba(245,158,11,0.4)', '0 0 18px rgba(245,158,11,0.7)', '0 0 12px rgba(245,158,11,0.4)'] }}
                        transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
                      >
                        Soon
                      </motion.div>
                    )}

                    <div className="relative flex flex-col items-center gap-2">
                      <Icon
                        className="w-6 h-6 transition-transform duration-300 group-hover:scale-110"
                        style={{
                          color: disabled
                            ? '#f59e0b'
                            : isActive
                              ? d.color
                              : '#6b5a80',
                          filter: disabled
                            ? 'drop-shadow(0 0 8px rgba(245,158,11,0.5))'
                            : isActive
                              ? `drop-shadow(0 0 8px ${d.color})`
                              : 'none',
                        }}
                      />
                      <span className={cn(
                        'text-sm font-bold',
                        disabled ? 'text-[#f0c800]' : isActive ? 'text-[#e8dff5]' : 'text-[#6b5a80]'
                      )}>
                        {t}
                      </span>
                      {disabled && (
                        <span className="text-[8px] font-bold uppercase tracking-widest text-[#f59e0b]">
                          Coming Soon
                        </span>
                      )}
                    </div>
                  </motion.button>
                )
              })}
            </div>

            {/* ── Method toggle pills ── */}
            <div className="flex justify-center">
              {os === 'Linux' && (
                <div
                  className="inline-flex rounded-full p-1 gap-0.5"
                  style={{
                    background: 'rgba(0, 0, 0, 0.5)',
                    border: '1px solid rgba(147,51,234,0.2)',
                    backdropFilter: 'blur(10px)',
                  }}
                >
                  {([['quick', 'Quick Install'], ['package', 'Package Manager'], ['docker', 'Docker']] as const).map(([key, label]) => (
                    <motion.button
                      key={key}
                      onClick={() => setLinuxMethod(key)}
                      whileTap={{ scale: 0.95 }}
                      className={cn(
                        'relative px-5 py-2 rounded-full text-xs font-bold transition-all duration-300',
                        linuxMethod === key ? 'text-white' : 'text-[#6b5a80] hover:text-[#c4b5d9]'
                      )}
                      style={{
                        background: linuxMethod === key
                          ? `linear-gradient(135deg, ${display.color} 0%, ${display.color}cc 100%)`
                          : 'transparent',
                        boxShadow: linuxMethod === key ? `0 0 20px ${display.glow}` : 'none',
                      }}
                    >
                      {label}
                    </motion.button>
                  ))}
                </div>
              )}

              {os === 'Windows' && (
                <div
                  className="inline-flex rounded-full p-1 gap-0.5"
                  style={{
                    background: 'rgba(0, 0, 0, 0.5)',
                    border: '1px solid rgba(6,182,212,0.2)',
                    backdropFilter: 'blur(10px)',
                  }}
                >
                  {([['quick', 'Quick Install'], ['docker', 'Docker']] as const).map(([key, label]) => (
                    <motion.button
                      key={key}
                      onClick={() => setWindowsMethod(key)}
                      whileTap={{ scale: 0.95 }}
                      className={cn(
                        'relative px-5 py-2 rounded-full text-xs font-bold transition-all duration-300',
                        windowsMethod === key ? 'text-white' : 'text-[#6b5a80] hover:text-[#c4b5d9]'
                      )}
                      style={{
                        background: windowsMethod === key
                          ? `linear-gradient(135deg, ${display.color} 0%, ${display.color}cc 100%)`
                          : 'transparent',
                        boxShadow: windowsMethod === key ? `0 0 20px ${display.glow}` : 'none',
                      }}
                    >
                      {label}
                    </motion.button>
                  ))}
                </div>
              )}
            </div>

            {/* ── Docker sub-method toggle ── */}
            {isDockerSelected && (
              <motion.div
                className="flex justify-center"
                initial={{ opacity: 0, y: -5 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
              >
                <div
                  className="inline-flex rounded-full p-1 gap-0.5"
                  style={{
                    background: 'rgba(0, 0, 0, 0.5)',
                    border: '1px solid rgba(0,230,118,0.25)',
                  }}
                >
                  {([['compose', 'Docker Compose'], ['allinone', 'All-in-One']] as const).map(([key, label]) => (
                    <button
                      key={key}
                      onClick={() => setDockerSubMethod(key)}
                      className={cn(
                        'px-4 py-1.5 rounded-full text-[11px] font-bold transition-all duration-300',
                        dockerSubMethod === key ? 'text-white' : 'text-[#6b5a80] hover:text-[#c4b5d9]'
                      )}
                      style={{
                        background: dockerSubMethod === key
                          ? 'linear-gradient(135deg, #00e676 0%, #00c853 100%)'
                          : 'transparent',
                        boxShadow: dockerSubMethod === key ? '0 0 16px rgba(0,230,118,0.4)' : 'none',
                      }}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </motion.div>
            )}

            {/* ── Terminal block ── */}
            <div className="space-y-3 relative">
              {/* Terminal label */}
              <div className="flex items-center justify-between text-[10px] uppercase tracking-widest">
                <div className="flex items-center gap-2 text-[#6b5a80]">
                  <TerminalIcon className="w-3 h-3" style={{ color: display.color }} />
                  <span>Live Install Preview</span>
                </div>
                <div className="flex items-center gap-1.5 text-[#00e676]">
                  <motion.span
                    className="w-1 h-1 rounded-full bg-[#00e676]"
                    style={{ boxShadow: '0 0 6px #00e676' }}
                    animate={{ opacity: [1, 0.3, 1] }}
                    transition={{ duration: 1.5, repeat: Infinity }}
                  />
                  <span>Recording</span>
                </div>
              </div>

              <TerminalBlock
                key={`${os}-${linuxMethod}-${windowsMethod}-${dockerSubMethod}`}
                title={getTerminalTitle(os, linuxMethod, windowsMethod, dockerSubMethod)}
                lines={active.terminalLines}
                autoPlay={true}
                loop={true}
                loopDelay={4000}
              />

              <div className="flex items-center justify-between gap-3 flex-wrap">
                <p className="text-xs text-[#6b5a80] flex items-center gap-2">
                  <Zap className="w-3 h-3" style={{ color: display.color }} />
                  {active.note}
                </p>
                <motion.button
                  onClick={copy}
                  whileTap={{ scale: 0.95 }}
                  className="flex items-center gap-1.5 text-xs font-semibold px-3.5 py-2 rounded-lg transition-all duration-200"
                  style={{
                    color: copied ? '#00e676' : display.color,
                    background: copied
                      ? 'rgba(0,230,118,0.1)'
                      : `${display.color}10`,
                    border: `1px solid ${copied ? 'rgba(0,230,118,0.3)' : `${display.color}30`}`,
                    boxShadow: copied ? '0 0 12px rgba(0,230,118,0.2)' : `0 0 12px ${display.color}15`,
                  }}
                >
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy command'}
                </motion.button>
              </div>

              {isDockerSelected && (
                <div
                  className="flex items-start gap-2.5 px-4 py-3 rounded-xl text-xs"
                  style={{
                    background: 'linear-gradient(135deg, rgba(255,122,47,0.1) 0%, rgba(255,122,47,0.04) 100%)',
                    border: '1px solid rgba(255,122,47,0.25)',
                  }}
                >
                  <span className="text-[#ff7a2f] shrink-0 mt-0.5 font-bold">!</span>
                  <span className="text-[#c4b5d9]">
                    <code className="text-[#ff7a2f] font-bold" style={{ fontFamily: "'JetBrains Mono', monospace" }}>permission denied</code>?
                    Add your user to the docker group: <code className="text-[#06b6d4]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>sudo usermod -aG docker $USER</code> then log out and back in.
                  </span>
                </div>
              )}
            </div>

            {/* ── Security stats grid ── */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {securityStats.map((stat, i) => {
                const Icon = stat.icon
                return (
                  <motion.div
                    key={stat.label}
                    className="relative px-4 py-3 rounded-xl overflow-hidden group cursor-default"
                    style={{
                      background: 'rgba(0, 0, 0, 0.4)',
                      border: `1px solid ${stat.color}25`,
                    }}
                    initial={{ opacity: 0, y: 10 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.2 + i * 0.05 }}
                    whileHover={{ y: -2, borderColor: `${stat.color}60` }}
                  >
                    <motion.div
                      className="absolute inset-0 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity"
                      style={{ background: `radial-gradient(circle at 50% 100%, ${stat.color}20, transparent 70%)` }}
                    />
                    <div className="relative flex items-center gap-2.5">
                      <Icon className="w-4 h-4 shrink-0" style={{ color: stat.color }} />
                      <div className="min-w-0">
                        <div className="text-xs font-bold text-[#e8dff5] truncate">{stat.value}</div>
                        <div className="text-[10px] text-[#6b5a80] uppercase tracking-wider truncate">{stat.label}</div>
                      </div>
                    </div>
                  </motion.div>
                )
              })}
            </div>

            {/* ── CTAs ── */}
            <div className="pt-2 flex flex-col sm:flex-row gap-3">
              <Link href="/download" className="flex-1">
                <Button variant="outline" size="lg" className="w-full">
                  Full Install Guide →
                </Button>
              </Link>
              <Link href="/register" className="flex-1">
                <Button variant="primary" size="lg" className="w-full">
                  <Shield className="w-4 h-4" />
                  Claim Your Spot
                </Button>
              </Link>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
