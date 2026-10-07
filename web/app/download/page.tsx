'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'
import { TerminalBlock } from '@/components/ui/TerminalBlock'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Copy, Check, Download, Package, Terminal as TerminalIcon, Settings, Server, Monitor, Apple, Shield, Eye, Activity, Lock, Zap } from 'lucide-react'
import { cn } from '@/lib/utils'
import Link from 'next/link'

type OS = 'Linux' | 'Windows' | 'macOS'
type LinuxMethodKey = 'quick' | 'package' | 'docker'
type WindowsMethodKey = 'quick' | 'docker'
type DockerSubMethodKey = 'compose' | 'allinone'
type StepLine = { text: string; type: 'info' | 'command' | 'output' | 'success' | 'blank'; delay: number }

type MethodConfig = {
  command: string
  installSteps: StepLine[]
  requirements: string[]
  downloads: { label: string; arch: string; url?: string }[]
}

const linuxMethods: Record<string, MethodConfig> = {
  quick: {
    command: 'curl -sSL https://correlic.com/install.sh | sudo bash',
    installSteps: [
      { text: '# Run as root or with sudo', type: 'info', delay: 300 },
      { text: 'curl -sSL https://correlic.com/install.sh | sudo bash', type: 'command', delay: 600 },
      { text: '', type: 'blank', delay: 200 },
      { text: '================================================', type: 'info', delay: 400 },
      { text: '  Correlic Installer v1.0.0', type: 'info', delay: 100 },
      { text: '  Security Observability — Self-Hosted', type: 'info', delay: 100 },
      { text: '================================================', type: 'info', delay: 400 },
      { text: '', type: 'blank', delay: 200 },
      { text: '[1/10] Checking prerequisites...', type: 'output', delay: 500 },
      { text: 'Running as root', type: 'success', delay: 300 },
      { text: 'Detected: Ubuntu 24.04 LTS (apt)', type: 'success', delay: 400 },
      { text: '[2/10] Downloading Correlic bundle...', type: 'output', delay: 800 },
      { text: 'Downloaded (245MB)', type: 'success', delay: 600 },
      { text: '[3/10] Setting up PostgreSQL...', type: 'output', delay: 500 },
      { text: 'PostgreSQL 16 running on port 5432', type: 'success', delay: 400 },
      { text: '[4/10] Setting up Neo4j...', type: 'output', delay: 500 },
      { text: 'Neo4j running (bolt://localhost:7687)', type: 'success', delay: 400 },
      { text: '[5/10] Generating mTLS certificates...', type: 'output', delay: 400 },
      { text: 'Certificates generated', type: 'success', delay: 300 },
      { text: '[6/10] Running migrations...', type: 'output', delay: 400 },
      { text: 'Database initialized', type: 'success', delay: 300 },
      { text: '[7/10] Installing systemd services...', type: 'output', delay: 400 },
      { text: 'All 5 services running', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 200 },
      { text: '================================================', type: 'success', delay: 200 },
      { text: '  Correlic is running!', type: 'success', delay: 200 },
      { text: '================================================', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 200 },
      { text: '  Dashboard:    http://localhost:3001', type: 'info', delay: 300 },
      { text: '  Install dir:  /opt/correlic', type: 'info', delay: 300 },
      { text: '', type: 'blank', delay: 200 },
      { text: '  All data stays on this device.', type: 'success', delay: 500 },
    ],
    requirements: [
      'Ubuntu 20.04+, Debian 11+, RHEL 8+, Fedora 36+, or Amazon Linux 2023',
      'Kernel 5.8+ with BTF (BPF Type Format) support',
      'Root / sudo access',
      'x86_64 architecture',
      '4GB+ RAM, 1GB free disk on /opt',
    ],
    downloads: [],
  },
  package: {
    command: 'curl -fsSL https://correlic.com/downloads/linux/repo/correlic.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/correlic.gpg && echo "deb [signed-by=/usr/share/keyrings/correlic.gpg] https://correlic.com/downloads/linux/repo/apt stable main" | sudo tee /etc/apt/sources.list.d/correlic.list && sudo apt update && sudo apt install correlic',
    installSteps: [
      { text: '# Debian / Ubuntu (APT)', type: 'info', delay: 400 },
      { text: '', type: 'blank', delay: 200 },
      { text: '# Import GPG key and add repository', type: 'info', delay: 300 },
      { text: 'curl -fsSL https://correlic.com/downloads/linux/repo/correlic.gpg.key \\', type: 'command', delay: 500 },
      { text: '  | sudo gpg --dearmor -o /usr/share/keyrings/correlic.gpg', type: 'output', delay: 300 },
      { text: '', type: 'blank', delay: 200 },
      { text: 'echo "deb [signed-by=/usr/share/keyrings/correlic.gpg] \\', type: 'command', delay: 400 },
      { text: '  https://correlic.com/downloads/linux/repo/apt stable main" \\', type: 'output', delay: 200 },
      { text: '  | sudo tee /etc/apt/sources.list.d/correlic.list', type: 'output', delay: 300 },
      { text: '', type: 'blank', delay: 300 },
      { text: '# Install', type: 'info', delay: 300 },
      { text: 'sudo apt update && sudo apt install correlic', type: 'command', delay: 600 },
      { text: 'Setting up correlic (1.0.0)...', type: 'output', delay: 400 },
      { text: 'Correlic installed successfully', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 400 },
      { text: '# RHEL / Fedora (YUM)', type: 'info', delay: 400 },
      { text: 'sudo rpm --import https://correlic.com/.../correlic.gpg.key', type: 'command', delay: 400 },
      { text: 'sudo yum install correlic', type: 'command', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: '# Upgrade', type: 'info', delay: 300 },
      { text: 'sudo apt update && sudo apt upgrade correlic', type: 'command', delay: 500 },
    ],
    requirements: [
      'Ubuntu 20.04+, Debian 11+ (APT) or RHEL 8+, Fedora 36+ (YUM)',
      'Kernel 5.8+ with BTF (BPF Type Format) support',
      'Root / sudo access',
      'x86_64 architecture',
      'Managed updates via package manager',
    ],
    downloads: [],
  },
}

const linuxDockerMethods: Record<DockerSubMethodKey, MethodConfig> = {
  compose: {
    command: 'export API_KEY=your-key && docker compose up -d',
    installSteps: [
      { text: '# Step 1: Download the compose file', type: 'info', delay: 400 },
      { text: 'curl -sSL https://correlic.com/docker-compose.yml -o docker-compose.yml', type: 'command', delay: 700 },
      { text: '', type: 'blank', delay: 300 },
      { text: '# Step 2: Set your API key and start', type: 'info', delay: 300 },
      { text: 'export API_KEY=your-key-from-correlic-com', type: 'command', delay: 500 },
      { text: 'docker compose up -d', type: 'command', delay: 600 },
      { text: '', type: 'blank', delay: 400 },
      { text: 'Generating mTLS certificates...  done', type: 'output', delay: 500 },
      { text: 'Running migrations...            done', type: 'output', delay: 400 },
      { text: 'Creating default organization... done', type: 'output', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Container correlic-db-1          Started', type: 'success', delay: 350 },
      { text: 'Container correlic-neo4j-1       Started', type: 'success', delay: 350 },
      { text: 'Container correlic-backend-api-1 Started', type: 'success', delay: 300 },
      { text: 'Container correlic-backend-tel-1 Started', type: 'success', delay: 300 },
      { text: 'Container correlic-agent-1       Started', type: 'success', delay: 300 },
      { text: 'Container correlic-ui-1          Started', type: 'success', delay: 300 },
      { text: 'Container correlic-ui-proxy-1    Started', type: 'success', delay: 300 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard ready → http://localhost:3001', type: 'success', delay: 500 },
      { text: '', type: 'blank', delay: 400 },
      { text: '# Update to latest version', type: 'info', delay: 400 },
      { text: 'docker compose pull && docker compose up -d', type: 'command', delay: 500 },
    ],
    requirements: [
      'Docker and Docker Compose installed',
      'Linux host with kernel 5.8+ and BTF support',
      '4GB+ RAM available',
      'Root/sudo access (eBPF requires privileged mode)',
      'API key from correlic.com (register and get approved)',
    ],
    downloads: [
      { label: 'docker-compose.yml', arch: 'Compose file', url: 'https://correlic.com/docker-compose.yml' },
    ],
  },
  allinone: {
    command: 'docker run -d -e API_KEY=your-key --privileged --pid=host -v /sys/kernel:/sys/kernel:ro -v correlic-data:/var/lib/correlic -p 127.0.0.1:3001:3001 ghcr.io/correlic/correlic:latest',
    installSteps: [
      { text: '# Step 1: Pull the all-in-one image', type: 'info', delay: 400 },
      { text: 'docker pull ghcr.io/correlic/correlic:latest', type: 'command', delay: 700 },
      { text: 'latest: Pulling from correlic/correlic', type: 'output', delay: 500 },
      { text: 'Status: Downloaded newer image', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 400 },
      { text: '# Step 2: Run with your API key', type: 'info', delay: 300 },
      { text: 'docker run -d --name correlic \\', type: 'command', delay: 500 },
      { text: '  -e API_KEY=your-key-from-correlic-com \\', type: 'output', delay: 200 },
      { text: '  --privileged --pid=host \\', type: 'output', delay: 200 },
      { text: '  -v /sys/kernel:/sys/kernel:ro \\', type: 'output', delay: 200 },
      { text: '  -v correlic-data:/var/lib/correlic \\', type: 'output', delay: 200 },
      { text: '  -p 127.0.0.1:3001:3001 \\', type: 'output', delay: 200 },
      { text: '  ghcr.io/correlic/correlic:latest', type: 'output', delay: 300 },
      { text: '', type: 'blank', delay: 500 },
      { text: 'Initializing PostgreSQL...       done', type: 'output', delay: 500 },
      { text: 'Generating mTLS certificates...  done', type: 'output', delay: 400 },
      { text: 'Running migrations...            done', type: 'output', delay: 400 },
      { text: 'Starting all services...         done', type: 'output', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard ready → http://localhost:3001', type: 'success', delay: 500 },
      { text: '', type: 'blank', delay: 400 },
      { text: '# Update to latest version', type: 'info', delay: 400 },
      { text: 'docker pull ghcr.io/correlic/correlic:latest', type: 'command', delay: 400 },
      { text: 'docker stop correlic && docker rm correlic', type: 'command', delay: 400 },
      { text: '# Re-run the docker run command above', type: 'info', delay: 300 },
    ],
    requirements: [
      'Docker installed (no Docker Compose needed)',
      'Linux host with kernel 5.8+ and BTF support',
      '4GB+ RAM available',
      'Root/sudo access (eBPF requires privileged mode)',
      'API key from correlic.com (register and get approved)',
    ],
    downloads: [],
  },
}

const windowsMethods: Record<string, MethodConfig> = {
  quick: {
    command: 'irm https://correlic.com/install/win | iex',
    installSteps: [
      { text: '# Run in PowerShell as Administrator', type: 'info', delay: 300 },
      { text: 'irm https://correlic.com/install/win | iex', type: 'command', delay: 600 },
      { text: '', type: 'blank', delay: 200 },
      { text: '================================================', type: 'info', delay: 400 },
      { text: '  Correlic Installer v1.0.0', type: 'info', delay: 100 },
      { text: '  Security Observability - Self-Hosted', type: 'info', delay: 100 },
      { text: '================================================', type: 'info', delay: 400 },
      { text: '', type: 'blank', delay: 200 },
      { text: '[1/10] Checking prerequisites...', type: 'output', delay: 500 },
      { text: 'Running as Administrator', type: 'success', delay: 400 },
      { text: '[2/10] Downloading Correlic bundle (~580MB)...', type: 'output', delay: 800 },
      { text: 'Downloaded (582MB)', type: 'success', delay: 600 },
      { text: '[3/10] Extracting to C:\\Correlic...', type: 'output', delay: 500 },
      { text: 'Extracted to C:\\Correlic', type: 'success', delay: 400 },
      { text: '[4/10] Verifying Neo4j graph database...', type: 'output', delay: 400 },
      { text: 'Java Runtime found', type: 'success', delay: 300 },
      { text: 'Neo4j 5.26.0 found', type: 'success', delay: 300 },
      { text: '[5/10] Generating mTLS certificates...', type: 'output', delay: 500 },
      { text: 'Certificates generated (CA + server + client)', type: 'success', delay: 600 },
      { text: '[6/10] Generating configuration...', type: 'output', delay: 400 },
      { text: 'Configuration generated', type: 'success', delay: 400 },
      { text: '[7/10] Setting up PostgreSQL...', type: 'output', delay: 500 },
      { text: 'PostgreSQL running on port 5432', type: 'success', delay: 400 },
      { text: '  Migrations complete', type: 'output', delay: 400 },
      { text: '  Default organization created', type: 'output', delay: 300 },
      { text: 'Database ready', type: 'success', delay: 400 },
      { text: '[8/10] Setting up Neo4j graph database...', type: 'output', delay: 500 },
      { text: 'Neo4j running on bolt://localhost:7687', type: 'success', delay: 600 },
      { text: '[9/10] Installing agent as Windows Service...', type: 'output', delay: 500 },
      { text: 'Agent service installed (ETW monitoring active)', type: 'success', delay: 400 },
      { text: '[10/10] Starting services...', type: 'output', delay: 500 },
      { text: '  Backend API on :8080', type: 'output', delay: 300 },
      { text: '  Telemetry on :8081', type: 'output', delay: 300 },
      { text: '  Dashboard on :3001', type: 'output', delay: 300 },
      { text: '  Proxy on :8788', type: 'output', delay: 300 },
      { text: 'All services started', type: 'success', delay: 500 },
      { text: '', type: 'blank', delay: 300 },
      { text: '================================================', type: 'success', delay: 200 },
      { text: '  Correlic is running!', type: 'success', delay: 200 },
      { text: '================================================', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 200 },
      { text: '  Dashboard:    http://localhost:3001', type: 'info', delay: 300 },
      { text: '  Neo4j:        bolt://localhost:7687', type: 'info', delay: 300 },
      { text: '  Install dir:  C:\\Correlic', type: 'info', delay: 300 },
      { text: '', type: 'blank', delay: 200 },
      { text: '  All data stays on this device. Nothing is sent externally.', type: 'success', delay: 500 },
    ],
    requirements: [
      'Windows 10/11 or Windows Server 2019+',
      'Administrator privileges (right-click PowerShell → Run as Admin)',
      'x86_64 architecture',
      '4GB+ RAM available',
      'Everything is bundled — zero external dependencies',
    ],
    downloads: [],
  },
}

const windowsDockerMethods: Record<DockerSubMethodKey, MethodConfig> = {
  compose: {
    command: 'docker compose up -d',
    installSteps: [
      { text: '# Step 1: Start backend services with Docker', type: 'info', delay: 400 },
      { text: 'curl -sSL https://correlic.com/docker-compose.yml -o docker-compose.yml', type: 'command', delay: 700 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'set API_KEY=your-key-from-correlic-com', type: 'command', delay: 500 },
      { text: 'docker compose up -d', type: 'command', delay: 600 },
      { text: '', type: 'blank', delay: 400 },
      { text: 'Generating mTLS certificates...  done', type: 'output', delay: 500 },
      { text: 'Running migrations...            done', type: 'output', delay: 400 },
      { text: 'Creating default organization... done', type: 'output', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Container correlic-db-1          Started', type: 'success', delay: 350 },
      { text: 'Container correlic-neo4j-1       Started', type: 'success', delay: 350 },
      { text: 'Container correlic-backend-api-1 Started', type: 'success', delay: 300 },
      { text: 'Container correlic-backend-tel-1 Started', type: 'success', delay: 300 },
      { text: 'Container correlic-ui-1          Started', type: 'success', delay: 300 },
      { text: 'Container correlic-ui-proxy-1    Started', type: 'success', delay: 300 },
      { text: '', type: 'blank', delay: 400 },
      { text: '# Step 2: Install Windows agent (ETW telemetry)', type: 'info', delay: 400 },
      { text: '# Run in PowerShell as Administrator', type: 'info', delay: 300 },
      { text: 'irm https://correlic.com/install/win-agent | iex', type: 'command', delay: 600 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Installing Correlic Agent...', type: 'output', delay: 500 },
      { text: 'Generating mTLS certificates...  done', type: 'output', delay: 400 },
      { text: 'CorrelixAgent service registered', type: 'success', delay: 400 },
      { text: 'Agent service started (ETW monitoring active)', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard ready → http://localhost:3001', type: 'success', delay: 500 },
    ],
    requirements: [
      'Docker Desktop for Windows installed',
      'Administrator privileges (for agent install)',
      'Windows 10/11 or Windows Server 2019+',
      '4GB+ RAM available',
      'API key from correlic.com (register and get approved)',
    ],
    downloads: [
      { label: 'docker-compose.yml', arch: 'Compose file', url: 'https://correlic.com/docker-compose.yml' },
    ],
  },
  allinone: {
    command: 'docker run -d -e API_KEY=your-key --name correlic -v correlic-data:/var/lib/correlic -p 127.0.0.1:3001:3001 ghcr.io/correlic/correlic:latest',
    installSteps: [
      { text: '# Step 1: Pull and run the all-in-one image', type: 'info', delay: 400 },
      { text: 'docker pull ghcr.io/correlic/correlic:latest', type: 'command', delay: 700 },
      { text: 'latest: Pulling from correlic/correlic', type: 'output', delay: 500 },
      { text: 'Status: Downloaded newer image', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 400 },
      { text: 'docker run -d --name correlic ^', type: 'command', delay: 500 },
      { text: '  -e API_KEY=your-key-from-correlic-com ^', type: 'output', delay: 200 },
      { text: '  -v correlic-data:/var/lib/correlic ^', type: 'output', delay: 200 },
      { text: '  -p 127.0.0.1:3001:3001 ^', type: 'output', delay: 200 },
      { text: '  ghcr.io/correlic/correlic:latest', type: 'output', delay: 300 },
      { text: '', type: 'blank', delay: 500 },
      { text: 'Initializing PostgreSQL...       done', type: 'output', delay: 500 },
      { text: 'Generating mTLS certificates...  done', type: 'output', delay: 400 },
      { text: 'Running migrations...            done', type: 'output', delay: 400 },
      { text: 'Starting all services...         done', type: 'output', delay: 400 },
      { text: '', type: 'blank', delay: 400 },
      { text: '# Step 2: Install Windows agent (ETW telemetry)', type: 'info', delay: 400 },
      { text: '# Run in PowerShell as Administrator', type: 'info', delay: 300 },
      { text: 'irm https://correlic.com/install/win-agent | iex', type: 'command', delay: 600 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Installing Correlic Agent...', type: 'output', delay: 500 },
      { text: 'CorrelixAgent service registered', type: 'success', delay: 400 },
      { text: 'Agent service started (ETW monitoring active)', type: 'success', delay: 400 },
      { text: '', type: 'blank', delay: 300 },
      { text: 'Correlic is running!', type: 'success', delay: 400 },
      { text: 'Dashboard ready → http://localhost:3001', type: 'success', delay: 500 },
    ],
    requirements: [
      'Docker Desktop for Windows installed',
      'Administrator privileges (for agent install)',
      'Windows 10/11 or Windows Server 2019+',
      '4GB+ RAM available',
      'API key from correlic.com (register and get approved)',
    ],
    downloads: [],
  },
}

const osConfig: Record<OS, {
  icon: typeof Server
  color: string
  glow: string
  badge?: string
  disabled?: boolean
  animated?: boolean
}> = {
  Linux: {
    icon: Server,
    color: '#a855f7',
    glow: 'rgba(168, 85, 247, 0.5)',
    animated: true,
  },
  Windows: {
    icon: Monitor,
    color: '#06b6d4',
    glow: 'rgba(6, 182, 212, 0.5)',
    animated: true,
  },
  macOS: {
    icon: Apple,
    color: '#f59e0b',
    glow: 'rgba(245, 158, 11, 0.5)',
    badge: 'Coming Soon',
    disabled: true,
  },
}

const securityStats = [
  { icon: Shield,   value: '13',        label: 'Detection Rules', color: '#06b6d4' },
  { icon: Eye,      value: 'Real-time', label: 'Process Monitor', color: '#a855f7' },
  { icon: Activity, value: 'Kernel',    label: 'eBPF / ETW',      color: '#00e676' },
  { icon: Lock,     value: '100%',      label: 'Self-Hosted',     color: '#f59e0b' },
]

const macOSFallback: MethodConfig = {
  command: 'curl -sSL https://correlic.com/install/macos | sudo bash',
  installSteps: [
    { text: '# Install Correlic (coming soon)', type: 'info', delay: 0 },
    { text: 'curl -sSL https://correlic.com/install/macos | sudo bash', type: 'command', delay: 0 },
    { text: '', type: 'blank', delay: 0 },
    { text: '# Dashboard: http://localhost:3001', type: 'info', delay: 0 },
    { text: 'All services started successfully', type: 'success', delay: 0 },
  ],
  requirements: [
    'macOS 13 Ventura or later',
    'Apple Silicon or Intel Mac',
    'Full Disk Access permission',
  ],
  downloads: [],
}

function getActiveMethod(
  os: OS,
  linuxMethod: LinuxMethodKey,
  windowsMethod: WindowsMethodKey,
  dockerSubMethod: DockerSubMethodKey,
): MethodConfig {
  if (os === 'Linux') {
    if (linuxMethod === 'docker') return linuxDockerMethods[dockerSubMethod]
    return linuxMethods[linuxMethod]
  }
  if (os === 'Windows') {
    if (windowsMethod === 'docker') return windowsDockerMethods[dockerSubMethod]
    return windowsMethods[windowsMethod]
  }
  return macOSFallback
}

function getMethodLabel(os: OS, linuxMethod: LinuxMethodKey, windowsMethod: WindowsMethodKey, dockerSubMethod: DockerSubMethodKey): string {
  if (os === 'Linux') {
    if (linuxMethod === 'quick') return 'Quick Install'
    if (linuxMethod === 'package') return 'Package Manager'
    return dockerSubMethod === 'compose' ? 'Docker Compose' : 'Docker All-in-One'
  }
  if (os === 'Windows') {
    if (windowsMethod === 'quick') return 'Quick Install'
    return dockerSubMethod === 'compose' ? 'Docker Compose' : 'Docker All-in-One'
  }
  return 'macOS'
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

export default function DownloadPage() {
  const [os, setOs] = useState<OS>('Linux')
  const [copied, setCopied] = useState(false)
  const [linuxMethod, setLinuxMethod] = useState<LinuxMethodKey>('quick')
  const [windowsMethod, setWindowsMethod] = useState<WindowsMethodKey>('quick')
  const [dockerSubMethod, setDockerSubMethod] = useState<DockerSubMethodKey>('compose')

  const config = osConfig[os]
  const active = getActiveMethod(os, linuxMethod, windowsMethod, dockerSubMethod)
  const isDockerSelected = (os === 'Linux' && linuxMethod === 'docker') || (os === 'Windows' && windowsMethod === 'docker')

  function copy() {
    navigator.clipboard.writeText(active.command)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <>
      <Navbar />
      <main className="pt-24 pb-20 min-h-screen relative overflow-hidden">
        {/* ── Animated cyber grid background ── */}
        <div
          className="absolute inset-0 pointer-events-none opacity-[0.07]"
          style={{
            backgroundImage: `
              linear-gradient(rgba(168, 85, 247, 0.4) 1px, transparent 1px),
              linear-gradient(90deg, rgba(6, 182, 212, 0.4) 1px, transparent 1px)
            `,
            backgroundSize: '60px 60px',
            maskImage: 'radial-gradient(ellipse 80% 60% at 50% 30%, black 30%, transparent 80%)',
          }}
        />

        {/* ── Vibrant glow blobs ── */}
        <motion.div
          className="absolute top-[15%] left-[10%] w-[500px] h-[500px] rounded-full pointer-events-none"
          style={{ background: 'radial-gradient(circle, rgba(168,85,247,0.15) 0%, transparent 60%)' }}
          animate={{ scale: [1, 1.1, 1], opacity: [0.4, 0.6, 0.4] }}
          transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut' }}
        />
        <motion.div
          className="absolute top-[40%] right-[10%] w-[500px] h-[500px] rounded-full pointer-events-none"
          style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.12) 0%, transparent 60%)' }}
          animate={{ scale: [1, 1.15, 1], opacity: [0.3, 0.5, 0.3] }}
          transition={{ duration: 10, repeat: Infinity, ease: 'easeInOut', delay: 2 }}
        />

        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12 relative">

          {/* ── Header ── */}
          <motion.div
            className="text-center space-y-5"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            {/* Animated badge with pulse */}
            <motion.div
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full relative"
              style={{
                background: 'linear-gradient(135deg, rgba(168,85,247,0.15) 0%, rgba(6,182,212,0.15) 100%)',
                border: '1px solid rgba(168,85,247,0.3)',
                boxShadow: '0 0 30px rgba(168,85,247,0.15)',
              }}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
            >
              <motion.span
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: '#00e676', boxShadow: '0 0 8px #00e676' }}
                animate={{ opacity: [1, 0.3, 1] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              />
              <span className="text-xs font-bold uppercase tracking-widest"
                style={{ background: 'linear-gradient(90deg, #a855f7, #06b6d4)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                v1.0.0 · Deploy Now
              </span>
            </motion.div>

            <h1
              className="text-4xl sm:text-5xl lg:text-6xl font-bold leading-[1.1]"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              <span className="text-[#e8dff5]">Install </span>
              <span style={{
                background: 'linear-gradient(135deg, #a855f7 0%, #06b6d4 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}>
                Correlic
              </span>
            </h1>
            <p className="text-lg text-[#c4b5d9] max-w-xl mx-auto leading-relaxed">
              Self-hosted security observability for AI agents. Installs the full stack —
              agent, backend, and dashboard. <span className="text-[#e8dff5]">All data stays on your device.</span>
            </p>
          </motion.div>

          {/* OS selector — big glowy cards */}
          <div className="grid grid-cols-3 gap-3">
            {(['Linux', 'Windows', 'macOS'] as OS[]).map((t) => {
              const c = osConfig[t]
              const Icon = c.icon
              const active = os === t
              return (
                <motion.button
                  key={t}
                  onClick={() => !c.disabled && setOs(t)}
                  disabled={c.disabled}
                  whileHover={!c.disabled && !active ? { y: -2 } : {}}
                  whileTap={!c.disabled ? { scale: 0.98 } : {}}
                  className={cn(
                    "relative px-4 py-5 rounded-2xl font-semibold transition-all duration-300 border overflow-hidden group",
                    c.disabled && "cursor-not-allowed"
                  )}
                  style={{
                    background: c.disabled
                      ? 'linear-gradient(135deg, rgba(245,158,11,0.08) 0%, rgba(245,158,11,0.03) 100%)'
                      : active
                        ? `linear-gradient(135deg, ${c.color}25 0%, ${c.color}10 100%)`
                        : 'rgba(10, 6, 18, 0.5)',
                    borderColor: c.disabled
                      ? 'rgba(245,158,11,0.35)'
                      : active
                        ? `${c.color}80`
                        : 'rgba(147,51,234,0.1)',
                    boxShadow: c.disabled
                      ? '0 0 25px rgba(245,158,11,0.12), inset 0 0 18px rgba(245,158,11,0.05)'
                      : active
                        ? `0 0 30px ${c.glow}, inset 0 0 20px ${c.color}10`
                        : 'none',
                  }}
                >
                  {/* Active pulsing glow */}
                  {active && !c.disabled && (
                    <motion.div
                      className="absolute inset-0 pointer-events-none"
                      style={{
                        background: `radial-gradient(circle at 50% 100%, ${c.color}30, transparent 70%)`,
                      }}
                      animate={{ opacity: [0.5, 0.8, 0.5] }}
                      transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
                    />
                  )}

                  {/* Coming Soon ribbon (macOS) */}
                  {c.disabled && (
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
                      className="w-7 h-7 transition-transform duration-300 group-hover:scale-110"
                      style={{
                        color: c.disabled
                          ? '#f59e0b'
                          : active
                            ? c.color
                            : '#6b5a80',
                        filter: c.disabled
                          ? 'drop-shadow(0 0 8px rgba(245,158,11,0.5))'
                          : active
                            ? `drop-shadow(0 0 8px ${c.color})`
                            : 'none',
                      }}
                    />
                    <span className={cn(
                      'text-sm font-bold',
                      c.disabled ? 'text-[#f0c800]' : active ? 'text-[#e8dff5]' : 'text-[#6b5a80]'
                    )}>
                      {t}
                    </span>
                    {c.disabled && (
                      <span className="text-[8px] font-bold uppercase tracking-widest text-[#f59e0b]">
                        Coming Soon
                      </span>
                    )}
                  </div>
                </motion.button>
              )
            })}
          </div>

          {/* Primary method toggle */}
          {os === 'Linux' && (
            <div className="flex justify-center">
              <div
                className="inline-flex rounded-full p-1 gap-0.5"
                style={{
                  background: 'rgba(0, 0, 0, 0.5)',
                  border: '1px solid rgba(168,85,247,0.2)',
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
                        ? `linear-gradient(135deg, ${config.color} 0%, ${config.color}cc 100%)`
                        : 'transparent',
                      boxShadow: linuxMethod === key ? `0 0 20px ${config.glow}` : 'none',
                    }}
                  >
                    {label}
                  </motion.button>
                ))}
              </div>
            </div>
          )}

          {os === 'Windows' && (
            <div className="flex justify-center">
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
                        ? `linear-gradient(135deg, ${config.color} 0%, ${config.color}cc 100%)`
                        : 'transparent',
                      boxShadow: windowsMethod === key ? `0 0 20px ${config.glow}` : 'none',
                    }}
                  >
                    {label}
                  </motion.button>
                ))}
              </div>
            </div>
          )}

          {/* Docker sub-method toggle (Compose / All-in-One) */}
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

          {/* Quick install */}
          <div
            className="p-6 space-y-4 rounded-2xl relative overflow-hidden"
            style={{
              background: 'linear-gradient(135deg, rgba(20, 12, 40, 0.8) 0%, rgba(15, 8, 30, 0.9) 100%)',
              border: `1px solid ${config.color}30`,
              boxShadow: `0 0 30px ${config.color}10`,
            }}
          >
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-widest text-[#6b5a80]">
              <TerminalIcon className="w-3 h-3" style={{ color: config.color }} />
              <span>Quick install — {os} ({getMethodLabel(os, linuxMethod, windowsMethod, dockerSubMethod)})</span>
            </div>
            <div
              className="flex items-center gap-3 rounded-xl px-4 py-3.5"
              style={{
                background: 'rgba(0, 0, 0, 0.5)',
                border: `1px solid ${config.color}25`,
                boxShadow: `inset 0 0 20px ${config.color}08`,
              }}
            >
              <code
                className="flex-1 text-sm truncate font-semibold"
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  color: config.color,
                  textShadow: `0 0 10px ${config.color}40`,
                }}
              >
                {active.command}
              </code>
              <motion.button
                onClick={copy}
                whileTap={{ scale: 0.95 }}
                className="p-2 rounded-lg transition-all"
                style={{
                  color: copied ? '#00e676' : config.color,
                  background: copied ? 'rgba(0,230,118,0.1)' : `${config.color}12`,
                  border: `1px solid ${copied ? 'rgba(0,230,118,0.3)' : `${config.color}30`}`,
                  boxShadow: copied ? '0 0 12px rgba(0,230,118,0.3)' : `0 0 12px ${config.color}15`,
                }}
              >
                {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              </motion.button>
            </div>
          </div>

          {/* Step-by-step */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-xs font-bold text-[#6b5a80] uppercase tracking-widest">
                <Settings className="w-3.5 h-3.5" style={{ color: config.color }} />
                Step-by-step guide
              </h2>
              <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-[#00e676]">
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
              lines={active.installSteps}
              autoPlay={config.animated || false}
            />
          </div>

          {/* Requirements */}
          <div
            className="p-6 space-y-4 rounded-2xl relative overflow-hidden"
            style={{
              background: 'linear-gradient(135deg, rgba(20, 12, 40, 0.8) 0%, rgba(15, 8, 30, 0.9) 100%)',
              border: `1px solid ${config.color}25`,
              boxShadow: `0 0 30px ${config.color}08`,
            }}
          >
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4" style={{ color: config.color }} />
              <h3 className="text-sm font-bold text-[#e8dff5]">
                Requirements — {os}
                <span className="text-[#6b5a80] font-normal"> ({getMethodLabel(os, linuxMethod, windowsMethod, dockerSubMethod)})</span>
              </h3>
            </div>
            <ul className="space-y-2.5">
              {active.requirements.map((r) => (
                <li key={r} className="flex items-center gap-2.5 text-sm text-[#c4b5d9]">
                  <span
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ background: config.color, boxShadow: `0 0 6px ${config.color}` }}
                  />
                  {r}
                </li>
              ))}
            </ul>
            {isDockerSelected && (
              <div
                className="flex items-start gap-2.5 px-4 py-3 rounded-xl text-xs mt-4"
                style={{
                  background: 'linear-gradient(135deg, rgba(255,122,47,0.1) 0%, rgba(255,122,47,0.04) 100%)',
                  border: '1px solid rgba(255,122,47,0.25)',
                }}
              >
                <span className="text-[#ff7a2f] shrink-0 mt-0.5 font-bold">!</span>
                <span className="text-[#c4b5d9]">
                  If you get <code className="text-[#ff7a2f] font-bold" style={{ fontFamily: "'JetBrains Mono', monospace" }}>permission denied</code> when
                  running Docker, add your user to the docker group: <code className="text-[#06b6d4]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>sudo usermod -aG docker $USER</code> then
                  log out and back in.
                  {os === 'Linux' && ' The eBPF agent requires privileged access to monitor kernel events.'}
                  {os === 'Windows' && ' The Windows agent is installed separately for ETW kernel telemetry.'}
                </span>
              </div>
            )}
          </div>

          {/* Security stats grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {securityStats.map((stat, i) => {
              const Icon = stat.icon
              return (
                <motion.div
                  key={stat.label}
                  className="relative px-4 py-3.5 rounded-xl overflow-hidden group cursor-default"
                  style={{
                    background: 'rgba(0, 0, 0, 0.4)',
                    border: `1px solid ${stat.color}25`,
                  }}
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.05 }}
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

          {/* Manual downloads */}
          {active.downloads.length > 0 && <div className="space-y-3">
            <h2 className="flex items-center gap-2 text-xs font-bold text-[#6b5a80] uppercase tracking-widest">
              <Package className="w-3.5 h-3.5" style={{ color: config.color }} />
              Downloads
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {active.downloads.map((f) => {
                const baseClasses = "flex items-center gap-3 px-4 py-3 rounded-xl transition-all group"
                const inner = (
                  <>
                    <Download className="w-4 h-4 shrink-0 transition-colors" style={{ color: config.color }} />
                    <span
                      className="text-xs text-[#c4b5d9] truncate flex-1"
                      style={{ fontFamily: "'JetBrains Mono', monospace" }}
                    >
                      {f.label}
                    </span>
                    <Badge variant="muted" className="text-[9px] shrink-0">{f.arch}</Badge>
                  </>
                )
                return f.url ? (
                  <a
                    key={f.label}
                    href={f.url}
                    download
                    className={baseClasses}
                    style={{
                      background: 'rgba(0, 0, 0, 0.4)',
                      border: `1px solid ${config.color}25`,
                    }}
                  >
                    {inner}
                  </a>
                ) : (
                  <span
                    key={f.label}
                    className={cn(baseClasses, "opacity-50 cursor-not-allowed")}
                    style={{
                      background: 'rgba(0, 0, 0, 0.4)',
                      border: '1px solid rgba(147,51,234,0.1)',
                    }}
                    title="Coming soon"
                  >
                    {inner}
                  </span>
                )
              })}
            </div>
          </div>}

          {/* What it monitors */}
          <div
            className="p-6 space-y-4 rounded-2xl relative overflow-hidden"
            style={{
              background: 'linear-gradient(135deg, rgba(20, 12, 40, 0.8) 0%, rgba(15, 8, 30, 0.9) 100%)',
              border: '1px solid rgba(168, 85, 247, 0.25)',
              boxShadow: '0 0 30px rgba(168, 85, 247, 0.08)',
            }}
          >
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-[#a855f7]" />
              <h3 className="text-sm font-bold text-[#e8dff5]">What Correlic monitors</h3>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {[
                { text: 'AI coding assistants (Cursor, Claude Code, Copilot)', color: '#a855f7' },
                { text: 'Autonomous AI pipelines and workflows', color: '#06b6d4' },
                { text: 'LLM-powered automation frameworks', color: '#00e676' },
                { text: 'Custom agent frameworks and tool-using AI', color: '#f59e0b' },
              ].map((item) => (
                <div key={item.text} className="flex items-center gap-2.5 text-sm text-[#c4b5d9]">
                  <span
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ background: item.color, boxShadow: `0 0 6px ${item.color}` }}
                  />
                  {item.text}
                </div>
              ))}
            </div>
          </div>

          {/* CTA */}
          <motion.div
            className="p-7 rounded-2xl relative overflow-hidden flex flex-col sm:flex-row items-center justify-between gap-4"
            style={{
              background: 'linear-gradient(135deg, rgba(168,85,247,0.1) 0%, rgba(6,182,212,0.1) 100%)',
              border: '1px solid rgba(168,85,247,0.3)',
              boxShadow: '0 0 40px rgba(168,85,247,0.1)',
            }}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            {/* Animated gradient top border */}
            <motion.div
              className="absolute top-0 left-0 right-0 h-[2px]"
              style={{ background: 'linear-gradient(90deg, transparent 0%, #a855f7 50%, #06b6d4 100%)' }}
              animate={{ backgroundPosition: ['0% 0%', '200% 0%'] }}
              transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
            />
            <div className="flex items-center gap-4">
              <div
                className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0"
                style={{
                  background: 'linear-gradient(135deg, rgba(168,85,247,0.2) 0%, rgba(6,182,212,0.2) 100%)',
                  border: '1px solid rgba(168,85,247,0.4)',
                  boxShadow: '0 0 20px rgba(168,85,247,0.2)',
                }}
              >
                <Shield className="w-5 h-5 text-[#a855f7]" />
              </div>
              <div>
                <p className="font-bold text-[#e8dff5]">Questions?</p>
                <p className="text-sm text-[#c4b5d9]">Register for early access or reach out for help.</p>
              </div>
            </div>
            <Link href="/register">
              <Button variant="primary" size="lg">
                <Shield className="w-4 h-4" />
                Get Early Access →
              </Button>
            </Link>
          </motion.div>
        </div>
      </main>
      <Footer />
    </>
  )
}
