import {
  Cpu, Radio, Filter, Network, Shield, Activity,
  FileSearch, GitBranch, Layers, BrainCircuit, Bell,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

export interface StageDetail {
  label: string
  text: string
}

export interface Stage {
  id: string
  index: number
  title: string
  subtitle: string
  icon: LucideIcon
  color: string
  description: string
  details: StageDetail[]
}

export const stages: Stage[] = [
  {
    id: 'kernel',
    index: 0,
    title: 'Kernel Collection',
    subtitle: 'Where It All Starts',
    icon: Cpu,
    color: '#9333ea',
    description:
      'When an AI agent like Cursor, Claude Code, or Copilot performs any action on your system, Correlic captures it directly at the kernel level — before the agent even knows it\'s being watched.',
    details: [
      { label: 'Linux', text: 'eBPF tracepoints and kprobes hook into the kernel for synchronous, zero-loss capture. Ring buffers with backpressure guarantee no event is silently dropped.' },
      { label: 'Windows', text: 'ETW providers combined with Security Audit events capture process creation, registry modifications, privilege usage, and scheduled tasks.' },
      { label: 'macOS', text: 'Built for developer workstations running AI coding assistants. kqueue monitors processes, FSEvents tracks file changes, lsof polls network connections.' },
      { label: 'Events Captured', text: 'Process execution, file access, network connections, DNS queries, registry writes, privilege changes, and process lifecycle events.' },
    ],
  },
  {
    id: 'session',
    index: 1,
    title: 'Session & PID Tracking',
    subtitle: 'Knowing Which Agent Did What',
    icon: Radio,
    color: '#c4b5d9',
    description:
      'Every AI agent process is assigned a unique session UUID that automatically inherits from parent to child — building a complete lineage tree so Correlic knows exactly which agent spawned which process.',
    details: [
      { label: 'Session UUID', text: 'Generated when an AI root process is detected. All children automatically inherit the session, linking an entire agent\'s activity into one traceable thread.' },
      { label: 'Grace Period', text: '10-second window after process exit preserves the session for late-arriving events. No orphaned events, no missing context.' },
      { label: 'Context Enrichment', text: 'Every event is enriched with full executable path, command-line arguments, working directory, and container context.' },
      { label: 'Actor Roles', text: 'Processes are classified as agent, tool, or shell — enabling smarter correlation. An agent spawning curl is tool usage, not a new agent.' },
    ],
  },
  {
    id: 'sampling',
    index: 2,
    title: 'Intelligent Sampling',
    subtitle: 'Keep What Matters, Drop What Doesn\'t',
    icon: Filter,
    color: '#f0c800',
    description:
      'Not every event is worth storing. Correlic\'s security-first sampling pipeline ensures AI agent activity is never filtered, suspicious patterns are always kept, and routine noise is intelligently removed.',
    details: [
      { label: 'AI Events Bypass', text: 'Any event from an AI agent session bypasses sampling entirely. Zero filtering for AI activity — the primary use case is never compromised.' },
      { label: 'Suspicious Patterns', text: 'Over 80 patterns are checked: SSH keys, cloud credentials, /etc/shadow, crypto material, container secrets, browser data, and more. Always kept.' },
      { label: 'Volume Reduction', text: 'Benign system activity is filtered and the remainder is sampled probabilistically — roughly 90% noise reduction while keeping every meaningful event.' },
      { label: 'Context Windows', text: 'Raw events are periodically rolled up into AI context windows for intelligent analysis, keeping storage lean while preserving full historical insight.' },
    ],
  },
  {
    id: 'correlation',
    index: 3,
    title: 'Correlation Engine',
    subtitle: 'The Heart of Correlic',
    icon: Network,
    color: '#00e676',
    description:
      'This is what Correlic is named for — correlation at the core. Every event is mapped by agent session and process ID, building a live relationship graph that connects everything an AI agent touches.',
    details: [
      { label: 'Real-Time Graph', text: 'Process tree edges are written to Neo4j immediately for exec events. When an AI agent spawns a child process, the relationship exists in the graph before detection rules even evaluate.' },
      { label: 'Batched Enrichment', text: 'File access, network connections, and other events are buffered and written in batches — ensuring graph consistency while maintaining throughput.' },
      { label: 'Dual Storage', text: 'PostgreSQL stores structured event data for fast time-series queries. Neo4j stores the relationship graph for traversal and pattern matching.' },
      { label: 'AI Propagation', text: 'The :AIAgent label propagates through the entire process tree — so even deeply nested child processes are correctly attributed to the originating AI agent.' },
    ],
  },
  {
    id: 'detection',
    index: 4,
    title: 'Threat Detection',
    subtitle: 'Purpose-Built for AI Agent Threats',
    icon: Shield,
    color: '#ff7a2f',
    description:
      'Every detection rule gates on AI process attribution first — system daemons and human activity never trigger false positives. Rules are designed for the specific ways AI agents go rogue.',
    details: [
      { label: 'AI-Gated', text: 'Rules only evaluate events from AI agent processes. This single gate eliminates the vast majority of false positives that plague traditional detection tools.' },
      { label: 'Comprehensive Coverage', text: 'Detection rules span the full MITRE ATT&CK framework — from initial access and credential theft through lateral movement, persistence, and data exfiltration. New rules are continuously added as AI agent threat patterns evolve.' },
      { label: 'Dynamic Severity', text: 'Confidence-based dampening automatically downgrades low-confidence critical findings, preventing alert fatigue while preserving real threats.' },
      { label: 'Deterministic Dedup', text: 'Each finding gets a deterministic ID — the same event never generates duplicate findings, even across retries or system restarts.' },
    ],
  },
  {
    id: 'behavioral',
    index: 5,
    title: 'Behavioral Engine',
    subtitle: 'Learning What\'s Normal',
    icon: Activity,
    color: '#c4b5d9',
    description:
      'Correlic continuously observes what your AI agents normally do and learns to suppress expected behavior — while ensuring that access to sensitive resources always generates a finding.',
    details: [
      { label: 'Auto-Learning', text: 'Strict rules govern what can be auto-learned. Only events that produce zero findings and pass safety checks become candidates. For best results, manually baseline expected agent behavior — this trains the system faster and eliminates false positives over time.' },
      { label: 'Manual Baselining', text: 'Baseline any finding temporarily for a custom period or indefinitely. Set a 24-hour window for a deployment, a week for a migration, or permanent for known-good patterns. Full control over what gets suppressed and for how long.' },
      { label: 'Protected Resources', text: 'Certain resources are always monitored regardless of baseline status — including sensitive credentials, privileged system files, high-risk network destinations, and known attack infrastructure. These protections are layered with org-defined rules for environment-specific coverage.' },
      { label: 'Continuous Improvement', text: 'Every baseline decision — auto-learned or manual — trains the system. Over time, Correlic adapts to your specific AI agent workflows and progressively reduces noise while maintaining full threat visibility.' },
    ],
  },
  {
    id: 'findings',
    index: 6,
    title: 'Findings & Triage',
    subtitle: 'Every Detection, Actionable',
    icon: FileSearch,
    color: '#f0c800',
    description:
      'Each threat detection generates a structured finding with severity, confidence, context, and MITRE technique mapping. Users can allow, dismiss, or investigate each finding — and their decisions feed back into the behavioral engine.',
    details: [
      { label: 'Suppression Pipeline', text: 'Before storage, each finding is checked against baselines, per-org exceptions, and cooldown windows. Only genuinely new, unsuppressed findings reach your dashboard.' },
      { label: 'User Actions', text: 'Allow a finding to create a baseline rule. Dismiss it to mark as false positive. Investigate to dig deeper. Every action trains the system for future accuracy.' },
      { label: 'Rule Exceptions', text: 'Create per-host, per-rule exceptions for environment-specific tuning. Suppress SSH reads on your config server without disabling credential access detection everywhere.' },
      { label: 'Cooldown Windows', text: 'Repeat findings are rate-limited to prevent alert storms. The first finding always fires; subsequent identical findings within the window are suppressed.' },
    ],
  },
  {
    id: 'chains',
    index: 7,
    title: 'Chain Correlation',
    subtitle: 'Connecting the Dots',
    icon: GitBranch,
    color: '#ff3b5c',
    description:
      'A single finding is a data point. A chain of findings is evidence. Correlic links individual detections into multi-step attack sequences — because AI agents can perform complex attack patterns faster than any human.',
    details: [
      { label: 'Attack Patterns', text: 'Credential theft followed by exfiltration. Command execution leading to unexpected network connections. Privilege escalation into persistence. Code tampering followed by data exfiltration.' },
      { label: 'Time Windows', text: 'Each pattern has a tuned window — 5 minutes for reverse shell setup, 20 minutes for credential theft chains, up to 30 minutes for full compromise sequences.' },
      { label: 'Cooldown Bypass', text: 'Chain findings always fire, even if individual component findings were recently suppressed. A multi-step attack is too important to rate-limit.' },
      { label: 'Severity Amplification', text: 'When a chain is detected, severity is amplified by one level. A medium finding becomes high. A high becomes critical. The whole is greater than the sum of its parts.' },
    ],
  },
  {
    id: 'incidents',
    index: 8,
    title: 'Incident Engine',
    subtitle: 'From Findings to Action',
    icon: Layers,
    color: '#00e676',
    description:
      'Findings are grouped by host and agent session into coherent incidents with full lifecycle management. Each incident gets a structured dossier — the foundation for AI-powered investigation.',
    details: [
      { label: 'Smart Grouping', text: 'Chain findings create new incidents with all constituent steps. Standalone findings merge into open incidents on the same host and session within a 30-minute window.' },
      { label: 'Lifecycle', text: 'Five states: open, investigating, resolved, dismissed, and auto-resolved. Low-severity seeds auto-resolve to keep your queue clean. Auto-resolved incidents reopen if a high-confidence finding merges in.' },
      { label: 'Dossier Assembly', text: 'A full incident dossier is built: process chain, detection timeline, network activity, sensitive file access, behavioral context, and related incidents — all linked and navigable.' },
      { label: 'User Engagement', text: 'Investigate incidents directly from the dashboard. View the full agent timeline, browse the process tree, and interact with the AI analysis chat.' },
    ],
  },
  {
    id: 'ai',
    index: 9,
    title: 'AI Analysis',
    subtitle: 'Evidence-Based, Never Assumed',
    icon: BrainCircuit,
    color: '#a855f7',
    description:
      'Correlic builds detailed context windows at every time scale — from 1-minute snapshots to yearly summaries. Raw events are periodically cleaned without affecting analysis, because the context windows preserve full intelligence. This is what makes Correlic capable of detecting long-term threats that other tools miss.',
    details: [
      { label: 'Context Windows', text: 'Agent activity is continuously rolled up into 1-minute, 1-hour, 1-day, 1-week, 1-month, and 1-year context windows. Each window captures a rich summary of what agents did, what they accessed, and what connections they made — at that granularity.' },
      { label: 'APT Detection', text: 'Short-term analysis catches fast attacks. But advanced persistent threats operate slowly — over days or weeks. As context windows broaden, the AI layer can spot patterns invisible at shorter time scales and flag threats that unfold across long periods.' },
      { label: 'Ask Anything', text: 'Query the AI about any incident, any agent, any time range. "What was this agent doing last Tuesday?" "Any attempts to access /etc/shadow this week?" "Show me all outbound connections from this session." The AI uses context windows to give a logical, evidence-backed response — no guesswork, no hallucination.' },
      { label: 'Zero Data Loss', text: 'Raw events in PostgreSQL are periodically cleaned to manage storage. But because context windows already captured the intelligence, analysis quality is never degraded. You get lean storage with full historical insight.' },
    ],
  },
  {
    id: 'alerts',
    index: 10,
    title: 'Alerts & Response',
    subtitle: 'The Right Alert, to the Right Place',
    icon: Bell,
    color: '#ff7a2f',
    description:
      'Every finding generates an in-app notification for full audit trail. Incidents are delivered externally via Slack or webhook — severity-gated and cryptographically signed.',
    details: [
      { label: 'In-App', text: 'All findings create in-app notifications visible in the dashboard bell. Full audit trail of everything Correlic detects — nothing is hidden.' },
      { label: 'External Delivery', text: 'Only incidents trigger Slack or webhook notifications — not individual findings. This prevents alert storms while ensuring real threats reach your team.' },
      { label: 'Severity Gating', text: 'Configure per-endpoint minimum severity. Some teams want only critical incidents on Slack, others want medium and above. No code changes required.' },
      { label: 'Webhook Security', text: 'Every webhook payload is signed with HMAC-SHA256. Receivers can verify the signature to ensure the alert is authentic and hasn\'t been tampered with.' },
    ],
  },
]
