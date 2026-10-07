'use client'

import { useEffect, useState } from 'react'
import { cn } from '@/lib/utils'

export interface TerminalLine {
  text: string
  type?: 'command' | 'output' | 'success' | 'alert' | 'info' | 'blank'
  delay?: number   // ms delay before this line appears
}

interface TerminalBlockProps {
  title?: string
  lines: TerminalLine[]
  className?: string
  autoPlay?: boolean
  loop?: boolean
  loopDelay?: number
}

const typeColors: Record<string, string> = {
  command: '#e8dff5',
  output:  '#c4b5d9',
  success: '#00e676',
  alert:   '#ff3b5c',
  info:    '#9333ea',
  blank:   'transparent',
}

const typePrefix: Record<string, string> = {
  command: '$ ',
  output:  '  ',
  success: '✓ ',
  alert:   '⚠ ',
  info:    '> ',
  blank:   '',
}

export function TerminalBlock({
  title = 'correlic-agent',
  lines,
  className,
  autoPlay = true,
  loop = false,
  loopDelay = 3000,
}: TerminalBlockProps) {
  const [visibleCount, setVisibleCount] = useState(autoPlay ? 0 : lines.length)
  const [showCursor, setShowCursor] = useState(true)

  useEffect(() => {
    if (!autoPlay) return

    let cancelled = false

    async function play() {
      setVisibleCount(0)
      for (let i = 0; i < lines.length; i++) {
        if (cancelled) return
        const delay = lines[i].delay ?? 400
        await new Promise((r) => setTimeout(r, delay))
        if (cancelled) return
        setVisibleCount(i + 1)
      }
      if (loop && !cancelled) {
        await new Promise((r) => setTimeout(r, loopDelay))
        if (!cancelled) play()
      }
    }

    play()
    return () => { cancelled = true }
  }, [autoPlay, lines, loop, loopDelay])

  // Cursor blink
  useEffect(() => {
    const t = setInterval(() => setShowCursor((v) => !v), 530)
    return () => clearInterval(t)
  }, [])

  return (
    <div
      className={cn(
        'rounded-[0.875rem] overflow-hidden border border-[rgba(147,51,234,0.15)] bg-[#0a0612]',
        'shadow-[0_8px_40px_rgba(0,0,0,0.7)]',
        className
      )}
    >
      {/* Title bar */}
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[rgba(147,51,234,0.08)] bg-[#120a24]">
        <span className="w-3 h-3 rounded-full bg-[#ff3b5c] opacity-80" />
        <span className="w-3 h-3 rounded-full bg-[#f0c800] opacity-80" />
        <span className="w-3 h-3 rounded-full bg-[#00e676] opacity-80" />
        <span
          className="ml-auto text-xs text-[#6b5a80] select-none"
          style={{ fontFamily: "'JetBrains Mono', monospace" }}
        >
          {title}
        </span>
      </div>

      {/* Content */}
      <div
        className="p-5 space-y-1 min-h-[180px]"
        style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.8rem', lineHeight: '1.7' }}
      >
        {lines.slice(0, visibleCount).map((line, i) => {
          const t = line.type ?? 'output'
          if (t === 'blank') return <div key={i} className="h-3" />
          return (
            <div key={i} className="flex gap-1" style={{ color: typeColors[t] }}>
              <span className="opacity-60 select-none shrink-0">{typePrefix[t]}</span>
              <span>{line.text}</span>
              {i === visibleCount - 1 && visibleCount < lines.length && (
                <span className="ml-0.5 text-[#9333ea]" style={{ opacity: showCursor ? 1 : 0 }}>▌</span>
              )}
            </div>
          )
        })}

        {/* Idle cursor when done */}
        {visibleCount === lines.length && (
          <div
            className="flex gap-1"
            style={{ color: typeColors.command, fontFamily: "'JetBrains Mono', monospace" }}
          >
            <span className="opacity-60 select-none">$ </span>
            <span className="text-[#9333ea]" style={{ opacity: showCursor ? 1 : 0 }}>▌</span>
          </div>
        )}
      </div>
    </div>
  )
}
