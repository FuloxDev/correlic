'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState } from 'react'
import {
  Bot,
  Settings,
  Bell,
  Sparkles,
  Activity,
  Server,
  Globe,
  Shield,
} from 'lucide-react'

const UI_VERSION = process.env.NEXT_PUBLIC_UI_VERSION ?? 'v0.1.0'

const NAV_ITEMS = [
  { href: '/ai-activity', label: 'AI Activity', icon: Bot, badge: 'NEW' },
  { href: '/ai-proof', label: 'AI Proof', icon: Sparkles, badge: 'PROOF' },
  { href: '/live-feed', label: 'Live Feed', icon: Activity },
  { href: '/ports', label: 'Ports', icon: Server },
  { href: '/network', label: 'Network', icon: Globe },
  { href: '/policies', label: 'Guards', icon: Shield },
]

const PUBLIC_PATHS = ['/login', '/verify-email', '/install']

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const [isConnected] = useState(true)

  const isActive = (href: string) => {
    if (href === '/') return pathname === '/'
    return pathname.startsWith(href)
  }

  const isPublicPath = PUBLIC_PATHS.some(p => pathname.startsWith(p))
  if (isPublicPath) {
    return <>{children}</>
  }

  return (
    <div
      className="min-h-screen flex"
      style={{ backgroundColor: 'var(--theme-body)' }}
    >
      {/* Sidebar */}
      <aside
        className="w-64 flex flex-col"
        style={{
          backgroundColor: 'var(--theme-sidebar)',
          borderRight: '1px solid var(--theme-sidebar-border)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
        }}
      >
        {/* Logo */}
        <div
          className="px-5 py-5"
          style={{ borderBottom: '1px solid var(--theme-sidebar-border)' }}
        >
          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center"
              style={{
                background: 'linear-gradient(135deg, rgba(147,51,234,0.20), rgba(147,51,234,0.05))',
                border: '1px solid var(--theme-nav-active-border)',
                boxShadow: '0 0 20px var(--theme-accent-glow)',
              }}
            >
              <Shield className="w-5 h-5" style={{ color: 'var(--theme-accent)' }} />
            </div>
            <div>
              <div
                className="font-bold text-lg tracking-tight"
                style={{
                  color: 'var(--theme-text-primary)',
                  fontFamily: "'Space Grotesk', system-ui, sans-serif",
                  letterSpacing: '-0.01em',
                }}
              >
                Correlic
              </div>
              <div
                className="text-[11px] uppercase tracking-wider"
                style={{ color: 'var(--theme-text-muted)' }}
              >
                AI Visibility
              </div>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-1 mt-2">
          {NAV_ITEMS.map(item => {
            const Icon = item.icon
            const active = isActive(item.href)
            return (
              <Link
                key={item.href}
                href={item.href}
                className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium"
                style={{
                  color: active ? 'var(--theme-text-primary)' : 'var(--theme-text-secondary)',
                  background: active
                    ? 'linear-gradient(135deg, var(--theme-nav-active-from), var(--theme-nav-active-to))'
                    : 'transparent',
                  border: active
                    ? '1px solid var(--theme-nav-active-border)'
                    : '1px solid transparent',
                  boxShadow: active ? '0 0 16px var(--theme-nav-active-shadow)' : 'none',
                }}
              >
                <Icon
                  className="w-[18px] h-[18px]"
                  style={{
                    color: active ? 'var(--theme-accent)' : 'var(--theme-text-muted)',
                  }}
                />
                {item.label}
                {item.badge && (
                  <span
                    className="ml-auto text-[9px] font-semibold tracking-wider px-1.5 py-0.5 rounded"
                    style={{
                      backgroundColor: 'var(--theme-accent-dim)',
                      color: 'var(--theme-accent)',
                      border: '1px solid var(--theme-nav-active-border)',
                    }}
                  >
                    {item.badge}
                  </span>
                )}
              </Link>
            )
          })}
        </nav>

        {/* Status footer */}
        <div
          className="px-4 py-4"
          style={{ borderTop: '1px solid var(--theme-sidebar-border)' }}
        >
          <div className="flex items-center gap-2 text-xs">
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{
                backgroundColor: isConnected ? 'var(--low)' : 'var(--critical)',
                boxShadow: isConnected
                  ? '0 0 8px var(--low)'
                  : '0 0 8px var(--critical)',
              }}
            />
            <span style={{ color: isConnected ? 'var(--low)' : 'var(--critical)' }}>
              {isConnected ? 'Agent Connected' : 'Agent Offline'}
            </span>
          </div>
          <div
            className="text-[11px] mt-1 font-mono"
            style={{ color: 'var(--theme-text-muted)' }}
          >
            {UI_VERSION}
          </div>
        </div>
      </aside>

      {/* Main content area */}
      <div className="flex-1 flex flex-col">
        {/* Top bar */}
        <header
          className="h-14 flex items-center justify-between px-6"
          style={{
            backgroundColor: 'var(--theme-topbar)',
            borderBottom: '1px solid var(--theme-topbar-border)',
            backdropFilter: 'blur(12px)',
            WebkitBackdropFilter: 'blur(12px)',
          }}
        >
          <div className="flex items-center gap-3">
            <div
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
              style={{
                backgroundColor: 'var(--theme-card)',
                border: '1px solid var(--theme-card-border)',
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{
                  backgroundColor: 'var(--low)',
                  boxShadow: '0 0 6px var(--low)',
                }}
              />
              <span
                className="text-sm font-mono"
                style={{ color: 'var(--theme-text-secondary)' }}
              >
                localhost
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              className="relative p-2 rounded-lg"
              style={{ color: 'var(--theme-text-secondary)' }}
              title="Notifications"
            >
              <Bell className="w-[18px] h-[18px]" />
              <span
                className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full"
                style={{
                  backgroundColor: 'var(--critical)',
                  boxShadow: '0 0 6px var(--critical)',
                }}
              />
            </button>

            <button
              className="p-2 rounded-lg"
              style={{ color: 'var(--theme-text-secondary)' }}
              title="Settings"
            >
              <Settings className="w-[18px] h-[18px]" />
            </button>
          </div>
        </header>

        {/* Page content */}
        <main
          className="flex-1 overflow-auto"
          style={{ backgroundColor: 'transparent' }}
        >
          {children}
        </main>
      </div>
    </div>
  )
}
