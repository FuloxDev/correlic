'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Menu, X, Shield, User } from 'lucide-react'
import { Logo } from '@/components/ui/Logo'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/utils'

const navLinks = [
  { label: 'Home',           href: '/' },
  { label: 'How It Works',   href: '/how-it-works' },
  { label: 'Download',       href: '/download' },
  { label: 'Posts',           href: '/posts' },
  { label: 'Pricing',        href: '/pricing' },
  { label: 'About',          href: '/about' },
]

export function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [open, setOpen] = useState(false)
  const [loggedIn, setLoggedIn] = useState(false)
  const pathname = usePathname()

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', handler, { passive: true })
    return () => window.removeEventListener('scroll', handler)
  }, [])

  useEffect(() => {
    setLoggedIn(!!localStorage.getItem('correlic_token'))
  }, [pathname])

  function isActive(href: string) {
    if (href === '/') return pathname === '/'
    if (href.startsWith('#')) return false
    return pathname.startsWith(href)
  }

  return (
    <header
      className={cn(
        'fixed top-0 left-0 right-0 z-50 transition-all duration-500',
        scrolled
          ? 'bg-[rgba(10,6,18,0.95)] backdrop-blur-2xl shadow-[0_4px_40px_rgba(0,0,0,0.6)]'
          : 'bg-[rgba(10,6,18,0.5)] backdrop-blur-md'
      )}
    >
      {/* Glowing bottom border */}
      <div className={cn(
        'nav-border-glow transition-opacity duration-500',
        scrolled ? 'opacity-100' : 'opacity-40'
      )} />

      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-[5rem]">

          {/* Left — Logo */}
          <Link
            href="/"
            className="flex items-center transition-[filter] duration-300 hover:drop-shadow-[0_0_14px_rgba(147,51,234,0.45)]"
          >
            <Logo />
          </Link>

          {/* Center — nav links */}
          <div className="hidden md:flex items-center gap-0.5">
            {navLinks.map((link) => (
              <Link
                key={link.label}
                href={link.href}
                className={cn(
                  'nav-link rounded-lg',
                  isActive(link.href) && 'nav-link-active'
                )}
              >
                {link.label}
              </Link>
            ))}
          </div>

          {/* Right — Auth-aware buttons */}
          <div className="hidden md:flex items-center gap-3">
            {loggedIn ? (
              <Link href="/account">
                <Button variant="primary" size="md">
                  <User className="w-4 h-4" />
                  My Account
                </Button>
              </Link>
            ) : (
              <>
                <Link href="/login">
                  <Button variant="ghost" size="md">Sign In</Button>
                </Link>
                <Link href="/register">
                  <Button variant="primary" size="md" className="animate-pulse-glow">
                    <Shield className="w-4 h-4" />
                    Claim Your Spot
                  </Button>
                </Link>
              </>
            )}
          </div>

          {/* Mobile hamburger */}
          <button
            className="md:hidden p-2 text-[#c4b5d9] hover:text-[#e8dff5] transition-colors"
            onClick={() => setOpen(!open)}
            aria-label="Toggle menu"
          >
            {open ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>

        {/* Mobile menu */}
        {open && (
          <div className="md:hidden py-4 space-y-1 border-t border-[rgba(147,51,234,0.08)] bg-[rgba(10,6,18,0.95)] backdrop-blur-2xl -mx-4 px-4 sm:-mx-6 sm:px-6">
            {navLinks.map((link) => (
              <Link
                key={link.label}
                href={link.href}
                className={cn(
                  'block px-4 py-2.5 text-sm rounded-lg transition-all',
                  isActive(link.href)
                    ? 'text-[#e8dff5] bg-[rgba(147,51,234,0.08)] border-l-2 border-[#9333ea]'
                    : 'text-[#c4b5d9] hover:text-[#e8dff5] hover:bg-[rgba(147,51,234,0.06)]'
                )}
                onClick={() => setOpen(false)}
              >
                {link.label}
              </Link>
            ))}
            <div className="pt-3 flex flex-col gap-2 px-2">
              {loggedIn ? (
                <Link href="/account" onClick={() => setOpen(false)}>
                  <Button variant="primary" size="md" className="w-full">
                    <User className="w-4 h-4" />
                    My Account
                  </Button>
                </Link>
              ) : (
                <>
                  <Link href="/login" onClick={() => setOpen(false)}>
                    <Button variant="outline" size="md" className="w-full">Sign In</Button>
                  </Link>
                  <Link href="/register" onClick={() => setOpen(false)}>
                    <Button variant="primary" size="md" className="w-full">
                      <Shield className="w-4 h-4" />
                      Claim Your Spot
                    </Button>
                  </Link>
                </>
              )}
            </div>
          </div>
        )}
      </nav>
    </header>
  )
}
