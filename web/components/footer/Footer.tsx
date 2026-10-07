import Link from 'next/link'
import { Logo } from '@/components/ui/Logo'
import { Twitter, Mail, BookOpen } from 'lucide-react'

const links = {
  Product: [
    { label: 'How It Works', href: '/how-it-works' },
    { label: 'Features',     href: '/how-it-works' },
    { label: 'Download',     href: '/download' },
    { label: 'Pricing',      href: '/pricing' },
    { label: 'Posts',         href: '/posts' },
  ],
  Company: [
    { label: 'About',           href: '/about' },
    { label: 'Feedback',        href: '/feedback' },
    { label: 'Privacy Policy',  href: '/privacy' },
    { label: 'Terms of Service', href: '/terms' },
  ],
  Account: [
    { label: 'Sign In',         href: '/login' },
    { label: 'Claim Your Spot', href: '/register' },
    { label: 'My Account',      href: '/account' },
  ],
}

export function Footer() {
  return (
    <footer className="border-t border-[rgba(147,51,234,0.08)] bg-[#0a0612] mt-24">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-10">
          {/* Brand */}
          <div className="md:col-span-2 space-y-4">
            <Logo />
            <p className="text-sm text-[#c4b5d9] leading-relaxed max-w-xs">
              Your AI agent has full access to your machine.
              <br />
              <span className="text-[#e8dff5] font-medium">We make sure you know what it does.</span>
            </p>
            <div className="flex items-center gap-3 pt-2">
              <a
                href="https://x.com/correlicHQ"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 rounded-lg border border-[rgba(147,51,234,0.10)] text-[#6b5a80] hover:text-[#9333ea] hover:border-[rgba(147,51,234,0.25)] transition-all"
                aria-label="Twitter / X"
              >
                <Twitter className="w-4 h-4" />
              </a>
              <a
                href="https://correlic.hashnode.dev/"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 rounded-lg border border-[rgba(147,51,234,0.10)] text-[#6b5a80] hover:text-[#9333ea] hover:border-[rgba(147,51,234,0.25)] transition-all"
                aria-label="Blog on Hashnode"
              >
                <BookOpen className="w-4 h-4" />
              </a>
              <a
                href="mailto:hello@correlic.com"
                className="p-2 rounded-lg border border-[rgba(147,51,234,0.10)] text-[#6b5a80] hover:text-[#9333ea] hover:border-[rgba(147,51,234,0.25)] transition-all"
                aria-label="Email"
              >
                <Mail className="w-4 h-4" />
              </a>
            </div>
          </div>

          {/* Links */}
          {Object.entries(links).map(([section, items]) => (
            <div key={section}>
              <h4 className="text-xs font-semibold text-[#6b5a80] uppercase tracking-widest mb-4">
                {section}
              </h4>
              <ul className="space-y-2.5">
                {items.map((item) => (
                  <li key={item.label}>
                    <Link
                      href={item.href}
                      className="text-sm text-[#c4b5d9] hover:text-[#e8dff5] transition-colors"
                    >
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div className="mt-14 pt-6 border-t border-[rgba(147,51,234,0.06)] flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#6b5a80]">
          <span>&copy; {new Date().getFullYear()} correlic. All rights reserved.</span>
          <div className="flex items-center gap-1.5">
            <span
              className="inline-block w-1.5 h-1.5 rounded-full bg-[#00e676]"
              style={{ animation: 'pulse-glow 2s infinite' }}
            />
            <span>Systems operational</span>
          </div>
        </div>
      </div>
    </footer>
  )
}
