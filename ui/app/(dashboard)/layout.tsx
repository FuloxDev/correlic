'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import { motion } from 'framer-motion';
import {
    LayoutDashboard, Settings, User, Shield, Clock, Database, ShieldAlert, Crosshair,
    Palette, Type, Menu, X,
} from 'lucide-react';
import NotificationBell from '@/components/NotificationBell';
import UserProfileModal from '@/components/UserProfileModal';
import AgentsIndicator from '@/components/AgentsIndicator';
import BackendStatusBanner from '@/components/BackendStatusBanner';
import {
    themes, fonts, applyTheme, applyFont, readStoredTheme, readStoredFont,
    type ThemeId, type FontId,
} from '@/lib/appearance';

const navItems = [
    { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/findings', icon: Crosshair, label: 'Findings' },
    { path: '/incidents', icon: ShieldAlert, label: 'Incidents' },
    { path: '/baselines', icon: Database, label: 'Baselines' },
    { path: '/timeline', icon: Clock, label: 'Timeline' },
    { path: '/settings', icon: Settings, label: 'Settings' },
];

export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    const pathname = usePathname();
    // The boot script in app/layout.tsx already applied the stored values to
    // <html>; this state only drives the (initially closed) picker, so reading
    // localStorage lazily here cannot cause a hydration mismatch.
    const [theme, setTheme] = useState<ThemeId>(readStoredTheme);
    const [font, setFont] = useState<FontId>(readStoredFont);
    const [showThemePicker, setShowThemePicker] = useState(false);
    const [showProfile, setShowProfile] = useState(false);
    const [navOpen, setNavOpen] = useState(false);

    const switchTheme = (id: ThemeId) => {
        setTheme(id);
        applyTheme(id);
    };

    const switchFont = (id: FontId) => {
        setFont(id);
        applyFont(id);
    };

    const isActive = (path: string) => {
        if (path === '/') return pathname === path;
        return pathname.startsWith(path);
    };

    const iconButtonStyle = {
        backgroundColor: 'var(--theme-accent-dim)',
        border: '1px solid var(--theme-card-border)',
    };

    return (
        <div
            className="min-h-screen text-white"
            style={{
                backgroundColor: 'var(--theme-body)',
                backgroundImage: 'var(--theme-bg-pattern)',
            }}
        >
            {/* Top Bar */}
            <header
                className="fixed top-0 left-0 right-0 h-16 backdrop-blur-xl z-50"
                style={{
                    backgroundColor: 'var(--theme-topbar)',
                    borderBottom: '1px solid var(--theme-topbar-border)',
                }}
            >
                <div className="h-full flex items-center gap-2 sm:gap-3 px-3 sm:px-6">
                    <button
                        type="button"
                        onClick={() => setNavOpen(open => !open)}
                        className="lg:hidden p-2 rounded-xl transition-colors hover:bg-white/10"
                        aria-label={navOpen ? 'Close navigation menu' : 'Open navigation menu'}
                        aria-expanded={navOpen}
                        aria-controls="dashboard-sidebar"
                        style={{ color: 'var(--theme-text-primary)' }}
                    >
                        {navOpen ? <X className="w-5 h-5" aria-hidden="true" /> : <Menu className="w-5 h-5" aria-hidden="true" />}
                    </button>

                    <Link href="/" className="flex items-center gap-2 shrink-0 lg:w-64" aria-label="Correlic dashboard home">
                        <Shield className="w-6 h-6" style={{ color: 'var(--theme-logo-color)' }} aria-hidden="true" />
                        <span className="text-xl font-semibold" style={{ color: 'var(--theme-text-primary)' }}>Correlic</span>
                    </Link>

                    <div className="flex-1" />

                    <div className="flex items-center gap-2 sm:gap-3">
                        <AgentsIndicator />

                        {/* Theme / font picker */}
                        <div className="relative">
                            <button
                                type="button"
                                onClick={() => setShowThemePicker(open => !open)}
                                className="p-2 rounded-xl transition-all duration-200 hover:scale-105"
                                style={iconButtonStyle}
                                aria-label="Switch theme or font"
                                aria-haspopup="dialog"
                                aria-expanded={showThemePicker}
                            >
                                <Palette className="w-4 h-4" style={{ color: 'var(--theme-accent)' }} aria-hidden="true" />
                            </button>
                            {showThemePicker && (
                                <>
                                    <div className="fixed inset-0 z-40" onClick={() => setShowThemePicker(false)} aria-hidden="true" />
                                    <div
                                        role="dialog"
                                        aria-label="Appearance"
                                        className="absolute right-0 top-full mt-2 p-2 rounded-xl backdrop-blur-xl z-50 min-w-[180px] animate-fade-in"
                                        style={{
                                            backgroundColor: 'var(--theme-card)',
                                            border: '1px solid var(--theme-card-border)',
                                            boxShadow: 'var(--shadow-lg)',
                                        }}
                                    >
                                        <p className="text-[10px] uppercase tracking-wider px-2 py-1 mb-1" style={{ color: 'var(--theme-text-muted)' }}>
                                            Theme
                                        </p>
                                        {themes.map(t => (
                                            <button
                                                type="button"
                                                key={t.id}
                                                onClick={() => switchTheme(t.id)}
                                                aria-pressed={theme === t.id}
                                                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-150"
                                                style={{
                                                    backgroundColor: theme === t.id ? 'var(--theme-accent-dim)' : 'transparent',
                                                    border: theme === t.id ? '1px solid var(--theme-nav-active-border)' : '1px solid transparent',
                                                }}
                                            >
                                                <span
                                                    className="w-3 h-3 rounded-full shrink-0"
                                                    style={{
                                                        backgroundColor: t.color,
                                                        boxShadow: theme === t.id ? `0 0 8px ${t.color}` : 'none',
                                                    }}
                                                    aria-hidden="true"
                                                />
                                                <span className="text-sm" style={{ color: theme === t.id ? 'var(--theme-text-primary)' : 'var(--theme-text-secondary)' }}>
                                                    {t.label}
                                                </span>
                                                {theme === t.id && (
                                                    <span className="ml-auto text-xs" style={{ color: 'var(--theme-accent)' }} aria-hidden="true">
                                                        &#10003;
                                                    </span>
                                                )}
                                            </button>
                                        ))}

                                        <div className="my-2 border-t" style={{ borderColor: 'var(--theme-card-border)' }} />

                                        <p className="text-[10px] uppercase tracking-wider px-2 py-1 mb-1 flex items-center gap-1.5" style={{ color: 'var(--theme-text-muted)' }}>
                                            <Type className="w-3 h-3" aria-hidden="true" />
                                            Font
                                        </p>
                                        {fonts.map(f => (
                                            <button
                                                type="button"
                                                key={f.id}
                                                onClick={() => switchFont(f.id)}
                                                aria-pressed={font === f.id}
                                                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-150"
                                                style={{
                                                    backgroundColor: font === f.id ? 'var(--theme-accent-dim)' : 'transparent',
                                                    border: font === f.id ? '1px solid var(--theme-nav-active-border)' : '1px solid transparent',
                                                }}
                                            >
                                                <span
                                                    className="text-sm w-6 text-center shrink-0 font-semibold"
                                                    style={{ fontFamily: `var(--font-${f.slug})`, color: font === f.id ? 'var(--theme-accent)' : 'var(--theme-text-muted)' }}
                                                    aria-hidden="true"
                                                >
                                                    Aa
                                                </span>
                                                <span className="text-sm" style={{ fontFamily: `var(--font-${f.slug})`, color: font === f.id ? 'var(--theme-text-primary)' : 'var(--theme-text-secondary)' }}>
                                                    {f.label}
                                                </span>
                                                {font === f.id && (
                                                    <span className="ml-auto text-xs" style={{ color: 'var(--theme-accent)' }} aria-hidden="true">
                                                        &#10003;
                                                    </span>
                                                )}
                                            </button>
                                        ))}
                                    </div>
                                </>
                            )}
                        </div>

                        <NotificationBell />

                        <button
                            type="button"
                            onClick={() => setShowProfile(true)}
                            className="flex items-center p-1.5 sm:p-2 hover:bg-white/10 rounded-xl transition-all"
                            aria-label="Open profile and account settings"
                            aria-haspopup="dialog"
                        >
                            <span
                                className="w-8 h-8 rounded-full flex items-center justify-center"
                                style={{
                                    background: 'linear-gradient(135deg, var(--theme-avatar-from), var(--theme-avatar-to))',
                                }}
                            >
                                <User className="w-4 h-4" aria-hidden="true" />
                            </span>
                        </button>
                    </div>
                </div>
            </header>

            {/* Drawer backdrop (mobile only) */}
            {navOpen && (
                <div
                    className="lg:hidden fixed inset-x-0 top-16 bottom-0 z-30 bg-black/50"
                    onClick={() => setNavOpen(false)}
                    aria-hidden="true"
                />
            )}

            {/* Sidebar: drawer below lg, fixed column at lg and up */}
            <aside
                id="dashboard-sidebar"
                aria-label="Primary navigation"
                className={`fixed left-0 top-16 bottom-0 w-64 z-40 backdrop-blur-xl p-4 transition-transform duration-200 ease-out lg:translate-x-0 ${navOpen ? 'translate-x-0' : '-translate-x-full'}`}
                style={{
                    backgroundColor: 'var(--theme-sidebar)',
                    borderRight: '1px solid var(--theme-sidebar-border)',
                }}
            >
                <nav className="space-y-1.5">
                    {navItems.map((item, idx) => {
                        const Icon = item.icon;
                        const active = isActive(item.path);
                        return (
                            <motion.div
                                key={item.path}
                                initial={{ opacity: 0, x: -20 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: 0.05 + idx * 0.06, duration: 0.35, ease: 'easeOut' }}
                            >
                                <Link
                                    href={item.path}
                                    onClick={() => setNavOpen(false)}
                                    aria-current={active ? 'page' : undefined}
                                    className="group/nav relative flex items-center space-x-3 px-4 py-3 rounded-xl transition-all duration-300"
                                    style={active ? {
                                        background: `linear-gradient(135deg, var(--theme-nav-active-from), var(--theme-nav-active-to))`,
                                        border: '1px solid var(--theme-nav-active-border)',
                                        boxShadow: `0 4px 20px var(--theme-nav-active-shadow), inset 0 1px 0 rgba(255,255,255,0.06)`,
                                        color: 'var(--theme-text-primary)',
                                    } : {
                                        color: 'var(--theme-text-muted)',
                                        border: '1px solid transparent',
                                    }}
                                >
                                    {active && (
                                        <motion.div
                                            layoutId="sidebar-active"
                                            className="absolute left-0 top-2 bottom-2 w-[3px] rounded-full"
                                            style={{ background: 'var(--theme-accent)' }}
                                            transition={{ type: 'spring', stiffness: 350, damping: 30 }}
                                        />
                                    )}
                                    {active && (
                                        <div className="absolute inset-x-0 top-0 h-px rounded-t-xl" style={{ background: 'linear-gradient(90deg, transparent 5%, var(--theme-accent), transparent 95%)', opacity: 0.4 }} />
                                    )}
                                    <div
                                        className="p-1 rounded-lg transition-all duration-300"
                                        style={active ? {
                                            background: 'var(--theme-accent-dim)',
                                            boxShadow: `0 0 12px var(--theme-nav-active-shadow)`,
                                        } : {}}
                                    >
                                        <Icon className="w-5 h-5 transition-transform duration-200 group-hover/nav:scale-110" aria-hidden="true" />
                                    </div>
                                    <span className="font-medium text-[14px] transition-all duration-200 group-hover/nav:translate-x-0.5">{item.label}</span>
                                    {!active && (
                                        <div className="absolute inset-0 rounded-xl opacity-0 group-hover/nav:opacity-100 transition-opacity duration-300 pointer-events-none" style={{ background: 'linear-gradient(135deg, var(--theme-nav-active-from), transparent 80%)' }} />
                                    )}
                                </Link>
                            </motion.div>
                        );
                    })}
                </nav>
            </aside>

            {/* Main Content */}
            <main className="absolute left-0 lg:left-64 right-0 top-16 bottom-0 overflow-y-auto overflow-x-hidden">
                <BackendStatusBanner />
                <div className="p-4 sm:p-6 min-w-0">
                    {children}
                </div>
            </main>

            <UserProfileModal open={showProfile} onClose={() => setShowProfile(false)} />
        </div>
    );
}
