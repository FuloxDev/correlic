'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
    LayoutDashboard, Settings,
    User, Shield, Clock, Database, ShieldAlert, Crosshair, Palette, Type
} from 'lucide-react';
import NotificationBell from '@/components/NotificationBell';
import UserProfileModal from '@/components/UserProfileModal';

const themes = [
    { id: 'cyber-grid', label: 'Cyber', color: '#00d4ff' },
    { id: 'dark-forge', label: 'Forge', color: '#f59e0b' },
    { id: 'neon-ops', label: 'Neon', color: '#22c55e' },
] as const;

type ThemeId = (typeof themes)[number]['id'];

const fonts = [
    { id: 'Inter', label: 'Inter', preview: 'Aa' },
    { id: 'Space Grotesk', label: 'Space Grotesk', preview: 'Aa' },
    { id: 'JetBrains Mono', label: 'JetBrains Mono', preview: 'Aa' },
    { id: 'IBM Plex Sans', label: 'IBM Plex Sans', preview: 'Aa' },
] as const;

type FontId = (typeof fonts)[number]['id'];

export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    const pathname = usePathname();
    const [theme, setTheme] = useState<ThemeId>('cyber-grid');
    const [font, setFont] = useState<FontId>('Inter');
    const [showThemePicker, setShowThemePicker] = useState(false);
    const [showProfile, setShowProfile] = useState(false);

    useEffect(() => {
        const savedTheme = localStorage.getItem('correlic-theme') as ThemeId | null;
        if (savedTheme && themes.some(t => t.id === savedTheme)) {
            setTheme(savedTheme);
        }
        const savedFont = localStorage.getItem('correlic-font') as FontId | null;
        if (savedFont && fonts.some(f => f.id === savedFont)) {
            setFont(savedFont);
        }
    }, []);

    const switchTheme = (id: ThemeId) => {
        setTheme(id);
        localStorage.setItem('correlic-theme', id);
        document.documentElement.setAttribute('data-theme', id);
    };

    const switchFont = (id: FontId) => {
        setFont(id);
        localStorage.setItem('correlic-font', id);
        document.documentElement.style.setProperty('--active-font', id);
    };

    const navItems = [
        { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
        { path: '/findings', icon: Crosshair, label: 'Findings' },
        { path: '/incidents', icon: ShieldAlert, label: 'Incidents' },
        { path: '/baselines', icon: Database, label: 'Baselines' },
        { path: '/timeline', icon: Clock, label: 'Timeline' },
        { path: '/settings', icon: Settings, label: 'Settings' },
    ];

    const isActive = (path: string) => {
        if (path === '/') return pathname === path;
        return pathname.startsWith(path);
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
            <div
                className="fixed top-0 left-0 right-0 h-16 backdrop-blur-xl z-50"
                style={{
                    backgroundColor: 'var(--theme-topbar)',
                    borderBottom: '1px solid var(--theme-topbar-border)',
                }}
            >
                <div className="h-full flex items-center justify-between px-6">
                    <Link href="/" className="flex items-center space-x-2 w-64">
                        <Shield className="w-6 h-6" style={{ color: 'var(--theme-logo-color)' }} />
                        <span className="text-xl font-semibold" style={{ color: 'var(--theme-text-primary)' }}>Correlic</span>
                    </Link>

                    <div className="flex-1" />

                    <div className="flex items-center space-x-3">
                        {/* Theme Toggle */}
                        <div className="relative">
                            <button
                                onClick={() => setShowThemePicker(!showThemePicker)}
                                className="p-2 rounded-xl transition-all duration-200 hover:scale-105"
                                style={{
                                    backgroundColor: 'var(--theme-accent-dim)',
                                    border: '1px solid var(--theme-card-border)',
                                }}
                                title="Switch theme"
                            >
                                <Palette className="w-4 h-4" style={{ color: 'var(--theme-accent)' }} />
                            </button>
                            {showThemePicker && (
                                <>
                                    <div className="fixed inset-0 z-40" onClick={() => setShowThemePicker(false)} />
                                    <div
                                        className="absolute right-0 top-full mt-2 p-2 rounded-xl backdrop-blur-xl z-50 min-w-[160px] animate-fade-in"
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
                                                key={t.id}
                                                onClick={() => { switchTheme(t.id); }}
                                                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-150"
                                                style={{
                                                    backgroundColor: theme === t.id ? 'var(--theme-accent-dim)' : 'transparent',
                                                    border: theme === t.id ? '1px solid var(--theme-nav-active-border)' : '1px solid transparent',
                                                }}
                                            >
                                                <div
                                                    className="w-3 h-3 rounded-full shrink-0"
                                                    style={{
                                                        backgroundColor: t.color,
                                                        boxShadow: theme === t.id ? `0 0 8px ${t.color}` : 'none',
                                                    }}
                                                />
                                                <span className="text-sm" style={{ color: theme === t.id ? 'var(--theme-text-primary)' : 'var(--theme-text-secondary)' }}>
                                                    {t.label}
                                                </span>
                                                {theme === t.id && (
                                                    <span className="ml-auto text-xs" style={{ color: 'var(--theme-accent)' }}>
                                                        &#10003;
                                                    </span>
                                                )}
                                            </button>
                                        ))}

                                        <div className="my-2 border-t" style={{ borderColor: 'var(--theme-card-border)' }} />

                                        <p className="text-[10px] uppercase tracking-wider px-2 py-1 mb-1 flex items-center gap-1.5" style={{ color: 'var(--theme-text-muted)' }}>
                                            <Type className="w-3 h-3" />
                                            Font
                                        </p>
                                        {fonts.map(f => (
                                            <button
                                                key={f.id}
                                                onClick={() => { switchFont(f.id); }}
                                                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-150"
                                                style={{
                                                    backgroundColor: font === f.id ? 'var(--theme-accent-dim)' : 'transparent',
                                                    border: font === f.id ? '1px solid var(--theme-nav-active-border)' : '1px solid transparent',
                                                }}
                                            >
                                                <span
                                                    className="text-sm w-6 text-center shrink-0 font-semibold"
                                                    style={{ fontFamily: f.id, color: font === f.id ? 'var(--theme-accent)' : 'var(--theme-text-muted)' }}
                                                >
                                                    {f.preview}
                                                </span>
                                                <span className="text-sm" style={{ fontFamily: f.id, color: font === f.id ? 'var(--theme-text-primary)' : 'var(--theme-text-secondary)' }}>
                                                    {f.label}
                                                </span>
                                                {font === f.id && (
                                                    <span className="ml-auto text-xs" style={{ color: 'var(--theme-accent)' }}>
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
                            onClick={() => setShowProfile(true)}
                            className="flex items-center space-x-2 p-2 hover:bg-white/10 rounded-xl transition-all"
                            title="Profile"
                        >
                            <div
                                className="w-8 h-8 rounded-full flex items-center justify-center"
                                style={{
                                    background: 'linear-gradient(135deg, var(--theme-avatar-from), var(--theme-avatar-to))',
                                }}
                            >
                                <User className="w-4 h-4" />
                            </div>
                        </button>
                    </div>
                </div>
            </div>

            {/* Sidebar */}
            <div
                className="fixed left-0 top-16 bottom-0 w-64 backdrop-blur-xl p-4"
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
                                    {/* Active indicator bar */}
                                    {active && (
                                        <motion.div
                                            layoutId="sidebar-active"
                                            className="absolute left-0 top-2 bottom-2 w-[3px] rounded-full"
                                            style={{ background: 'var(--theme-accent)' }}
                                            transition={{ type: 'spring', stiffness: 350, damping: 30 }}
                                        />
                                    )}
                                    {/* Top edge glow for active */}
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
                                        <Icon className="w-5 h-5 transition-transform duration-200 group-hover/nav:scale-110" />
                                    </div>
                                    <span className="font-medium text-[14px] transition-all duration-200 group-hover/nav:translate-x-0.5">{item.label}</span>
                                    {/* Hover glow (non-active only) */}
                                    {!active && (
                                        <div className="absolute inset-0 rounded-xl opacity-0 group-hover/nav:opacity-100 transition-opacity duration-300 pointer-events-none" style={{ background: 'linear-gradient(135deg, var(--theme-nav-active-from), transparent 80%)' }} />
                                    )}
                                </Link>
                            </motion.div>
                        );
                    })}
                </nav>
            </div>

            {/* Main Content */}
            <main className="absolute left-64 right-0 top-16 bottom-0 overflow-auto">
                <div className="p-6">
                    {children}
                </div>
            </main>

            {/* User Profile Modal */}
            <UserProfileModal open={showProfile} onClose={() => setShowProfile(false)} />
        </div>
    );
}
