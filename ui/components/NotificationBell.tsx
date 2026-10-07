'use client'

import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Bell, Check, CheckCheck, X, ShieldAlert, AlertTriangle, Info } from 'lucide-react'
import { useRouter } from 'next/navigation'
import {
    getNotificationCount,
    getNotifications,
    markNotificationRead,
    markAllNotificationsRead,
    dismissNotification,
    getFinding,
    AppNotification,
} from '@/lib/api-client'

function timeAgo(dateStr: string): string {
    const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
    if (seconds < 60) return 'just now'
    const minutes = Math.floor(seconds / 60)
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    return `${days}d ago`
}

function severityIcon(severity: string) {
    switch (severity) {
        case 'critical':
            return <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0" />
        case 'high':
            return <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0" />
        case 'medium':
            return <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0" />
        default:
            return <Info className="w-4 h-4 text-blue-400 flex-shrink-0" />
    }
}

interface GroupedNotification {
    latest: AppNotification
    allIds: string[]
    count: number
    unreadCount: number
}

export default function NotificationBell() {
    const [unreadCount, setUnreadCount] = useState(0)
    const [isOpen, setIsOpen] = useState(false)
    const [notifications, setNotifications] = useState<AppNotification[]>([])
    const [loading, setLoading] = useState(false)
    const panelRef = useRef<HTMLDivElement>(null)
    const prevUnreadRef = useRef<number>(0)
    const initialLoadRef = useRef(true)
    const router = useRouter()

    // Group notifications by reference (incident/finding ID)
    const grouped = useMemo(() => {
        const groups = new Map<string, GroupedNotification>()
        for (const n of notifications) {
            const key = n.reference_id && n.reference_type
                ? `${n.reference_type}:${n.reference_id}`
                : n.id // ungrouped fallback
            const existing = groups.get(key)
            if (!existing) {
                groups.set(key, {
                    latest: n,
                    allIds: [n.id],
                    count: 1,
                    unreadCount: n.read ? 0 : 1,
                })
            } else {
                existing.allIds.push(n.id)
                existing.count++
                if (!n.read) existing.unreadCount++
                // Keep highest severity or most recent as representative
                if (new Date(n.created_at) > new Date(existing.latest.created_at)) {
                    existing.latest = n
                }
            }
        }
        return Array.from(groups.values())
    }, [notifications])

    // Desktop notification helper
    const showDesktopNotification = useCallback(async (newCount: number) => {
        if (typeof window === 'undefined' || !('Notification' in window)) return
        if (Notification.permission === 'default') {
            await Notification.requestPermission()
        }
        if (Notification.permission !== 'granted') return

        // Fetch the latest notifications to get actual titles
        try {
            const data = await getNotifications(false, newCount)
            const fresh = data.notifications?.filter(n => !n.read).slice(0, newCount) || []
            if (fresh.length === 0) return

            if (fresh.length === 1) {
                const n = fresh[0]
                const severityEmoji = n.severity === 'critical' ? '🔴' : n.severity === 'high' ? '🟠' : n.severity === 'medium' ? '🟡' : '🔵'
                new Notification(`${severityEmoji} ${n.title}`, {
                    body: n.summary || `${n.severity} severity alert`,
                    icon: '/favicon.ico',
                    tag: `correlic-${n.id}`,
                })
            } else {
                const critical = fresh.filter(n => n.severity === 'critical').length
                const high = fresh.filter(n => n.severity === 'high').length
                const parts: string[] = []
                if (critical > 0) parts.push(`${critical} critical`)
                if (high > 0) parts.push(`${high} high`)
                if (fresh.length - critical - high > 0) parts.push(`${fresh.length - critical - high} other`)

                new Notification(`Correlic: ${fresh.length} new alerts`, {
                    body: parts.join(', '),
                    icon: '/favicon.ico',
                    tag: 'correlic-batch',
                })
            }
        } catch { /* silent — don't block UI for desktop notification failure */ }
    }, [])

    // Poll unread count every 10s
    const fetchCount = useCallback(async () => {
        try {
            const data = await getNotificationCount()
            const newCount = data.unread_count
            const prev = prevUnreadRef.current

            // Fire desktop notification when count increases (skip initial load)
            if (!initialLoadRef.current && newCount > prev) {
                showDesktopNotification(newCount - prev)
            }

            initialLoadRef.current = false
            prevUnreadRef.current = newCount
            setUnreadCount(newCount)
        } catch { /* silent */ }
    }, [showDesktopNotification])

    useEffect(() => {
        fetchCount()
        const interval = setInterval(fetchCount, 10000)
        return () => clearInterval(interval)
    }, [fetchCount])

    // Request notification permission proactively on first user interaction with bell
    const handleBellClick = useCallback(() => {
        if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission()
        }
        setIsOpen(prev => !prev)
    }, [])

    // Load notifications when panel opens
    useEffect(() => {
        if (!isOpen) return
        setLoading(true)
        getNotifications(false, 50)
            .then(data => setNotifications(data.notifications))
            .catch(() => {})
            .finally(() => setLoading(false))
    }, [isOpen])

    // Close on outside click
    useEffect(() => {
        if (!isOpen) return
        function handleClick(e: MouseEvent) {
            if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
                setIsOpen(false)
            }
        }
        document.addEventListener('mousedown', handleClick)
        return () => document.removeEventListener('mousedown', handleClick)
    }, [isOpen])

    const handleMarkRead = async (ids: string[]) => {
        await Promise.allSettled(ids.map(id => markNotificationRead(id)))
        setNotifications(prev => prev.map(n => ids.includes(n.id) ? { ...n, read: true } : n))
        setUnreadCount(prev => Math.max(0, prev - ids.length))
    }

    const handleMarkAllRead = async () => {
        await markAllNotificationsRead().catch(() => {})
        setNotifications(prev => prev.map(n => ({ ...n, read: true })))
        setUnreadCount(0)
    }

    const handleDismiss = async (ids: string[], unreadInGroup: number) => {
        await Promise.allSettled(ids.map(id => dismissNotification(id)))
        const idSet = new Set(ids)
        setNotifications(prev => prev.filter(n => !idSet.has(n.id)))
        if (unreadInGroup > 0) setUnreadCount(prev => Math.max(0, prev - unreadInGroup))
    }

    const handleClick = async (g: GroupedNotification) => {
        const n = g.latest
        if (g.unreadCount > 0) handleMarkRead(g.allIds.filter(id => {
            const notif = notifications.find(x => x.id === id)
            return notif && !notif.read
        }))
        if (n.reference_type === 'incident' && n.reference_id) {
            router.push(`/incidents/${encodeURIComponent(n.reference_id)}`)
            setIsOpen(false)
        } else if (n.reference_type === 'finding' && n.reference_id) {
            setIsOpen(false)
            try {
                const finding = await getFinding(n.reference_id)
                if (finding.incident_id) {
                    router.push(`/incidents/${encodeURIComponent(finding.incident_id)}`)
                } else {
                    router.push('/findings')
                }
            } catch {
                router.push('/findings')
            }
        } else {
            router.push('/incidents')
            setIsOpen(false)
        }
    }

    return (
        <div className="relative" ref={panelRef}>
            <button
                onClick={handleBellClick}
                className="relative p-2 hover:bg-white/10 rounded-xl transition-all duration-200"
            >
                <Bell className="w-5 h-5" />
                {unreadCount > 0 && (
                    <span className="absolute -top-0.5 -right-0.5 min-w-[18px] h-[18px] bg-red-500 rounded-full text-[10px] font-bold flex items-center justify-center px-1">
                        {unreadCount > 99 ? '99+' : unreadCount}
                    </span>
                )}
            </button>

            {isOpen && (
                <div className="absolute right-0 top-full mt-2 w-96 bg-[#1a1a2e] border border-orange-900/30 rounded-xl shadow-2xl shadow-black/50 z-50 overflow-hidden">
                    {/* Header */}
                    <div className="flex items-center justify-between px-4 py-3 border-b border-white/10">
                        <h3 className="text-sm font-semibold">Notifications</h3>
                        {unreadCount > 0 && (
                            <button
                                onClick={handleMarkAllRead}
                                className="text-xs text-orange-400 hover:text-orange-300 flex items-center gap-1"
                            >
                                <CheckCheck className="w-3.5 h-3.5" />
                                Mark all read
                            </button>
                        )}
                    </div>

                    {/* List */}
                    <div className="max-h-[400px] overflow-y-auto">
                        {loading && (
                            <div className="p-8 text-center text-gray-500 text-sm">Loading...</div>
                        )}
                        {!loading && grouped.length === 0 && (
                            <div className="p-8 text-center text-gray-500 text-sm">No notifications</div>
                        )}
                        {!loading && grouped.map(g => {
                            const n = g.latest
                            const hasUnread = g.unreadCount > 0
                            return (
                                <div
                                    key={g.allIds[0]}
                                    className={`flex items-start gap-3 px-4 py-3 border-b border-white/5 hover:bg-white/5 cursor-pointer transition-colors ${hasUnread ? 'bg-orange-500/5' : ''}`}
                                    onClick={() => handleClick(g)}
                                >
                                    {severityIcon(n.severity)}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2">
                                            <span className={`text-sm truncate ${hasUnread ? 'font-medium text-white' : 'text-gray-300'}`}>
                                                {n.title}
                                            </span>
                                            {hasUnread && (
                                                <span className="w-2 h-2 bg-orange-500 rounded-full flex-shrink-0" />
                                            )}
                                            {g.count > 1 && (
                                                <span className="px-1.5 py-0.5 text-[10px] bg-white/10 text-gray-400 rounded-full flex-shrink-0">
                                                    {g.count}x
                                                </span>
                                            )}
                                        </div>
                                        {n.summary && (
                                            <p className="text-xs text-gray-500 mt-0.5 truncate">{n.summary}</p>
                                        )}
                                        <span className="text-[10px] text-gray-600 mt-1 block">
                                            {timeAgo(n.created_at)}
                                            {n.host_id && ` · ${n.host_id}`}
                                        </span>
                                    </div>
                                    <div className="flex items-center gap-1 flex-shrink-0">
                                        {hasUnread && (
                                            <button
                                                onClick={(e) => {
                                                    e.stopPropagation()
                                                    handleMarkRead(g.allIds.filter(id => {
                                                        const notif = notifications.find(x => x.id === id)
                                                        return notif && !notif.read
                                                    }))
                                                }}
                                                className="p-1 hover:bg-white/10 rounded-lg font-medium border border-transparent transition-all duration-200"
                                                title="Mark read"
                                            >
                                                <Check className="w-3.5 h-3.5 text-gray-500" />
                                            </button>
                                        )}
                                        <button
                                            onClick={(e) => { e.stopPropagation(); handleDismiss(g.allIds, g.unreadCount) }}
                                            className="p-1 hover:bg-white/10 rounded-lg font-medium border border-transparent transition-all duration-200"
                                            title="Dismiss"
                                        >
                                            <X className="w-3.5 h-3.5 text-gray-500" />
                                        </button>
                                    </div>
                                </div>
                            )
                        })}
                    </div>

                    {/* Footer */}
                    {grouped.length > 0 && (
                        <div className="px-4 py-2 border-t border-white/10 text-center">
                            <button
                                onClick={() => { router.push('/incidents'); setIsOpen(false) }}
                                className="text-xs text-orange-400 hover:text-orange-300"
                            >
                                View all incidents
                            </button>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}
