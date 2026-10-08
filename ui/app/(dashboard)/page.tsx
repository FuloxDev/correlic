'use client'

import { useState, useCallback } from 'react'
import { RefreshCw, Radio } from 'lucide-react'
import {
    getDashboardStats, getDashboardTrends, getIncidents,
    type DashboardStats, type TrendPoint, type Incident,
} from '@/lib/api-client'
import { usePolling } from '@/lib/use-polling'
import { PageHeading } from '@/components/ui/page-heading'
import SecurityPostureHero from '@/components/dashboard/SecurityPostureHero'
import TrendChart from '@/components/dashboard/TrendChart'
import LiveActivityFeed from '@/components/dashboard/LiveActivityFeed'
import FindingsBreakdown from '@/components/dashboard/FindingsBreakdown'
import RecentIncidents from '@/components/dashboard/RecentIncidents'
import DetectionHealth from '@/components/dashboard/DetectionHealth'
import IncidentTrendChart from '@/components/dashboard/IncidentTrendChart'

const refreshOptions = [
    { label: 'Off', value: 0 },
    { label: '5s', value: 5 },
    { label: '10s', value: 10 },
    { label: '30s', value: 30 },
    { label: '1m', value: 60 },
]

export default function Dashboard() {
    const [stats, setStats] = useState<DashboardStats | null>(null)
    const [statsFailed, setStatsFailed] = useState(false)
    const [trends, setTrends] = useState<TrendPoint[]>([])
    const [incidents, setIncidents] = useState<Incident[]>([])

    const [loading, setLoading] = useState(true)
    const [refreshRate, setRefreshRate] = useState(60)
    const [isLive, setIsLive] = useState(false)
    const [lastRefresh, setLastRefresh] = useState<Date | null>(null)
    const [refreshCount, setRefreshCount] = useState(0)

    const fetchData = useCallback(async () => {
        setLoading(true)
        try {
            // Detection/incident counts come from /dashboard/stats; the dashboard
            // never pulls the findings list itself.
            const [statsData, trendsData, incidentsData] = await Promise.allSettled([
                getDashboardStats(60),
                getDashboardTrends(24, 5),
                getIncidents({ status: 'open', limit: 5 }),
            ])

            if (statsData.status === 'fulfilled') {
                setStats(statsData.value)
                setStatsFailed(false)
            } else {
                setStatsFailed(true)
            }
            if (trendsData.status === 'fulfilled') setTrends(trendsData.value.points || [])
            if (incidentsData.status === 'fulfilled') setIncidents(incidentsData.value.incidents || [])

            setLastRefresh(new Date())
            setRefreshCount(c => c + 1)
        } finally {
            setLoading(false)
        }
    }, [])

    // Polls while the tab is visible; pauses when hidden.
    const effectiveRefresh = isLive ? 5 : refreshRate
    usePolling(fetchData, effectiveRefresh * 1000)

    return (
        <div className="space-y-7">
            {/* Header + Controls */}
            <PageHeading
                title="Security Dashboard"
                subtitle="Real-time threat monitoring"
                actions={
                    <div className="flex flex-wrap items-center gap-2">
                        {/* Refresh Rate */}
                        <div className="flex items-center bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl overflow-hidden">
                            <div className="px-2.5 py-1.5 border-r border-white/[0.07]">
                                <RefreshCw className={`w-3.5 h-3.5 ${effectiveRefresh > 0 ? 'text-[var(--low)] animate-spin' : 'text-[var(--foreground-muted)]'}`} style={{ animationDuration: '3s' }} aria-hidden="true" />
                            </div>
                            <select
                                value={refreshRate}
                                onChange={(e) => setRefreshRate(Number(e.target.value))}
                                disabled={isLive}
                                aria-label="Auto-refresh interval"
                                className="bg-transparent text-xs text-[var(--foreground-muted)] px-2.5 py-1.5 outline-none cursor-pointer disabled:opacity-50"
                            >
                                {refreshOptions.map((opt) => (
                                    <option key={opt.value} value={opt.value} className="bg-[var(--background)]">
                                        {opt.label}
                                    </option>
                                ))}
                            </select>
                        </div>

                        {/* Live Mode */}
                        <button
                            type="button"
                            onClick={() => setIsLive(!isLive)}
                            aria-pressed={isLive}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-2xl text-xs font-medium transition-all ${
                                isLive
                                    ? 'bg-[var(--critical)]/20 border-2 border-[var(--critical)]/40 text-[var(--critical)]'
                                    : 'bg-[#0d1117]/60 border-2 border-white/[0.07] text-gray-400 hover:text-white hover:border-white/[0.13]'
                            }`}
                        >
                            <Radio className={`w-3.5 h-3.5 ${isLive ? 'animate-pulse' : ''}`} aria-hidden="true" />
                            {isLive ? 'LIVE' : 'Live'}
                        </button>

                        {/* Manual Refresh */}
                        <button
                            type="button"
                            onClick={() => { void fetchData() }}
                            disabled={loading}
                            className="p-1.5 bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl text-gray-400 hover:text-white hover:border-white/[0.13] transition-all disabled:opacity-50"
                            title="Refresh now"
                            aria-label="Refresh now"
                        >
                            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
                        </button>
                    </div>
                }
            >
                {lastRefresh && (
                    <span className="text-xs text-dim opacity-60">
                        Updated {lastRefresh.toLocaleTimeString()}
                    </span>
                )}
            </PageHeading>

            {/* Row 1: Security Posture Hero */}
            <SecurityPostureHero stats={stats} failed={statsFailed} />

            {/* Row 2: Trend Chart */}
            <TrendChart initialTrends={trends} />

            {/* Row 3: Activity Feed + Findings Breakdown */}
            <div className="grid grid-cols-12 gap-6">
                <div className="col-span-12 lg:col-span-5">
                    <LiveActivityFeed refreshTrigger={refreshCount} />
                </div>
                <div className="col-span-12 lg:col-span-7">
                    <FindingsBreakdown stats={stats} />
                </div>
            </div>

            {/* Row 4: Incidents Over Time */}
            <IncidentTrendChart initialTrends={trends} />

            {/* Row 5: Recent Incidents + Detection Health */}
            <div className="grid grid-cols-12 gap-6">
                <div className="col-span-12 lg:col-span-7">
                    <RecentIncidents incidents={incidents} />
                </div>
                <div className="col-span-12 lg:col-span-5">
                    <DetectionHealth stats={stats} />
                </div>
            </div>
        </div>
    )
}
