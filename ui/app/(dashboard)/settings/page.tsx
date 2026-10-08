'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Key,
    Cpu,
    Bell,
    Copy,
    Eye,
    EyeOff,
    Check,
    RefreshCw,
    Plus,
    Trash2,
    Send,
    Webhook,
    Bot,
    Sparkles,
    AlertTriangle,
    Loader2,
    ChevronUp,
    Zap,
    Lock,
    Radio,
    MessageSquare,
    ExternalLink,
    Hash
} from 'lucide-react';
import { PageHeading } from '@/components/ui/page-heading';
import {
    getLLMSettings, saveLLMSettings, switchLLMProvider,
    getAPIKeys, createAPIKey, deleteAPIKey,
    getNotificationEndpoints, createNotificationEndpoint, updateNotificationEndpoint,
    deleteNotificationEndpoint, testNotificationEndpoint,
    getAgentPatterns, createAgentPattern, deleteAgentPattern, suggestAIPatterns,
    type LLMProvider, type APIKey, type NotificationEndpoint, type AIAgentPattern
} from '@/lib/api-client';

/* ── Glass card (dashboard-matching) ── */
function GlassCard({ children, className = '', glow }: { children: React.ReactNode; className?: string; glow?: string }) {
    return (
        <div className={`relative bg-[#0d1117]/80 border-2 border-white/[0.07] rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 hover:border-white/[0.13] transition-all duration-300 ${className}`}>
            {glow && <div className="absolute inset-0 rounded-3xl opacity-[0.03] pointer-events-none" style={{ background: `radial-gradient(ellipse at top, ${glow}, transparent 70%)` }} />}
            <div className="relative">{children}</div>
        </div>
    );
}

/* ── Stagger variants ── */
const sectionVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: (i: number) => ({
        opacity: 1, y: 0,
        transition: { delay: 0.15 + i * 0.1, duration: 0.5 },
    }),
};

const listItemVariants = {
    hidden: { opacity: 0, x: -20 },
    visible: { opacity: 1, x: 0, transition: { duration: 0.3 } },
    exit: { opacity: 0, x: 20, transition: { duration: 0.2 } },
};

/* ── Provider meta ── */
const providerMeta: Record<string, { label: string; sub: string; icon: React.ReactNode; color: string }> = {
    groq: { label: 'Groq', sub: 'Fast inference', icon: <Zap className="w-5 h-5" />, color: '#f97316' },
    openai: { label: 'OpenAI', sub: 'GPT-4o', icon: <Sparkles className="w-5 h-5" />, color: '#22c55e' },
    gemini: { label: 'Gemini', sub: 'Google AI', icon: <Radio className="w-5 h-5" />, color: '#3b82f6' },
    anthropic: { label: 'Anthropic', sub: 'Claude', icon: <MessageSquare className="w-5 h-5" />, color: '#f59e0b' },
    xai: { label: 'xAI', sub: 'Grok', icon: <Bot className="w-5 h-5" />, color: '#8b5cf6' },
};

/* ── Severity badge helper ── */
const severityBadge: Record<string, { bg: string; border: string; text: string }> = {
    critical: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400' },
    high: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400' },
    medium: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400' },
    low: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400' },
};

/* ── Section nav tabs ── */
type SectionId = 'api-keys' | 'llm' | 'notifications' | 'ai-patterns';
const sections: { id: SectionId; label: string; icon: React.ReactNode; dot?: string }[] = [
    { id: 'api-keys', label: 'API Keys', icon: <Key className="w-4 h-4" />, dot: 'bg-amber-400' },
    { id: 'llm', label: 'LLM Provider', icon: <Cpu className="w-4 h-4" />, dot: 'bg-purple-400' },
    { id: 'notifications', label: 'Notifications', icon: <Bell className="w-4 h-4" />, dot: 'bg-cyan-400' },
    { id: 'ai-patterns', label: 'AI Agents', icon: <Bot className="w-4 h-4" />, dot: 'bg-emerald-400' },
];

export default function Settings() {
    const [activeSection, setActiveSection] = useState<SectionId>('api-keys');
    const [llmProviders, setLLMProviders] = useState<LLMProvider[]>([]);
    const [apiKeys, setAPIKeys] = useState<APIKey[]>([]);
    const [loading, setLoading] = useState(true);

    const [selectedProvider, setSelectedProvider] = useState('groq');
    const [providerApiKey, setProviderApiKey] = useState('');
    const [showApiKey, setShowApiKey] = useState(false);
    const [newKeyName, setNewKeyName] = useState('');
    const [newKey, setNewKey] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);
    const [saving, setSaving] = useState(false);

    const [endpoints, setEndpoints] = useState<NotificationEndpoint[]>([]);
    const [showEndpointForm, setShowEndpointForm] = useState(false);
    const [endpointForm, setEndpointForm] = useState({
        name: '', channel_type: 'webhook' as string, url: '', secret: '', min_severity: 'medium',
    });
    const [testingEndpoint, setTestingEndpoint] = useState<string | null>(null);
    const [testResult, setTestResult] = useState<{ id: string, ok: boolean, error?: string } | null>(null);

    const [agentPatterns, setAgentPatterns] = useState<AIAgentPattern[]>([]);
    const [showPatternForm, setShowPatternForm] = useState(false);
    const [patternForm, setPatternForm] = useState({ pattern: '', agent_type: '', description: '' });
    const [patternError, setPatternError] = useState<string | null>(null);

    const [suggestQuery, setSuggestQuery] = useState('');
    const [suggesting, setSuggesting] = useState(false);
    const [suggestions, setSuggestions] = useState<{ pattern: string; agent_type: string; description: string }[]>([]);
    const [suggestError, setSuggestError] = useState<string | null>(null);

    useEffect(() => { fetchData(); }, []);

    async function fetchData() {
        try {
            setLoading(true);
            const [providers, keys, endpointsData, patternsData] = await Promise.all([
                getLLMSettings().catch(() => []),
                getAPIKeys().catch(() => []),
                getNotificationEndpoints().catch(() => ({ endpoints: [] })),
                getAgentPatterns().catch(() => []),
            ]);
            setLLMProviders(providers);
            setAPIKeys(keys);
            setEndpoints(endpointsData.endpoints || []);
            setAgentPatterns(patternsData);
            const active = providers.find((p: LLMProvider) => p.enabled);
            if (active) setSelectedProvider(active.provider);
        } catch (err) {
            console.error('Failed to fetch settings:', err);
        } finally {
            setLoading(false);
        }
    }

    async function handleSwitchProvider(provider: string) {
        setSelectedProvider(provider);
        const existing = llmProviders.find(p => p.provider === provider);
        if (existing && !existing.enabled) {
            try {
                setSaving(true);
                await switchLLMProvider(provider);
                await fetchData();
            } catch (err) {
                console.error('Failed to switch provider:', err);
            } finally {
                setSaving(false);
            }
        }
    }

    async function handleSaveLLMSettings() {
        if (!providerApiKey.trim()) return;
        try {
            setSaving(true);
            await saveLLMSettings({ provider: selectedProvider, api_key: providerApiKey });
            await switchLLMProvider(selectedProvider);
            setProviderApiKey('');
            await fetchData();
        } catch (err) {
            console.error('Failed to save LLM settings:', err);
        } finally {
            setSaving(false);
        }
    }

    async function handleCreateAPIKey() {
        if (!newKeyName.trim()) return;
        try {
            const result = await createAPIKey(newKeyName);
            setNewKey(result.key);
            setNewKeyName('');
            await fetchData();
        } catch (err) {
            console.error('Failed to create API key:', err);
        }
    }

    async function handleDeleteAPIKey(id: string) {
        try { await deleteAPIKey(id); await fetchData(); }
        catch (err) { console.error('Failed to delete API key:', err); }
    }

    function copyToClipboard(text: string) {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    }

    async function handleSuggest() {
        if (!suggestQuery.trim()) return;
        setSuggesting(true);
        setSuggestError(null);
        setSuggestions([]);
        try {
            const resp = await suggestAIPatterns(suggestQuery.trim());
            const text = resp.suggestion.trim();
            const cleaned = text.replace(/^```(?:json)?\n?/i, '').replace(/\n?```$/i, '').trim();
            const parsed = JSON.parse(cleaned);
            if (Array.isArray(parsed)) {
                setSuggestions((parsed as Array<Record<string, unknown>>).map((item) => ({
                    pattern: String(item?.pattern || ''),
                    agent_type: String(item?.agent_type || ''),
                    description: String(item?.description || ''),
                })).filter((s) => s.pattern && s.agent_type));
            } else {
                setSuggestError('Unexpected response format from AI.');
            }
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : '';
            if (message.includes('400') || message.includes('no LLM provider')) {
                setSuggestError('Configure an LLM provider first.');
            } else {
                setSuggestError('Failed to get suggestions. Try again.');
            }
        } finally {
            setSuggesting(false);
        }
    }

    async function handleCreateEndpoint() {
        if (!endpointForm.name || !endpointForm.url) return;
        const config: Record<string, unknown> = endpointForm.channel_type === 'slack'
            ? { webhook_url: endpointForm.url }
            : { url: endpointForm.url, ...(endpointForm.secret ? { secret: endpointForm.secret } : {}) };
        try {
            await createNotificationEndpoint({
                name: endpointForm.name, channel_type: endpointForm.channel_type,
                config, min_severity: endpointForm.min_severity,
            });
            setEndpointForm({ name: '', channel_type: 'webhook', url: '', secret: '', min_severity: 'medium' });
            setShowEndpointForm(false);
            fetchData();
        } catch (err) {
            console.error('Failed to create endpoint:', err);
        }
    }

    async function handleCreatePattern() {
        if (!patternForm.pattern.trim() || !patternForm.agent_type.trim()) return;
        setPatternError(null);
        try {
            await createAgentPattern({
                pattern: patternForm.pattern.trim(),
                agent_type: patternForm.agent_type.trim(),
                description: patternForm.description.trim() || undefined,
            });
            setPatternForm({ pattern: '', agent_type: '', description: '' });
            setShowPatternForm(false);
            setSuggestions([]);
            setSuggestQuery('');
            fetchData();
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : '';
            if (message.includes('409') || message.includes('already exists')) {
                setPatternError('This pattern already exists.');
            } else {
                setPatternError('Failed to create pattern.');
            }
        }
    }

    const activeProvider = llmProviders.find(p => p.enabled);

    return (
        <div className="space-y-7 max-w-5xl mx-auto">
            {/* ── Header ── */}
            <PageHeading
                title="Settings"
                subtitle="Configure your Correlic workspace"
                actions={
                    <motion.button
                        whileHover={{ scale: 1.04 }}
                        whileTap={{ scale: 0.96 }}
                        onClick={fetchData}
                        className="flex items-center gap-2 px-4 py-2 rounded-2xl text-sm font-medium bg-[#0d1117]/60 border-2 border-white/[0.07] text-gray-400 hover:text-white hover:border-white/[0.13] transition-all duration-200"
                    >
                        <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} style={loading ? { animationDuration: '3s' } : undefined} />
                        Refresh
                    </motion.button>
                }
            />

            {/* ── Section Nav ── */}
            <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2, duration: 0.4 }}
                className="flex items-center gap-2 bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-1.5"
            >
                {sections.map((s) => (
                    <button
                        key={s.id}
                        onClick={() => setActiveSection(s.id)}
                        className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all duration-200 ${
                            activeSection === s.id
                                ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                                : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                        }`}
                    >
                        <span className={`w-1.5 h-1.5 rounded-full ${activeSection === s.id ? s.dot : 'bg-gray-600'}`} />
                        {s.icon}
                        <span className="hidden sm:inline">{s.label}</span>
                        {/* Badge counts */}
                        {s.id === 'api-keys' && apiKeys.length > 0 && (
                            <span className="text-xs tabular-nums opacity-60">{apiKeys.length}</span>
                        )}
                        {s.id === 'notifications' && endpoints.length > 0 && (
                            <span className="text-xs tabular-nums opacity-60">{endpoints.length}</span>
                        )}
                        {s.id === 'ai-patterns' && agentPatterns.length > 0 && (
                            <span className="text-xs tabular-nums opacity-60">{agentPatterns.length}</span>
                        )}
                    </button>
                ))}
            </motion.div>

            {/* ── Loading State ── */}
            <AnimatePresence mode="wait">
                {loading && (
                    <motion.div
                        key="loading"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="flex items-center justify-center py-20 text-gray-400 gap-3"
                    >
                        <Loader2 className="w-5 h-5 animate-spin" />
                        <span className="text-sm">Loading settings...</span>
                    </motion.div>
                )}

                {/* ── API Keys Section ── */}
                {!loading && activeSection === 'api-keys' && (
                    <motion.div key="api-keys" custom={0} variants={sectionVariants} initial="hidden" animate="visible">
                        <GlassCard className="p-6" glow="#f59e0b">
                            <div className="flex items-center justify-between mb-6">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20">
                                        <Key className="w-5 h-5 text-amber-400" />
                                    </div>
                                    <div>
                                        <h2 className="text-lg font-semibold text-white">API Keys</h2>
                                        <p className="text-xs text-gray-400">Manage authentication keys for agents and integrations</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2 text-xs text-dim">
                                    <Lock className="w-3.5 h-3.5" />
                                    <span>{apiKeys.length} key{apiKeys.length !== 1 ? 's' : ''}</span>
                                </div>
                            </div>

                            {/* Create new key */}
                            <div className="flex items-center gap-2 mb-5">
                                <div className="relative flex-1">
                                    <Hash className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dim" />
                                    <input
                                        type="text"
                                        value={newKeyName}
                                        onChange={(e) => setNewKeyName(e.target.value)}
                                        onKeyDown={(e) => { if (e.key === 'Enter' && newKeyName.trim()) handleCreateAPIKey(); }}
                                        placeholder="Key name (e.g., Production Agent)"
                                        className="w-full pl-9 pr-4 py-2.5 text-sm bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl text-gray-200 placeholder-gray-500 focus:outline-none focus:border-[var(--accent)]/40 focus:ring-1 focus:ring-[var(--accent)]/20 transition-all"
                                    />
                                </div>
                                <motion.button
                                    whileHover={{ scale: 1.03 }}
                                    whileTap={{ scale: 0.97 }}
                                    onClick={handleCreateAPIKey}
                                    disabled={!newKeyName.trim()}
                                    className="px-5 py-2.5 bg-[var(--accent)]/15 border border-[var(--accent)]/30 text-[var(--accent)] rounded-2xl text-sm font-semibold hover:bg-[var(--accent)]/25 hover:shadow-lg hover:shadow-[var(--accent)]/5 hover:border-[var(--accent)]/50 transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                                >
                                    <Plus className="w-4 h-4" />
                                    Generate
                                </motion.button>
                            </div>

                            {/* New key banner */}
                            <AnimatePresence>
                                {newKey && (
                                    <motion.div
                                        initial={{ opacity: 0, height: 0 }}
                                        animate={{ opacity: 1, height: 'auto' }}
                                        exit={{ opacity: 0, height: 0 }}
                                        className="mb-5"
                                    >
                                        <div className="bg-green-500/10 border-2 border-green-500/30 rounded-2xl p-4">
                                            <div className="flex items-center gap-2 mb-2">
                                                <Check className="w-4 h-4 text-green-400" />
                                                <p className="text-green-400 text-sm font-medium">Key created! Copy it now — it won&apos;t be shown again.</p>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <code className="flex-1 bg-black/30 border border-white/[0.07] px-4 py-2.5 rounded-xl font-mono text-sm text-gray-200 select-all">{newKey}</code>
                                                <motion.button
                                                    whileHover={{ scale: 1.08 }}
                                                    whileTap={{ scale: 0.92 }}
                                                    onClick={() => copyToClipboard(newKey)}
                                                    className="p-2.5 bg-white/10 rounded-xl hover:bg-white/20 transition-all duration-200"
                                                >
                                                    {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4 text-gray-300" />}
                                                </motion.button>
                                            </div>
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>

                            {/* Keys list */}
                            <div className="space-y-2">
                                <AnimatePresence>
                                    {apiKeys.length === 0 ? (
                                        <motion.div
                                            initial={{ opacity: 0, scale: 0.95 }}
                                            animate={{ opacity: 1, scale: 1 }}
                                            className="text-center py-10"
                                        >
                                            <motion.div
                                                initial={{ scale: 0 }}
                                                animate={{ scale: 1 }}
                                                transition={{ type: 'spring', stiffness: 200, damping: 15, delay: 0.1 }}
                                            >
                                                <Key className="w-10 h-10 text-amber-400/30 mx-auto mb-3" />
                                            </motion.div>
                                            <p className="text-sm text-gray-400">No API keys yet</p>
                                            <p className="text-xs text-dim mt-1">Generate a key to connect agents to your workspace</p>
                                        </motion.div>
                                    ) : apiKeys.map((key) => (
                                        <motion.div
                                            key={key.id}
                                            variants={listItemVariants}
                                            initial="hidden"
                                            animate="visible"
                                            exit="exit"
                                            layout
                                            className="group flex items-center justify-between bg-[#0d1117]/60 border border-white/[0.07] rounded-2xl px-4 py-3 hover:border-white/[0.14] hover:bg-white/[0.03] transition-all duration-200"
                                        >
                                            <div className="flex items-center gap-3">
                                                <div className="p-1.5 rounded-lg bg-amber-500/10">
                                                    <Key className="w-3.5 h-3.5 text-amber-400" />
                                                </div>
                                                <div>
                                                    <p className="text-sm font-medium text-white">{key.name}</p>
                                                    <div className="flex items-center gap-2 mt-0.5">
                                                        <span className="text-xs text-dim font-mono">{key.key_prefix}...</span>
                                                        {key.last_used && (
                                                            <span className="text-xs text-dim">· Last used {new Date(key.last_used).toLocaleDateString()}</span>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                            <motion.button
                                                whileHover={{ scale: 1.1 }}
                                                whileTap={{ scale: 0.9 }}
                                                onClick={() => handleDeleteAPIKey(key.id)}
                                                className="p-2 rounded-xl text-dim hover:text-red-400 hover:bg-red-500/10 opacity-0 group-hover:opacity-100 transition-all duration-200"
                                                title="Revoke key"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </motion.button>
                                        </motion.div>
                                    ))}
                                </AnimatePresence>
                            </div>
                        </GlassCard>
                    </motion.div>
                )}

                {/* ── LLM Provider Section ── */}
                {!loading && activeSection === 'llm' && (
                    <motion.div key="llm" custom={0} variants={sectionVariants} initial="hidden" animate="visible" className="space-y-5">
                        {/* Active provider badge */}
                        {activeProvider && (
                            <motion.div
                                initial={{ opacity: 0, scale: 0.95 }}
                                animate={{ opacity: 1, scale: 1 }}
                                transition={{ delay: 0.2 }}
                                className="flex items-center gap-3 bg-green-500/8 border-2 border-green-500/20 rounded-2xl px-5 py-3"
                            >
                                <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                                <span className="text-sm text-green-400 font-medium">Active:</span>
                                <span className="text-sm text-white font-semibold">{providerMeta[activeProvider.provider]?.label || activeProvider.provider}</span>
                                <span className="text-xs text-gray-400">· {activeProvider.model || 'default model'}</span>
                            </motion.div>
                        )}

                        <GlassCard className="p-6" glow="#8b5cf6">
                            <div className="flex items-center gap-3 mb-6">
                                <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20">
                                    <Cpu className="w-5 h-5 text-purple-400" />
                                </div>
                                <div>
                                    <h2 className="text-lg font-semibold text-white">LLM Provider</h2>
                                    <p className="text-xs text-gray-400">Choose an AI provider for incident analysis and explanations</p>
                                </div>
                            </div>

                            {/* Provider grid */}
                            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
                                {Object.entries(providerMeta).map(([id, meta], i) => {
                                    const isSelected = selectedProvider === id;
                                    const config = llmProviders.find(p => p.provider === id);
                                    return (
                                        <motion.button
                                            key={id}
                                            initial={{ opacity: 0, y: 10 }}
                                            animate={{ opacity: 1, y: 0 }}
                                            transition={{ delay: 0.3 + i * 0.06 }}
                                            whileHover={{ scale: 1.03, y: -2 }}
                                            whileTap={{ scale: 0.97 }}
                                            onClick={() => handleSwitchProvider(id)}
                                            className={`relative p-4 rounded-2xl border-2 transition-all duration-200 text-center ${
                                                isSelected
                                                    ? 'bg-[var(--accent)]/10 border-[var(--accent)]/40 shadow-lg shadow-[var(--accent)]/5'
                                                    : 'bg-[#0d1117]/60 border-white/[0.07] hover:border-white/[0.14] hover:bg-white/[0.03]'
                                            }`}
                                        >
                                            <div className={`mx-auto mb-2 p-2 rounded-xl w-fit ${isSelected ? 'bg-[var(--accent)]/15' : 'bg-white/5'}`}>
                                                <span className={isSelected ? 'text-[var(--accent)]' : 'text-gray-400'}>{meta.icon}</span>
                                            </div>
                                            <div className="text-sm font-semibold mb-0.5 text-white">{meta.label}</div>
                                            <div className="text-xs text-dim">{meta.sub}</div>
                                            {config && (
                                                <div className={`text-[10px] mt-2 font-medium flex items-center justify-center gap-1 ${config.enabled ? 'text-green-400' : 'text-dim'}`}>
                                                    <span className={`w-1.5 h-1.5 rounded-full ${config.enabled ? 'bg-green-400' : 'bg-gray-600'}`} />
                                                    {config.enabled ? 'Active' : 'Configured'}
                                                </div>
                                            )}
                                        </motion.button>
                                    );
                                })}
                            </div>

                            {/* API key input */}
                            <div className="space-y-3">
                                <label className="text-sm text-gray-400 flex items-center gap-2">
                                    <Lock className="w-3.5 h-3.5" />
                                    API Key for {providerMeta[selectedProvider]?.label || selectedProvider}
                                </label>
                                <div className="flex items-center gap-2">
                                    <div className="relative flex-1">
                                        <input
                                            type={showApiKey ? 'text' : 'password'}
                                            value={providerApiKey}
                                            onChange={(e) => setProviderApiKey(e.target.value)}
                                            onKeyDown={(e) => { if (e.key === 'Enter' && providerApiKey.trim()) handleSaveLLMSettings(); }}
                                            placeholder={`Enter your ${providerMeta[selectedProvider]?.label || selectedProvider} API key`}
                                            className="w-full px-4 py-2.5 text-sm bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl text-gray-200 placeholder-gray-500 focus:outline-none focus:border-purple-500/40 focus:ring-1 focus:ring-purple-500/20 transition-all"
                                        />
                                    </div>
                                    <button
                                        onClick={() => setShowApiKey(!showApiKey)}
                                        className="p-2.5 bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-xl hover:bg-white/[0.06] hover:border-white/[0.14] transition-all duration-200"
                                    >
                                        {showApiKey ? <EyeOff className="w-4 h-4 text-gray-400" /> : <Eye className="w-4 h-4 text-gray-400" />}
                                    </button>
                                    <motion.button
                                        whileHover={{ scale: 1.03 }}
                                        whileTap={{ scale: 0.97 }}
                                        onClick={handleSaveLLMSettings}
                                        disabled={!providerApiKey.trim() || saving}
                                        className="px-5 py-2.5 bg-purple-500/15 border border-purple-500/30 text-purple-400 rounded-2xl text-sm font-semibold hover:bg-purple-500/25 hover:shadow-lg hover:shadow-purple-500/5 hover:border-purple-500/50 transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                                    >
                                        {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                                        {saving ? 'Saving...' : 'Save'}
                                    </motion.button>
                                </div>
                            </div>
                        </GlassCard>
                    </motion.div>
                )}

                {/* ── Notifications Section ── */}
                {!loading && activeSection === 'notifications' && (
                    <motion.div key="notifications" custom={0} variants={sectionVariants} initial="hidden" animate="visible">
                        <GlassCard className="p-6" glow="#06b6d4">
                            <div className="flex items-center justify-between mb-6">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20">
                                        <Bell className="w-5 h-5 text-cyan-400" />
                                    </div>
                                    <div>
                                        <h2 className="text-lg font-semibold text-white">Notification Channels</h2>
                                        <p className="text-xs text-gray-400">Receive incident alerts via webhook or Slack</p>
                                    </div>
                                </div>
                                <motion.button
                                    whileHover={{ scale: 1.03 }}
                                    whileTap={{ scale: 0.97 }}
                                    onClick={() => setShowEndpointForm(!showEndpointForm)}
                                    className="px-4 py-2 bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 rounded-2xl text-sm font-semibold hover:bg-cyan-500/25 hover:shadow-lg hover:shadow-cyan-500/5 hover:border-cyan-500/50 transition-all duration-200 flex items-center gap-2"
                                >
                                    {showEndpointForm ? <ChevronUp className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
                                    {showEndpointForm ? 'Cancel' : 'Add Channel'}
                                </motion.button>
                            </div>

                            {/* Add endpoint form */}
                            <AnimatePresence>
                                {showEndpointForm && (
                                    <motion.div
                                        initial={{ opacity: 0, height: 0 }}
                                        animate={{ opacity: 1, height: 'auto' }}
                                        exit={{ opacity: 0, height: 0 }}
                                        className="mb-5 overflow-hidden"
                                    >
                                        <div className="bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-5 space-y-4">
                                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                                <div>
                                                    <label className="text-xs text-dim mb-1.5 block uppercase tracking-wider">Channel Name</label>
                                                    <input
                                                        type="text"
                                                        value={endpointForm.name}
                                                        onChange={e => setEndpointForm({ ...endpointForm, name: e.target.value })}
                                                        placeholder="e.g., Production Alerts"
                                                        className="w-full bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-xl px-4 py-2.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="text-xs text-dim mb-1.5 block uppercase tracking-wider">Type</label>
                                                    <div className="flex gap-2">
                                                        {(['webhook', 'slack'] as const).map(type => (
                                                            <button
                                                                key={type}
                                                                onClick={() => setEndpointForm({ ...endpointForm, channel_type: type })}
                                                                className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium border-2 transition-all duration-200 ${
                                                                    endpointForm.channel_type === type
                                                                        ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                                                                        : 'bg-[#0d1117]/60 border-white/[0.07] text-gray-400 hover:border-white/[0.14] hover:text-gray-200'
                                                                }`}
                                                            >
                                                                {type === 'webhook' ? <Webhook className="w-4 h-4" /> : <MessageSquare className="w-4 h-4" />}
                                                                {type.charAt(0).toUpperCase() + type.slice(1)}
                                                            </button>
                                                        ))}
                                                    </div>
                                                </div>
                                            </div>

                                            <div>
                                                <label className="text-xs text-dim mb-1.5 block uppercase tracking-wider">
                                                    {endpointForm.channel_type === 'slack' ? 'Slack Webhook URL' : 'Webhook URL'}
                                                </label>
                                                <div className="relative">
                                                    <ExternalLink className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dim" />
                                                    <input
                                                        type="url"
                                                        value={endpointForm.url}
                                                        onChange={e => setEndpointForm({ ...endpointForm, url: e.target.value })}
                                                        placeholder={endpointForm.channel_type === 'slack' ? 'https://hooks.slack.com/services/...' : 'https://your-endpoint.com/webhook'}
                                                        className="w-full pl-9 pr-4 py-2.5 text-sm bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-xl text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                                                    />
                                                </div>
                                            </div>

                                            {endpointForm.channel_type === 'webhook' && (
                                                <div>
                                                    <label className="text-xs text-dim mb-1.5 block uppercase tracking-wider">HMAC Secret (optional)</label>
                                                    <div className="relative">
                                                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dim" />
                                                        <input
                                                            type="text"
                                                            value={endpointForm.secret}
                                                            onChange={e => setEndpointForm({ ...endpointForm, secret: e.target.value })}
                                                            placeholder="Used for X-Correlic-Signature verification"
                                                            className="w-full pl-9 pr-4 py-2.5 text-sm bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-xl text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                                                        />
                                                    </div>
                                                </div>
                                            )}

                                            <div className="flex items-center justify-between">
                                                <div>
                                                    <label className="text-xs text-dim mb-1.5 block uppercase tracking-wider">Min Severity</label>
                                                    <div className="flex gap-1.5">
                                                        {(['low', 'medium', 'high', 'critical'] as const).map(sev => {
                                                            const s = severityBadge[sev];
                                                            return (
                                                                <button
                                                                    key={sev}
                                                                    onClick={() => setEndpointForm({ ...endpointForm, min_severity: sev })}
                                                                    className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all duration-200 capitalize ${
                                                                        endpointForm.min_severity === sev
                                                                            ? `${s.bg} ${s.border} ${s.text}`
                                                                            : 'bg-[#0d1117]/60 border-white/[0.07] text-dim hover:text-gray-300 hover:border-white/[0.14]'
                                                                    }`}
                                                                >
                                                                    {sev}
                                                                </button>
                                                            );
                                                        })}
                                                    </div>
                                                </div>
                                                <motion.button
                                                    whileHover={{ scale: 1.03 }}
                                                    whileTap={{ scale: 0.97 }}
                                                    onClick={handleCreateEndpoint}
                                                    disabled={!endpointForm.name || !endpointForm.url}
                                                    className="px-5 py-2.5 bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 rounded-2xl text-sm font-semibold hover:bg-cyan-500/25 hover:shadow-lg hover:shadow-cyan-500/5 hover:border-cyan-500/50 transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                                                >
                                                    <Plus className="w-4 h-4" />
                                                    Create Channel
                                                </motion.button>
                                            </div>
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>

                            {/* Endpoint list */}
                            <div className="space-y-2">
                                <AnimatePresence>
                                    {endpoints.length === 0 && !showEndpointForm ? (
                                        <motion.div
                                            initial={{ opacity: 0, scale: 0.95 }}
                                            animate={{ opacity: 1, scale: 1 }}
                                            className="text-center py-10"
                                        >
                                            <motion.div
                                                initial={{ scale: 0 }}
                                                animate={{ scale: 1 }}
                                                transition={{ type: 'spring', stiffness: 200, damping: 15, delay: 0.1 }}
                                            >
                                                <Bell className="w-10 h-10 text-cyan-400/30 mx-auto mb-3" />
                                            </motion.div>
                                            <p className="text-sm text-gray-400">No notification channels configured</p>
                                            <p className="text-xs text-dim mt-1">Add a webhook or Slack channel to receive incident alerts</p>
                                        </motion.div>
                                    ) : endpoints.map((ep) => {
                                        const sevStyle = severityBadge[ep.min_severity] || severityBadge.medium;
                                        return (
                                            <motion.div
                                                key={ep.id}
                                                variants={listItemVariants}
                                                initial="hidden"
                                                animate="visible"
                                                exit="exit"
                                                layout
                                                className="group flex items-center justify-between bg-[#0d1117]/60 border border-white/[0.07] rounded-2xl px-4 py-3 hover:border-white/[0.14] hover:bg-white/[0.03] transition-all duration-200"
                                            >
                                                <div className="flex items-center gap-3 min-w-0 flex-1">
                                                    <div className={`p-2 rounded-xl ${ep.enabled ? 'bg-cyan-500/10' : 'bg-white/5'}`}>
                                                        {ep.channel_type === 'slack'
                                                            ? <MessageSquare className={`w-4 h-4 ${ep.enabled ? 'text-cyan-400' : 'text-dim'}`} />
                                                            : <Webhook className={`w-4 h-4 ${ep.enabled ? 'text-cyan-400' : 'text-dim'}`} />
                                                        }
                                                    </div>
                                                    <div className="min-w-0 flex-1">
                                                        <div className="flex items-center gap-2 flex-wrap">
                                                            <span className="text-sm font-medium text-white">{ep.name}</span>
                                                            <span className="text-[10px] px-1.5 py-0.5 rounded-lg bg-white/[0.06] text-gray-400 uppercase tracking-wider font-medium">{ep.channel_type}</span>
                                                            <span className={`text-[10px] px-1.5 py-0.5 rounded-lg ${sevStyle.bg} ${sevStyle.text} uppercase tracking-wider font-medium border ${sevStyle.border}`}>
                                                                {ep.min_severity}+
                                                            </span>
                                                        </div>
                                                        <p className="text-xs text-dim mt-0.5 truncate">
                                                            {(ep.channel_type === 'slack' ? ep.config.webhook_url as string : ep.config.url as string) || '—'}
                                                        </p>
                                                    </div>
                                                </div>

                                                <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                                                    {/* Test result */}
                                                    <AnimatePresence>
                                                        {testResult?.id === ep.id && (
                                                            <motion.span
                                                                initial={{ opacity: 0, x: 10 }}
                                                                animate={{ opacity: 1, x: 0 }}
                                                                exit={{ opacity: 0 }}
                                                                className={`text-xs font-medium ${testResult.ok ? 'text-green-400' : 'text-red-400'}`}
                                                            >
                                                                {testResult.ok ? 'Delivered!' : testResult.error || 'Failed'}
                                                            </motion.span>
                                                        )}
                                                    </AnimatePresence>

                                                    {/* Test button */}
                                                    <motion.button
                                                        whileHover={{ scale: 1.1 }}
                                                        whileTap={{ scale: 0.9 }}
                                                        onClick={async () => {
                                                            setTestingEndpoint(ep.id);
                                                            setTestResult(null);
                                                            try {
                                                                const result = await testNotificationEndpoint(ep.id);
                                                                setTestResult({ id: ep.id, ...result });
                                                            } catch {
                                                                setTestResult({ id: ep.id, ok: false, error: 'Request failed' });
                                                            }
                                                            setTestingEndpoint(null);
                                                        }}
                                                        disabled={testingEndpoint === ep.id}
                                                        className="p-2 rounded-xl text-dim hover:text-cyan-400 hover:bg-cyan-500/10 transition-all duration-200"
                                                        title="Send test"
                                                    >
                                                        <Send className={`w-4 h-4 ${testingEndpoint === ep.id ? 'animate-pulse text-cyan-400' : ''}`} />
                                                    </motion.button>

                                                    {/* Toggle */}
                                                    <button
                                                        onClick={async () => {
                                                            await updateNotificationEndpoint(ep.id, { enabled: !ep.enabled });
                                                            fetchData();
                                                        }}
                                                        className={`relative w-11 h-6 rounded-full transition-all duration-300 ${
                                                            ep.enabled ? 'bg-cyan-500/80' : 'bg-white/[0.1]'
                                                        }`}
                                                    >
                                                        <motion.div
                                                            layout
                                                            className="absolute top-1 w-4 h-4 bg-white rounded-full shadow-sm"
                                                            style={{ left: ep.enabled ? 'calc(100% - 20px)' : '4px' }}
                                                            transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                                                        />
                                                    </button>

                                                    {/* Delete */}
                                                    <motion.button
                                                        whileHover={{ scale: 1.1 }}
                                                        whileTap={{ scale: 0.9 }}
                                                        onClick={async () => {
                                                            if (!confirm('Delete this notification channel?')) return;
                                                            await deleteNotificationEndpoint(ep.id);
                                                            fetchData();
                                                        }}
                                                        className="p-2 rounded-xl text-dim hover:text-red-400 hover:bg-red-500/10 opacity-0 group-hover:opacity-100 transition-all duration-200"
                                                        title="Delete"
                                                    >
                                                        <Trash2 className="w-4 h-4" />
                                                    </motion.button>
                                                </div>
                                            </motion.div>
                                        );
                                    })}
                                </AnimatePresence>
                            </div>
                        </GlassCard>
                    </motion.div>
                )}

                {/* ── AI Agent Patterns Section ── */}
                {!loading && activeSection === 'ai-patterns' && (
                    <motion.div key="ai-patterns" custom={0} variants={sectionVariants} initial="hidden" animate="visible">
                        <GlassCard className="p-6" glow="#10b981">
                            <div className="flex items-center justify-between mb-6">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
                                        <Bot className="w-5 h-5 text-emerald-400" />
                                    </div>
                                    <div>
                                        <h2 className="text-lg font-semibold text-white">AI Agent Patterns</h2>
                                        <p className="text-xs text-gray-400">Process name patterns to identify AI coding agents. Changes apply immediately.</p>
                                    </div>
                                </div>
                                <motion.button
                                    whileHover={{ scale: 1.03 }}
                                    whileTap={{ scale: 0.97 }}
                                    onClick={() => { setShowPatternForm(!showPatternForm); setPatternError(null); }}
                                    className="px-4 py-2 bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 rounded-2xl text-sm font-semibold hover:bg-emerald-500/25 hover:shadow-lg hover:shadow-emerald-500/5 hover:border-emerald-500/50 transition-all duration-200 flex items-center gap-2"
                                >
                                    {showPatternForm ? <ChevronUp className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
                                    {showPatternForm ? 'Cancel' : 'Add Pattern'}
                                </motion.button>
                            </div>

                            {/* Add pattern form */}
                            <AnimatePresence>
                                {showPatternForm && (
                                    <motion.div
                                        initial={{ opacity: 0, height: 0 }}
                                        animate={{ opacity: 1, height: 'auto' }}
                                        exit={{ opacity: 0, height: 0 }}
                                        className="mb-5 overflow-hidden"
                                    >
                                        <div className="bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-5 space-y-5">
                                            {/* AI Suggestion */}
                                            <div className="space-y-3">
                                                <label className="text-sm text-gray-400 flex items-center gap-2">
                                                    <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                                                    Ask AI for pattern suggestions
                                                </label>
                                                <div className="flex items-center gap-2">
                                                    <div className="relative flex-1">
                                                        <Sparkles className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dim" />
                                                        <input
                                                            type="text"
                                                            value={suggestQuery}
                                                            onChange={e => setSuggestQuery(e.target.value)}
                                                            placeholder="Describe your software (e.g., VS Code, Docker)"
                                                            className="w-full pl-9 pr-4 py-2.5 text-sm bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-xl text-gray-200 placeholder-gray-500 focus:outline-none focus:border-purple-500/40 focus:ring-1 focus:ring-purple-500/20 transition-all"
                                                            onKeyDown={e => { if (e.key === 'Enter' && suggestQuery.trim()) handleSuggest(); }}
                                                        />
                                                    </div>
                                                    <motion.button
                                                        whileHover={{ scale: 1.03 }}
                                                        whileTap={{ scale: 0.97 }}
                                                        onClick={handleSuggest}
                                                        disabled={!suggestQuery.trim() || suggesting}
                                                        className="px-4 py-2.5 bg-purple-500/15 border border-purple-500/30 text-purple-400 rounded-xl text-sm font-semibold hover:bg-purple-500/25 hover:shadow-lg hover:shadow-purple-500/5 hover:border-purple-500/50 transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                                                    >
                                                        {suggesting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                                                        {suggesting ? 'Asking...' : 'Suggest'}
                                                    </motion.button>
                                                </div>

                                                {suggestError && (
                                                    <motion.p
                                                        initial={{ opacity: 0 }}
                                                        animate={{ opacity: 1 }}
                                                        className="text-red-400 text-xs flex items-center gap-1.5"
                                                    >
                                                        <AlertTriangle className="w-3 h-3" />
                                                        {suggestError}
                                                    </motion.p>
                                                )}

                                                <AnimatePresence>
                                                    {suggestions.length > 0 && (
                                                        <motion.div
                                                            initial={{ opacity: 0, y: -5 }}
                                                            animate={{ opacity: 1, y: 0 }}
                                                            exit={{ opacity: 0, y: -5 }}
                                                            className="space-y-1.5"
                                                        >
                                                            <p className="text-xs text-dim">Click a suggestion to auto-fill:</p>
                                                            {suggestions.map((s, i) => (
                                                                <motion.button
                                                                    key={i}
                                                                    initial={{ opacity: 0, x: -10 }}
                                                                    animate={{ opacity: 1, x: 0 }}
                                                                    transition={{ delay: i * 0.05 }}
                                                                    whileHover={{ scale: 1.01, x: 4 }}
                                                                    onClick={() => {
                                                                        setPatternForm({ pattern: s.pattern, agent_type: s.agent_type, description: s.description });
                                                                        setPatternError(null);
                                                                    }}
                                                                    className="w-full text-left bg-purple-500/5 border border-purple-500/20 rounded-xl px-4 py-2.5 hover:bg-purple-500/10 hover:border-purple-500/30 transition-all duration-200"
                                                                >
                                                                    <div className="flex items-center gap-2">
                                                                        <span className="font-mono text-sm text-white">{s.pattern}</span>
                                                                        <span className="text-[10px] px-2 py-0.5 rounded-lg bg-purple-500/20 text-purple-400 uppercase tracking-wider font-medium">{s.agent_type}</span>
                                                                        {s.pattern.length > 15 && (
                                                                            <span className="text-[10px] px-1.5 py-0.5 rounded-lg bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 flex items-center gap-1">
                                                                                <AlertTriangle className="w-3 h-3" />
                                                                                &gt;15 chars
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                    {s.description && (
                                                                        <p className="text-xs text-dim mt-1">{s.description}</p>
                                                                    )}
                                                                </motion.button>
                                                            ))}
                                                        </motion.div>
                                                    )}
                                                </AnimatePresence>
                                            </div>

                                            <div className="border-t border-white/[0.07]" />

                                            {/* Manual entry */}
                                            <div className="space-y-3">
                                                <label className="text-sm text-gray-400">Manual entry</label>
                                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                                    <div>
                                                        <label className="text-xs text-dim mb-1.5 block uppercase tracking-wider">Process Name</label>
                                                        <input
                                                            type="text"
                                                            value={patternForm.pattern}
                                                            onChange={e => setPatternForm({ ...patternForm, pattern: e.target.value })}
                                                            placeholder="e.g., my-agent"
                                                            className="w-full bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-xl px-4 py-2.5 text-sm font-mono text-gray-200 placeholder-gray-500 focus:outline-none focus:border-emerald-500/40 focus:ring-1 focus:ring-emerald-500/20 transition-all"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="text-xs text-dim mb-1.5 block uppercase tracking-wider">Agent Type</label>
                                                        <input
                                                            type="text"
                                                            value={patternForm.agent_type}
                                                            onChange={e => setPatternForm({ ...patternForm, agent_type: e.target.value })}
                                                            placeholder="e.g., my_agent"
                                                            className="w-full bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-xl px-4 py-2.5 text-sm font-mono text-gray-200 placeholder-gray-500 focus:outline-none focus:border-emerald-500/40 focus:ring-1 focus:ring-emerald-500/20 transition-all"
                                                        />
                                                    </div>
                                                </div>
                                                <div>
                                                    <label className="text-xs text-dim mb-1.5 block uppercase tracking-wider">Description (optional)</label>
                                                    <input
                                                        type="text"
                                                        value={patternForm.description}
                                                        onChange={e => setPatternForm({ ...patternForm, description: e.target.value })}
                                                        placeholder="What this agent does"
                                                        className="w-full bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-xl px-4 py-2.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-emerald-500/40 focus:ring-1 focus:ring-emerald-500/20 transition-all"
                                                    />
                                                </div>

                                                {patternForm.pattern.length > 15 && (
                                                    <motion.div
                                                        initial={{ opacity: 0 }}
                                                        animate={{ opacity: 1 }}
                                                        className="flex items-center gap-2 px-3 py-2 bg-yellow-500/10 border border-yellow-500/20 rounded-xl"
                                                    >
                                                        <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0" />
                                                        <p className="text-yellow-400 text-xs">
                                                            Linux limits process names to 15 chars. This pattern may only match via command line fallback.
                                                        </p>
                                                    </motion.div>
                                                )}

                                                {patternError && (
                                                    <motion.p
                                                        initial={{ opacity: 0 }}
                                                        animate={{ opacity: 1 }}
                                                        className="text-red-400 text-xs flex items-center gap-1.5"
                                                    >
                                                        <AlertTriangle className="w-3 h-3" />
                                                        {patternError}
                                                    </motion.p>
                                                )}

                                                <div className="flex justify-end">
                                                    <motion.button
                                                        whileHover={{ scale: 1.03 }}
                                                        whileTap={{ scale: 0.97 }}
                                                        onClick={handleCreatePattern}
                                                        disabled={!patternForm.pattern.trim() || !patternForm.agent_type.trim()}
                                                        className="px-5 py-2.5 bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 rounded-2xl text-sm font-semibold hover:bg-emerald-500/25 hover:shadow-lg hover:shadow-emerald-500/5 hover:border-emerald-500/50 transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                                                    >
                                                        <Plus className="w-4 h-4" />
                                                        Save Pattern
                                                    </motion.button>
                                                </div>
                                            </div>
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>

                            {/* Pattern list */}
                            <div className="space-y-2">
                                <AnimatePresence>
                                    {agentPatterns.length === 0 && !showPatternForm ? (
                                        <motion.div
                                            initial={{ opacity: 0, scale: 0.95 }}
                                            animate={{ opacity: 1, scale: 1 }}
                                            className="text-center py-10"
                                        >
                                            <motion.div
                                                initial={{ scale: 0 }}
                                                animate={{ scale: 1 }}
                                                transition={{ type: 'spring', stiffness: 200, damping: 15, delay: 0.1 }}
                                            >
                                                <Bot className="w-10 h-10 text-emerald-400/30 mx-auto mb-3" />
                                            </motion.div>
                                            <p className="text-sm text-gray-400">No AI agent patterns configured</p>
                                            <p className="text-xs text-dim mt-1">Add patterns to track AI coding agent processes</p>
                                        </motion.div>
                                    ) : agentPatterns.map((p) => (
                                        <motion.div
                                            key={p.id}
                                            variants={listItemVariants}
                                            initial="hidden"
                                            animate="visible"
                                            exit="exit"
                                            layout
                                            className="group flex items-center justify-between bg-[#0d1117]/60 border border-white/[0.07] rounded-2xl px-4 py-3 hover:border-white/[0.14] hover:bg-white/[0.03] transition-all duration-200"
                                        >
                                            <div className="flex items-center gap-3">
                                                <div className="p-1.5 rounded-lg bg-emerald-500/10">
                                                    <Bot className="w-3.5 h-3.5 text-emerald-400" />
                                                </div>
                                                <div>
                                                    <div className="flex items-center gap-2 flex-wrap">
                                                        <span className="text-sm font-medium font-mono text-white">{p.pattern}</span>
                                                        <span className="text-[10px] px-2 py-0.5 rounded-lg bg-emerald-500/15 text-emerald-400 border border-emerald-500/25 uppercase tracking-wider font-medium">{p.agent_type}</span>
                                                        {p.pattern.length > 15 && (
                                                            <span className="text-[10px] px-1.5 py-0.5 rounded-lg bg-yellow-500/15 text-yellow-400 border border-yellow-500/25 flex items-center gap-1" title="Exceeds 15 char Linux comm limit">
                                                                <AlertTriangle className="w-3 h-3" />
                                                                &gt;15
                                                            </span>
                                                        )}
                                                    </div>
                                                    {p.description && (
                                                        <p className="text-xs text-dim mt-0.5">{p.description}</p>
                                                    )}
                                                </div>
                                            </div>
                                            <motion.button
                                                whileHover={{ scale: 1.1 }}
                                                whileTap={{ scale: 0.9 }}
                                                onClick={async () => {
                                                    if (!confirm(`Delete pattern "${p.pattern}"?`)) return;
                                                    try {
                                                        await deleteAgentPattern(p.id);
                                                        fetchData();
                                                    } catch (err) {
                                                        console.error('Failed to delete pattern:', err);
                                                    }
                                                }}
                                                className="p-2 rounded-xl text-dim hover:text-red-400 hover:bg-red-500/10 opacity-0 group-hover:opacity-100 transition-all duration-200"
                                                title="Delete pattern"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </motion.button>
                                        </motion.div>
                                    ))}
                                </AnimatePresence>
                            </div>
                        </GlassCard>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
