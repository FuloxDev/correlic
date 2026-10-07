'use client';

import { useState, useMemo, useCallback, useRef } from 'react';
import { motion } from 'framer-motion';
import { GitBranch, Maximize2, Minus, Plus } from 'lucide-react';
import type { EventNode, EventEdge } from '@/lib/api-client';

interface EventGraphViewProps {
    nodes: EventNode[];
    edges: EventEdge[];
}

const LANE_CONFIG: Record<string, { y: number; color: string; label: string }> = {
    process_exec: { y: 0, color: '#f97316', label: 'Process' },
    process_exit: { y: 0, color: '#f97316', label: 'Process' },
    file_open:    { y: 1, color: '#06b6d4', label: 'File' },
    net_connect:  { y: 2, color: '#a855f7', label: 'Network' },
    net_dns:      { y: 2, color: '#8b5cf6', label: 'DNS' },
};

const LANE_HEIGHT = 80;
const LANE_PADDING = 30;
const NODE_R = 10;
const LEFT_MARGIN = 100;
const RIGHT_MARGIN = 40;
const TOP_MARGIN = 30;

const EDGE_COLORS: Record<string, { stroke: string; dash?: string }> = {
    TEMPORAL:        { stroke: 'rgba(255,255,255,0.06)', dash: '4 4' },
    PROCESS_PARENT:  { stroke: '#f9731660' },
    AI_SPAWNED:      { stroke: '#06b6d460' },
    FILE_OPEN:       { stroke: '#06b6d430', dash: '3 3' },
    NET_CONNECT:     { stroke: '#a855f730', dash: '3 3' },
};

interface LayoutNode {
    node: EventNode;
    x: number;
    y: number;
}

export default function EventGraphView({ nodes, edges }: EventGraphViewProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
    const [dragging, setDragging] = useState(false);
    const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
    const [hoveredId, setHoveredId] = useState<string | null>(null);
    const [selectedId, setSelectedId] = useState<string | null>(null);

    // Layout: x = scaled timestamp, y = lane by event type
    const layoutNodes = useMemo(() => {
        if (!nodes.length) return [];
        const times = nodes.map(n => new Date(n.timestamp).getTime());
        const minT = Math.min(...times);
        const maxT = Math.max(...times);
        const timeSpan = Math.max(maxT - minT, 1000);
        const graphWidth = Math.max(600, nodes.length * 40);

        return nodes.map(n => {
            const t = new Date(n.timestamp).getTime();
            const x = LEFT_MARGIN + ((t - minT) / timeSpan) * graphWidth;
            const lane = LANE_CONFIG[n.type] || { y: 3, color: '#64748b' };
            const y = TOP_MARGIN + lane.y * (LANE_HEIGHT + LANE_PADDING) + LANE_HEIGHT / 2;
            return { node: n, x, y };
        });
    }, [nodes]);

    const nodeMap = useMemo(() => {
        const map = new Map<string, LayoutNode>();
        for (const ln of layoutNodes) map.set(ln.node.id, ln);
        return map;
    }, [layoutNodes]);

    // Connected nodes to selected
    const connectedIds = useMemo(() => {
        if (!selectedId) return new Set<string>();
        const ids = new Set<string>([selectedId]);
        for (const e of edges) {
            if (e.from === selectedId) ids.add(e.to);
            if (e.to === selectedId) ids.add(e.from);
        }
        return ids;
    }, [selectedId, edges]);

    const svgWidth = useMemo(() => {
        if (!layoutNodes.length) return 700;
        return Math.max(...layoutNodes.map(n => n.x)) + RIGHT_MARGIN + LEFT_MARGIN;
    }, [layoutNodes]);

    const svgHeight = useMemo(() => {
        const lanes = new Set(nodes.map(n => (LANE_CONFIG[n.type] || { y: 3 }).y));
        return TOP_MARGIN + (Math.max(...lanes) + 1) * (LANE_HEIGHT + LANE_PADDING) + 20;
    }, [nodes]);

    const handleMouseDown = useCallback((e: React.MouseEvent) => {
        if (e.button !== 0) return;
        setDragging(true);
        setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
    }, [transform]);

    const handleMouseMove = useCallback((e: React.MouseEvent) => {
        if (!dragging) return;
        setTransform(t => ({ ...t, x: e.clientX - dragStart.x, y: e.clientY - dragStart.y }));
    }, [dragging, dragStart]);

    const handleMouseUp = useCallback(() => setDragging(false), []);

    const handleWheel = useCallback((e: React.WheelEvent) => {
        e.preventDefault();
        setTransform(t => {
            const delta = e.deltaY > 0 ? 0.9 : 1.1;
            const newScale = Math.min(Math.max(t.scale * delta, 0.3), 3);
            return { ...t, scale: newScale };
        });
    }, []);

    const resetView = useCallback(() => setTransform({ x: 0, y: 0, scale: 1 }), []);

    if (!nodes.length) {
        return (
            <div className="bg-white/5 border border-orange-900/20 rounded-2xl backdrop-blur-sm p-6">
                <div className="flex items-center gap-2 mb-4">
                    <GitBranch className="w-5 h-5 text-orange-400" />
                    <h2 className="text-lg font-semibold">Event Graph</h2>
                </div>
                <div className="text-center py-12 text-gray-500">
                    <GitBranch className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No event graph data available</p>
                    <p className="text-xs text-gray-600 mt-1">Event graph requires Neo4j graph store</p>
                </div>
            </div>
        );
    }

    // Lane labels
    const activeLanes = useMemo(() => {
        const seen = new Map<number, string>();
        for (const n of nodes) {
            const cfg = LANE_CONFIG[n.type];
            if (cfg && !seen.has(cfg.y)) seen.set(cfg.y, cfg.label);
        }
        return Array.from(seen.entries()).sort((a, b) => a[0] - b[0]);
    }, [nodes]);

    return (
        <div className="bg-white/5 border border-orange-900/20 rounded-2xl backdrop-blur-sm overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-white/5">
                <div className="flex items-center gap-2">
                    <GitBranch className="w-5 h-5 text-orange-400" />
                    <h2 className="text-lg font-semibold">Event Graph</h2>
                    <span className="text-xs text-gray-500">{nodes.length} nodes, {edges.length} edges</span>
                </div>
                <div className="flex items-center gap-1">
                    {selectedId && (
                        <button onClick={() => setSelectedId(null)} className="px-2 py-1 text-[10px] text-gray-400 hover:text-white bg-white/5 rounded-xl transition-all duration-200 mr-2">
                            Clear selection
                        </button>
                    )}
                    <button onClick={() => setTransform(t => ({ ...t, scale: Math.min(t.scale * 1.2, 3) }))} className="p-1.5 bg-white/5 rounded-xl hover:bg-white/10 transition-all duration-200">
                        <Plus className="w-3.5 h-3.5 text-gray-400" />
                    </button>
                    <button onClick={() => setTransform(t => ({ ...t, scale: Math.max(t.scale * 0.8, 0.3) }))} className="p-1.5 bg-white/5 rounded-xl hover:bg-white/10 transition-all duration-200">
                        <Minus className="w-3.5 h-3.5 text-gray-400" />
                    </button>
                    <button onClick={resetView} className="p-1.5 bg-white/5 rounded-xl hover:bg-white/10 transition-all duration-200">
                        <Maximize2 className="w-3.5 h-3.5 text-gray-400" />
                    </button>
                </div>
            </div>

            {/* Canvas */}
            <div
                ref={containerRef}
                className="relative h-[350px] overflow-hidden cursor-grab active:cursor-grabbing select-none"
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
                onWheel={handleWheel}
            >
                <svg
                    width={svgWidth * transform.scale + 200}
                    height={svgHeight * transform.scale + 100}
                    className="absolute"
                    style={{ transform: `translate(${transform.x}px, ${transform.y}px) scale(${transform.scale})`, transformOrigin: '0 0' }}
                >
                    {/* Lane backgrounds */}
                    {activeLanes.map(([laneY, label]) => {
                        const y = TOP_MARGIN + laneY * (LANE_HEIGHT + LANE_PADDING);
                        return (
                            <g key={laneY}>
                                <rect x={0} y={y} width={svgWidth} height={LANE_HEIGHT} fill="rgba(255,255,255,0.01)" rx={8} />
                                <text x={12} y={y + 16} fill="rgba(255,255,255,0.15)" fontSize={10} fontFamily="monospace">{label}</text>
                            </g>
                        );
                    })}

                    {/* Edges */}
                    {edges.map((edge, i) => {
                        const from = nodeMap.get(edge.from);
                        const to = nodeMap.get(edge.to);
                        if (!from || !to) return null;
                        const cfg = EDGE_COLORS[edge.type] || EDGE_COLORS.TEMPORAL;
                        const dimmed = selectedId && !connectedIds.has(edge.from) && !connectedIds.has(edge.to);
                        const mx = (from.x + to.x) / 2;
                        const my = (from.y + to.y) / 2 + (from.y === to.y ? -20 : 0);
                        return (
                            <motion.path
                                key={i}
                                d={from.y === to.y
                                    ? `M ${from.x} ${from.y} Q ${mx} ${my - 15}, ${to.x} ${to.y}`
                                    : `M ${from.x} ${from.y} C ${from.x + 30} ${from.y}, ${to.x - 30} ${to.y}, ${to.x} ${to.y}`
                                }
                                fill="none"
                                stroke={cfg.stroke}
                                strokeWidth={1.5}
                                strokeDasharray={cfg.dash}
                                opacity={dimmed ? 0.15 : 1}
                                initial={{ pathLength: 0 }}
                                animate={{ pathLength: 1 }}
                                transition={{ delay: 0.2 + i * 0.02, duration: 0.4 }}
                            />
                        );
                    })}

                    {/* Nodes */}
                    {layoutNodes.map((ln, i) => {
                        const n = ln.node;
                        const cfg = LANE_CONFIG[n.type] || { color: '#64748b' };
                        const isHovered = hoveredId === n.id;
                        const isSelected = selectedId === n.id;
                        const dimmed = selectedId && !connectedIds.has(n.id);

                        return (
                            <motion.g
                                key={n.id}
                                initial={{ opacity: 0, scale: 0 }}
                                animate={{ opacity: dimmed ? 0.2 : 1, scale: 1 }}
                                transition={{ delay: 0.1 + i * 0.015 }}
                                style={{ cursor: 'pointer' }}
                                onMouseEnter={() => setHoveredId(n.id)}
                                onMouseLeave={() => setHoveredId(null)}
                                onClick={(e) => { e.stopPropagation(); setSelectedId(isSelected ? null : n.id); }}
                            >
                                {/* Glow for finding nodes */}
                                {n.is_finding && (
                                    <circle cx={ln.x} cy={ln.y} r={NODE_R + 4} fill="none" stroke={cfg.color} strokeWidth={1} opacity={0.5}>
                                        <animate attributeName="r" values={`${NODE_R + 3};${NODE_R + 6};${NODE_R + 3}`} dur="2s" repeatCount="indefinite" />
                                        <animate attributeName="opacity" values="0.5;0.2;0.5" dur="2s" repeatCount="indefinite" />
                                    </circle>
                                )}
                                <circle
                                    cx={ln.x} cy={ln.y} r={NODE_R}
                                    fill={cfg.color}
                                    opacity={isHovered || isSelected ? 1 : 0.7}
                                    stroke={isSelected ? '#fff' : isHovered ? '#fff8' : 'none'}
                                    strokeWidth={isSelected ? 2 : 1}
                                />
                                {n.is_finding && (
                                    <circle cx={ln.x} cy={ln.y} r={3} fill="#fff" opacity={0.8} />
                                )}
                            </motion.g>
                        );
                    })}
                </svg>

                {/* Hover tooltip */}
                {hoveredId && (() => {
                    const ln = layoutNodes.find(n => n.node.id === hoveredId);
                    if (!ln) return null;
                    const n = ln.node;
                    return (
                        <div
                            className="absolute pointer-events-none z-20 backdrop-blur-xl bg-[#0f1729]/95 rounded-lg px-3 py-2 border border-white/10 text-[10px] space-y-0.5 shadow-xl max-w-[300px]"
                            style={{
                                left: ln.x * transform.scale + transform.x,
                                top: (ln.y + NODE_R + 8) * transform.scale + transform.y,
                                transform: 'translateX(-50%)',
                            }}
                        >
                            <div className="text-gray-200 font-medium break-words">{n.label}</div>
                            <div className="text-gray-500">{n.type} &middot; {new Date(n.timestamp).toLocaleTimeString()}</div>
                            {n.pid && <div className="text-gray-500 font-mono">PID {n.pid}</div>}
                            {n.is_finding && <div className="text-orange-400 font-medium">Finding linked</div>}
                        </div>
                    );
                })()}
            </div>

            {/* Legend */}
            <div className="flex flex-wrap items-center gap-4 px-6 py-3 border-t border-white/5">
                {Object.entries(LANE_CONFIG)
                    .filter((_, i, arr) => arr.findIndex(([, v]) => v.y === arr[i][1].y) === i)
                    .map(([type, cfg]) => (
                        <div key={type} className="flex items-center gap-1.5">
                            <span className="w-2.5 h-2.5 rounded-full" style={{ background: cfg.color }} />
                            <span className="text-[10px] text-gray-500">{cfg.label}</span>
                        </div>
                    ))}
                <span className="w-px h-3 bg-white/10" />
                <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full border border-orange-500 bg-orange-500/30" />
                    <span className="text-[10px] text-gray-500">Finding</span>
                </div>
            </div>
        </div>
    );
}
