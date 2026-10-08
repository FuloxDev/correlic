'use client';

import { useState, useMemo, useCallback, useRef } from 'react';
import { motion } from 'framer-motion';
import { Cpu, Bot, AlertTriangle, User, Maximize2, Minus, Plus } from 'lucide-react';

// Simplified process node from incident API (subset of ProcessNode)
interface TreeNode {
    pid: number;
    ppid: number;
    comm: string;
    exe_path?: string;
    user?: string;
    ai_type?: string;
    started_at?: string;
    finding_ids?: string[];
    children?: TreeNode[];
}

interface ProcessTreeViewProps {
    tree: TreeNode | null;
}

const NODE_W = 180;
const NODE_H = 52;
const V_GAP = 64;
const H_GAP = 20;

interface LayoutNode {
    node: TreeNode;
    x: number;
    y: number;
    children: LayoutNode[];
}

function countLeaves(node: TreeNode): number {
    if (!node.children || node.children.length === 0) return 1;
    return node.children.reduce((sum, c) => sum + countLeaves(c), 0);
}

function layout(node: TreeNode, depth: number, offsetX: number): LayoutNode {
    const children: LayoutNode[] = [];
    let x = offsetX;

    if (node.children && node.children.length > 0) {
        let childOffset = offsetX;
        for (const child of node.children) {
            const childLayout = layout(child, depth + 1, childOffset);
            children.push(childLayout);
            const leaves = countLeaves(child);
            childOffset += leaves * (NODE_W + H_GAP);
        }
        // Center parent above its children
        const firstChild = children[0];
        const lastChild = children[children.length - 1];
        x = (firstChild.x + lastChild.x) / 2;
    }

    return { node, x, y: depth * (NODE_H + V_GAP), children };
}

function flattenLayout(ln: LayoutNode): LayoutNode[] {
    const result: LayoutNode[] = [ln];
    for (const child of ln.children) {
        result.push(...flattenLayout(child));
    }
    return result;
}

function getEdges(ln: LayoutNode): Array<{ from: LayoutNode; to: LayoutNode }> {
    const edges: Array<{ from: LayoutNode; to: LayoutNode }> = [];
    for (const child of ln.children) {
        edges.push({ from: ln, to: child });
        edges.push(...getEdges(child));
    }
    return edges;
}

export default function ProcessTreeView({ tree }: ProcessTreeViewProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const [transform, setTransform] = useState({ x: 40, y: 40, scale: 1 });
    const [dragging, setDragging] = useState(false);
    const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
    const [hoveredPid, setHoveredPid] = useState<number | null>(null);

    const root = useMemo(() => tree ? layout(tree, 0, 0) : null, [tree]);
    const nodes = useMemo(() => root ? flattenLayout(root) : [], [root]);
    const edges = useMemo(() => root ? getEdges(root) : [], [root]);

    const svgWidth = useMemo(() => {
        if (!nodes.length) return 400;
        return Math.max(...nodes.map(n => n.x + NODE_W)) + 80;
    }, [nodes]);
    const svgHeight = useMemo(() => {
        if (!nodes.length) return 200;
        return Math.max(...nodes.map(n => n.y + NODE_H)) + 80;
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

    const resetView = useCallback(() => setTransform({ x: 40, y: 40, scale: 1 }), []);

    if (!tree) {
        return (
            <div className="bg-white/5 border border-orange-900/20 rounded-2xl backdrop-blur-sm p-6">
                <div className="flex items-center gap-2 mb-4">
                    <Cpu className="w-5 h-5 text-orange-400" />
                    <h2 className="text-lg font-semibold">Process Tree</h2>
                </div>
                <div className="text-center py-12 text-dim">
                    <Cpu className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No process tree data available</p>
                    <p className="text-xs text-dim mt-1">Process tree requires Neo4j graph store</p>
                </div>
            </div>
        );
    }

    return (
        <div className="bg-white/5 border border-orange-900/20 rounded-2xl backdrop-blur-sm overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-white/5">
                <div className="flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-orange-400" />
                    <h2 className="text-lg font-semibold">Process Tree</h2>
                    <span className="text-xs text-dim">{nodes.length} processes</span>
                </div>
                <div className="flex items-center gap-1">
                    <button onClick={() => setTransform(t => ({ ...t, scale: Math.min(t.scale * 1.2, 3) }))} className="p-1.5 bg-white/5 rounded-xl hover:bg-white/10 transition-all duration-200" title="Zoom in">
                        <Plus className="w-3.5 h-3.5 text-gray-400" />
                    </button>
                    <button onClick={() => setTransform(t => ({ ...t, scale: Math.max(t.scale * 0.8, 0.3) }))} className="p-1.5 bg-white/5 rounded-xl hover:bg-white/10 transition-all duration-200" title="Zoom out">
                        <Minus className="w-3.5 h-3.5 text-gray-400" />
                    </button>
                    <button onClick={resetView} className="p-1.5 bg-white/5 rounded-xl hover:bg-white/10 transition-all duration-200" title="Reset view">
                        <Maximize2 className="w-3.5 h-3.5 text-gray-400" />
                    </button>
                </div>
            </div>

            {/* Canvas */}
            <div
                ref={containerRef}
                className="relative h-[400px] overflow-hidden cursor-grab active:cursor-grabbing select-none"
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
                onWheel={handleWheel}
            >
                <svg
                    width={svgWidth * transform.scale + 200}
                    height={svgHeight * transform.scale + 200}
                    className="absolute"
                    style={{ transform: `translate(${transform.x}px, ${transform.y}px) scale(${transform.scale})`, transformOrigin: '0 0' }}
                >
                    {/* Edges */}
                    {edges.map((edge, i) => {
                        const fx = edge.from.x + NODE_W / 2;
                        const fy = edge.from.y + NODE_H;
                        const tx = edge.to.x + NODE_W / 2;
                        const ty = edge.to.y;
                        const my = (fy + ty) / 2;
                        return (
                            <motion.path
                                key={i}
                                d={`M ${fx} ${fy} C ${fx} ${my}, ${tx} ${my}, ${tx} ${ty}`}
                                fill="none"
                                stroke={edge.to.node.ai_type ? '#06b6d4' : 'rgba(255,255,255,0.08)'}
                                strokeWidth={edge.to.node.finding_ids?.length ? 2 : 1}
                                initial={{ pathLength: 0, opacity: 0 }}
                                animate={{ pathLength: 1, opacity: 1 }}
                                transition={{ delay: 0.3 + i * 0.05, duration: 0.5 }}
                            />
                        );
                    })}

                    {/* Nodes */}
                    {nodes.map((ln, i) => {
                        const n = ln.node;
                        const hasFindings = n.finding_ids && n.finding_ids.length > 0;
                        const isHovered = hoveredPid === n.pid;
                        const name = n.comm || n.exe_path?.split('/').pop() || `PID ${n.pid}`;

                        return (
                            <motion.g
                                key={n.pid}
                                initial={{ opacity: 0, y: -10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: 0.1 + i * 0.03 }}
                            >
                                {/* Glow for finding nodes */}
                                {hasFindings && (
                                    <rect
                                        x={ln.x - 2} y={ln.y - 2}
                                        width={NODE_W + 4} height={NODE_H + 4}
                                        rx={12} fill="none"
                                        stroke="#f97316" strokeWidth={1.5}
                                        opacity={0.4}
                                    />
                                )}
                                <foreignObject x={ln.x} y={ln.y} width={NODE_W} height={NODE_H}>
                                    <div
                                        className={`h-full px-3 py-2 rounded-xl border transition-all ${
                                            hasFindings
                                                ? 'bg-orange-500/[0.08] border-orange-500/20'
                                                : n.ai_type
                                                    ? 'bg-cyan-500/[0.06] border-cyan-500/15'
                                                    : 'bg-white/[0.04] border-white/[0.08]'
                                        } ${isHovered ? 'ring-1 ring-white/20' : ''}`}
                                        onMouseEnter={() => setHoveredPid(n.pid)}
                                        onMouseLeave={() => setHoveredPid(null)}
                                    >
                                        <div className="flex items-center gap-1.5 mb-0.5">
                                            {n.ai_type ? (
                                                <Bot className="w-3 h-3 text-cyan-400 shrink-0" />
                                            ) : (
                                                <Cpu className="w-3 h-3 text-dim shrink-0" />
                                            )}
                                            <span className="text-[11px] text-white font-medium truncate">{name}</span>
                                        </div>
                                        <div className="flex items-center gap-1.5">
                                            <span className="text-[9px] text-dim font-mono">PID {n.pid}</span>
                                            {n.ai_type && (
                                                <span className="text-[8px] px-1 py-0.5 bg-cyan-500/15 text-cyan-400 rounded">{n.ai_type}</span>
                                            )}
                                            {n.user && (
                                                <span className="text-[8px] text-dim flex items-center gap-0.5">
                                                    <User className="w-2.5 h-2.5" />{n.user}
                                                </span>
                                            )}
                                            {hasFindings && (
                                                <AlertTriangle className="w-3 h-3 text-orange-400 shrink-0" />
                                            )}
                                        </div>
                                    </div>
                                </foreignObject>
                            </motion.g>
                        );
                    })}
                </svg>

                {/* Hovered node tooltip */}
                {hoveredPid !== null && (() => {
                    const ln = nodes.find(n => n.node.pid === hoveredPid);
                    if (!ln) return null;
                    const n = ln.node;
                    return (
                        <div
                            className="absolute pointer-events-none z-20 backdrop-blur-xl bg-[#0f1729]/95 rounded-lg px-3 py-2 border border-white/10 text-[10px] space-y-0.5 shadow-xl max-w-[280px]"
                            style={{
                                left: (ln.x + NODE_W / 2) * transform.scale + transform.x,
                                top: (ln.y + NODE_H + 8) * transform.scale + transform.y,
                                transform: 'translateX(-50%)',
                            }}
                        >
                            {n.exe_path && <div className="text-gray-300 font-mono break-all">{n.exe_path}</div>}
                            {n.user && <div className="text-gray-400">User: {n.user}</div>}
                            <div className="text-dim">PID {n.pid} → PPID {n.ppid}</div>
                            {n.started_at && <div className="text-dim">{new Date(n.started_at).toLocaleTimeString()}</div>}
                            {n.finding_ids && n.finding_ids.length > 0 && (
                                <div className="text-orange-400">{n.finding_ids.length} finding{n.finding_ids.length > 1 ? 's' : ''}</div>
                            )}
                        </div>
                    );
                })()}
            </div>
        </div>
    );
}
