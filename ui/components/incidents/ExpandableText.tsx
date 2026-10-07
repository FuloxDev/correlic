'use client';

import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown } from 'lucide-react';

interface ExpandableTextProps {
    text: string;
    maxLines?: number;
    mono?: boolean;
    className?: string;
}

export default function ExpandableText({ text, maxLines = 2, mono = false, className = '' }: ExpandableTextProps) {
    const [expanded, setExpanded] = useState(false);
    const [clamped, setClamped] = useState(false);
    const ref = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const el = ref.current;
        if (!el) return;
        setClamped(el.scrollHeight > el.clientHeight + 2);
    }, [text, maxLines]);

    const baseClasses = mono
        ? 'font-mono text-[11px] break-all'
        : 'text-sm break-words';

    return (
        <div className={`relative ${className}`}>
            <div
                ref={ref}
                className={`${baseClasses} overflow-hidden transition-all duration-200 ${expanded ? '' : `line-clamp-${maxLines}`}`}
                style={expanded ? undefined : { WebkitLineClamp: maxLines, display: '-webkit-box', WebkitBoxOrient: 'vertical' }}
            >
                {text}
            </div>
            <AnimatePresence>
                {clamped && !expanded && (
                    <motion.button
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={() => setExpanded(true)}
                        className="mt-1 text-[10px] text-purple-400 hover:text-purple-300 transition-colors flex items-center gap-0.5"
                    >
                        Show more
                        <ChevronDown className="w-3 h-3" />
                    </motion.button>
                )}
            </AnimatePresence>
            {expanded && clamped && (
                <button
                    onClick={() => setExpanded(false)}
                    className="mt-1 text-[10px] text-purple-400 hover:text-purple-300 transition-colors flex items-center gap-0.5"
                >
                    Show less
                    <ChevronDown className="w-3 h-3 rotate-180" />
                </button>
            )}
        </div>
    );
}
