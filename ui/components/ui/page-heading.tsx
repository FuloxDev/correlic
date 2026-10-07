'use client';

import { motion } from 'framer-motion';

interface PageHeadingProps {
    title: string;
    subtitle: string;
    children?: React.ReactNode; // for pills/badges after subtitle
    actions?: React.ReactNode;  // right-aligned content (buttons, filters)
}

export function PageHeading({ title, subtitle, children, actions }: PageHeadingProps) {
    return (
        <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="flex flex-col md:flex-row md:items-center justify-between gap-4"
        >
            <div>
                <div className="relative inline-block">
                    <motion.h1
                        className="text-4xl font-extrabold tracking-tight bg-clip-text text-transparent"
                        style={{
                            backgroundImage: 'linear-gradient(135deg, #ffffff 0%, rgba(255,255,255,0.7) 50%, #ffffff 100%)',
                            backgroundSize: '200% 100%',
                        }}
                        initial={{ backgroundPosition: '200% 0' }}
                        animate={{ backgroundPosition: '0% 0' }}
                        transition={{ duration: 1.2, ease: 'easeOut' }}
                    >
                        {title}
                    </motion.h1>
                    {/* Underline accent */}
                    <motion.div
                        className="absolute -bottom-1 left-0 h-[2px] rounded-full"
                        style={{ background: 'linear-gradient(90deg, var(--theme-accent, #06b6d4), transparent)' }}
                        initial={{ width: 0 }}
                        animate={{ width: '60%' }}
                        transition={{ delay: 0.3, duration: 0.6, ease: 'easeOut' }}
                    />
                </div>
                <motion.div
                    className="flex items-center gap-3 mt-2"
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.15, duration: 0.35 }}
                >
                    <p className="text-gray-300/70 text-[15px]">{subtitle}</p>
                    {children}
                </motion.div>
            </div>
            {actions && (
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.2, duration: 0.3 }}
                >
                    {actions}
                </motion.div>
            )}
        </motion.div>
    );
}
