import { ReactNode } from 'react';

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  hover?: boolean;
}

export function GlassCard({ children, className = '', hover = true }: GlassCardProps) {
  return (
    <div
      className={`
        bg-white/5 border border-orange-900/20 rounded-2xl backdrop-blur-sm
        ${hover ? 'hover:bg-white/10 hover:border-white/20 transition-all cursor-pointer' : ''}
        ${className}
      `}
    >
      {children}
    </div>
  );
}

export default GlassCard;
