import { GlassCard } from './GlassCard';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  icon: LucideIcon;
  label: string;
  value: string | number;
  trend?: string;
  color?: 'blue' | 'purple' | 'cyan' | 'red' | 'orange' | 'yellow';
}

const colorClasses = {
  blue: 'from-blue-500/20 to-blue-600/20 text-blue-400',
  purple: 'from-purple-500/20 to-purple-600/20 text-purple-400',
  cyan: 'from-cyan-500/20 to-cyan-600/20 text-cyan-400',
  red: 'from-red-500/20 to-red-600/20 text-red-400',
  orange: 'from-orange-500/20 to-orange-600/20 text-orange-400',
  yellow: 'from-yellow-500/20 to-yellow-600/20 text-yellow-400',
};

export function MetricCard({ icon: Icon, label, value, trend, color = 'blue' }: MetricCardProps) {
  return (
    <GlassCard hover={false} className="p-6">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm text-gray-400 mb-2">{label}</p>
          <p className="text-3xl text-white mb-1">{value}</p>
          {trend && <p className="text-xs text-gray-500">{trend}</p>}
        </div>
        <div className={`p-3 bg-gradient-to-br ${colorClasses[color].split(' ')[0]} ${colorClasses[color].split(' ')[1]} rounded-lg`}>
          <Icon className={`w-5 h-5 ${colorClasses[color].split(' ')[2]}`} />
        </div>
      </div>
    </GlassCard>
  );
}
