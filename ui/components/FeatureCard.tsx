import { GlassCard } from './GlassCard';
import { LucideIcon } from 'lucide-react';

interface FeatureCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
}

export function FeatureCard({ icon: Icon, title, description }: FeatureCardProps) {
  return (
    <GlassCard className="p-6">
      <div className="flex flex-col items-start space-y-4">
        <div className="p-3 bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-lg">
          <Icon className="w-6 h-6 text-blue-400" />
        </div>
        <h3 className="text-xl text-white">{title}</h3>
        <p className="text-gray-400 leading-relaxed">{description}</p>
      </div>
    </GlassCard>
  );
}
