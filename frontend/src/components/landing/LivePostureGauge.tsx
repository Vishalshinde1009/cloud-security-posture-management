import React from 'react';
import { ShieldAlert } from 'lucide-react';

interface LivePostureGaugeProps {
  score?: number;
  rating?: string;
  isDemo?: boolean;
}

export const LivePostureGauge: React.FC<LivePostureGaugeProps> = ({
  score = 47.8,
  rating = 'POOR',
  isDemo = true,
}) => {
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="glass-panel p-4 rounded-2xl border border-slate-800 shadow-xl flex items-center gap-4 relative overflow-hidden group hover:border-amber-500/40 transition-colors">
      {/* Background glow */}
      <div className="absolute -right-6 -bottom-6 w-20 h-20 bg-amber-500/10 rounded-full blur-xl pointer-events-none" />

      {/* SVG Radial Meter */}
      <div className="relative w-20 h-20 flex-shrink-0 flex items-center justify-center">
        <svg className="w-20 h-20 -rotate-90 transform" viewBox="0 0 80 80">
          <circle
            cx="40"
            cy="40"
            r={radius}
            stroke="currentColor"
            strokeWidth="6"
            className="text-slate-800/80"
            fill="transparent"
          />
          <circle
            cx="40"
            cy="40"
            r={radius}
            stroke="currentColor"
            strokeWidth="6"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="text-amber-400 transition-all duration-1000 ease-out drop-shadow-[0_0_8px_rgba(245,158,11,0.4)]"
            fill="transparent"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-base font-extrabold font-mono text-white tracking-tight leading-none">
            {score.toFixed(1)}
          </span>
          <span className="text-[9px] font-mono text-slate-400 mt-0.5">/ 100</span>
        </div>
      </div>

      {/* Gauge Details */}
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-amber-400" />
            Posture Score
          </span>
          {isDemo && (
            <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-800 border border-slate-700 text-cyan-300">
              DEMO
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
            {rating}
          </span>
          <span className="text-[11px] text-slate-400">Baseline Audit</span>
        </div>
        <p className="text-[10px] text-slate-400 font-mono">
          Continuous Risk Calculation
        </p>
      </div>
    </div>
  );
};
