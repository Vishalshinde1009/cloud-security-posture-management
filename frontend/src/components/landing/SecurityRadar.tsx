import React from 'react';

export const SecurityRadar: React.FC = () => {
  // Pre-positioned asset blips across concentric rings
  const blips = [
    { x: '28%', y: '35%', color: 'bg-cyan-400', label: 'S3-Bucket', delay: '0s' },
    { x: '72%', y: '30%', color: 'bg-emerald-400', label: 'IAM-Role', delay: '1.2s' },
    { x: '35%', y: '68%', color: 'bg-blue-400', label: 'EC2-Node', delay: '0.6s' },
    { x: '65%', y: '65%', color: 'bg-purple-400', label: 'VPC-Gw', delay: '2.1s' },
    { x: '50%', y: '22%', color: 'bg-emerald-400', label: 'CT-Trail', delay: '1.8s' },
    { x: '78%', y: '52%', color: 'bg-amber-400', label: 'RDS-Inst', delay: '0.9s' },
  ];

  return (
    <div className="absolute inset-0 flex items-center justify-center pointer-events-none select-none overflow-hidden opacity-35">
      <div className="relative w-[480px] h-[480px] sm:w-[600px] sm:h-[600px] rounded-full flex items-center justify-center">
        {/* Concentric Radar Rings */}
        <div className="absolute inset-0 rounded-full border border-cyan-500/10" />
        <div className="absolute inset-16 rounded-full border border-cyan-500/15" />
        <div className="absolute inset-32 rounded-full border border-blue-500/20" />
        <div className="absolute inset-48 rounded-full border border-slate-700/30" />

        {/* Crosshair Axes */}
        <div className="absolute w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent" />
        <div className="absolute h-full w-[1px] bg-gradient-to-b from-transparent via-cyan-500/20 to-transparent" />

        {/* Rotating Radar Sweep Beam */}
        <div className="absolute inset-0 rounded-full radar-beam animate-radar-sweep origin-center" />

        {/* Asset Blips */}
        {blips.map((b, idx) => (
          <div
            key={idx}
            className="absolute flex items-center gap-1.5"
            style={{ left: b.x, top: b.y }}
          >
            <span
              className={`relative flex h-2 w-2 rounded-full ${b.color} shadow-glow-cyan`}
              style={{ animationDelay: b.delay }}
            >
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${b.color} opacity-75`} />
            </span>
            <span className="hidden sm:inline-block font-mono text-[9px] text-slate-500 tracking-wider">
              {b.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
