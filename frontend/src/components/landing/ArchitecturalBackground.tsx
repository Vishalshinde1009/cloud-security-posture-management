import React from 'react';

interface ArchitecturalBackgroundProps {
  parallaxOffset?: { x: number; y: number };
}

export const ArchitecturalBackground: React.FC<ArchitecturalBackgroundProps> = ({ parallaxOffset = { x: 0, y: 0 } }) => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none select-none z-0">
      {/* 1. Deep data-center foundation */}
      <div className="absolute inset-0 bg-[#070B12]" />

      {/* 2. Soft overhead luminaire (neutral-white/soft cyan, low key studio light) */}
      <div 
        className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[400px] bg-gradient-to-b from-slate-400/5 via-cyan-950/10 to-transparent blur-[140px] rounded-full pointer-events-none"
        style={{
          transform: `translate(calc(-50% + ${parallaxOffset.x * 0.25}px), ${parallaxOffset.y * 0.25}px)`
        }}
      />

      {/* 3. Subtle equipment rack silhouettes in distant background */}
      <div className="absolute inset-x-0 top-12 flex justify-between px-8 sm:px-20 opacity-15 pointer-events-none">
        {/* Left Rack Pillar */}
        <div className="w-16 h-96 border-r border-t border-slate-700 flex flex-col gap-2 p-1">
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
        </div>
        {/* Right Rack Pillar */}
        <div className="w-16 h-96 border-l border-t border-slate-700 flex flex-col gap-2 p-1">
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
          <div className="h-4 border-b border-slate-700/60" />
        </div>
      </div>

      {/* 4. Raised equipment platform & floor perspective grid */}
      <div 
        className="absolute inset-x-0 bottom-0 h-[480px] datacenter-floor opacity-25"
        style={{
          maskImage: 'linear-gradient(to top, rgba(0,0,0,1) 0%, rgba(0,0,0,0) 100%)',
          WebkitMaskImage: 'linear-gradient(to top, rgba(0,0,0,1) 0%, rgba(0,0,0,0) 100%)',
          transform: `perspective(600px) rotateX(45deg) translate(${parallaxOffset.x * 0.15}px, ${parallaxOffset.y * 0.15}px)`
        }}
      />

      {/* 5. Physical cable channel conduits crossing floor plane */}
      <div className="absolute inset-x-0 bottom-16 h-[2px] bg-slate-800/40">
        <div className="absolute left-1/4 w-1/2 h-[1px] bg-cyan-500/20" />
      </div>
      <div className="absolute inset-x-0 bottom-8 h-[2px] bg-slate-800/30" />

      {/* 6. Precision engineering alignment markers */}
      <div className="absolute top-20 left-8 text-[9px] font-mono text-slate-600 opacity-40">
        [SYS-LAB-01] // ENCL-Z100 // CALIBRATED
      </div>
      <div className="absolute top-20 right-8 text-[9px] font-mono text-slate-600 opacity-40">
        PWR: DUAL-FEED // GND-REF: 0.02Ω
      </div>

      {/* 7. Subtle boundary vignette */}
      <div className="absolute inset-0 bg-radial-gradient from-transparent via-[#070B12]/40 to-[#070B12]" />
    </div>
  );
};
