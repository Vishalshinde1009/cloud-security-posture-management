import React from 'react';

interface LiveGridBackgroundProps {
  parallaxOffset: { x: number; y: number };
}

export const LiveGridBackground: React.FC<LiveGridBackgroundProps> = ({ parallaxOffset }) => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none select-none z-0">
      {/* 1. Deep ambient gradient lights */}
      <div 
        className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[450px] bg-cyan-600/10 blur-[140px] rounded-full transition-transform duration-700 ease-out"
        style={{
          transform: `translate(calc(-50% + ${parallaxOffset.x * 0.5}px), calc(-50% + ${parallaxOffset.y * 0.5}px))`
        }}
      />
      <div 
        className="absolute top-1/3 left-1/4 w-[500px] h-[400px] bg-blue-600/10 blur-[130px] rounded-full transition-transform duration-700 ease-out"
        style={{
          transform: `translate(${parallaxOffset.x * -0.4}px, ${parallaxOffset.y * -0.4}px)`
        }}
      />
      <div 
        className="absolute top-2/3 right-1/4 w-[450px] h-[350px] bg-purple-600/10 blur-[120px] rounded-full transition-transform duration-700 ease-out"
        style={{
          transform: `translate(${parallaxOffset.x * 0.3}px, ${parallaxOffset.y * 0.3}px)`
        }}
      />

      {/* 2. Cyber perspective grid */}
      <div 
        className="absolute inset-0 cyber-grid-moving opacity-40 transition-transform duration-500 ease-out"
        style={{
          transform: `translate(${parallaxOffset.x * 0.2}px, ${parallaxOffset.y * 0.2}px)`
        }}
      />

      {/* 3. Subtle network constellation nodes */}
      <svg className="absolute inset-0 w-full h-full opacity-30">
        <defs>
          <radialGradient id="dotGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#38BDF8" stopOpacity="0" />
          </radialGradient>
        </defs>
        {/* Floating network nodes & lines */}
        <line x1="15%" y1="20%" x2="28%" y2="35%" stroke="#1E293B" strokeWidth="1" strokeDasharray="3 3" />
        <line x1="75%" y1="18%" x2="88%" y2="30%" stroke="#1E293B" strokeWidth="1" strokeDasharray="3 3" />
        <line x1="82%" y1="65%" x2="68%" y2="80%" stroke="#1E293B" strokeWidth="1" strokeDasharray="3 3" />
        <line x1="20%" y1="70%" x2="32%" y2="82%" stroke="#1E293B" strokeWidth="1" strokeDasharray="3 3" />

        <circle cx="15%" cy="20%" r="2.5" fill="#38BDF8" className="animate-pulse-subtle" />
        <circle cx="28%" cy="35%" r="2" fill="#06B6D4" />
        <circle cx="75%" cy="18%" r="2" fill="#818CF8" />
        <circle cx="88%" cy="30%" r="2.5" fill="#38BDF8" className="animate-pulse-subtle" />
        <circle cx="82%" cy="65%" r="2" fill="#06B6D4" />
        <circle cx="68%" cy="80%" r="2" fill="#818CF8" />
        <circle cx="20%" cy="70%" r="2" fill="#38BDF8" />
        <circle cx="32%" cy="82%" r="2" fill="#06B6D4" />
      </svg>
    </div>
  );
};
