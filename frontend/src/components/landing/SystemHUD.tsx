import React from 'react';

interface SystemHUDProps {
  currentStageName?: string;
}

export const SystemHUD: React.FC<SystemHUDProps> = ({ currentStageName = 'HERO DISCOVERY' }) => {
  return (
    <aside 
      aria-label="System Diagnostics HUD"
      className="fixed bottom-5 right-5 z-50 pointer-events-none hidden md:flex items-center gap-4 px-3.5 py-2 rounded-lg chassis-steel border border-[#203248] shadow-2xl backdrop-blur-md"
    >
      <div className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
        <span className="text-[9px] font-mono text-slate-300 font-bold uppercase tracking-wider">
          CSPM ENGINE: ONLINE
        </span>
      </div>

      <span className="w-[1px] h-3 bg-slate-700" />

      <div className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
        <span className="text-[9px] font-mono text-slate-300 font-bold uppercase tracking-wider">
          AWS STS: VERIFIED
        </span>
      </div>

      <span className="w-[1px] h-3 bg-slate-700" />

      <div className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
        <span className="text-[9px] font-mono text-emerald-400 font-bold uppercase tracking-wider">
          READ-ONLY: ENFORCED
        </span>
      </div>

      <span className="w-[1px] h-3 bg-slate-700" />

      <div className="text-[8px] font-mono text-slate-500 uppercase">
        ACTIVE: {currentStageName}
      </div>
    </aside>
  );
};
