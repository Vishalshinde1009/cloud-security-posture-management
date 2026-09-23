import React from 'react';
import { Activity, ShieldCheck, Flame } from 'lucide-react';

interface SeverityItem {
  level: string;
  scoreRange: string;
  count: number;
  barPct: string;
  color: string;
  bgGrad: string;
  badge: string;
  desc: string;
}

const SEVERITIES: SeverityItem[] = [
  {
    level: 'CRITICAL',
    scoreRange: '90 – 100',
    count: 3,
    barPct: '85%',
    color: 'text-rose-400',
    bgGrad: 'bg-gradient-to-r from-rose-600 to-rose-400',
    badge: 'bg-rose-950/60 text-rose-300 border-rose-800/60',
    desc: 'Publicly exposed admin services or unauthenticated access risks.',
  },
  {
    level: 'HIGH',
    scoreRange: '70 – 89',
    count: 8,
    barPct: '68%',
    color: 'text-amber-400',
    bgGrad: 'bg-gradient-to-r from-amber-600 to-amber-400',
    badge: 'bg-amber-950/60 text-amber-300 border-amber-800/60',
    desc: 'Inactive credentials, unencrypted data stores, or broad IAM roles.',
  },
  {
    level: 'MEDIUM',
    scoreRange: '40 – 69',
    count: 12,
    barPct: '52%',
    color: 'text-yellow-400',
    bgGrad: 'bg-gradient-to-r from-yellow-600 to-yellow-400',
    badge: 'bg-yellow-950/60 text-yellow-300 border-yellow-800/60',
    desc: 'Missing telemetry, absent flow logging, or incomplete backup configs.',
  },
  {
    level: 'LOW',
    scoreRange: '0 – 39',
    count: 3,
    barPct: '25%',
    color: 'text-emerald-400',
    bgGrad: 'bg-gradient-to-r from-emerald-600 to-emerald-400',
    badge: 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60',
    desc: 'Minor posture discrepancies, tagging anomalies, or advisory checks.',
  },
];

export const RiskIntelligenceSection: React.FC = () => {
  return (
    <section id="risk-intelligence" className="py-20 border-b border-slate-800/60 bg-[#0A0F1D] relative">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center max-w-2xl mx-auto mb-14 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-xs font-mono uppercase tracking-wider">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            Explainable Risk Scoring
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Transparent, Deterministic Prioritization
          </h2>
          <p className="text-sm sm:text-base text-slate-400">
            Prioritize security findings using deterministic, transparent risk calculations rather than opaque scores.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
          {/* Left: 4-tier Severity Bar Breakdown */}
          <div className="glass-panel p-6 sm:p-8 rounded-2xl border border-slate-800 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                Risk Distribution Spectrum
              </span>
              <span className="text-[10px] font-mono text-cyan-400">
                26 Security Checks Mapped
              </span>
            </div>

            <div className="space-y-5">
              {SEVERITIES.map((item) => (
                <div key={item.level} className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${item.badge}`}>
                        {item.level}
                      </span>
                      <span className="font-mono text-slate-400 text-[11px]">Score {item.scoreRange}</span>
                    </div>
                    <span className="font-mono text-white font-bold">{item.count} findings</span>
                  </div>

                  {/* Meter Bar */}
                  <div className="w-full h-2.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800/80">
                    <div
                      className={`h-full rounded-full ${item.bgGrad} transition-all duration-1000`}
                      style={{ width: item.barPct }}
                    />
                  </div>

                  <p className="text-[11px] text-slate-400">
                    {item.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Right: Risk Formula Architecture Card */}
          <div className="space-y-4">
            <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Flame className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white tracking-tight">
                    Mathematical Risk Weighting
                  </h3>
                  <p className="text-xs font-mono text-cyan-400">
                    Risk = Base Severity × Exploitability × Asset Sensitivity
                  </p>
                </div>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">
                Rather than treating all cloud misconfigurations identically, our deterministic risk model
                amplifies findings that involve Internet ingress, public access blocks, and production workload contexts.
              </p>

              <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800 text-center font-mono text-xs">
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">BASE RULE</span>
                  <span className="font-bold text-white">10 – 100</span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">EXPOSURE</span>
                  <span className="font-bold text-cyan-400">0.0.0.0/0</span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">ISOLATION</span>
                  <span className="font-bold text-emerald-400">Multi-Tenant</span>
                </div>
              </div>
            </div>

            <div className="glass-panel p-4 rounded-xl border border-slate-800 flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Verified Deterministic Engine
              </span>
              <span className="font-mono text-[10px] text-slate-500">Zero Random Heuristics</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
