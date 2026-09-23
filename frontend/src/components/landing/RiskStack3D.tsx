import React, { useState } from 'react';
import { ShieldCheck, ChevronRight } from 'lucide-react';

interface RiskLevel {
  level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  scoreRange: string;
  weight: number;
  statusText: string;
  color: string;
  borderColor: string;
  textColor: string;
  accentBar: string;
  exampleFinding: string;
  remediationTime: string;
  impactFormula: string;
  engravingMark: string;
}

export const RiskStack3D: React.FC = () => {
  const [activeLevel, setActiveLevel] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('CRITICAL');

  const riskLevels: RiskLevel[] = [
    {
      level: 'CRITICAL',
      scoreRange: '9.0 – 10.0',
      weight: 10,
      statusText: 'Immediate Action',
      color: '#f43f5e',
      borderColor: 'border-rose-500/50',
      textColor: 'text-rose-400',
      accentBar: 'bg-rose-500 led-rose',
      exampleFinding: 'IAM Root User Access Keys Active without MFA requirement',
      remediationTime: 'Immediate (< 4 Hours)',
      impactFormula: 'Severity (10) × Exploitability (1.0) × Sensitivity (1.0) = 10.0 Impact',
      engravingMark: 'BLOCK-CRIT // WT: 10.0 // SLA: 4H'
    },
    {
      level: 'HIGH',
      scoreRange: '7.0 – 8.9',
      weight: 7.5,
      statusText: 'Urgent Remediation',
      color: '#f97316',
      borderColor: 'border-orange-500/50',
      textColor: 'text-orange-400',
      accentBar: 'bg-orange-500',
      exampleFinding: 'Security Group authorizes Ingress TCP 22 (SSH) from CIDR 0.0.0.0/0',
      remediationTime: 'Urgent (< 24 Hours)',
      impactFormula: 'Severity (8) × Exploitability (0.9) × Sensitivity (1.0) = 7.2 Impact',
      engravingMark: 'BLOCK-HIGH // WT: 7.5 // SLA: 24H'
    },
    {
      level: 'MEDIUM',
      scoreRange: '4.0 – 6.9',
      weight: 5.0,
      statusText: 'Scheduled Review',
      color: '#eab308',
      borderColor: 'border-amber-500/50',
      textColor: 'text-amber-400',
      accentBar: 'bg-amber-500 led-amber',
      exampleFinding: 'Amazon S3 Bucket Server-Side Encryption (SSE) not enforced via default KMS key',
      remediationTime: 'Scheduled (< 7 Days)',
      impactFormula: 'Severity (5) × Exploitability (0.7) × Sensitivity (1.0) = 3.5 Impact',
      engravingMark: 'BLOCK-MED // WT: 5.0 // SLA: 7D'
    },
    {
      level: 'LOW',
      scoreRange: '0.1 – 3.9',
      weight: 2.0,
      statusText: 'Standard Baseline',
      color: '#06b6d4',
      borderColor: 'border-cyan-500/50',
      textColor: 'text-cyan-400',
      accentBar: 'bg-cyan-500 led-cyan',
      exampleFinding: 'VPC Default Security Group allows unrestricted intra-group egress communication',
      remediationTime: 'Standard Sprint Cycle',
      impactFormula: 'Severity (2) × Exploitability (0.4) × Sensitivity (0.8) = 0.6 Impact',
      engravingMark: 'BLOCK-LOW // WT: 2.0 // SLA: SPRINT'
    }
  ];

  const current = riskLevels.find(r => r.level === activeLevel) || riskLevels[0];

  return (
    <section id="risk-scoring" className="relative py-28 px-4 sm:px-6 lg:px-8 border-t border-[#182638] bg-[#070B12] overflow-hidden">
      {/* Subtle background glow */}
      <div className="absolute top-1/2 right-1/4 w-[600px] h-[350px] bg-rose-950/10 rounded-full blur-[140px] pointer-events-none" />

      <div className="max-w-7xl mx-auto relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#0D1522] border border-[#1E2E44] text-xs font-mono text-cyan-400">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
            QUANTITATIVE RISK ENGINE
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white">
            Explainable Risk Scoring. Zero Guesswork.
          </h2>
          <p className="text-slate-400 text-base leading-relaxed">
            Every finding is evaluated mathematically based on base severity, asset exposure, and compliance weight. 
            Prioritize actionable remediation by quantified risk instead of endless alert fatigue.
          </p>
        </div>

        {/* 3D Stacked Metal Blocks and Engineering Formula Bay */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          
          {/* Left: 4 Physical Stacked Metal Blocks with Engravings */}
          <div className="lg:col-span-6 flex flex-col justify-between space-y-4 perspective-1000">
            {riskLevels.map((risk, index) => {
              const isSelected = activeLevel === risk.level;
              const elevation = (riskLevels.length - index) * 6;
              
              return (
                <div
                  key={risk.level}
                  onClick={() => setActiveLevel(risk.level)}
                  className={`group relative cursor-pointer p-5 rounded-xl border transition-all duration-300 preserve-3d chassis-steel ${
                    isSelected 
                      ? `${risk.borderColor} shadow-[0_16px_36px_rgba(0,0,0,0.8)] -translate-y-1.5` 
                      : 'border-[#182638] hover:border-slate-600 hover:-translate-y-0.5'
                  }`}
                  style={{
                    transform: isSelected ? `translateZ(${elevation + 12}px)` : `translateZ(${elevation}px)`,
                  }}
                >
                  {/* Physical Engraved Plate Screws */}
                  <div className="absolute top-2 left-2 screw-head" />
                  <div className="absolute top-2 right-2 screw-head" />
                  <div className="absolute bottom-2 left-2 screw-head" />
                  <div className="absolute bottom-2 right-2 screw-head" />

                  <div className="flex items-center justify-between px-3">
                    <div className="flex items-center gap-3.5">
                      <div className={`w-3 h-3 rounded-sm ${risk.accentBar}`} />
                      <div>
                        {/* Physical Engraving Label */}
                        <div className="text-[8px] font-mono text-slate-500 uppercase tracking-widest">
                          {risk.engravingMark}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-lg font-black tracking-wider font-mono ${isSelected ? risk.textColor : 'text-slate-200'}`}>
                            {risk.level}
                          </span>
                          <span className="text-xs font-mono text-slate-500">
                            (CVSS {risk.scoreRange})
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5 line-clamp-1">
                          {risk.exampleFinding}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 pl-3 shrink-0">
                      <div className="text-right">
                        <div className="text-xs font-mono text-slate-300 font-semibold uppercase">
                          {risk.statusText}
                        </div>
                        <div className="text-[9px] font-mono text-slate-500 uppercase">
                          Tier Priority
                        </div>
                      </div>
                      <ChevronRight className={`w-4 h-4 transition-transform ${isSelected ? `${risk.textColor} translate-x-1` : 'text-slate-600'}`} />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right: Mathematical Evaluation Engine Display */}
          <div className="lg:col-span-6 chassis-steel rounded-xl p-6 shadow-2xl flex flex-col justify-between border border-[#203046] relative">
            <div className="absolute top-2 left-2 screw-head" />
            <div className="absolute top-2 right-2 screw-head" />
            <div className="absolute bottom-2 left-2 screw-head" />
            <div className="absolute bottom-2 right-2 screw-head" />

            <div>
              {/* Card Header */}
              <div className="flex items-center justify-between pb-4 border-b border-[#1A283B] mb-5">
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${riskLevels.find(r => r.level === activeLevel)?.accentBar}`} />
                  <span className="text-xs font-mono font-medium text-slate-300 tracking-wider">
                    MATHEMATICAL RISK FORMULA
                  </span>
                </div>
                <span className="text-[10px] font-mono text-slate-500 uppercase">
                  WEIGHT FACTOR: {current.weight}x
                </span>
              </div>

              {/* Title & Selected Severity */}
              <div className="mb-5">
                <div className="text-xs font-mono text-cyan-400 mb-1">
                  CALCULATED SEVERITY MATRIX
                </div>
                <h3 className="text-2xl font-bold text-white flex items-center gap-3">
                  <span>{current.level} PROFILE</span>
                  <span className={`text-xs px-2.5 py-0.5 rounded font-mono ${current.textColor} bg-[#0A101A] border ${current.borderColor}`}>
                    CVSS {current.scoreRange}
                  </span>
                </h3>
              </div>

              {/* Formula Breakdown */}
              <div className="p-4 rounded-lg recessed-bay border border-[#182638] mb-5">
                <div className="text-[10px] font-mono text-slate-400 uppercase mb-2 flex items-center justify-between">
                  <span>Algorithm Execution</span>
                  <span className="text-cyan-400">RiskScore = Base × Exposure × AssetWeight</span>
                </div>
                <div className="text-xs font-mono text-slate-200 bg-[#070B12] p-3 rounded border border-[#15202E]">
                  {current.impactFormula}
                </div>
              </div>

              {/* Active Example Breakdown */}
              <div className="space-y-2 mb-5">
                <div className="text-[10px] font-mono uppercase text-slate-400">
                  Representative Active Violation
                </div>
                <div className="p-3 rounded-lg bg-[#070B12] border border-[#182638]">
                  <p className="text-xs text-slate-300 font-mono mb-2">
                    {current.exampleFinding}
                  </p>
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-2 border-t border-[#15202E]">
                    <span>Target Remediation SLA:</span>
                    <span className={current.textColor}>{current.remediationTime}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Bottom Proof Metric */}
            <div className="pt-4 border-t border-[#182638] flex items-center justify-between text-xs font-mono text-slate-400">
              <span className="flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Deterministic Scoring Engine</span>
              </span>
              <span className="text-slate-500 text-[11px]">
                ZERO PROPRIETARY BLACKBOXES
              </span>
            </div>
          </div>

        </div>

      </div>
    </section>
  );
};
