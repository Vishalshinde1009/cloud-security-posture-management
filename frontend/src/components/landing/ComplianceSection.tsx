import React from 'react';
import { ShieldCheck, Info } from 'lucide-react';

interface FrameworkItem {
  id: string;
  name: string;
  code: string;
  percentage: number;
  controlsPass: number;
  totalControls: number;
  category: string;
  colorClass: string;
}

const FRAMEWORKS: FrameworkItem[] = [
  {
    id: 'cis',
    name: 'CIS AWS Foundations',
    code: 'CIS Benchmark v1.4.0',
    percentage: 78.4,
    controlsPass: 42,
    totalControls: 54,
    category: 'Cloud Security Baseline',
    colorClass: 'text-cyan-400 stroke-cyan-400',
  },
  {
    id: 'nist',
    name: 'NIST SP 800-53',
    code: 'Security & Privacy Controls',
    percentage: 71.2,
    controlsPass: 68,
    totalControls: 96,
    category: 'Federal & Enterprise',
    colorClass: 'text-blue-400 stroke-blue-400',
  },
  {
    id: 'iso',
    name: 'ISO/IEC 27001',
    code: 'Information Security Mgmt',
    percentage: 84.0,
    controlsPass: 38,
    totalControls: 45,
    category: 'International Standard',
    colorClass: 'text-purple-400 stroke-purple-400',
  },
  {
    id: 'pci',
    name: 'PCI DSS v4.0',
    code: 'Payment Card Industry',
    percentage: 65.8,
    controlsPass: 29,
    totalControls: 44,
    category: 'Cardholder Data Security',
    colorClass: 'text-emerald-400 stroke-emerald-400',
  },
];

export const ComplianceSection: React.FC = () => {
  const radius = 28;
  const circumference = 2 * Math.PI * radius;

  return (
    <section id="compliance" className="py-20 border-b border-slate-800/60 bg-[#080C14] relative">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center max-w-2xl mx-auto mb-14 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-xs font-mono uppercase tracking-wider">
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            Continuous Compliance Posture
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Industry Benchmark Alignment
          </h2>
          <p className="text-sm sm:text-base text-slate-400">
            Automated translation of cloud resource configurations into structured compliance assessments.
          </p>
        </div>

        {/* 4 Framework Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {FRAMEWORKS.map((fw) => {
            const strokeDashoffset = circumference - (fw.percentage / 100) * circumference;

            return (
              <div
                key={fw.id}
                className="glass-panel p-6 rounded-2xl border border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col justify-between space-y-5 shadow-xl hover:scale-[1.02] group"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                      {fw.category}
                    </span>
                  </div>

                  <h3 className="text-base font-bold text-white tracking-tight">
                    {fw.name}
                  </h3>
                  <p className="text-xs font-mono text-cyan-400/80">
                    {fw.code}
                  </p>
                </div>

                {/* Circular Gauge Meter */}
                <div className="flex items-center justify-between pt-4 border-t border-slate-800/80">
                  <div>
                    <span className="text-2xl font-black font-mono text-white">
                      {fw.percentage}%
                    </span>
                    <div className="text-[10px] font-mono text-slate-400">
                      {fw.controlsPass} / {fw.totalControls} Controls
                    </div>
                  </div>

                  <div className="relative w-16 h-16 flex items-center justify-center">
                    <svg className="w-16 h-16 -rotate-90 transform" viewBox="0 0 72 72">
                      <circle
                        cx="36"
                        cy="36"
                        r={radius}
                        stroke="currentColor"
                        strokeWidth="5"
                        className="text-slate-800"
                        fill="transparent"
                      />
                      <circle
                        cx="36"
                        cy="36"
                        r={radius}
                        stroke="currentColor"
                        strokeWidth="5"
                        strokeDasharray={circumference}
                        strokeDashoffset={strokeDashoffset}
                        strokeLinecap="round"
                        className={`${fw.colorClass} transition-all duration-1000 ease-out`}
                        fill="transparent"
                      />
                    </svg>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Regulatory Disclaimer Banner */}
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 flex items-start gap-3 max-w-4xl mx-auto text-xs text-slate-400">
          <Info className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
          <p className="leading-relaxed">
            <strong className="text-slate-300">Compliance Disclaimer:</strong> Compliance mappings represent automated security
            assessment alignment and gap detection. They do not constitute formal certification or regulatory endorsement.
          </p>
        </div>
      </div>
    </section>
  );
};
