import React from 'react';
import { Award, CheckCircle2, ArrowUpRight, ShieldCheck } from 'lucide-react';

interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  category: string;
  engravedStandardId: string;
  statusLabel: string;
}

export const ComplianceCards3D: React.FC = () => {
  const frameworks: ComplianceFramework[] = [
    {
      id: 'cis',
      name: 'CIS Amazon Web Services Foundations Benchmark',
      version: 'v1.4.0',
      description: 'Prescriptive consensus-based security configuration baseline for AWS accounts and IAM policies.',
      category: 'Industry Standard',
      engravedStandardId: 'STD: CIS-AWS-FND-1.4',
      statusLabel: 'CONTROL MAPPING'
    },
    {
      id: 'nist',
      name: 'NIST SP 800-53 Rev. 5',
      version: 'Moderate Baseline',
      description: 'Federal catalog of security and privacy controls for federal information systems and cloud hosting.',
      category: 'Federal & Defense',
      engravedStandardId: 'STD: NIST-SP-800-53-R5',
      statusLabel: 'CONTROL MAPPING'
    },
    {
      id: 'iso',
      name: 'ISO/IEC 27001:2022',
      version: 'Annex A Controls',
      description: 'International benchmark for establishing, implementing, maintaining, and improving an ISMS.',
      category: 'International',
      engravedStandardId: 'STD: ISO-27001-2022',
      statusLabel: 'CONTROL MAPPING'
    },
    {
      id: 'pci',
      name: 'PCI DSS',
      version: 'v4.0 Cloud Guidelines',
      description: 'Technical and operational requirements designed to protect cardholder data within cloud environments.',
      category: 'Payment Security',
      engravedStandardId: 'STD: PCI-DSS-V4.0-CLD',
      statusLabel: 'CONTROL MAPPING'
    }
  ];

  return (
    <section id="compliance" className="relative py-28 px-4 sm:px-6 lg:px-8 border-t border-[#182638] bg-[#070B12] overflow-hidden">
      {/* Restrained back illumination */}
      <div className="absolute top-1/2 left-1/3 w-[600px] h-[300px] bg-cyan-950/10 rounded-full blur-[140px] pointer-events-none" />

      <div className="max-w-7xl mx-auto relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#0D1522] border border-[#1E2E44] text-xs font-mono text-cyan-400">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
            REGULATORY FRAMEWORK MAPPING
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white">
            Continuous Regulatory Alignment
          </h2>
          <p className="text-slate-400 text-base leading-relaxed">
            Every discovered asset and evaluated rule is continuously cross-referenced against authoritative 
            cybersecurity frameworks for audit-ready compliance tracking.
          </p>
        </div>

        {/* 4 Physical Benchmark Plates with Engravings and Screws */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 perspective-1000">
          {frameworks.map((fw) => {
            return (
              <div
                key={fw.id}
                className="group relative p-6 rounded-xl border border-[#1B273A] chassis-steel hover:border-cyan-500/50 transition-all duration-300 preserve-3d hover:-translate-y-2 hover:shadow-[0_20px_40px_rgba(0,0,0,0.8)] flex flex-col justify-between"
              >
                {/* Physical Engraved Plate Screws */}
                <div className="absolute top-2 left-2 screw-head" />
                <div className="absolute top-2 right-2 screw-head" />
                <div className="absolute bottom-2 left-2 screw-head" />
                <div className="absolute bottom-2 right-2 screw-head" />

                <div>
                  {/* Category Pill & Engraved Plate Marking */}
                  <div className="flex items-center justify-between text-[9px] font-mono mb-4 text-slate-500 pt-1">
                    <span>{fw.engravedStandardId}</span>
                    <span className="px-1.5 py-0.5 rounded bg-[#09101A] border border-[#182638] text-slate-400">
                      {fw.version}
                    </span>
                  </div>

                  {/* Physical Standard Emblem Box */}
                  <div className="p-4 rounded-xl recessed-bay border border-[#182638] my-3 text-center flex flex-col items-center justify-center space-y-1.5">
                    <div className="p-2 rounded-lg bg-[#0E1624] border border-[#1E2E44] text-cyan-400">
                      <ShieldCheck className="w-5 h-5" />
                    </div>
                    <span className="text-[11px] font-mono font-bold text-white uppercase tracking-wider block">
                      {fw.statusLabel}
                    </span>
                    <span className="text-[9px] font-mono text-cyan-400 block">
                      AUTOMATED RULE MAPPING
                    </span>
                  </div>

                  {/* Framework Name */}
                  <h3 className="font-semibold text-white text-base mb-2 group-hover:text-cyan-300 transition-colors">
                    {fw.name}
                  </h3>

                  {/* Description */}
                  <p className="text-xs text-slate-400 leading-relaxed line-clamp-3 mb-4">
                    {fw.description}
                  </p>
                </div>

                {/* Bottom Audit Status */}
                <div className="pt-3 border-t border-[#182638]">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-400 text-[11px]">Audit Engine:</span>
                    <span className="text-white font-semibold flex items-center gap-1 text-[11px]">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      Dynamic Evaluation
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Regulatory Disclaimer Instrument Bar */}
        <div className="mt-12 p-4 rounded-xl chassis-steel border border-[#1E2E44] max-w-4xl mx-auto flex items-center justify-between gap-4 relative">
          <div className="absolute top-2 left-2 screw-head" />
          <div className="absolute top-2 right-2 screw-head" />
          <div className="absolute bottom-2 left-2 screw-head" />
          <div className="absolute bottom-2 right-2 screw-head" />

          <div className="flex items-center gap-3 pl-3">
            <Award className="w-5 h-5 text-cyan-400 shrink-0" />
            <p className="text-xs text-slate-400 leading-relaxed">
              <strong className="text-slate-200">Continuous Automated Mapping:</strong> Compliance status is recalculated 
              on every completed scan. Audit reports can be generated directly in executive PDF format.
            </p>
          </div>
          <span className="text-xs font-mono text-cyan-400 whitespace-nowrap hidden sm:inline-flex items-center gap-1 pr-3">
            <span>Executive PDF Export</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </span>
        </div>

      </div>
    </section>
  );
};
