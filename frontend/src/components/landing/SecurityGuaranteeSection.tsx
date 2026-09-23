import React from 'react';
import { 
  Lock, 
  Key, 
  ShieldCheck, 
  Database, 
  Users 
} from 'lucide-react';

interface GuaranteeCardItem {
  id: string;
  step: string;
  title: string;
  summary: string;
  detail: string;
  icon: React.ReactNode;
  colorClass: string;
  borderClass: string;
}

const GUARANTEES: GuaranteeCardItem[] = [
  {
    id: 'readonly',
    step: '01',
    title: '100% READ-ONLY ACCESS',
    summary: 'Strict client-level execution safeguards',
    detail: 'Zero cloud mutations or write permissions. Runtime guard blocks all modifying requests, permitting only discovery APIs (list_*, describe_*, get_*, head_*).',
    icon: <Lock className="w-5 h-5" />,
    colorClass: 'text-cyan-400 bg-cyan-500/10',
    borderClass: 'border-cyan-500/30 hover:border-cyan-400/60',
  },
  {
    id: 'sts',
    step: '02',
    title: 'STS ASSUMEROLE',
    summary: 'Short-lived ephemeral sessions',
    detail: 'Authentication via AWS Security Token Service generates short-lived 1-hour session credentials on demand. No permanent IAM credentials exist.',
    icon: <Key className="w-5 h-5" />,
    colorClass: 'text-purple-400 bg-purple-500/10',
    borderClass: 'border-purple-500/30 hover:border-purple-400/60',
  },
  {
    id: 'external-id',
    step: '03',
    title: 'CRYPTOGRAPHIC EXTERNAL ID',
    summary: 'Confused Deputy Attack Mitigation',
    detail: 'Every registered cloud account receives a cryptographically secure 128-bit external identifier, strictly validating caller identity across multi-tenant environments.',
    icon: <ShieldCheck className="w-5 h-5" />,
    colorClass: 'text-blue-400 bg-blue-500/10',
    borderClass: 'border-blue-500/30 hover:border-blue-400/60',
  },
  {
    id: 'zero-storage',
    step: '04',
    title: 'ZERO SECRET KEY STORAGE',
    summary: 'No access keys stored in database',
    detail: 'The platform never accepts, requests, stores, or logs customer AWS secret access keys or root credentials. All access operates through IAM trust policy delegation.',
    icon: <Database className="w-5 h-5" />,
    colorClass: 'text-emerald-400 bg-emerald-500/10',
    borderClass: 'border-emerald-500/30 hover:border-emerald-400/60',
  },
  {
    id: 'isolation',
    step: '05',
    title: 'MULTI-TENANT ISOLATION',
    summary: 'Strict per-user boundary enforcement',
    detail: 'Complete tenant isolation across database rows, scans, resources, findings, audit logs, and PDF reports with IDOR protection at the API gateway layer.',
    icon: <Users className="w-5 h-5" />,
    colorClass: 'text-amber-400 bg-amber-500/10',
    borderClass: 'border-amber-500/30 hover:border-amber-400/60',
  },
];

export const SecurityGuaranteeSection: React.FC = () => {
  return (
    <section id="security" className="py-20 border-b border-slate-800/60 bg-[#0A0F1D] relative">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-14 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-xs font-mono uppercase tracking-wider">
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            Security Built Into The Architecture
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Designed for Zero-Trust Cloud Auditing
          </h2>
          <p className="text-sm sm:text-base text-slate-400 max-w-2xl mx-auto">
            Our architecture guarantees zero write permissions, temporary token delegation, and cryptographic protection against cross-account exploits.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-5">
          {GUARANTEES.map((item) => (
            <div
              key={item.id}
              className={`p-6 rounded-2xl bg-slate-900/70 border transition-all duration-300 flex flex-col justify-between space-y-4 hover:scale-[1.02] shadow-xl group ${item.borderClass}`}
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className={`p-2.5 rounded-xl border ${item.colorClass} border-slate-700/50 group-hover:scale-110 transition-transform`}>
                    {item.icon}
                  </div>
                  <span className="font-mono text-xl font-black text-slate-600 group-hover:text-cyan-400 transition-colors">
                    {item.step}
                  </span>
                </div>

                <h3 className="text-xs font-mono font-bold text-white tracking-wider uppercase">
                  {item.title}
                </h3>
                <p className="text-xs text-cyan-300/80 font-medium">
                  {item.summary}
                </p>
                <p className="text-xs text-slate-400 leading-relaxed font-normal">
                  {item.detail}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-800 text-[10px] font-mono text-slate-500">
                Verified Safeguard
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
