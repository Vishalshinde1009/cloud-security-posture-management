import React from 'react';
import { 
  PlusCircle, 
  Key, 
  Search, 
  CheckCircle2, 
  Activity, 
  FileCheck 
} from 'lucide-react';

interface WorkflowStep {
  step: string;
  title: string;
  subtitle: string;
  desc: string;
  technical: string;
  icon: React.ReactNode;
  accent: string;
}

const STEPS: WorkflowStep[] = [
  {
    step: '01',
    title: 'CONNECT',
    subtitle: 'Register Cloud Target',
    desc: 'Configure target AWS account using the platform-generated External ID and standard IAM Trust Policy.',
    technical: 'STS ExternalId Provisioning',
    icon: <PlusCircle className="w-5 h-5" />,
    accent: 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10',
  },
  {
    step: '02',
    title: 'ASSUME',
    subtitle: 'Delegated Token Auth',
    desc: 'Backend requests temporary 1-hour session credentials via AWS Security Token Service (AssumeRole).',
    technical: 'Short-Lived Ephemeral Token',
    icon: <Key className="w-5 h-5" />,
    accent: 'text-purple-400 border-purple-500/30 bg-purple-500/10',
  },
  {
    step: '03',
    title: 'DISCOVER',
    subtitle: 'Read-Only Asset Crawl',
    desc: 'Automated collectors enumerate live inventory across S3, IAM, EC2, VPC, CloudTrail, and RDS.',
    technical: 'Non-Destructive Inspection',
    icon: <Search className="w-5 h-5" />,
    accent: 'text-blue-400 border-blue-500/30 bg-blue-500/10',
  },
  {
    step: '04',
    title: 'EVALUATE',
    subtitle: 'Deterministic Rules',
    desc: 'Security rule engine checks asset evidence against 26 misconfiguration detection rules.',
    technical: '26 Automated Security Rules',
    icon: <CheckCircle2 className="w-5 h-5" />,
    accent: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
  },
  {
    step: '05',
    title: 'SCORE',
    subtitle: 'Explainable Risk Model',
    desc: 'Deterministic algorithm evaluates exposure, exploitability, and sensitivity to calculate 0–100 risk.',
    technical: 'Transparent Risk Formula',
    icon: <Activity className="w-5 h-5" />,
    accent: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
  },
  {
    step: '06',
    title: 'REPORT',
    subtitle: 'Compliance & Export',
    desc: 'Map findings to CIS AWS, NIST, ISO 27001, PCI DSS, and generate executive server-side PDF reports.',
    technical: 'Executive PDF Assessments',
    icon: <FileCheck className="w-5 h-5" />,
    accent: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
  },
];

export const WorkflowTimeline: React.FC = () => {
  return (
    <section id="how-it-works" className="py-20 border-b border-slate-800/60 bg-[#080C14] relative">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center max-w-2xl mx-auto mb-16 space-y-3">
          <span className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400">
            Automated Audit Lifecycle
          </span>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            How It Works
          </h2>
          <p className="text-sm sm:text-base text-slate-400">
            A 6-phase continuous discovery and posture evaluation sequence executed in seconds.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4 relative">
          {STEPS.map((step) => (
            <div
              key={step.step}
              className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col justify-between space-y-4 group hover:scale-[1.02] shadow-lg"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-2xl font-black text-cyan-400/80 group-hover:text-cyan-300">
                    {step.step}
                  </span>
                  <div className={`p-2 rounded-xl border ${step.accent} group-hover:scale-110 transition-transform`}>
                    {step.icon}
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-white tracking-tight">
                    {step.title}
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    {step.subtitle}
                  </p>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  {step.desc}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 text-[10px] font-mono text-cyan-400/80">
                {step.technical}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
