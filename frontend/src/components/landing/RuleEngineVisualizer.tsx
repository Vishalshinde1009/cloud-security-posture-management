import React, { useState } from 'react';
import { 
  Cpu, 
  AlertTriangle 
} from 'lucide-react';

interface RuleDemoItem {
  id: string;
  resource: string;
  config: string;
  ruleId: string;
  ruleTitle: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  riskScore: number;
  findingTitle: string;
  service: string;
}

const SAMPLE_RULES: RuleDemoItem[] = [
  {
    id: 'iam',
    service: 'IAM',
    resource: 'AWS Account (Root)',
    config: 'AccountMFAEnabled = false',
    ruleId: 'IAM-001',
    ruleTitle: 'Root account MFA must be enabled',
    severity: 'CRITICAL',
    riskScore: 95,
    findingTitle: 'Root User MFA is not active on AWS Account',
  },
  {
    id: 's3',
    service: 'S3',
    resource: 'finance-docs-archive',
    config: 'BlockPublicAcls = false',
    ruleId: 'S3-002',
    ruleTitle: 'S3 buckets should prohibit public read ACLs',
    severity: 'HIGH',
    riskScore: 84,
    findingTitle: 'Public read ACL enabled on sensitive S3 bucket',
  },
  {
    id: 'ec2',
    service: 'EC2',
    resource: 'sg-0a8b9c1d2e3f (prod-dmz)',
    config: 'Ingress: 0.0.0.0/0 -> Port 22',
    ruleId: 'EC2-004',
    ruleTitle: 'Security groups must not allow 0.0.0.0/0 to SSH port 22',
    severity: 'CRITICAL',
    riskScore: 92,
    findingTitle: 'Unrestricted SSH exposure (0.0.0.0/0:22) detected',
  },
  {
    id: 'vpc',
    service: 'VPC',
    resource: 'vpc-07b8a9c0 (main-vpc)',
    config: 'FlowLogsActive = false',
    ruleId: 'VPC-001',
    ruleTitle: 'VPC flow logging must be enabled for network auditing',
    severity: 'MEDIUM',
    riskScore: 58,
    findingTitle: 'Network telemetry missing: VPC flow logs disabled',
  },
  {
    id: 'ct',
    service: 'CloudTrail',
    resource: 'trail-prod-global',
    config: 'IsMultiRegionTrail = false',
    ruleId: 'CT-001',
    ruleTitle: 'CloudTrail should be enabled across all AWS regions',
    severity: 'HIGH',
    riskScore: 78,
    findingTitle: 'CloudTrail disabled in inactive secondary regions',
  },
];

export const RuleEngineVisualizer: React.FC = () => {
  const [selectedId, setSelectedId] = useState<string>('ec2');
  const activeRule = SAMPLE_RULES.find((r) => r.id === selectedId) || SAMPLE_RULES[0];

  return (
    <section id="rules-engine" className="py-20 border-b border-slate-800/60 bg-[#0A0F1D] relative">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center max-w-2xl mx-auto mb-14 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-xs font-mono uppercase tracking-wider">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            Security Rule Engine
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Deterministic Configuration Evaluation
          </h2>
          <p className="text-sm sm:text-base text-slate-400">
            Automated rules evaluate cloud state to identify security violations without human guesswork.
          </p>
        </div>

        {/* Rule Selector Tabs */}
        <div className="flex flex-wrap items-center justify-center gap-2 mb-10">
          {SAMPLE_RULES.map((rule) => (
            <button
              key={rule.id}
              onClick={() => setSelectedId(rule.id)}
              className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition-all border ${
                selectedId === rule.id
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-glow-cyan'
                  : 'bg-slate-900/80 text-slate-400 border-slate-800 hover:border-slate-700'
              }`}
            >
              [{rule.ruleId}] {rule.service}
            </button>
          ))}
        </div>

        {/* Pipeline Diagram */}
        <div className="glass-panel p-6 sm:p-8 rounded-2xl border border-slate-800 shadow-2xl">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-center">
            {/* Step 1: AWS Resource */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 h-full flex flex-col justify-between">
              <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase">
                01 &bull; AWS Resource
              </span>
              <div>
                <div className="font-bold text-white text-xs">{activeRule.resource}</div>
                <div className="text-[10px] text-slate-400 font-mono mt-0.5">{activeRule.service} Service</div>
              </div>
              <div className="text-[9px] font-mono text-slate-500 pt-1 border-t border-slate-900">Discovered Live</div>
            </div>

            {/* Step 2: Configuration */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 h-full flex flex-col justify-between">
              <span className="text-[10px] font-mono text-blue-400 font-bold uppercase">
                02 &bull; Configuration
              </span>
              <div>
                <div className="font-mono text-xs text-amber-300 truncate">{activeRule.config}</div>
                <div className="text-[10px] text-slate-400 font-mono mt-0.5">Evidence Snapshot</div>
              </div>
              <div className="text-[9px] font-mono text-slate-500 pt-1 border-t border-slate-900">Ingested State</div>
            </div>

            {/* Step 3: Security Rule */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 h-full flex flex-col justify-between">
              <span className="text-[10px] font-mono text-purple-400 font-bold uppercase">
                03 &bull; Security Rule
              </span>
              <div>
                <span className="text-xs font-mono font-bold text-cyan-300">[{activeRule.ruleId}]</span>
                <p className="text-[11px] text-slate-300 font-medium leading-tight mt-1">
                  {activeRule.ruleTitle}
                </p>
              </div>
              <div className="text-[9px] font-mono text-slate-500 pt-1 border-t border-slate-900">Rule Logic Match</div>
            </div>

            {/* Step 4: Risk Score */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 h-full flex flex-col justify-between">
              <span className="text-[10px] font-mono text-amber-400 font-bold uppercase">
                04 &bull; Risk Score
              </span>
              <div>
                <div className="flex items-baseline gap-1.5">
                  <span className="text-2xl font-black font-mono text-amber-400">{activeRule.riskScore}</span>
                  <span className="text-[10px] font-mono text-slate-500">/ 100</span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase bg-rose-950/60 text-rose-300 border border-rose-800/60">
                  {activeRule.severity}
                </span>
              </div>
              <div className="text-[9px] font-mono text-slate-500 pt-1 border-t border-slate-900">Exploitability Weight</div>
            </div>

            {/* Step 5: Finding */}
            <div className="p-4 rounded-xl bg-slate-950 border border-rose-900/40 space-y-2 h-full flex flex-col justify-between">
              <span className="text-[10px] font-mono text-rose-400 font-bold uppercase flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-rose-400" />
                05 &bull; Finding
              </span>
              <div>
                <div className="font-bold text-white text-xs leading-snug">{activeRule.findingTitle}</div>
                <div className="text-[10px] text-slate-400 font-mono mt-0.5">Remediation Ready</div>
              </div>
              <div className="text-[9px] font-mono text-slate-500 pt-1 border-t border-slate-900">Audit Trail Created</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
