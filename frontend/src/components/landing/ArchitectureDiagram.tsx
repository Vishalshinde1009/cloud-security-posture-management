import React, { useState, useEffect } from 'react';
import { 
  Server, 
  Key, 
  Eye, 
  Cpu, 
  Activity, 
  FileText, 
  ShieldAlert,
  Lock
} from 'lucide-react';

interface ArchitectureNodeItem {
  id: string;
  name: string;
  sub: string;
  tag: string;
  icon: React.ReactNode;
  colorClass: string;
  borderClass: string;
}

const NODES: ArchitectureNodeItem[] = [
  {
    id: 'aws',
    name: 'AWS Cloud',
    sub: 'Customer VPC',
    tag: 'Multi-Region',
    icon: <Server className="w-5 h-5" />,
    colorClass: 'text-orange-400 bg-orange-500/10',
    borderClass: 'border-orange-500/30',
  },
  {
    id: 'iam',
    name: 'IAM Identity',
    sub: 'Delegated Role',
    tag: 'Least-Privilege',
    icon: <Lock className="w-5 h-5" />,
    colorClass: 'text-purple-400 bg-purple-500/10',
    borderClass: 'border-purple-500/30',
  },
  {
    id: 'sts',
    name: 'STS AssumeRole',
    sub: 'ExternalId Token',
    tag: 'Ephemeral 1h',
    icon: <Key className="w-5 h-5" />,
    colorClass: 'text-purple-300 bg-purple-600/10',
    borderClass: 'border-purple-500/40',
  },
  {
    id: 'discovery',
    name: 'Discovery Engine',
    sub: 'Read-Only Guard',
    tag: 'Zero Mutation',
    icon: <Eye className="w-5 h-5" />,
    colorClass: 'text-blue-400 bg-blue-500/10',
    borderClass: 'border-blue-500/30',
  },
  {
    id: 'rules',
    name: 'Security Rules',
    sub: '26 Deterministic',
    tag: 'Continuous',
    icon: <Cpu className="w-5 h-5" />,
    colorClass: 'text-cyan-400 bg-cyan-500/10',
    borderClass: 'border-cyan-500/30',
  },
  {
    id: 'risk',
    name: 'Risk Engine',
    sub: 'Formula Scoring',
    tag: 'Explainable',
    icon: <Activity className="w-5 h-5" />,
    colorClass: 'text-amber-400 bg-amber-500/10',
    borderClass: 'border-amber-500/30',
  },
  {
    id: 'findings',
    name: 'Findings Matrix',
    sub: 'Prioritized Gaps',
    tag: 'Low-Critical',
    icon: <ShieldAlert className="w-5 h-5" />,
    colorClass: 'text-rose-400 bg-rose-500/10',
    borderClass: 'border-rose-500/30',
  },
  {
    id: 'reports',
    name: 'Audit Reports',
    sub: 'PDF + Frameworks',
    tag: 'Executive',
    icon: <FileText className="w-5 h-5" />,
    colorClass: 'text-emerald-400 bg-emerald-500/10',
    borderClass: 'border-emerald-500/30',
  },
];

export const ArchitectureDiagram: React.FC = () => {
  const [activeStep, setActiveStep] = useState<number>(0);

  // Cycle the active pulse node every 1.5s to simulate moving telemetry
  useEffect(() => {
    const timer = setInterval(() => {
      setActiveStep((prev) => (prev + 1) % NODES.length);
    }, 1500);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="relative w-full">
      {/* Visual Pipeline Header */}
      <div className="flex items-center justify-between pb-3 mb-6 border-b border-slate-800/80">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          <span className="text-slate-300 font-bold">CENTRAL LIVE CSPM ARCHITECTURE</span>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono">
          <span className="text-slate-400">TELEMETRY PACKET TRANSIT:</span>
          <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-bold">
            ACTIVE &bull; 100% READ-ONLY
          </span>
        </div>
      </div>

      {/* Nodes Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 relative z-10">
        {NODES.map((node, index) => {
          const isActive = activeStep === index;
          return (
            <div
              key={node.id}
              className={`p-3.5 rounded-xl transition-all duration-500 flex flex-col items-center text-center space-y-2 relative group ${
                isActive
                  ? 'glass-panel border-cyan-400 shadow-glow-cyan scale-[1.04]'
                  : 'bg-slate-950/70 border border-slate-800/80 hover:border-slate-700'
              }`}
            >
              {/* Pulse Ring when packet reaches node */}
              {isActive && (
                <span className="absolute -inset-0.5 rounded-xl bg-cyan-500/20 blur-sm pointer-events-none animate-pulse" />
              )}

              {/* Icon */}
              <div
                className={`p-2.5 rounded-lg border transition-transform duration-300 ${node.colorClass} ${node.borderClass} ${
                  isActive ? 'scale-110' : 'group-hover:scale-105'
                }`}
              >
                {node.icon}
              </div>

              {/* Text Info */}
              <div className="space-y-0.5 w-full">
                <span className="text-xs font-bold text-white block truncate tracking-tight">
                  {node.name}
                </span>
                <span className="text-[10px] text-slate-400 font-mono block truncate">
                  {node.sub}
                </span>
              </div>

              {/* Badge */}
              <span
                className={`text-[9px] font-mono px-1.5 py-0.2 rounded mt-1 truncate ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                    : 'bg-slate-900 text-slate-400 border border-slate-800'
                }`}
              >
                {node.tag}
              </span>
            </div>
          );
        })}
      </div>

      {/* Connecting animated data packets bar */}
      <div className="mt-6 pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
        <div className="flex items-center gap-3 font-mono text-[11px]">
          <span className="text-slate-400">Data Pipeline Flow:</span>
          <div className="flex items-center gap-1.5 text-cyan-400">
            <span>AWS Cloud</span>
            <span>&rarr;</span>
            <span>STS AssumeRole</span>
            <span>&rarr;</span>
            <span>Discovery</span>
            <span>&rarr;</span>
            <span>Rule Engine</span>
            <span>&rarr;</span>
            <span>Posture Score</span>
          </div>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 px-2.5 py-1 rounded-full">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Zero Secret Storage Enforced
        </div>
      </div>
    </div>
  );
};
