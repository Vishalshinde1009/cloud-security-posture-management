import React from 'react';
import { 
  Database, 
  Server, 
  ShieldCheck, 
  Layers, 
  KeyRound, 
  Radio, 
  Lock,
  Cpu 
} from 'lucide-react';

interface FloatingAssetBadgeItem {
  id: string;
  label: string;
  detail: string;
  icon: React.ReactNode;
  colorClass: string;
}

const ASSETS: FloatingAssetBadgeItem[] = [
  { id: 's3', label: 'Amazon S3', detail: 'Public Access Blocks', icon: <Database className="w-3.5 h-3.5" />, colorClass: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30' },
  { id: 'ec2', label: 'Amazon EC2', detail: 'IMDSv2 & Ingress SG', icon: <Server className="w-3.5 h-3.5" />, colorClass: 'text-blue-400 bg-blue-500/10 border-blue-500/30' },
  { id: 'iam', label: 'AWS IAM', detail: 'MFA & Inactive Keys', icon: <KeyRound className="w-3.5 h-3.5" />, colorClass: 'text-purple-400 bg-purple-500/10 border-purple-500/30' },
  { id: 'vpc', label: 'Amazon VPC', detail: 'Flow Logs & Subnets', icon: <Layers className="w-3.5 h-3.5" />, colorClass: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30' },
  { id: 'rds', label: 'Amazon RDS', detail: 'Storage Encryption', icon: <Lock className="w-3.5 h-3.5" />, colorClass: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' },
  { id: 'ct', label: 'CloudTrail', detail: 'Multi-Region Trails', icon: <Radio className="w-3.5 h-3.5" />, colorClass: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
  { id: 'sg', label: 'Security Groups', detail: 'Port 22/3389 0.0.0.0/0', icon: <ShieldCheck className="w-3.5 h-3.5" />, colorClass: 'text-rose-400 bg-rose-500/10 border-rose-500/30' },
  { id: 'rules', label: 'CSPM Rules', detail: '26 Deterministic Checks', icon: <Cpu className="w-3.5 h-3.5" />, colorClass: 'text-cyan-300 bg-cyan-400/10 border-cyan-400/30' },
];

export const FloatingAssetBadges: React.FC = () => {
  return (
    <div className="flex flex-wrap items-center justify-center gap-2.5 max-w-4xl mx-auto pt-4">
      {ASSETS.map((asset) => (
        <div
          key={asset.id}
          className={`px-3 py-1.5 rounded-xl border text-xs flex items-center gap-2 backdrop-blur-md hover:scale-105 transition-transform duration-300 shadow-sm ${asset.colorClass}`}
        >
          {asset.icon}
          <span className="font-semibold text-white">{asset.label}</span>
          <span className="text-[10px] text-slate-400 font-mono hidden sm:inline">&bull; {asset.detail}</span>
        </div>
      ))}
    </div>
  );
};
