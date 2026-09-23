import React, { useState } from 'react';
import { 
  Database, 
  Server, 
  Key, 
  Network, 
  Layers, 
  FileText, 
  CheckCircle, 
  ExternalLink
} from 'lucide-react';

interface AssetItem {
  id: string;
  name: string;
  service: string;
  count: string;
  icon: React.ElementType;
  status: 'clean' | 'attention';
  statusText: string;
  highlightProps: string[];
  moduleGeometry: string;
  specs: string;
}

export const AssetExplorer3D: React.FC = () => {
  const [activeAsset, setActiveAsset] = useState<string>('s3');

  const assets: AssetItem[] = [
    {
      id: 's3',
      name: 'Amazon S3',
      service: 'OBJECT STORAGE',
      count: 'Discovery Available',
      icon: Database,
      status: 'attention',
      statusText: 'Configuration Audit Active',
      highlightProps: ['SSE-S3 / SSE-KMS Check', 'Public Access Block Status', 'Bucket Policy Evaluation', 'Lifecycle Configuration'],
      moduleGeometry: 'Dual Storage Bay // Dual Bus',
      specs: 'KMS Key Alias Check // Bucket Policy Parser'
    },
    {
      id: 'iam',
      name: 'AWS IAM',
      service: 'IDENTITY & ACCESS',
      count: 'Role Discovery Active',
      icon: Key,
      status: 'attention',
      statusText: 'Least Privilege Verification',
      highlightProps: ['AdministratorAccess Attached', 'MFA Status Verification', 'Cross-Account Trust Policies', 'Access Key Rotation Age'],
      moduleGeometry: 'Cryptographic Auth Terminal',
      specs: 'Inline & Managed Policy AST Evaluation'
    },
    {
      id: 'ec2',
      name: 'Amazon EC2',
      service: 'COMPUTE WORKLOADS',
      count: 'Instance Audit Ready',
      icon: Server,
      status: 'attention',
      statusText: 'Security Group Ingress Check',
      highlightProps: ['Port 22/3389 Ingress Rules', 'IMDSv2 Enforced Tokens', 'Default VPC In Use', 'EBS Encryption Enabled'],
      moduleGeometry: 'Blade Compute Rack // Vented',
      specs: 'Nitro Enclaves // IMDSv2 Token State'
    },
    {
      id: 'vpc',
      name: 'Amazon VPC',
      service: 'NETWORK SEGMENTATION',
      count: 'Network Topology Active',
      icon: Network,
      status: 'clean',
      statusText: 'Flow Logs & Route Audit',
      highlightProps: ['VPC Flow Logs to CloudWatch', 'Default Security Group Isolation', 'Route Table Configurations', 'Internet Gateway Boundaries'],
      moduleGeometry: 'Segmented Network Chassis',
      specs: 'Subnet Boundary & Ingress Route Validation'
    },
    {
      id: 'rds',
      name: 'Amazon RDS',
      service: 'DATABASE CLUSTERS',
      count: 'Database Audit Ready',
      icon: Layers,
      status: 'clean',
      statusText: 'Storage Encryption Check',
      highlightProps: ['Automated Backups Retention', 'KMS Storage Encryption', 'Publicly Accessible Flag', 'Multi-AZ Deployment'],
      moduleGeometry: 'Encrypted DB Cluster Bay',
      specs: 'KMS Storage Cipher & Multi-AZ Assertion'
    },
    {
      id: 'cloudtrail',
      name: 'AWS CloudTrail',
      service: 'AUDIT & TELEMETRY',
      count: 'Audit Logging Active',
      icon: FileText,
      status: 'clean',
      statusText: 'Multi-Region Log Integrity',
      highlightProps: ['Multi-Region Trail Status', 'S3 Log File Validation', 'CloudWatch Logs Integration', 'KMS Encryption on Trails'],
      moduleGeometry: 'Hardware Event Logger Unit',
      specs: 'Digest File Validation & CloudWatch Forwarding'
    }
  ];

  const current = assets.find(a => a.id === activeAsset) || assets[0];

  return (
    <section id="assets" className="relative py-28 px-4 sm:px-6 lg:px-8 border-t border-[#182638] bg-[#070B12] overflow-hidden">
      {/* Background illumination accent */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[350px] bg-cyan-950/10 rounded-full blur-[140px] pointer-events-none" />

      <div className="max-w-7xl mx-auto relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#0D1522] border border-[#1E2E44] text-xs font-mono text-cyan-400">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
            MULTI-SERVICE INVENTORY DISCOVERY
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white">
            Everything In Your Cloud, In One View
          </h2>
          <p className="text-slate-400 text-base leading-relaxed">
            Continuous discovery inspects cloud assets across your AWS footprint through read-only access. 
            View misconfigurations, security policies, and posture risks in a unified technical hierarchy.
          </p>
        </div>

        {/* 3D Asset Modules Grid & Physical Inspection Bay */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          
          {/* Left: 6 Physical Infrastructure Modules */}
          <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4 perspective-1000">
            {assets.map((asset) => {
              const Icon = asset.icon;
              const isSelected = activeAsset === asset.id;
              
              return (
                <button
                  key={asset.id}
                  onClick={() => setActiveAsset(asset.id)}
                  className={`group relative text-left p-5 rounded-xl border transition-all duration-300 preserve-3d chassis-steel ${
                    isSelected 
                      ? 'border-cyan-500/60 shadow-[0_16px_36px_rgba(6,182,212,0.15)] -translate-y-2' 
                      : 'border-[#1B273A] hover:border-slate-600 hover:-translate-y-1'
                  }`}
                  style={{
                    transform: isSelected ? 'translateZ(16px)' : 'translateZ(0px)',
                  }}
                >
                  {/* Corner screws on each physical module */}
                  <div className="absolute top-2 left-2 screw-head" />
                  <div className="absolute top-2 right-2 screw-head" />
                  <div className="absolute bottom-2 left-2 screw-head" />
                  <div className="absolute bottom-2 right-2 screw-head" />

                  {/* Top Bar: Icon + Status */}
                  <div className="flex items-center justify-between mb-4 pl-2 pr-2 pt-1">
                    <div className={`p-2 rounded-lg border ${
                      isSelected 
                        ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400' 
                        : 'bg-[#0E1624] border-[#1E2E44] text-slate-400 group-hover:text-slate-200'
                    }`}>
                      <Icon className="w-4 h-4" />
                    </div>

                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-[#0E1624] text-slate-300 border border-[#1E2E44]">
                      <CheckCircle className="w-3 h-3 text-cyan-400" />
                      DISCOVERY ACTIVE
                    </span>
                  </div>

                  {/* Physical Module Geometry Tag */}
                  <div className="px-2 mb-2">
                    <span className="text-[9px] font-mono text-slate-500 uppercase block tracking-wider">
                      {asset.moduleGeometry}
                    </span>
                    <h3 className={`font-semibold text-base transition-colors ${
                      isSelected ? 'text-white' : 'text-slate-200 group-hover:text-white'
                    }`}>
                      {asset.name}
                    </h3>
                  </div>

                  {/* Vented / Stacked Physical Indicators */}
                  <div className="px-2 mb-3">
                    <div className="h-1.5 hardware-vent rounded opacity-60 mb-2" />
                    <div className="text-[10px] font-mono text-slate-400 flex items-center justify-between">
                      <span>{asset.service}</span>
                      <span className="text-slate-300 font-semibold">{asset.count}</span>
                    </div>
                  </div>

                  {/* Micro Status Summary Line */}
                  <div className="pt-2.5 mx-2 border-t border-[#182638] flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-mono text-[10px]">
                      {asset.statusText}
                    </span>
                    <span className={`text-[10px] font-mono font-medium transition-colors ${
                      isSelected ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-400'
                    }`}>
                      Inspect &rarr;
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Right: Technical Inspection Console for Selected Asset */}
          <div className="lg:col-span-5 chassis-steel rounded-xl p-6 shadow-2xl relative overflow-hidden border border-[#203046]">
            <div className="absolute top-2 left-2 screw-head" />
            <div className="absolute top-2 right-2 screw-head" />
            <div className="absolute bottom-2 left-2 screw-head" />
            <div className="absolute bottom-2 right-2 screw-head" />

            {/* Top header bar */}
            <div className="flex items-center justify-between pb-4 border-b border-[#1A283B] mb-5">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 led-cyan" />
                <span className="text-xs font-mono font-medium text-slate-300 tracking-wider">
                  REAL-TIME CONFIGURATION AUDIT
                </span>
              </div>
              <span className="text-[9px] font-mono text-slate-500 uppercase">
                AWS STS SESSION
              </span>
            </div>

            {/* Selected Asset Header */}
            <div className="mb-5">
              <div className="text-xs font-mono text-cyan-400 mb-1">
                RESOURCE AUDIT // {current.id.toUpperCase()}
              </div>
              <h3 className="text-xl font-bold text-white mb-1">
                {current.name}
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {current.specs}
              </p>
            </div>

            {/* Automated Checks List */}
            <div className="space-y-2.5 mb-6">
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                Evaluated Security Assertions
              </div>
              {current.highlightProps.map((prop, idx) => (
                <div 
                  key={idx} 
                  className="flex items-center justify-between p-2.5 rounded-lg bg-[#070B12] border border-[#182638] text-xs font-mono"
                >
                  <span className="text-slate-300 text-[11px]">{prop}</span>
                  <span className="text-[10px] text-cyan-400 font-semibold">PASS/FAIL AUTO</span>
                </div>
              ))}
            </div>

            {/* Risk Breakdown Box */}
            <div className="p-4 rounded-lg recessed-bay border border-[#1B2B3E] mb-5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400">Posture Impact</span>
                <span className="text-xs font-mono font-bold text-cyan-400">
                  DETERMINISTIC EVALUATION
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Evaluates resource security controls against declarative baseline rules to detect misconfigurations and unintended exposure before they impact compliance.
              </p>
            </div>

            {/* Micro Specs */}
            <div className="pt-3 border-t border-[#182638] flex items-center justify-between text-[10px] font-mono text-slate-500">
              <span>SCANNER: AWS READ-ONLY GUARD</span>
              <span className="flex items-center gap-1 text-cyan-400">
                <span>Rule Engine v2</span>
                <ExternalLink className="w-3 h-3" />
              </span>
            </div>
          </div>

        </div>

      </div>
    </section>
  );
};
