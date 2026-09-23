import React from 'react';
import { 
  Key, 
  RefreshCw, 
  Search, 
  ShieldAlert, 
  BarChart3, 
  FileCheck2, 
  ArrowRight 
} from 'lucide-react';

interface StepItem {
  number: string;
  title: string;
  shortDesc: string;
  icon: React.ElementType;
  outputArtifact: string;
  technicalDetails: string;
  hardwareEnclosure: string;
}

export const HowItWorks3D: React.FC = () => {
  const steps: StepItem[] = [
    {
      number: '01',
      title: 'CONNECT',
      shortDesc: 'Register AWS Account & Generate External ID',
      icon: Key,
      outputArtifact: 'Unique External ID Token',
      technicalDetails: 'Generates a 32-char crypto External ID and prepares an AWS IAM Trust Policy snippet for zero-trust cross-account access.',
      hardwareEnclosure: 'STATION-01 // REGISTRATION BAY'
    },
    {
      number: '02',
      title: 'ASSUME',
      shortDesc: 'STS AssumeRole with External ID Verification',
      icon: RefreshCw,
      outputArtifact: 'Temporary 1-Hour Credentials',
      technicalDetails: 'Calls AWS Security Token Service (STS) to obtain short-lived read-only access keys. No persistent secret keys stored.',
      hardwareEnclosure: 'STATION-02 // STS AUTH CONDUIT'
    },
    {
      number: '03',
      title: 'DISCOVER',
      shortDesc: 'Inventory Multi-Service Cloud Assets',
      icon: Search,
      outputArtifact: 'Asset Metadata Graph',
      technicalDetails: 'Enumerates S3 buckets, EC2 instances, security groups, IAM roles, VPCs, and RDS databases via read-only APIs.',
      hardwareEnclosure: 'STATION-03 // INVENTORY CRAWLER'
    },
    {
      number: '04',
      title: 'EVALUATE',
      shortDesc: 'Deterministic Security Rule Engine',
      icon: ShieldAlert,
      outputArtifact: 'Audit Assertions (Pass/Fail)',
      technicalDetails: 'Executes declarative security rules against live configurations: public bucket checks, SSH ingress, MFA enforcement, and encryption status.',
      hardwareEnclosure: 'STATION-04 // RULE PROCESSOR'
    },
    {
      number: '05',
      title: 'SCORE',
      shortDesc: 'Explainable Quantitative Risk Algorithm',
      icon: BarChart3,
      outputArtifact: 'Posture Score (0-100) & CVSS',
      technicalDetails: 'Calculates asset criticality, exploitability factor, and weighted finding severities to yield an audit-grade cloud posture score.',
      hardwareEnclosure: 'STATION-05 // RISK MATRIX CO-PROC'
    },
    {
      number: '06',
      title: 'REPORT',
      shortDesc: 'Executive & Regulatory PDF Compliance',
      icon: FileCheck2,
      outputArtifact: 'Signed PDF Audit Report',
      technicalDetails: 'Synthesizes compliance mapping against CIS AWS Foundations, NIST SP 800-53, and ISO 27001 with timestamped executive exports.',
      hardwareEnclosure: 'STATION-06 // AUDIT REPORT VAULT'
    }
  ];

  return (
    <section id="how-it-works" className="relative py-28 px-4 sm:px-6 lg:px-8 border-t border-[#182638] bg-[#070B12] overflow-hidden">
      {/* Restrained back lighting */}
      <div className="absolute top-1/2 left-1/4 w-[500px] h-[300px] bg-cyan-950/10 rounded-full blur-[140px] pointer-events-none" />

      <div className="max-w-7xl mx-auto relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#0D1522] border border-[#1E2E44] text-xs font-mono text-cyan-400">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
            END-TO-END EXECUTION LIFECYCLE
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white">
            How The Platform Works
          </h2>
          <p className="text-slate-400 text-base leading-relaxed">
            From cross-account credential assumption to executive compliance reporting, 
            understand the deterministic six-stage lifecycle that powers every CSPM scan.
          </p>
        </div>

        {/* 6 Connected Physical Stations */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {steps.map((step, idx) => {
            const Icon = step.icon;

            return (
              <div
                key={step.number}
                className="group relative p-6 rounded-xl border border-[#1B273A] chassis-steel hover:border-cyan-500/50 transition-all duration-300 flex flex-col justify-between shadow-lg hover:-translate-y-1"
              >
                {/* Physical Station Screws */}
                <div className="absolute top-2 left-2 screw-head" />
                <div className="absolute top-2 right-2 screw-head" />
                <div className="absolute bottom-2 left-2 screw-head" />
                <div className="absolute bottom-2 right-2 screw-head" />

                <div>
                  {/* Station Enclosure Header */}
                  <div className="flex items-center justify-between mb-3 pt-1">
                    <span className="text-[8px] font-mono text-slate-500 uppercase tracking-wider">
                      {step.hardwareEnclosure}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                        {step.number}
                      </span>
                    </div>
                  </div>

                  {/* Title & Short Description */}
                  <div className="flex items-center gap-3 mb-2">
                    <div className="p-2 rounded-lg bg-[#0E1624] border border-[#1E2E44] text-cyan-400">
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
                        <span>{step.title}</span>
                        {idx < steps.length - 1 && (
                          <ArrowRight className="w-3 h-3 text-slate-600 hidden lg:inline-block" />
                        )}
                      </h3>
                      <div className="text-[10px] font-mono text-cyan-400/90">
                        {step.shortDesc}
                      </div>
                    </div>
                  </div>

                  {/* Technical Summary */}
                  <p className="text-xs text-slate-400 leading-relaxed mb-5 mt-3">
                    {step.technicalDetails}
                  </p>
                </div>

                {/* Artifact Output Recessed Box */}
                <div className="p-2.5 rounded-lg recessed-bay border border-[#182638] flex items-center justify-between text-[10px] font-mono">
                  <span className="text-slate-500">Output Artifact:</span>
                  <span className="text-slate-200 font-medium">{step.outputArtifact}</span>
                </div>
              </div>
            );
          })}
        </div>

      </div>
    </section>
  );
};
