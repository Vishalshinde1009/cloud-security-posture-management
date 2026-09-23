import React, { useState } from 'react';
import { 
  User, 
  Shield, 
  Key, 
  FileLock, 
  Server, 
  Search, 
  Cpu, 
  Activity, 
  ShieldCheck, 
  FileText,
  ArrowRight
} from 'lucide-react';

interface ArchStage {
  step: string;
  name: string;
  sub: string;
  desc: string;
  icon: React.ReactNode;
  ledColor: string;
  conduitType: string;
}

const STAGES: ArchStage[] = [
  { step: '01', name: 'Authenticated User', sub: 'JWT / RBAC Client', desc: 'Secure browser session with strict multi-tenant boundary.', icon: <User className="w-4 h-4" />, ledColor: 'bg-cyan-400 led-cyan', conduitType: 'TLS 1.3 / HTTPS' },
  { step: '02', name: 'CSPM Control Plane', sub: 'FastAPI Backend', desc: 'IDOR-protected API gateway enforcing tenant isolation context.', icon: <Shield className="w-4 h-4" />, ledColor: 'bg-blue-400', conduitType: 'Internal Bus' },
  { step: '03', name: 'STS AssumeRole', sub: 'External ID Security', desc: 'Cryptographic 32-char external ID token verification.', icon: <Key className="w-4 h-4" />, ledColor: 'bg-purple-400', conduitType: 'STS API Call' },
  { step: '04', name: 'Temporary Credentials', sub: '1-Hour Ephemeral Session', desc: 'Short-lived AWS tokens created strictly for scan duration.', icon: <FileLock className="w-4 h-4" />, ledColor: 'bg-purple-300', conduitType: 'Memory Only' },
  { step: '05', name: 'Read-Only AWS APIs', sub: 'Client Runtime Guard', desc: 'Hardware/software guard prohibiting mutating AWS commands.', icon: <Server className="w-4 h-4" />, ledColor: 'bg-emerald-400 led-emerald', conduitType: 'Read Filter' },
  { step: '06', name: 'Discovery Engine', sub: 'Multi-Service Ingestion', desc: 'Collects configuration snapshots across 6 AWS services.', icon: <Search className="w-4 h-4" />, ledColor: 'bg-cyan-400 led-cyan', conduitType: 'JSON Stream' },
  { step: '07', name: 'Security Rule Engine', sub: '26 Deterministic Checks', desc: 'Evaluates ingested state against CIS and best practices.', icon: <Cpu className="w-4 h-4" />, ledColor: 'bg-amber-400 led-amber', conduitType: 'AST Evaluator' },
  { step: '08', name: 'Risk Engine', sub: 'Explainable Formula', desc: 'Calculates transparent 0–100 scores weighted by exposure.', icon: <Activity className="w-4 h-4" />, ledColor: 'bg-rose-400 led-rose', conduitType: 'Math CVSS' },
  { step: '09', name: 'Compliance Mappings', sub: '4 Regulatory Standards', desc: 'Maps findings to CIS AWS, NIST, ISO 27001, and PCI DSS.', icon: <ShieldCheck className="w-4 h-4" />, ledColor: 'bg-emerald-400 led-emerald', conduitType: 'Matrix Cross' },
  { step: '10', name: 'Audit & PDF Reports', sub: 'Executive Assessment', desc: 'Server-side generated documentation for compliance teams.', icon: <FileText className="w-4 h-4" />, ledColor: 'bg-cyan-400 led-cyan', conduitType: 'PDF Artifact' },
];

export const Enterprise3DArchitecture: React.FC = () => {
  const [selectedStage, setSelectedStage] = useState<number>(2);

  return (
    <section id="pipeline" className="py-24 border-b border-[#182638] bg-[#070B12] relative overflow-hidden">
      {/* Subtle floor conduit lines in background */}
      <div className="absolute inset-0 datacenter-floor opacity-15 pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#0D1522] border border-[#1E2E44] text-slate-300 text-xs font-mono uppercase tracking-wider">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
            10-STAGE ENGINEERING PIPELINE
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Security Architecture, By Design
          </h2>
          <p className="text-slate-400 text-sm sm:text-base leading-relaxed font-normal">
            Physical separation between control plane, tenant isolation, delegated AWS credentials, and read-only discovery.
          </p>
        </div>

        {/* 10-Stage Physical Architecture Rack Enclosure */}
        <div className="chassis-steel rounded-2xl border border-[#203046] p-6 sm:p-8 shadow-[0_20px_50px_-15px_rgba(0,0,0,0.9)] relative">
          
          {/* Top Chassis Hardware Bar */}
          <div className="flex items-center justify-between pb-4 border-b border-[#1A283B] mb-6">
            <div className="flex items-center gap-3">
              <span className="screw-head" />
              <span className="text-xs font-mono font-bold text-slate-300 tracking-wider">
                PIPELINE BUS // 10 MODULAR STATIONS
              </span>
            </div>
            <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
              <span>CONNECTOR: SERIAL CONDUIT</span>
              <span className="screw-head" />
            </div>
          </div>

          {/* 10 Physical Modular Stations Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-4">
            {STAGES.map((stage, idx) => {
              const isSelected = selectedStage === idx;

              return (
                <button
                  key={stage.step}
                  onClick={() => setSelectedStage(idx)}
                  className={`text-left p-4 rounded-xl transition-all duration-300 flex flex-col justify-between space-y-3 relative preserve-3d group ${
                    isSelected 
                      ? 'bg-[#101927] border-2 border-cyan-500/60 shadow-[0_10px_25px_-5px_rgba(6,182,212,0.2)] -translate-y-1' 
                      : 'bg-[#0A1019] border border-[#182638] hover:border-slate-600 hover:bg-[#0E1522]'
                  }`}
                >
                  <div className="space-y-2">
                    {/* Top Station Tag & Icon */}
                    <div className="flex items-center justify-between">
                      <span className={`text-[10px] font-mono font-bold ${
                        isSelected ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-400'
                      }`}>
                        STATION {stage.step}
                      </span>
                      <div className={`p-1.5 rounded-lg border ${
                        isSelected 
                          ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400' 
                          : 'bg-[#060910] border-[#182638] text-slate-400'
                      }`}>
                        {stage.icon}
                      </div>
                    </div>

                    <div>
                      <h3 className="text-xs font-bold text-white tracking-tight flex items-center gap-1.5">
                        <span>{stage.name}</span>
                        <span className={`w-1.5 h-1.5 rounded-full ${stage.ledColor}`} />
                      </h3>
                      <span className="text-[10px] font-mono text-cyan-400/80 block mt-0.5 truncate">
                        {stage.sub}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
                      {stage.desc}
                    </p>
                  </div>

                  {/* Physical Conduit Port Badge */}
                  <div className="pt-2 border-t border-[#162232] flex items-center justify-between text-[9px] font-mono text-slate-500">
                    <span>{stage.conduitType}</span>
                    <span className={isSelected ? 'text-cyan-400 font-bold' : 'text-slate-600'}>
                      {isSelected ? 'ACTIVE' : 'IDLE'}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Active Station Detailed Telemetry Inspection Bay */}
          <div className="mt-8 p-4 sm:p-5 rounded-xl recessed-bay border border-[#1C2C40] flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-[#0E1624] border border-[#23354C] text-cyan-400">
                {STAGES[selectedStage].icon}
              </div>
              <div>
                <div className="text-[10px] font-mono text-cyan-400">
                  SELECTED: STATION {STAGES[selectedStage].step} // {STAGES[selectedStage].name.toUpperCase()}
                </div>
                <div className="text-sm font-bold text-white">
                  {STAGES[selectedStage].desc}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs font-mono text-slate-400 shrink-0">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 led-emerald" />
                Read-Only Guard: list_*, describe_*, get_* Only
              </span>
              <ArrowRight className="w-4 h-4 text-cyan-400 hidden md:inline" />
            </div>
          </div>

        </div>

      </div>
    </section>
  );
};
