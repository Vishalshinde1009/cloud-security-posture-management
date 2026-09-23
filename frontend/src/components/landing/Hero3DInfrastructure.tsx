import React, { useState, useEffect, useRef } from 'react';
import { 
  Server, 
  Key, 
  Database, 
  Layers, 
  Radio, 
  ShieldCheck, 
  Cpu, 
  UserCheck, 
  Activity
} from 'lucide-react';

interface Hero3DInfrastructureProps {
  onNodeClick?: (id: string) => void;
  scrollYProgress?: number; // 0 to 1 as page scrolls
}

interface HoveredObjectInfo {
  id: string;
  name: string;
  type: string;
  status: string;
  region: string;
  source: string;
}

export const Hero3DInfrastructure: React.FC<Hero3DInfrastructureProps> = ({ scrollYProgress = 0 }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [tilt, setTilt] = useState<{ rx: number; ry: number }>({ rx: 0, ry: 0 });
  const [activeStageIndex, setActiveStageIndex] = useState<number>(0);
  const [hoveredNode, setHoveredNode] = useState<HoveredObjectInfo | null>(null);

  // Controlled 3-4 deg camera parallax with layered responsiveness
  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!containerRef.current) return;
    if (typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const rect = containerRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;

    const ry = (x / (rect.width / 2)) * 3.2;
    const rx = -(y / (rect.height / 2)) * 3.2;

    setTilt({ rx, ry });
  };

  const handleMouseLeave = () => {
    setTilt({ rx: 0, ry: 0 });
    setHoveredNode(null);
  };

  // Subtly step through pipeline data packet flow
  useEffect(() => {
    const timer = setInterval(() => {
      setActiveStageIndex((prev) => (prev + 1) % 6);
    }, 3200);
    return () => clearInterval(timer);
  }, []);

  // Cinematic scroll camera interpolation:
  const cameraRotateX = tilt.rx + scrollYProgress * 4;
  const cameraRotateY = tilt.ry - scrollYProgress * 3;
  const cameraTranslateZ = scrollYProgress * 40;
  const cameraScale = 1 + scrollYProgress * 0.05;

  return (
    <div className="w-full relative select-none">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* =========================================================================
            1. Physical 3D Infrastructure Laboratory Scene (7 cols desktop)
           ========================================================================= */}
        <div
          ref={containerRef}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
          className="lg:col-span-8 relative min-h-[520px] sm:min-h-[580px] flex items-center justify-center perspective-1200 cursor-crosshair overflow-hidden rounded-2xl border border-[#1E2D42] bg-[#070B12] shadow-[0_24px_60px_-15px_rgba(0,0,0,0.95)]"
        >
          {/* Subtle Key Light from top-left */}
          <div className="absolute -top-12 -left-12 w-96 h-96 bg-cyan-950/15 rounded-full blur-3xl pointer-events-none" />

          {/* Top Chassis Rig Rail & Lab Identification */}
          <div className="absolute top-0 inset-x-0 h-9 bg-[#0B121E] border-b border-[#182638] px-4 flex items-center justify-between z-30 pointer-events-none">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <span className="screw-head" />
                <span className="text-[10px] font-mono text-slate-400 font-semibold tracking-wider">
                  RIG: CSPM-CHASSIS-MODULAR
                </span>
              </div>
              <span className="text-slate-600 font-mono text-[9px] hidden sm:inline">|</span>
              <span className="text-[9px] font-mono text-slate-500 hidden sm:inline">
                SLOT: 08-BAY // DUAL-BUS
              </span>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
                <span className="text-[9px] font-mono text-emerald-400 font-medium">
                  PWR-1: OK
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
                <span className="text-[9px] font-mono text-cyan-400 font-medium">
                  CONDUIT: SYNC
                </span>
              </div>
              <span className="screw-head" />
            </div>
          </div>

          {/* Recessed Equipment Floor with Mounting Brackets & Contact Rails */}
          <div className="absolute inset-x-8 bottom-6 h-12 border-t border-[#152233] flex justify-between items-center opacity-40 pointer-events-none">
            <span className="text-[9px] font-mono text-slate-600">BRACKET-L // TORQUE 4.2Nm</span>
            <div className="flex items-center gap-4">
              <span className="w-12 h-1 bg-slate-800 rounded shadow-inner" />
              <span className="w-12 h-1 bg-slate-800 rounded shadow-inner" />
              <span className="w-12 h-1 bg-slate-800 rounded shadow-inner" />
            </div>
            <span className="text-[9px] font-mono text-slate-600">BRACKET-R // TORQUE 4.2Nm</span>
          </div>

          {/* Hover Inspection Overlay (Fixed in bottom-left corner of viewport) */}
          {hoveredNode && (
            <div className="absolute bottom-10 left-6 z-40 p-3 rounded-lg chassis-steel border border-cyan-500/40 shadow-2xl pointer-events-none transition-all duration-200">
              <div className="flex items-center justify-between gap-4 pb-1 border-b border-[#182638] mb-1.5">
                <span className="text-[10px] font-mono font-bold text-white tracking-wider">
                  {hoveredNode.name}
                </span>
                <span className="text-[8px] font-mono px-1.5 py-0.2 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/40">
                  {hoveredNode.status}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[8px] font-mono text-slate-400">
                <span>TYPE: {hoveredNode.type}</span>
                <span>REGION: {hoveredNode.region}</span>
                <span className="col-span-2 text-cyan-400">SRC: {hoveredNode.source}</span>
              </div>
            </div>
          )}

          {/* =========================================================================
              Physical 3D Assembly Container with Parallax & Physical Depth Planes
             ========================================================================= */}
          <div
            className="relative w-[340px] h-[360px] sm:w-[480px] sm:h-[460px] flex items-center justify-center preserve-3d transition-transform duration-300 ease-out mt-4"
            style={{
              transform: `rotateX(${cameraRotateX}deg) rotateY(${cameraRotateY}deg) translateZ(${cameraTranslateZ}px) scale(${cameraScale})`,
            }}
          >
            {/* -----------------------------------------------------------------------
                Physical Fiber-Optic Cable Conduits & Trace Paths (SVG)
               ----------------------------------------------------------------------- */}
            <svg 
              className="absolute inset-0 w-full h-full pointer-events-none z-10" 
              viewBox="0 0 480 460"
            >
              <defs>
                {/* Physical cable shadow */}
                <filter id="cable-shadow" x="-20%" y="-20%" width="140%" height="140%">
                  <feDropShadow dx="0" dy="3" stdDeviation="2" floodColor="#000000" floodOpacity="0.9" />
                </filter>
              </defs>

              {/* Physical conduit bundle from AWS CLOUD (Top-Left) to IAM (Top) */}
              <path 
                d="M 110 95 C 150 95, 170 60, 240 60" 
                stroke="#090E16" 
                strokeWidth="4.5" 
                fill="none" 
                filter="url(#cable-shadow)"
              />
              <path 
                d="M 110 95 C 150 95, 170 60, 240 60" 
                stroke="#1E2F44" 
                strokeWidth="2" 
                fill="none" 
              />

              {/* Conduit: IAM (Top) to STS (Top-Right) */}
              <path 
                d="M 240 60 C 310 60, 330 95, 370 95" 
                stroke="#090E16" 
                strokeWidth="4.5" 
                fill="none" 
                filter="url(#cable-shadow)"
              />
              <path 
                d="M 240 60 C 310 60, 330 95, 370 95" 
                stroke="#1E2F44" 
                strokeWidth="2" 
                fill="none" 
              />

              {/* Fiber Cable: STS to Central CSPM Engine (Center) */}
              <path 
                d="M 370 95 C 370 160, 300 180, 270 200" 
                stroke="#090E16" 
                strokeWidth="4" 
                fill="none" 
                filter="url(#cable-shadow)"
              />
              <path 
                d="M 370 95 C 370 160, 300 180, 270 200" 
                stroke="#06B6D4" 
                strokeWidth="1.2" 
                strokeDasharray="4 6" 
                className="animate-conduit opacity-80"
                fill="none" 
              />

              {/* Conduits from Central Engine to S3, EC2, VPC, RDS, CloudTrail */}
              {/* Engine -> S3 (Right) */}
              <path d="M 270 230 C 320 230, 340 215, 385 215" stroke="#090E16" strokeWidth="3.5" fill="none" filter="url(#cable-shadow)" />
              <path d="M 270 230 C 320 230, 340 215, 385 215" stroke="#1D2E42" strokeWidth="1.5" fill="none" />

              {/* Engine -> EC2 (Bottom-Right) */}
              <path d="M 255 255 C 290 300, 320 330, 355 350" stroke="#090E16" strokeWidth="3.5" fill="none" filter="url(#cable-shadow)" />
              <path d="M 255 255 C 290 300, 320 330, 355 350" stroke="#1D2E42" strokeWidth="1.5" fill="none" />

              {/* Engine -> RDS (Bottom) */}
              <path d="M 240 260 L 240 375" stroke="#090E16" strokeWidth="4" fill="none" filter="url(#cable-shadow)" />
              <path d="M 240 260 L 240 375" stroke="#1D2E42" strokeWidth="1.8" fill="none" />

              {/* Engine -> VPC (Bottom-Left) */}
              <path d="M 225 255 C 190 300, 160 330, 125 350" stroke="#090E16" strokeWidth="3.5" fill="none" filter="url(#cable-shadow)" />
              <path d="M 225 255 C 190 300, 160 330, 125 350" stroke="#1D2E42" strokeWidth="1.5" fill="none" />

              {/* Engine -> CloudTrail (Left) */}
              <path d="M 210 230 C 160 230, 140 215, 95 215" stroke="#090E16" strokeWidth="3.5" fill="none" filter="url(#cable-shadow)" />
              <path d="M 210 230 C 160 230, 140 215, 95 215" stroke="#1D2E42" strokeWidth="1.5" fill="none" />

              {/* Physical Cable Clip Clamps */}
              <rect x="180" y="69" width="8" height="5" rx="1" fill="#334155" stroke="#0B121E" strokeWidth="0.8" />
              <rect x="290" y="69" width="8" height="5" rx="1" fill="#334155" stroke="#0B121E" strokeWidth="0.8" />
              <rect x="330" y="159" width="5" height="8" rx="1" fill="#334155" stroke="#0B121E" strokeWidth="0.8" />
            </svg>

            {/* Subtle moving optical packet dot along STS to Engine path */}
            <div 
              className="absolute w-2 h-2 rounded-full bg-cyan-300 led-cyan transition-all duration-700 pointer-events-none z-20"
              style={{
                top: activeStageIndex === 0 ? '19%' : activeStageIndex === 1 ? '16%' : activeStageIndex === 2 ? '22%' : activeStageIndex === 3 ? '47%' : activeStageIndex === 4 ? '58%' : '78%',
                left: activeStageIndex === 0 ? '24%' : activeStageIndex === 1 ? '50%' : activeStageIndex === 2 ? '76%' : activeStageIndex === 3 ? '50%' : activeStageIndex === 4 ? '73%' : '50%',
                opacity: 0.9,
              }}
            />

            {/* -----------------------------------------------------------------------
                CENTRAL OBJECT: Cylindrical Engineered Security Appliance
                "CSPM SECURITY ENGINE" with recessed bays, ventilation, screws & internal modules
               ----------------------------------------------------------------------- */}
            <div
              className="absolute z-20 w-44 sm:w-48 p-4 rounded-xl chassis-steel text-center contact-shadow-lg flex flex-col items-center justify-between border border-[#263C58] transition-transform duration-300 hover:scale-[1.02]"
              style={{ 
                transform: 'translateZ(38px)',
                top: 'calc(50% - 92px)',
                left: 'calc(50% - 96px)',
              }}
            >
              {/* Corner Fastener Screws */}
              <div className="absolute top-2 left-2 screw-head" />
              <div className="absolute top-2 right-2 screw-head" />
              <div className="absolute bottom-2 left-2 screw-head" />
              <div className="absolute bottom-2 right-2 screw-head" />

              {/* Hardware Bezel & Status Line */}
              <div className="w-full flex items-center justify-between pb-2 border-b border-[#1A283B] mb-2 px-1">
                <span className="text-[8px] font-mono text-slate-400 font-bold tracking-widest">
                  CSPM-SEC-001
                </span>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
                  <span className="text-[8px] font-mono text-emerald-400 font-bold">ONLINE</span>
                </div>
              </div>

              {/* Recessed Engine Core Emblem */}
              <div className="w-full p-2.5 rounded-lg recessed-bay flex items-center justify-center gap-2 mb-2">
                <div className="p-1.5 rounded bg-[#0D1522] border border-[#1F3046] text-cyan-400">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div className="text-left">
                  <div className="text-[11px] font-mono font-bold text-white tracking-tight leading-none">
                    CSPM ENGINE
                  </div>
                  <div className="text-[8px] font-mono text-cyan-400/90 leading-tight mt-0.5">
                    READ-ONLY GUARD
                  </div>
                </div>
              </div>

              {/* Physical Internal Pipeline Stack Layers (Physical Modules) */}
              <div className="w-full space-y-1 mb-2">
                <div className="flex items-center justify-between px-2 py-0.5 rounded bg-[#060A10] border border-[#141F2C] text-[8px] font-mono text-slate-300">
                  <span>[01] DISCOVERY</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
                </div>
                <div className="flex items-center justify-between px-2 py-0.5 rounded bg-[#060A10] border border-[#141F2C] text-[8px] font-mono text-slate-300">
                  <span>[02] RULE ENGINE</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
                </div>
                <div className="flex items-center justify-between px-2 py-0.5 rounded bg-[#060A10] border border-[#141F2C] text-[8px] font-mono text-slate-300">
                  <span>[03] RISK ENGINE</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
                </div>
                <div className="flex items-center justify-between px-2 py-0.5 rounded bg-[#060A10] border border-[#141F2C] text-[8px] font-mono text-slate-300">
                  <span>[04] COMPLIANCE</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
                </div>
                <div className="flex items-center justify-between px-2 py-0.5 rounded bg-[#060A10] border border-[#141F2C] text-[8px] font-mono text-slate-300">
                  <span>[05] REPORTING</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
                </div>
              </div>

              {/* Hardware Heat-Sink / Ventilation Slots */}
              <div className="w-full h-3 hardware-vent rounded opacity-50 border-t border-[#141F2C] pt-1" />
            </div>

            {/* -----------------------------------------------------------------------
                REAL AWS INFRASTRUCTURE OBJECTS (With interactive hover labels)
               ----------------------------------------------------------------------- */}

            {/* 1. AWS CLOUD (Top-Left Background: Cloud Gateway Enclosure) */}
            <div
              onMouseEnter={() => setHoveredNode({
                id: 'aws',
                name: 'AWS CLOUD ROOT',
                type: 'ROOT ACCOUNT',
                status: 'VERIFIED',
                region: 'eu-north-1',
                source: 'AWS READ-ONLY'
              })}
              onMouseLeave={() => setHoveredNode(null)}
              className="absolute z-10 p-2.5 rounded-lg graphite-metal border border-[#203248] hover:border-cyan-400/60 contact-shadow-md w-32 cursor-pointer transition-all duration-200 hover:scale-105"
              style={{
                top: '55px',
                left: '25px',
                transform: 'translateZ(14px)',
                filter: 'brightness(0.92)',
              }}
            >
              <div className="flex items-center justify-between pb-1.5 border-b border-[#182638] mb-1.5">
                <div className="flex items-center gap-1.5 text-slate-300">
                  <Server className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-[10px] font-bold font-mono tracking-tight text-white">AWS CLOUD</span>
                </div>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
              </div>
              <div className="text-[8px] font-mono text-slate-400 flex items-center justify-between">
                <span>REGION: eu-north-1</span>
                <span className="text-cyan-400">ONLINE</span>
              </div>
            </div>

            {/* 2. IAM (Top Midground: Identity Control Terminal) */}
            <div
              onMouseEnter={() => setHoveredNode({
                id: 'iam',
                name: 'IAM IDENTITY TERMINAL',
                type: 'ROLE PRINCIPAL',
                status: 'ATTACHED',
                region: 'GLOBAL',
                source: 'STS TRUST POLICY'
              })}
              onMouseLeave={() => setHoveredNode(null)}
              className="absolute z-10 p-2 rounded-lg graphite-metal border border-[#203248] hover:border-purple-400/60 contact-shadow-md w-36 cursor-pointer transition-all duration-200 hover:scale-105"
              style={{
                top: '25px',
                left: 'calc(50% - 72px)',
                transform: 'translateZ(18px)',
                filter: 'brightness(0.95)',
              }}
            >
              <div className="flex items-center justify-between pb-1 border-b border-[#182638] mb-1">
                <div className="flex items-center gap-1.5 text-slate-300">
                  <UserCheck className="w-3.5 h-3.5 text-purple-400" />
                  <span className="text-[10px] font-bold font-mono text-white">IAM TERMINAL</span>
                </div>
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
              </div>
              <div className="text-[8px] font-mono text-slate-400">
                ROLE: CSPMViewerReadOnly
              </div>
            </div>

            {/* 3. STS ASSUMEROLE (Top-Right: Secure Auth Gateway) */}
            <div
              onMouseEnter={() => setHoveredNode({
                id: 'sts',
                name: 'STS ASSUMEROLE GATEWAY',
                type: 'AUTH DELEGATION',
                status: 'CONFIGURED',
                region: 'GLOBAL STS',
                source: 'EXTERNAL-ID VERIFIED'
              })}
              onMouseLeave={() => setHoveredNode(null)}
              className="absolute z-10 p-2.5 rounded-lg graphite-metal border border-cyan-500/35 hover:border-cyan-400 contact-shadow-md w-36 cursor-pointer transition-all duration-200 hover:scale-105"
              style={{
                top: '55px',
                right: '25px',
                transform: 'translateZ(26px)',
              }}
            >
              <div className="flex items-center justify-between pb-1 border-b border-[#182638] mb-1">
                <div className="flex items-center gap-1.5">
                  <Key className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-[10px] font-bold font-mono text-white">STS GATEWAY</span>
                </div>
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan animate-pulse" />
              </div>
              <div className="text-[8px] font-mono text-slate-400">
                EXTERNAL ID: VERIFIED
              </div>
            </div>

            {/* 4. S3 (Midground Right: Storage Server with Stacked Drive Slots) */}
            <div
              onMouseEnter={() => setHoveredNode({
                id: 's3',
                name: 'S3 STORAGE RIG',
                type: 'OBJECT STORAGE',
                status: 'DISCOVERY AVAILABLE',
                region: 'eu-north-1',
                source: 's3:ListAllMyBuckets'
              })}
              onMouseLeave={() => setHoveredNode(null)}
              className="absolute z-15 p-2 rounded-lg graphite-metal border border-[#203248] hover:border-cyan-400/60 contact-shadow-md w-32 cursor-pointer transition-all duration-200 hover:scale-105"
              style={{
                top: '190px',
                right: '15px',
                transform: 'translateZ(25px)',
              }}
            >
              <div className="flex items-center justify-between pb-1 border-b border-[#182638] mb-1.5">
                <div className="flex items-center gap-1 text-slate-300">
                  <Database className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-[10px] font-bold font-mono text-white">S3 STORAGE</span>
                </div>
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
              </div>
              {/* Stacked storage drive bays */}
              <div className="space-y-1">
                <div className="h-2 rounded-sm bg-[#060A10] border border-[#16212E] flex items-center px-1 justify-between">
                  <span className="w-2 h-0.5 bg-slate-600 rounded-full" />
                  <span className="w-1 h-1 rounded-full bg-emerald-400" />
                </div>
                <div className="h-2 rounded-sm bg-[#060A10] border border-[#16212E] flex items-center px-1 justify-between">
                  <span className="w-2 h-0.5 bg-slate-600 rounded-full" />
                  <span className="w-1 h-1 rounded-full bg-emerald-400" />
                </div>
              </div>
              <div className="text-[8px] font-mono text-slate-400 mt-1">
                OBJECT STORAGE AUDIT
              </div>
            </div>

            {/* 5. EC2 (Foreground Right: Compute Module with CPU & Ventilation) */}
            <div
              onMouseEnter={() => setHoveredNode({
                id: 'ec2',
                name: 'EC2 COMPUTE RIG',
                type: 'COMPUTE INSTANCES',
                status: 'DISCOVERY AVAILABLE',
                region: 'eu-north-1',
                source: 'ec2:DescribeInstances'
              })}
              onMouseLeave={() => setHoveredNode(null)}
              className="absolute z-20 p-2.5 rounded-lg graphite-metal border border-[#24374E] hover:border-blue-400/60 contact-shadow-lg w-36 cursor-pointer transition-all duration-200 hover:scale-105"
              style={{
                bottom: '40px',
                right: '35px',
                transform: 'translateZ(42px)',
              }}
            >
              <div className="flex items-center justify-between pb-1 border-b border-[#182638] mb-1">
                <div className="flex items-center gap-1.5 text-slate-300">
                  <Cpu className="w-3.5 h-3.5 text-blue-400" />
                  <span className="text-[10px] font-bold font-mono text-white">EC2 COMPUTE</span>
                </div>
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
              </div>
              <div className="w-full h-2 hardware-vent rounded mb-1 opacity-70" />
              <div className="text-[8px] font-mono text-slate-400 flex justify-between">
                <span>WORKLOAD AUDIT</span>
                <span className="text-emerald-400 font-bold">READY</span>
              </div>
            </div>

            {/* 6. RDS (Foreground Bottom Center: Database Cylinder Bay) */}
            <div
              onMouseEnter={() => setHoveredNode({
                id: 'rds',
                name: 'RDS DATABASE BAY',
                type: 'MANAGED DB',
                status: 'KMS ENFORCED',
                region: 'eu-north-1',
                source: 'rds:DescribeDBInstances'
              })}
              onMouseLeave={() => setHoveredNode(null)}
              className="absolute z-20 p-2.5 rounded-lg graphite-metal border border-[#24374E] hover:border-emerald-400/60 contact-shadow-lg w-36 cursor-pointer transition-all duration-200 hover:scale-105"
              style={{
                bottom: '15px',
                left: 'calc(50% - 72px)',
                transform: 'translateZ(46px)',
              }}
            >
              <div className="flex items-center justify-between pb-1 border-b border-[#182638] mb-1">
                <div className="flex items-center gap-1.5 text-slate-300">
                  <Database className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-[10px] font-bold font-mono text-white">RDS DATABASE</span>
                </div>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
              </div>
              <div className="text-[8px] font-mono text-slate-400 flex justify-between">
                <span>STORAGE ENCRYPT</span>
                <span className="text-emerald-400 font-bold">AUDIT</span>
              </div>
            </div>

            {/* 7. VPC (Foreground Left: Segmented Network Enclosure) */}
            <div
              onMouseEnter={() => setHoveredNode({
                id: 'vpc',
                name: 'VPC NETWORK BAY',
                type: 'NETWORK ISOLATION',
                status: 'FLOW LOGS CHECK',
                region: 'eu-north-1',
                source: 'ec2:DescribeVpcs'
              })}
              onMouseLeave={() => setHoveredNode(null)}
              className="absolute z-20 p-2.5 rounded-lg graphite-metal border border-[#24374E] hover:border-emerald-400/60 contact-shadow-lg w-36 cursor-pointer transition-all duration-200 hover:scale-105"
              style={{
                bottom: '40px',
                left: '35px',
                transform: 'translateZ(40px)',
              }}
            >
              <div className="flex items-center justify-between pb-1 border-b border-[#182638] mb-1">
                <div className="flex items-center gap-1.5 text-slate-300">
                  <Layers className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-[10px] font-bold font-mono text-white">VPC NETWORK</span>
                </div>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
              </div>
              <div className="grid grid-cols-3 gap-1 my-1">
                <span className="h-1.5 bg-[#09111C] border border-cyan-500/30 rounded" />
                <span className="h-1.5 bg-[#09111C] border border-cyan-500/30 rounded" />
                <span className="h-1.5 bg-[#09111C] border border-cyan-500/30 rounded" />
              </div>
              <div className="text-[8px] font-mono text-slate-400">
                SEGMENTATION AUDIT
              </div>
            </div>

            {/* 8. CLOUDTRAIL (Midground Left: Audit Activity Recorder) */}
            <div
              onMouseEnter={() => setHoveredNode({
                id: 'cloudtrail',
                name: 'CLOUDTRAIL RECORDER',
                type: 'AUDIT LOGGING',
                status: 'TRAIL VALIDATION',
                region: 'MULTI-REGION',
                source: 'cloudtrail:DescribeTrails'
              })}
              onMouseLeave={() => setHoveredNode(null)}
              className="absolute z-15 p-2 rounded-lg graphite-metal border border-[#203248] hover:border-amber-400/60 contact-shadow-md w-32 cursor-pointer transition-all duration-200 hover:scale-105"
              style={{
                top: '190px',
                left: '15px',
                transform: 'translateZ(25px)',
              }}
            >
              <div className="flex items-center justify-between pb-1 border-b border-[#182638] mb-1">
                <div className="flex items-center gap-1 text-slate-300">
                  <Radio className="w-3.5 h-3.5 text-amber-400" />
                  <span className="text-[10px] font-bold font-mono text-white">CLOUDTRAIL</span>
                </div>
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 led-amber" />
              </div>
              <div className="text-[8px] font-mono text-slate-400">
                INTEGRITY CHECK
              </div>
            </div>

          </div>

          {/* Bottom Precision Engineering Specs Bar */}
          <div className="absolute bottom-2 left-4 right-4 flex items-center justify-between text-[10px] font-mono text-slate-500 border-t border-[#182638] pt-1.5 pointer-events-none">
            <span>CHASSIS REF: 100% READ-ONLY PHYSICAL BOUNDARY</span>
            <span>STS DURATION: 3600s MAX // NO KEYS STORED</span>
          </div>
        </div>

        {/* =========================================================================
            2. Physical Engineering Monitoring Displays (4 cols desktop)
           ========================================================================= */}
        <div className="lg:col-span-4 space-y-5">
          
          {/* Hardware Monitoring Display: SYSTEM STATUS */}
          <div className="chassis-steel rounded-xl border border-[#1E2E44] p-5 shadow-2xl relative">
            <div className="absolute top-2 left-2 screw-head" />
            <div className="absolute top-2 right-2 screw-head" />
            <div className="absolute bottom-2 left-2 screw-head" />
            <div className="absolute bottom-2 right-2 screw-head" />

            <div className="flex items-center justify-between pb-3 border-b border-[#1A283B] mb-4">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-mono font-bold tracking-wider text-white uppercase">
                  SYSTEM STATUS
                </span>
              </div>
              <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-[#09101A] text-slate-400 border border-[#1A283B]">
                CH-01 // AUDIT-READY
              </span>
            </div>

            {/* Machine Status Rows with Individual Hardware Status LEDs */}
            <div className="space-y-2.5 font-mono text-xs">
              <div className="flex items-center justify-between py-1.5 px-2 rounded bg-[#060A10] border border-[#131D2A]">
                <span className="text-slate-400 text-[11px]">AWS CONNECTION</span>
                <span className="flex items-center gap-1.5 text-emerald-400 font-bold text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
                  ACTIVE
                </span>
              </div>

              <div className="flex items-center justify-between py-1.5 px-2 rounded bg-[#060A10] border border-[#131D2A]">
                <span className="text-slate-400 text-[11px]">STS ASSUMEROLE</span>
                <span className="flex items-center gap-1.5 text-cyan-400 font-bold text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
                  VERIFIED
                </span>
              </div>

              <div className="flex items-center justify-between py-1.5 px-2 rounded bg-[#060A10] border border-[#131D2A]">
                <span className="text-slate-400 text-[11px]">READ-ONLY ACCESS</span>
                <span className="flex items-center gap-1.5 text-emerald-400 font-bold text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
                  ENFORCED
                </span>
              </div>

              <div className="flex items-center justify-between py-1.5 px-2 rounded bg-[#060A10] border border-[#131D2A]">
                <span className="text-slate-400 text-[11px]">ASSET DISCOVERY</span>
                <span className="flex items-center gap-1.5 text-cyan-300 font-bold text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
                  DISCOVERY ACTIVE
                </span>
              </div>

              <div className="flex items-center justify-between py-1.5 px-2 rounded bg-[#060A10] border border-[#131D2A]">
                <span className="text-slate-400 text-[11px]">SECURITY RULES</span>
                <span className="flex items-center gap-1.5 text-cyan-300 font-bold text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
                  EVALUATION ENGINE
                </span>
              </div>

              <div className="flex items-center justify-between py-1.5 px-2 rounded bg-[#060A10] border border-[#131D2A]">
                <span className="text-slate-400 text-[11px]">RISK ENGINE</span>
                <span className="flex items-center gap-1.5 text-emerald-400 font-bold text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
                  ONLINE
                </span>
              </div>

              <div className="flex items-center justify-between py-1.5 px-2 rounded bg-[#060A10] border border-[#131D2A]">
                <span className="text-slate-400 text-[11px]">AUDIT LOGGING</span>
                <span className="flex items-center gap-1.5 text-emerald-400 font-bold text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 led-emerald" />
                  ACTIVE
                </span>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-[#182638] flex items-center justify-between text-[9px] font-mono text-slate-500">
              <span>ZERO SECRET STORAGE</span>
              <span>TENANT ISOLATED</span>
            </div>
          </div>

          {/* Physical Security Assessment Instrument: CALIBRATED GAUGE PANEL */}
          <div className="chassis-steel rounded-xl border border-[#1E2E44] p-5 shadow-2xl relative">
            <div className="absolute top-2 left-2 screw-head" />
            <div className="absolute top-2 right-2 screw-head" />
            <div className="absolute bottom-2 left-2 screw-head" />
            <div className="absolute bottom-2 right-2 screw-head" />

            <div className="flex items-center justify-between pb-3 border-b border-[#1A283B] mb-3">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-amber-400 led-amber" />
                <span className="text-[10px] font-mono font-bold tracking-wider text-slate-300 uppercase">
                  SECURITY POSTURE INSTRUMENT
                </span>
              </div>
              <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
                SAMPLE EVALUATION
              </span>
            </div>

            <div className="flex items-center justify-between py-1">
              <div className="space-y-1">
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                  SAMPLE POSTURE SCORE
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl font-extrabold font-mono text-white tracking-tight">
                    47.8
                  </span>
                  <span className="text-xs font-mono text-slate-500">/ 100</span>
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
                    POOR
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-mono pt-1">
                  Illustrative benchmark posture calculation
                </p>
              </div>

              {/* Physical Calibrated Instrumentation Dial (Metal bezel, calibrated ticks, needle) */}
              <div className="relative w-24 h-24 flex items-center justify-center p-1 rounded-full recessed-bay border-2 border-[#203046] shadow-inner">
                {/* Metallic Bezel Rim */}
                <div className="absolute inset-0 rounded-full border border-white/10 pointer-events-none" />

                <svg className="w-full h-full" viewBox="0 0 100 100">
                  {/* Calibrated Ticks around perimeter */}
                  {[...Array(11)].map((_, i) => {
                    const angle = 135 + i * 27; // 135 deg to 405 deg (270 arc)
                    const rad = (angle * Math.PI) / 180;
                    const x1 = 50 + 38 * Math.cos(rad);
                    const y1 = 50 + 38 * Math.sin(rad);
                    const x2 = 50 + 44 * Math.cos(rad);
                    const y2 = 50 + 44 * Math.sin(rad);
                    return (
                      <line 
                        key={i} 
                        x1={x1} 
                        y1={y1} 
                        x2={x2} 
                        y2={y2} 
                        stroke={i === 5 ? '#F59E0B' : '#334155'} 
                        strokeWidth={i % 2 === 0 ? '2' : '1'} 
                      />
                    );
                  })}

                  {/* Dial Arc Track */}
                  <path
                    d="M 23.2 76.8 A 38 38 0 1 1 76.8 76.8"
                    fill="none"
                    stroke="#141E2C"
                    strokeWidth="5"
                    strokeLinecap="round"
                  />

                  {/* Active Value Arc (47.8%) */}
                  <path
                    d="M 23.2 76.8 A 38 38 0 0 1 50 12"
                    fill="none"
                    stroke="#F59E0B"
                    strokeWidth="5"
                    strokeLinecap="round"
                  />

                  {/* Center Pivot Bezel */}
                  <circle cx="50" cy="50" r="5" fill="#1E293B" stroke="#475569" strokeWidth="1" />
                  <circle cx="50" cy="50" r="2" fill="#F59E0B" />

                  {/* Physical Indicator Needle pointing to 47.8 */}
                  <line
                    x1="50"
                    y1="50"
                    x2={50 + 30 * Math.cos((264 * Math.PI) / 180)}
                    y2={50 + 30 * Math.sin((264 * Math.PI) / 180)}
                    stroke="#F59E0B"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                </svg>

                {/* Glass Cover Reflection Glare */}
                <div 
                  className="absolute inset-1 rounded-full pointer-events-none opacity-20"
                  style={{
                    background: 'linear-gradient(135deg, rgba(255,255,255,0.4) 0%, transparent 60%)',
                  }}
                />
              </div>
            </div>

            <div className="mt-3 pt-2.5 border-t border-[#182638] flex items-center justify-between text-[9px] font-mono text-slate-500">
              <span>CALIBRATED: NIST / CIS</span>
              <span>MATH CVSS 3.1</span>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};
