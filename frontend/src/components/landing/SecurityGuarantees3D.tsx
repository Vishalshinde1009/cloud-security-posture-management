import React from 'react';
import { 
  ShieldCheck, 
  KeyRound, 
  Fingerprint, 
  Lock, 
  Users
} from 'lucide-react';

interface Guarantee {
  icon: React.ElementType;
  title: string;
  badge: string;
  summary: string;
  details: string[];
  techCode: string;
  enclosureTag: string;
}

export const SecurityGuarantees3D: React.FC = () => {
  const guarantees: Guarantee[] = [
    {
      icon: ShieldCheck,
      title: '100% Read-Only Enforcement',
      badge: 'Code Guarded',
      summary: 'Architecturally incapable of modifying or destroying cloud infrastructure.',
      details: [
        'Dedicated Python ReadOnlyGuard validates every AWS API request before execution',
        'Strictly blocks mutating AWS actions (Create, Delete, Put, Update, Terminate, Attach)',
        'IAM policy enforces read-only permissions directly on the customer AWS account side'
      ],
      techCode: 'CSPM-Scanner-ReadOnly',
      enclosureTag: 'ENCL-SEC-01 // READ-ONLY GUARD'
    },
    {
      icon: KeyRound,
      title: 'AWS STS AssumeRole Integration',
      badge: 'No Static Credentials',
      summary: 'Temporary credentials generated on-demand with automatic expiration.',
      details: [
        'No long-lived AWS Access Keys (AKIA...) stored or required',
        'Requests short-lived credentials (maximum 1-hour session duration)',
        'Session tokens automatically discarded from memory immediately after scan completion'
      ],
      techCode: 'sts:AssumeRole',
      enclosureTag: 'ENCL-SEC-02 // STS GATEWAY'
    },
    {
      icon: Fingerprint,
      title: 'Cryptographic External ID Security',
      badge: 'Confused Deputy Immune',
      summary: 'Protects customer IAM trust relationships against cross-tenant attack vectors.',
      details: [
        'Cryptographically secure 32-character hexadecimal token generated per cloud account',
        'Immutable once created; verified in trust relationship condition block',
        'Eliminates the AWS Confused Deputy vulnerability across all tenants'
      ],
      techCode: 'sts:ExternalId',
      enclosureTag: 'ENCL-SEC-03 // EXTERNAL-ID'
    },
    {
      icon: Lock,
      title: 'Zero Secret Storage Guarantee',
      badge: 'Zero-Knowledge',
      summary: 'Your AWS master credentials never touch our database or application servers.',
      details: [
        'Database stores ONLY Role ARN, Cloud Account Name, and the generated External ID',
        'Zero IAM secret keys, zero password hashes, zero credentials on disk',
        'If the CSPM database were leaked, an attacker gains zero access keys'
      ],
      techCode: 'NO_SECRETS_STORED',
      enclosureTag: 'ENCL-SEC-04 // ZERO SECRETS'
    },
    {
      icon: Users,
      title: 'Multi-Tenant Isolation & IDOR Protection',
      badge: 'Cryptographic Boundary',
      summary: 'Strict cryptographic separation between tenants at the ORM and database layer.',
      details: [
        'Every CloudAccount, Scan, Finding, and Report is bound to an authenticated User ID',
        'SQLAlchemy queries enforce WHERE user_id = current_user across all routes',
        'Automated IDOR security tests verify no user can query another tenant’s assets'
      ],
      techCode: 'TENANT_ISOLATED',
      enclosureTag: 'ENCL-SEC-05 // ISOLATION BUS'
    }
  ];

  return (
    <section id="security-guarantees" className="relative py-28 px-4 sm:px-6 lg:px-8 border-t border-[#182638] bg-[#070B12] overflow-hidden">
      {/* Subtle ambient lighting */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[350px] bg-cyan-950/10 rounded-full blur-[140px] pointer-events-none" />

      <div className="max-w-7xl mx-auto relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#0D1522] border border-[#1E2E44] text-xs font-mono text-cyan-400">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 led-cyan" />
            ENTERPRISE ASSURANCE GUARANTEES
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white">
            Security Designed For Security Teams
          </h2>
          <p className="text-slate-400 text-base leading-relaxed">
            Connecting an external tool to your AWS infrastructure requires uncompromising trust. 
            Here is our architectural contract with your security and compliance leadership.
          </p>
        </div>

        {/* 5 Physical Guarantee Chassis Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 perspective-1000">
          {guarantees.map((item, index) => {
            const Icon = item.icon;
            const isLast = index === 4;

            return (
              <div
                key={item.title}
                className={`p-6 rounded-xl border border-[#1B273A] chassis-steel hover:border-cyan-500/40 transition-all duration-300 preserve-3d hover:-translate-y-1.5 hover:shadow-[0_20px_40px_rgba(0,0,0,0.8)] flex flex-col justify-between relative ${
                  isLast ? 'md:col-span-2 lg:col-span-1' : ''
                }`}
              >
                {/* Physical Chassis Screws */}
                <div className="absolute top-2 left-2 screw-head" />
                <div className="absolute top-2 right-2 screw-head" />
                <div className="absolute bottom-2 left-2 screw-head" />
                <div className="absolute bottom-2 right-2 screw-head" />

                <div>
                  {/* Top Bar */}
                  <div className="flex items-center justify-between mb-3 pt-1">
                    <span className="text-[8px] font-mono text-slate-500 uppercase tracking-wider">
                      {item.enclosureTag}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-[#0A101A] text-slate-300 border border-[#182638]">
                      {item.badge}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 rounded-lg bg-[#0E1624] border border-[#1E2E44] text-cyan-400">
                      <Icon className="w-4 h-4" />
                    </div>
                    <h3 className="font-semibold text-white text-base leading-snug">
                      {item.title}
                    </h3>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed mb-4">
                    {item.summary}
                  </p>

                  {/* Detailed Specs Bullet List */}
                  <ul className="space-y-2 mb-6">
                    {item.details.map((detail, dIdx) => (
                      <li key={dIdx} className="text-xs text-slate-400 leading-relaxed flex items-start gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 shrink-0" />
                        <span>{detail}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Technical Code Signature */}
                <div className="pt-3 border-t border-[#182638] flex items-center justify-between text-[10px] font-mono text-slate-500">
                  <span>SPECIFICATION:</span>
                  <span className="text-cyan-400 font-medium">{item.techCode}</span>
                </div>
              </div>
            );
          })}
        </div>

      </div>
    </section>
  );
};
