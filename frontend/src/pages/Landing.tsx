import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  ArrowRight,
  ChevronRight,
  ShieldCheck,
  CheckCircle2,
  Lock,
  RefreshCw
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ArchitecturalBackground } from '../components/landing/ArchitecturalBackground';
import { Hero3DInfrastructure } from '../components/landing/Hero3DInfrastructure';
import { Enterprise3DArchitecture } from '../components/landing/Enterprise3DArchitecture';
import { HowItWorks3D } from '../components/landing/HowItWorks3D';
import { AssetExplorer3D } from '../components/landing/AssetExplorer3D';
import { RiskStack3D } from '../components/landing/RiskStack3D';
import { ComplianceCards3D } from '../components/landing/ComplianceCards3D';
import { SecurityGuarantees3D } from '../components/landing/SecurityGuarantees3D';
import { SystemHUD } from '../components/landing/SystemHUD';

export const Landing: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [scrollYProgress, setScrollYProgress] = useState<number>(0);
  const [currentStageName, setCurrentStageName] = useState<string>('CLOUD CONNECTION');

  // Smooth scroll tracking to determine camera stage and hero scroll progress
  useEffect(() => {
    const handleScroll = () => {
      const scrollY = window.scrollY;
      const heroHeight = window.innerHeight * 0.85;
      const progress = Math.min(Math.max(scrollY / heroHeight, 0), 1);
      setScrollYProgress(progress);

      // Determine active stage based on scroll depth (accurate stage names)
      if (scrollY < 450) {
        setCurrentStageName('CLOUD CONNECTION');
      } else if (scrollY < 1100) {
        setCurrentStageName('STS ASSUMEROLE');
      } else if (scrollY < 1850) {
        setCurrentStageName('DISCOVERY');
      } else if (scrollY < 2600) {
        setCurrentStageName('SECURITY RULES');
      } else if (scrollY < 3400) {
        setCurrentStageName('RISK SCORING');
      } else if (scrollY < 4200) {
        setCurrentStageName('COMPLIANCE');
      } else {
        setCurrentStageName('REPORTING');
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <div className="min-h-screen bg-[#070b12] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-200 relative overflow-x-hidden">
      
      {/* Fixed Minimal Engineering HUD */}
      <SystemHUD currentStageName={currentStageName} />

      {/* 1. Header Navigation — Solid Precision Technical Header */}
      <header className="sticky top-0 z-50 border-b border-[#182333] bg-[#070b12]/95 backdrop-blur-md px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="p-2 rounded-lg bg-[#0e1624] border border-[#22354c] text-cyan-400 group-hover:border-cyan-500/50 transition-colors shadow-sm">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="text-sm font-bold tracking-tight text-white flex items-center gap-2 font-mono">
                ENTERPRISE CSPM
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40 font-normal">
                  v2.0
                </span>
              </span>
              <p className="text-[11px] text-slate-500 font-mono">Cloud Security Posture Management</p>
            </div>
          </Link>

          {/* Nav Links */}
          <nav className="hidden lg:flex items-center gap-7 text-xs font-mono uppercase tracking-wider text-slate-400">
            <a href="#pipeline" className="hover:text-cyan-400 transition-colors">Pipeline</a>
            <a href="#how-it-works" className="hover:text-cyan-400 transition-colors">Lifecycle</a>
            <a href="#assets" className="hover:text-cyan-400 transition-colors">Inventory</a>
            <a href="#risk-scoring" className="hover:text-cyan-400 transition-colors">Risk Scoring</a>
            <a href="#compliance" className="hover:text-cyan-400 transition-colors">Compliance</a>
            <a href="#security-guarantees" className="hover:text-cyan-400 transition-colors">Guarantees</a>
          </nav>

          {/* Action CTAs */}
          <div className="flex items-center gap-3">
            {isAuthenticated ? (
              <Link
                to="/dashboard"
                className="px-4 py-2 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-all shadow-sm flex items-center gap-2 font-mono"
              >
                Go to Console <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            ) : (
              <>
                <Link
                  to="/login"
                  className="px-4 py-2 text-xs font-mono text-slate-300 hover:text-white transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="px-4 py-2 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-all shadow-sm flex items-center gap-1.5 font-mono"
                >
                  Start Securing Your Cloud <ChevronRight className="w-3.5 h-3.5" />
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* 2. Hero Section — Cinematic Composition: Left Copy (42%) / Right 3D Scene (58%) */}
      <section className="relative pt-12 pb-24 border-b border-[#172335] overflow-hidden">
        {/* Subtle architectural background with engineering grid lines */}
        <ArchitecturalBackground />

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
            
            {/* Left Column: Clear, Non-Overlapping Typography & CTAs (42-45% width) */}
            <div className="lg:col-span-5 space-y-6 text-left">
              {/* Eyebrow badge */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#0d1522] border border-[#1e2e44] text-slate-300 text-xs font-mono font-medium shadow-sm">
                <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
                <span className="text-cyan-300 font-bold uppercase tracking-wider">
                  CLOUD SECURITY POSTURE MANAGEMENT
                </span>
              </div>

              {/* Headline with restrained white + cyan typography */}
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white leading-[1.1]">
                Know Your <br />
                Cloud. <br />
                <span className="text-white">Control Your </span>
                <span className="text-cyan-400">Risk.</span>
              </h1>

              {/* Supporting Text */}
              <p className="text-base sm:text-lg text-slate-300 leading-relaxed font-normal">
                Continuously discover cloud assets, evaluate security configurations, measure posture, 
                and prioritize risk — through secure read-only AWS access.
              </p>

              {/* CTAs */}
              <div className="pt-2 space-y-4">
                <div className="flex flex-wrap items-center gap-4">
                  <Link
                    to={isAuthenticated ? "/dashboard" : "/register"}
                    className="px-7 py-3.5 rounded-lg font-semibold text-sm text-white bg-cyan-600 hover:bg-cyan-500 shadow-md transition-all flex items-center gap-2 group font-mono"
                  >
                    {isAuthenticated ? "OPEN CSPM CONSOLE" : "START SECURING YOUR CLOUD"}
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                  </Link>
                  <a
                    href="#pipeline"
                    className="px-7 py-3.5 rounded-lg font-semibold text-sm text-slate-300 bg-[#0d1420] hover:bg-[#131d2e] border border-[#203046] hover:border-slate-500 transition-all flex items-center gap-2 font-mono"
                  >
                    EXPLORE PLATFORM
                  </a>
                </div>

                {/* Subtext under buttons */}
                <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400 pt-1">
                  <span className="flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-cyan-400" />
                    READ-ONLY AWS
                  </span>
                  <span className="text-slate-600">&bull;</span>
                  <span className="flex items-center gap-1.5">
                    <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                    STS ASSUMEROLE
                  </span>
                  <span className="text-slate-600">&bull;</span>
                  <span className="flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    NO SECRET KEY STORAGE
                  </span>
                </div>
              </div>
            </div>

            {/* Right Column: Physical 3D Infrastructure Scene & Instruments (55-58% width) */}
            <div className="lg:col-span-7 relative">
              <Hero3DInfrastructure scrollYProgress={scrollYProgress} />
            </div>

          </div>
        </div>
      </section>

      {/* 3. 10-Stage 3D Enterprise Architecture Pipeline */}
      <Enterprise3DArchitecture />

      {/* 4. 6-Step End-to-End Lifecycle */}
      <HowItWorks3D />

      {/* 5. 3D Asset Explorer Cluster */}
      <AssetExplorer3D />

      {/* 6. Quantitative 3D Risk Stack */}
      <RiskStack3D />

      {/* 7. Regulatory Compliance Mappings */}
      <ComplianceCards3D />

      {/* 8. Enterprise Assurance Guarantees */}
      <SecurityGuarantees3D />

      {/* 9. Final Call to Action */}
      <section className="py-24 relative overflow-hidden bg-[#0a0f19] border-t border-b border-[#182638]">
        <div className="max-w-4xl mx-auto px-6 text-center space-y-7 relative z-10">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#111b2b] border border-[#22354c] text-cyan-300 text-xs font-mono uppercase tracking-wider">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            ENTERPRISE POSTURE AUDIT
          </div>

          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            See Your Cloud Security Posture
          </h2>

          <p className="text-slate-300 text-sm sm:text-base max-w-2xl mx-auto leading-relaxed">
            Connect your AWS account via cross-account IAM AssumeRole and evaluate your security 
            posture in minutes without giving up write access or storing secret keys.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-3">
            <Link
              to="/register"
              className="px-8 py-3.5 rounded-lg font-semibold text-sm text-white bg-cyan-600 hover:bg-cyan-500 shadow-md transition-all flex items-center gap-2 font-mono"
            >
              CREATE FREE ACCOUNT <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              to="/login"
              className="px-8 py-3.5 rounded-lg font-semibold text-sm text-slate-300 bg-[#0d1420] hover:bg-[#131e2e] border border-[#203046] hover:border-slate-500 transition-all font-mono"
            >
              SIGN IN
            </Link>
          </div>

          {/* Security Checklist */}
          <div className="pt-6 border-t border-[#182638] flex flex-wrap items-center justify-center gap-6 text-xs text-slate-400 font-mono">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              100% Read-only AWS access
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-cyan-400" />
              STS temporary credentials
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-purple-400" />
              External ID validation
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Zero secret keys stored
            </span>
          </div>
        </div>
      </section>

      {/* 10. Footer */}
      <footer className="border-t border-[#172335] bg-[#070b12] px-6 py-10 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="space-y-1.5 text-center md:text-left">
            <div className="flex items-center justify-center md:justify-start gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-white text-sm font-mono">
                ENTERPRISE CSPM
              </span>
            </div>
            <p className="text-[11px] text-slate-500 font-mono">
              Deterministic Cloud Security Posture Management &bull; AWS Read-Only &bull; CIS / NIST / ISO / PCI DSS
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-6 text-slate-400 font-mono text-[11px]">
            <a href="#pipeline" className="hover:text-cyan-300 transition-colors">Pipeline</a>
            <a href="#how-it-works" className="hover:text-cyan-300 transition-colors">Lifecycle</a>
            <a href="#assets" className="hover:text-cyan-300 transition-colors">Inventory</a>
            <a href="#risk-scoring" className="hover:text-cyan-300 transition-colors">Risk Scoring</a>
            <a href="#compliance" className="hover:text-cyan-300 transition-colors">Compliance</a>
            <a href="#security-guarantees" className="hover:text-cyan-300 transition-colors">Guarantees</a>
            <Link to="/login" className="hover:text-cyan-300 transition-colors">Login</Link>
            <Link to="/register" className="hover:text-cyan-300 transition-colors">Register</Link>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
