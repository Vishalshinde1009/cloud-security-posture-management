import { useState, useEffect } from 'react';
import { Shield, Server, CheckCircle, AlertTriangle, Cloud, Activity, Terminal } from 'lucide-react';

interface HealthData {
  status: string;
  service: string;
  version: string;
  mode: string;
  environment: string;
}

function App() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/health')
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        setHealth(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100 flex flex-col font-sans">
      {/* Header */}
      <header className="border-b border-gray-800 bg-[#111827]/80 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600/20 border border-blue-500/30 rounded-lg text-blue-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              Cloud Security Posture Management
              <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono font-normal">
                CSPM v1.0
              </span>
            </h1>
            <p className="text-xs text-gray-400">Automated Misconfiguration Detection & Risk Assessment Platform</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-gray-800/80 border border-gray-700 text-xs">
            <Cloud className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-gray-400">Target Provider:</span>
            <span className="font-semibold text-white">AWS</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-gray-800/80 border border-gray-700 text-xs">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-gray-400">System Mode:</span>
            <span className="font-mono font-semibold text-emerald-400 uppercase">
              {health?.mode || 'MOCK'}
            </span>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        {/* Banner */}
        <div className="rounded-xl border border-blue-900/40 bg-gradient-to-r from-blue-950/40 via-indigo-950/20 to-gray-900/60 p-6">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs uppercase font-semibold tracking-wider text-blue-400 font-mono">
                  Final Year Cybersecurity Project
                </span>
                <span className="text-xs text-gray-400">•</span>
                <span className="text-xs text-emerald-400 font-mono">Phase 1 Architecture Initialized</span>
              </div>
              <h2 className="text-2xl font-bold text-white tracking-tight">
                Enterprise Cloud Security Posture Engine
              </h2>
              <p className="text-sm text-gray-300 max-w-3xl">
                Automated multi-service security scanner evaluating AWS S3, IAM, EC2, VPC, CloudTrail, and RDS against 
                CIS Benchmarks with explainable risk scoring and non-destructive read-only inspection.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-300">
                Safe Read-Only Scanner
              </span>
            </div>
          </div>
        </div>

        {/* Status Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Backend Health Card */}
          <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">FastAPI Backend</span>
              <Server className="w-4 h-4 text-blue-400" />
            </div>
            {loading ? (
              <div className="flex items-center gap-2 text-sm text-gray-400">
                <Activity className="w-4 h-4 animate-spin text-blue-400" /> Checking API connectivity...
              </div>
            ) : error ? (
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-red-400 text-sm font-medium">
                  <AlertTriangle className="w-4 h-4" /> API Offline or Proxy Connecting
                </div>
                <p className="text-xs text-gray-400 font-mono">{error}</p>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium">
                  <CheckCircle className="w-4 h-4" /> Connected & Healthy
                </div>
                <div className="text-xs space-y-1 font-mono text-gray-400">
                  <div>Service: <span className="text-gray-200">{health?.service}</span></div>
                  <div>Version: <span className="text-gray-200">{health?.version}</span></div>
                  <div>Environment: <span className="text-gray-200">{health?.environment}</span></div>
                </div>
              </div>
            )}
          </div>

          {/* Architecture Skeleton Card */}
          <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Security Engine</span>
              <Terminal className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="space-y-2">
              <div className="text-sm font-medium text-gray-200">6 Core AWS Services Target</div>
              <div className="flex flex-wrap gap-1.5">
                {['S3 Storage', 'IAM Identity', 'EC2 Compute', 'VPC Network', 'CloudTrail Audit', 'RDS Database'].map((svc) => (
                  <span key={svc} className="text-xs px-2 py-1 rounded bg-gray-800/80 border border-gray-700 text-gray-300 font-mono">
                    {svc}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Mode & Zero Trust Card */}
          <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Security Architecture</span>
              <Shield className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-xs space-y-2 text-gray-300">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                <span>Zero hardcoded credentials policy enforced</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                <span>Least-privilege read-only IAM auditing</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                <span>Explainable 0–100 mathematical risk scoring</span>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800/80 bg-[#0B0F19] px-6 py-4 text-center text-xs text-gray-400">
        Cloud Security Posture Management (CSPM) Platform • Academic Cybersecurity Project • Phase 1 Complete
      </footer>
    </div>
  );
}

export default App;
