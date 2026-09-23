import { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Flame, 
  Layers, 
  Radio, 
  ArrowUpRight, 
  ArrowDownRight, 
  Minus, 
  RefreshCw, 
  ChevronRight, 
  TrendingUp, 
  Clock, 
  Activity, 
  Zap,
  Cloud,
  Plus,
  CheckCircle,
  ShieldCheck,
  CheckCheck,
  AlertCircle,
  Bell
} from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { useCountUp } from '../hooks/useCountUp';
import {
  resolvePreferredAccountId,
  getStoredAccountId,
  setStoredAccountId,
  isAccountVerified,
  onAccountChanged,
  type CloudAccountOption,
} from '../utils/accountSelection';

interface DashboardStats {
  latest_scan_id: string | null;
  security_score: number;
  posture_rating: string;
  total_resources: number;
  total_findings: number;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  priority_distribution: {
    immediate: number;
    high: number;
    medium: number;
    low: number;
  };
  risk_metrics: {
    avg_risk: number;
    max_risk: number;
  };
  score_trend: Array<{
    id: string;
    date: string;
    score: number;
    rating: string;
    findings: number;
  }>;
  top_findings: Array<{
    id: string;
    title: string;
    severity: string;
    risk_score: number;
    risk_level: string;
    risk_priority: string;
    rule_code: string | null;
    service: string | null;
    resource_name: string | null;
    resource_identifier: string | null;
    explanation: string | null;
  }>;
  top_risky_resources: Array<{
    id: string;
    resource_id: string;
    resource_name: string;
    service: string;
    resource_type: string;
    security_status: string;
    open_findings_count: number;
    highest_risk_score: number;
  }>;
  comparison: {
    has_previous_scan: boolean;
    current_scan_id?: string;
    previous_scan_id?: string | null;
    score_change: number;
    risk_change: number;
    new_findings: number;
    resolved_findings: number;
    persistent_findings: number;
    previous_security_score?: number | null;
    current_security_score?: number | null;
    previous_posture_rating?: string | null;
    current_posture_rating?: string | null;
  };
}

export function Dashboard() {
  const { hasRole } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [accounts, setAccounts] = useState<CloudAccountOption[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<string>(getStoredAccountId());
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [alertSummary, setAlertSummary] = useState<{
    total_open: number;
    new_findings: number;
    risk_increases: number;
    resolved: number;
  } | null>(null);
  const [monitoringStatus, setMonitoringStatus] = useState<{
    enabled: boolean;
    next_scan_at: string | null;
    last_scan_at: string | null;
  } | null>(null);
  const [useDemo, setUseDemo] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem('cspm_use_demo') === 'true';
    } catch {
      return false;
    }
  });

  const realAccounts = accounts.filter(
    (a) => a.provider === 'AWS' && a.name.trim().toLowerCase() !== 'audit target'
  );

  const selectableAccounts = realAccounts.length > 0
    ? realAccounts
    : (useDemo ? accounts : []);

  const selectedAccount = accounts.find((a) => a.id === selectedAccountId);
  const isRoleAccount = selectedAccount?.provider === 'AWS' && selectedAccount?.credential_mode === 'ROLE';
  const isVerified = isAccountVerified(selectedAccount);

  // Hook calls MUST be called unconditionally at the top level before any early returns
  const comparison = stats?.comparison;
  const scoreDiff = comparison?.score_change ?? 0;
  const currentScore = stats?.security_score ?? 0;
  const animatedScore = useCountUp(currentScore, 1200, 1);
  const animatedResources = useCountUp(stats?.total_resources ?? 0, 900, 0);
  const animatedFindings = useCountUp(stats?.total_findings ?? 0, 900, 0);
  const animatedMaxRisk = useCountUp(stats?.risk_metrics?.max_risk ?? 0, 900, 0);

  const loadAccounts = async () => {
    try {
      const res = await api.get<any>('/cloud-accounts');
      const items: CloudAccountOption[] = Array.isArray(res.data) ? res.data : (res.data?.items || []);
      setAccounts(items);

      const realList = items.filter(
        (a) => a.provider === 'AWS' && a.name.trim().toLowerCase() !== 'audit target'
      );

      // If user has real accounts, never stick to demo mode
      if (realList.length > 0) {
        setUseDemo(false);
        try { sessionStorage.removeItem('cspm_use_demo'); } catch {}
      }

      const preferredId = resolvePreferredAccountId(items, getStoredAccountId());
      setSelectedAccountId(preferredId);
      const chosen = items.find((a) => a.id === preferredId);
      setStoredAccountId(preferredId, chosen);
    } catch {
      // Ignore
    }
  };

  useEffect(() => {
    loadAccounts();

    // Re-sync when returning from /cloud-accounts or switching tabs
    window.addEventListener('focus', loadAccounts);
    const unsubscribe = onAccountChanged((id) => {
      setSelectedAccountId(id);
    });

    return () => {
      window.removeEventListener('focus', loadAccounts);
      unsubscribe();
    };
  }, []);

  const fetchStats = async (accId?: string) => {
    try {
      setLoading(true);
      setError(null);
      const targetId = accId !== undefined ? accId : selectedAccountId;
      const url = targetId ? `/dashboard/stats?account_id=${encodeURIComponent(targetId)}` : '/dashboard/stats';
      const res = await api.get<DashboardStats>(url);
      setStats(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch dashboard statistics.');
    } finally {
      setLoading(false);
    }
  };

  const fetchAlertSummary = async (accountId?: string) => {
    try {
      const q = accountId ? `?cloud_account_id=${accountId}` : '';
      const res = await api.get(`/alerts/summary${q}`);
      setAlertSummary(res.data);
    } catch {
      // Ignore
    }
  };

  const fetchMonitoringStatus = async (accountId?: string) => {
    if (!accountId) {
      setMonitoringStatus(null);
      return;
    }
    try {
      const res = await api.get(`/monitoring/${accountId}`);
      setMonitoringStatus({
        enabled: res.data.enabled,
        next_scan_at: res.data.next_scan_at ?? null,
        last_scan_at: res.data.last_scan_at ?? null,
      });
    } catch {
      setMonitoringStatus(null);
    }
  };

  useEffect(() => {
    if (selectedAccountId) {
      fetchStats(selectedAccountId);
      fetchAlertSummary(selectedAccountId);
      fetchMonitoringStatus(selectedAccountId);
    } else {
      fetchStats();
      fetchAlertSummary();
      setMonitoringStatus(null);
    }
  }, [selectedAccountId]);

  const triggerScan = async () => {
    if (!selectedAccountId) {
      alert('Please select or connect a cloud account target before triggering a scan.');
      return;
    }

    if (isRoleAccount && !isVerified) {
      alert('Please test and verify live AWS connection on the Cloud Accounts page before running scans.');
      navigate('/cloud-accounts');
      return;
    }

    try {
      setScanning(true);
      const payload = {
        account_id: selectedAccountId,
        cloud_account_id: selectedAccountId,
      };
      await api.post('/scans', payload);
      await fetchStats(selectedAccountId);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to trigger cloud scan.');
    } finally {
      setScanning(false);
    }
  };

  const getRatingBadge = (rating: string) => {
    switch (rating.toUpperCase()) {
      case 'EXCELLENT':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'GOOD':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'MODERATE':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      case 'POOR':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'CRITICAL':
      default:
        return 'bg-red-500/10 text-red-400 border-red-500/30';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-400';
    if (score >= 75) return 'text-blue-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const getPriorityBadge = (priority: string) => {
    switch (priority.toUpperCase()) {
      case 'IMMEDIATE':
        return 'bg-red-500/20 text-red-300 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
      case 'LOW':
      default:
        return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
    }
  };

  if (loading && !stats) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] space-y-3">
        <Activity className="w-8 h-8 animate-spin text-cyan-400" />
        <p className="text-sm text-slate-400 font-mono">Loading Security Posture Intelligence...</p>
      </div>
    );
  }

  // Onboarding Empty State: Zero real cloud accounts and not using demo environment
  if (!loading && realAccounts.length === 0 && !useDemo) {
    return (
      <div className="space-y-6">
        {/* Onboarding Empty State Hero */}
        <div className="rounded-2xl border border-blue-500/30 bg-gradient-to-r from-blue-950/60 via-slate-900 to-indigo-950/40 p-8 shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
            <Shield className="w-64 h-64 text-blue-400" />
          </div>

          <div className="max-w-2xl space-y-4 relative z-10">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">
                ONBOARDING
              </span>
              <span className="text-xs text-cyan-400 font-mono">Step 1: Connect Target</span>
            </div>

            <h1 className="text-3xl font-extrabold text-white tracking-tight">
              No AWS account connected
            </h1>

            <p className="text-base text-slate-300 leading-relaxed">
              Connect a read-only AWS account using STS AssumeRole to begin cloud posture assessment.
            </p>

            <div className="pt-2 flex flex-wrap items-center gap-4">
              <button
                onClick={() => navigate('/cloud-accounts')}
                className="px-5 py-3 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-bold text-sm flex items-center gap-2 shadow-xl shadow-blue-600/30 transition transform hover:-translate-y-0.5"
              >
                <Plus className="w-4 h-4" />
                + Connect AWS Account
              </button>

              <button
                onClick={() => {
                  setUseDemo(true);
                  try {
                    sessionStorage.setItem('cspm_use_demo', 'true');
                  } catch {}
                  const mockAcc = accounts.find((a) => a.provider === 'MOCK' || a.name.toLowerCase() === 'audit target');
                  if (mockAcc) {
                    setSelectedAccountId(mockAcc.id);
                    setStoredAccountId(mockAcc.id, mockAcc);
                  }
                }}
                className="px-4 py-3 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 text-sm font-medium transition"
              >
                Use Demo Environment
              </button>
            </div>
          </div>
        </div>

        {/* 3-Step Integration Guide */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center font-bold text-sm font-mono">
              1
            </div>
            <h4 className="text-sm font-semibold text-white">Register AWS Target</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Specify your 12-digit AWS Account ID and primary operating region to generate a cryptographically unique External ID.
            </p>
          </div>

          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold text-sm font-mono">
              2
            </div>
            <h4 className="text-sm font-semibold text-white">STS AssumeRole Setup</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Create an IAM Role using the provided one-click trust policy. Read-only permissions guarantee zero mutation of AWS resources.
            </p>
          </div>

          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center font-bold text-sm font-mono">
              3
            </div>
            <h4 className="text-sm font-semibold text-white">Automated Posture Audit</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Audit IAM, S3, EC2, RDS, and CloudTrail across 26 security rules, compliance framework mappings, and risk priorities.
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="rounded-xl border border-red-900/50 bg-red-950/20 p-6 text-center space-y-4">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto" />
        <h3 className="text-lg font-semibold text-white">Security Intelligence Unavailable</h3>
        <p className="text-sm text-slate-400">{error}</p>
        <button
          onClick={() => fetchStats()}
          className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 text-center space-y-4">
        <Activity className="w-8 h-8 text-cyan-400 mx-auto" />
        <h3 className="text-lg font-semibold text-white">No Security Intelligence Data</h3>
        <p className="text-sm text-slate-400">Please run a scan or register a cloud account to evaluate posture.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner & Scan Action */}
      <div className="rounded-xl border border-blue-900/40 bg-gradient-to-r from-blue-950/40 via-indigo-950/20 to-gray-900/60 p-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase font-semibold tracking-wider text-blue-400 font-mono">
                Executive Security Console
              </span>
              <span className="text-xs text-gray-400">&bull;</span>
              <span className="text-xs text-emerald-400 font-mono">Continuous Posture Evaluation</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              Cloud Security Posture Intelligence
            </h2>
            <p className="text-sm text-gray-300 max-w-2xl">
              Deterministic, explainable risk calculations assessing asset exposure, exploitability, and sensitivity across discovered cloud workloads.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-3 w-full md:w-auto">
            {/* Target Account Selector */}
            {selectableAccounts.length > 0 && (
              <div className="flex items-center gap-2 bg-slate-800/90 px-3 py-1.5 rounded-lg border border-slate-700">
                <span className="text-xs text-slate-400 font-medium whitespace-nowrap">Target Account:</span>
                <select
                  value={selectedAccountId}
                  onChange={(e) => {
                    setSelectedAccountId(e.target.value);
                    const chosen = accounts.find((a) => a.id === e.target.value);
                    setStoredAccountId(e.target.value, chosen);
                  }}
                  className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded px-2.5 py-1 focus:outline-none focus:border-cyan-500 font-sans cursor-pointer max-w-[220px] truncate"
                >
                  {selectableAccounts.map((acc) => (
                    <option key={acc.id} value={acc.id}>
                      {acc.name} • {acc.default_region || 'us-east-1'}{acc.provider === 'MOCK' ? ' (Demo)' : ''}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* + Connect AWS Account Button */}
            <button
              onClick={() => navigate('/cloud-accounts')}
              className="px-3.5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-semibold flex items-center justify-center gap-1.5 shadow-md shadow-blue-600/20 border border-cyan-400/30 transition shrink-0"
              title="Add or configure an AWS account using STS AssumeRole"
            >
              <Cloud className="w-4 h-4 text-cyan-300" />
              + Connect AWS Account
            </button>

            {/* Refresh Button */}
            <button
              onClick={() => fetchStats()}
              disabled={loading}
              className="px-3 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 text-xs flex items-center justify-center gap-1.5 transition shrink-0"
              title="Refresh Stats"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>

            {/* Scan Action */}
            {hasRole(['ADMIN', 'SECURITY_ANALYST']) && (
              isRoleAccount && !isVerified ? (
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    disabled
                    className="px-3.5 py-2 rounded-lg bg-slate-800/90 text-slate-400 border border-slate-700 text-xs font-semibold flex items-center gap-2 opacity-60 cursor-not-allowed"
                    title="Please verify live AWS STS connection before running scans"
                  >
                    <AlertCircle className="w-4 h-4 text-amber-400" />
                    Test AWS Connection First
                  </button>
                  <button
                    onClick={() => navigate('/cloud-accounts')}
                    className="px-3 py-2 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-semibold flex items-center gap-1 transition underline"
                  >
                    Test Connection &rarr;
                  </button>
                </div>
              ) : (
                <button
                  onClick={triggerScan}
                  disabled={scanning}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 transition disabled:opacity-50 shrink-0"
                >
                  <Radio className={`w-4 h-4 ${scanning ? 'animate-pulse text-yellow-300' : ''}`} />
                  {scanning ? 'Running Posture Scan...' : 'Trigger Cloud Scan'}
                </button>
              )
            )}
          </div>
        </div>

        {/* Connected Target Status Card */}
        {selectedAccount && selectedAccount.provider === 'AWS' && selectedAccount.credential_mode === 'ROLE' ? (
          <div className="mt-4 pt-4 border-t border-blue-900/30 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-950/60 border border-blue-800 text-blue-300 font-mono text-[11px]">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-gray-400 uppercase tracking-wider font-semibold">CONNECTED TARGET:</span>
                <span className="font-bold text-white text-xs">{selectedAccount.name}</span>
                <span className="px-1.5 py-0.5 rounded bg-blue-900/60 text-cyan-300 text-[10px]">
                  AWS • ROLE • {selectedAccount.default_region || 'us-east-1'}
                </span>
              </div>

              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[11px] font-mono">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                STS AssumeRole
              </span>
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[11px] font-mono font-bold uppercase tracking-wider">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                Read-Only Access
              </span>
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-[11px] font-mono">
                <CheckCheck className="w-3.5 h-3.5 text-cyan-400" />
                External ID Verified
              </span>

              <button
                onClick={() => navigate('/cloud-accounts')}
                className="text-cyan-400 hover:text-cyan-300 hover:underline text-[11px] font-medium transition ml-1"
              >
                Configure Target &rarr;
              </button>
            </div>
            <div className="text-gray-400 text-[11px] font-mono">
              Zero Mutating Actions &bull; Least-Privilege Assumed Role &bull; No Secret Storage
            </div>
          </div>
        ) : selectedAccount && selectedAccount.provider === 'AWS' ? (
          <div className="mt-4 pt-4 border-t border-blue-900/30 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-950/60 border border-blue-800 text-blue-300 font-mono text-[11px]">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                <span className="text-gray-400 uppercase tracking-wider font-semibold">CONNECTED TARGET:</span>
                <span className="font-bold text-white text-xs">{selectedAccount.name}</span>
                <span className="px-1.5 py-0.5 rounded bg-blue-900/60 text-cyan-300 text-[10px]">
                  AWS • ENVIRONMENT • {selectedAccount.default_region || 'us-east-1'}
                </span>
              </div>
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[11px] font-mono font-bold uppercase tracking-wider">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                Read-Only Access
              </span>
              <button
                onClick={() => navigate('/cloud-accounts')}
                className="text-cyan-400 hover:text-cyan-300 hover:underline text-[11px] font-medium transition ml-1"
              >
                Configure Target &rarr;
              </button>
            </div>
            <div className="text-gray-400 text-[11px] font-mono">
              Zero Mutating Actions &bull; Instance Metadata Credentials &bull; No Secret Storage
            </div>
          </div>
        ) : (
          <div className="mt-4 pt-4 border-t border-amber-900/30 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-950/40 border border-amber-800/60 text-amber-300 font-mono text-[11px]">
                <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                <span className="text-amber-400 uppercase tracking-wider font-semibold">DEMO TARGET:</span>
                <span className="font-bold text-white text-xs">{selectedAccount?.name || 'Mock Environment'}</span>
                <span className="px-1.5 py-0.5 rounded bg-amber-900/40 text-amber-300 text-[10px]">
                  Simulated Environment
                </span>
              </div>

              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 text-[11px] font-mono">
                Synthetic Telemetry
              </span>

              <button
                onClick={() => navigate('/cloud-accounts')}
                className="text-cyan-400 hover:text-cyan-300 hover:underline text-[11px] font-medium transition ml-1"
              >
                + Connect Real AWS Account &rarr;
              </button>
            </div>
            <div className="text-amber-400/80 text-[11px] font-mono">
              Demo Mode: Synthetic assets and sample findings for platform demonstration only.
            </div>
          </div>
        )}
      </div>

      {/* Primary KPI Grid: Security Score + Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Security Posture Score Card with Radial Gauge */}
        <div className="rounded-2xl border border-slate-800/80 bg-slate-900/80 backdrop-blur-md p-6 space-y-4 relative overflow-hidden shadow-xl hover:border-cyan-500/40 transition-all group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-cyan-400" />
              Security Posture Score
            </span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-bold ${getRatingBadge(stats?.posture_rating || 'GOOD')}`}>
              {stats?.posture_rating || 'GOOD'}
            </span>
          </div>

          <div className="flex items-center gap-4">
            {/* Radial Circular Meter */}
            <div className="relative w-16 h-16 flex-shrink-0 flex items-center justify-center">
              <svg className="w-16 h-16 -rotate-90 transform" viewBox="0 0 64 64">
                <circle
                  cx="32"
                  cy="32"
                  r="26"
                  stroke="currentColor"
                  strokeWidth="5"
                  className="text-slate-800"
                  fill="transparent"
                />
                <circle
                  cx="32"
                  cy="32"
                  r="26"
                  stroke="currentColor"
                  strokeWidth="5"
                  strokeDasharray={163.36}
                  strokeDashoffset={163.36 - (currentScore / 100) * 163.36}
                  strokeLinecap="round"
                  className={`transition-all duration-1000 ease-out ${
                    currentScore >= 80 ? 'text-emerald-400' :
                    currentScore >= 60 ? 'text-cyan-400' :
                    currentScore >= 40 ? 'text-amber-400' : 'text-rose-500'
                  }`}
                  fill="transparent"
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-[10px] font-mono font-bold text-slate-400">%</span>
              </div>
            </div>

            <div>
              <div className="flex items-baseline gap-2">
                <span className={`text-3xl font-extrabold tracking-tight font-mono ${getScoreColor(currentScore)}`}>
                  {stats ? animatedScore : '--'}
                </span>
                <span className="text-xs text-slate-500 font-mono">/ 100</span>
              </div>
              {comparison?.has_previous_scan && (
                <div className={`flex items-center text-xs font-semibold font-mono mt-1 ${scoreDiff > 0 ? 'text-emerald-400' : scoreDiff < 0 ? 'text-red-400' : 'text-slate-400'}`}>
                  {scoreDiff > 0 ? (
                    <ArrowUpRight className="w-3.5 h-3.5 mr-0.5" />
                  ) : scoreDiff < 0 ? (
                    <ArrowDownRight className="w-3.5 h-3.5 mr-0.5" />
                  ) : (
                    <Minus className="w-3.5 h-3.5 mr-0.5" />
                  )}
                  {scoreDiff > 0 ? `+${scoreDiff}` : scoreDiff} pts
                </div>
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400 flex flex-col gap-1">
            <div className="flex items-center justify-between">
              <span>Comparison:</span>
              <span className="font-mono text-slate-200">
                {comparison?.has_previous_scan
                  ? `Prev: ${comparison.previous_security_score ?? '--'} \u2192 Curr: ${comparison.current_security_score ?? stats?.security_score}`
                  : 'Baseline assessment'}
              </span>
            </div>
            {comparison?.has_previous_scan && (
              <div className="flex items-center justify-between text-[10px] text-slate-500">
                <span>Delta:</span>
                <span>+{comparison.new_findings} new &bull; {comparison.resolved_findings} fixed</span>
              </div>
            )}
          </div>
        </div>

        {/* Total Assets Scanned */}
        <div className="rounded-2xl border border-slate-800/80 bg-slate-900/80 backdrop-blur-md p-6 space-y-4 shadow-xl hover:border-emerald-500/40 transition-all group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-emerald-400" />
              Discovered Inventory
            </span>
            <button 
              onClick={() => navigate('/resources')}
              className="text-[10px] text-cyan-400 hover:text-cyan-300 font-medium hover:underline flex items-center"
            >
              View Assets <ChevronRight className="w-3 h-3" />
            </button>
          </div>

          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-white font-mono">
              {stats ? animatedResources : 0}
            </span>
            <span className="text-xs text-slate-400">monitored resources</span>
          </div>

          <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Multi-Service Scope:</span>
            <span className="text-emerald-400 font-medium">S3, IAM, EC2, VPC, CT, RDS</span>
          </div>
        </div>

        {/* Active Findings */}
        <div className="rounded-2xl border border-slate-800/80 bg-slate-900/80 backdrop-blur-md p-6 space-y-4 shadow-xl hover:border-amber-500/40 transition-all group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Active Violations
            </span>
            <button 
              onClick={() => navigate('/findings')}
              className="text-[10px] text-cyan-400 hover:text-cyan-300 font-medium hover:underline flex items-center"
            >
              Inspect <ChevronRight className="w-3 h-3" />
            </button>
          </div>

          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-white font-mono">
              {stats ? animatedFindings : 0}
            </span>
            <span className="text-xs text-slate-400">unresolved issues</span>
          </div>

          <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Critical Severity:</span>
            <span className="text-rose-400 font-mono font-semibold">
              {stats?.severity_distribution.critical ?? 0} Critical
            </span>
          </div>
        </div>

        {/* Maximum Risk & Priority */}
        <div className="rounded-2xl border border-slate-800/80 bg-slate-900/80 backdrop-blur-md p-6 space-y-4 shadow-xl hover:border-rose-500/40 transition-all group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Flame className="w-4 h-4 text-rose-400" />
              Peak Workload Risk
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/40 text-rose-300 border border-rose-900/50">
              Avg: {stats?.risk_metrics.avg_risk ?? 0}/100
            </span>
          </div>

          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-rose-400 font-mono">
              {stats ? animatedMaxRisk : 0}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100 max risk</span>
          </div>

          <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Immediate Actions:</span>
            <span className="text-rose-400 font-mono font-bold">
              {stats?.priority_distribution.immediate ?? 0} Immediate
            </span>
          </div>
        </div>
      </div>

      {/* Continuous Monitoring & Security Alerts Summary */}
      <div className="rounded-2xl border border-slate-800/80 bg-slate-900/70 backdrop-blur-md p-5 shadow-xl space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bell className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Continuous Monitoring &amp; Security Alerts
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              Live Drift Detection
            </span>
          </div>
          <div className="flex items-center gap-2">
            {/* Monitoring Status Badge */}
            {monitoringStatus?.enabled ? (
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-mono font-bold uppercase">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse inline-block" />
                  Monitoring: ACTIVE
                </span>
                {monitoringStatus.next_scan_at && (
                  <span className="text-[10px] text-slate-400 font-mono hidden sm:inline">
                    Next: {new Date(monitoringStatus.next_scan_at).toLocaleTimeString()}
                  </span>
                )}
              </div>
            ) : selectedAccountId ? (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 text-slate-400 border border-slate-700 text-[10px] font-mono uppercase">
                Monitoring: OFF
              </span>
            ) : null}
            <button
              onClick={() => navigate('/alerts')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium hover:underline flex items-center gap-1"
            >
              Alert Center &rarr;
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
          {/* OPEN ALERTS */}
          <div
            onClick={() => navigate('/alerts?status=OPEN')}
            className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/50 hover:border-slate-700 cursor-pointer transition"
          >
            <span className="text-[10px] font-mono font-semibold text-slate-400 uppercase tracking-wider block">
              OPEN ALERTS
            </span>
            <span className="text-2xl font-extrabold text-white font-mono mt-1 block">
              {alertSummary?.total_open ?? 0}
            </span>
          </div>

          {/* NEW FINDINGS */}
          <div
            onClick={() => navigate('/alerts?type=NEW_FINDING')}
            className="p-3.5 rounded-xl border border-rose-900/30 bg-rose-950/20 hover:border-rose-800/50 cursor-pointer transition"
          >
            <span className="text-[10px] font-mono font-semibold text-rose-400 uppercase tracking-wider block">
              NEW FINDINGS
            </span>
            <span className="text-2xl font-extrabold text-rose-400 font-mono mt-1 block">
              {alertSummary?.new_findings ?? 0}
            </span>
          </div>

          {/* RISK INCREASES */}
          <div
            onClick={() => navigate('/alerts?type=RISK_INCREASED')}
            className="p-3.5 rounded-xl border border-amber-900/30 bg-amber-950/20 hover:border-amber-800/50 cursor-pointer transition"
          >
            <span className="text-[10px] font-mono font-semibold text-amber-400 uppercase tracking-wider block">
              RISK INCREASES
            </span>
            <span className="text-2xl font-extrabold text-amber-400 font-mono mt-1 block">
              {alertSummary?.risk_increases ?? 0}
            </span>
          </div>

          {/* RESOLVED */}
          <div
            onClick={() => navigate('/alerts?status=RESOLVED')}
            className="p-3.5 rounded-xl border border-emerald-900/30 bg-emerald-950/20 hover:border-emerald-800/50 cursor-pointer transition"
          >
            <span className="text-[10px] font-mono font-semibold text-emerald-400 uppercase tracking-wider block">
              RESOLVED
            </span>
            <span className="text-2xl font-extrabold text-emerald-400 font-mono mt-1 block">
              {alertSummary?.resolved ?? 0}
            </span>
          </div>
        </div>
      </div>

      {/* Distribution & History Charts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              Rule Severity Breakdown
            </span>
            <span className="text-xs text-gray-500 font-mono">{stats?.total_findings} total</span>
          </div>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-red-400 font-semibold">CRITICAL</span>
                <span className="font-mono text-gray-300">{stats?.severity_distribution?.critical ?? 0}</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="bg-red-500 h-2 rounded-full" 
                  style={{ width: `${stats?.total_findings ? ((stats?.severity_distribution?.critical ?? 0) / stats.total_findings) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-orange-400 font-semibold">HIGH</span>
                <span className="font-mono text-gray-300">{stats?.severity_distribution?.high ?? 0}</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="bg-orange-500 h-2 rounded-full" 
                  style={{ width: `${stats?.total_findings ? ((stats?.severity_distribution?.high ?? 0) / stats.total_findings) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-yellow-400 font-semibold">MEDIUM</span>
                <span className="font-mono text-gray-300">{stats?.severity_distribution?.medium ?? 0}</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="bg-yellow-500 h-2 rounded-full" 
                  style={{ width: `${stats?.total_findings ? ((stats?.severity_distribution?.medium ?? 0) / stats.total_findings) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-blue-400 font-semibold">LOW</span>
                <span className="font-mono text-gray-300">{stats?.severity_distribution?.low ?? 0}</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="bg-blue-500 h-2 rounded-full" 
                  style={{ width: `${stats?.total_findings ? ((stats?.severity_distribution?.low ?? 0) / stats.total_findings) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Priority Distribution */}
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <Zap className="w-4 h-4 text-blue-400" />
              Remediation Priorities
            </span>
            <span className="text-xs text-gray-500 font-mono">Action Queues</span>
          </div>

          <div className="grid grid-cols-2 gap-3 pt-2">
            <div className="p-3 rounded-lg bg-red-950/20 border border-red-900/30">
              <div className="text-[10px] uppercase font-mono text-red-400 font-bold">IMMEDIATE</div>
              <div className="text-2xl font-extrabold text-white font-mono mt-1">
                {stats?.priority_distribution.immediate ?? 0}
              </div>
              <div className="text-[10px] text-gray-400 mt-1">Direct exploit risk</div>
            </div>

            <div className="p-3 rounded-lg bg-orange-950/20 border border-orange-900/30">
              <div className="text-[10px] uppercase font-mono text-orange-400 font-bold">HIGH</div>
              <div className="text-2xl font-extrabold text-white font-mono mt-1">
                {stats?.priority_distribution.high ?? 0}
              </div>
              <div className="text-[10px] text-gray-400 mt-1">Critical defense gaps</div>
            </div>

            <div className="p-3 rounded-lg bg-yellow-950/20 border border-yellow-900/30">
              <div className="text-[10px] uppercase font-mono text-yellow-400 font-bold">MEDIUM</div>
              <div className="text-2xl font-extrabold text-white font-mono mt-1">
                {stats?.priority_distribution.medium ?? 0}
              </div>
              <div className="text-[10px] text-gray-400 mt-1">Internal deviations</div>
            </div>

            <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-900/30">
              <div className="text-[10px] uppercase font-mono text-blue-400 font-bold">LOW</div>
              <div className="text-2xl font-extrabold text-white font-mono mt-1">
                {stats?.priority_distribution.low ?? 0}
              </div>
              <div className="text-[10px] text-gray-400 mt-1">Hygiene / Logging</div>
            </div>
          </div>
        </div>

        {/* Historical Score Trend */}
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-emerald-400" />
              Posture Score Trend
            </span>
            <span className="text-xs text-gray-500 font-mono">Recent Scans</span>
          </div>

          <div className="space-y-2.5 pt-1">
            {stats?.score_trend && stats.score_trend.length > 0 ? (
              stats.score_trend.map((point, idx) => (
                <div key={point.id || idx} className="flex items-center justify-between text-xs py-1 border-b border-gray-800/50 last:border-0">
                  <div className="flex items-center gap-2">
                    <Clock className="w-3.5 h-3.5 text-gray-500" />
                    <span className="font-mono text-gray-300">
                      {new Date(point.date).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] font-mono text-gray-400">{point.findings} findings</span>
                    <span className={`font-mono font-bold ${getScoreColor(point.score)}`}>
                      {point.score}%
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-xs text-gray-500 py-6 text-center">No prior scan history recorded.</div>
            )}
          </div>
        </div>
      </div>

      {/* Tables: Top Riskiest Assets & Highest Risk Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Highest Risk Findings */}
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <Flame className="w-4 h-4 text-red-400" />
              Highest-Risk Findings
            </span>
            <button 
              onClick={() => navigate('/findings')}
              className="text-xs text-blue-400 hover:underline flex items-center gap-1"
            >
              All Findings <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {stats?.top_findings && stats.top_findings.length > 0 ? (
              stats.top_findings.map((f) => (
                <div 
                  key={f.id}
                  onClick={() => navigate('/findings')}
                  className="p-3 rounded-lg bg-gray-900/60 border border-gray-800 hover:border-gray-700 transition cursor-pointer space-y-2"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 font-semibold">
                          {f.rule_code || 'RULE'}
                        </span>
                        <span className="text-[10px] font-mono text-blue-400 uppercase">
                          {f.service}
                        </span>
                      </div>
                      <h4 className="text-xs font-semibold text-gray-200 line-clamp-1">{f.title}</h4>
                    </div>

                    <div className="text-right">
                      <div className="flex items-center gap-1.5 justify-end">
                        <span className="text-sm font-extrabold font-mono text-red-400">{f.risk_score}</span>
                        <span className="text-[10px] text-gray-500 font-mono">/100</span>
                      </div>
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase font-bold ${getPriorityBadge(f.risk_priority)}`}>
                        {f.risk_priority}
                      </span>
                    </div>
                  </div>

                  {f.explanation && (
                    <p className="text-[11px] text-gray-400 line-clamp-2 italic">
                      "{f.explanation}"
                    </p>
                  )}
                </div>
              ))
            ) : (
              <div className="text-xs text-gray-500 py-8 text-center">No open security violations detected.</div>
            )}
          </div>
        </div>

        {/* Top Risky Cloud Resources */}
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4 text-orange-400" />
              Highest-Exposure Cloud Resources
            </span>
            <button 
              onClick={() => navigate('/resources')}
              className="text-xs text-blue-400 hover:underline flex items-center gap-1"
            >
              Inventory <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {stats?.top_risky_resources && stats.top_risky_resources.length > 0 ? (
              stats.top_risky_resources.map((r) => (
                <div 
                  key={r.id}
                  onClick={() => navigate('/resources')}
                  className="p-3 rounded-lg bg-gray-900/60 border border-gray-800 hover:border-gray-700 transition cursor-pointer space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-950/40 border border-blue-900/40 text-blue-400 font-semibold">
                        {r.service}
                      </span>
                      <span className="text-xs font-semibold text-white font-mono">{r.resource_name}</span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border uppercase font-bold ${
                      r.security_status === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border-red-500/30' : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                    }`}>
                      {r.security_status}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-gray-400 pt-1">
                    <span className="font-mono text-gray-500 truncate max-w-[240px]">{r.resource_id}</span>
                    <div className="flex items-center gap-3">
                      <span>{r.open_findings_count} open violations</span>
                      <span className="font-mono text-red-400 font-semibold">Peak Risk: {r.highest_risk_score}</span>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-xs text-gray-500 py-8 text-center">All inventory assets are evaluated as SECURE.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
