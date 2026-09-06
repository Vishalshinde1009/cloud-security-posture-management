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
  Zap
} from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';

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
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get<DashboardStats>('/dashboard/stats');
      setStats(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch dashboard statistics.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const triggerScan = async () => {
    try {
      setScanning(true);
      await api.post('/scans', {});
      await fetchStats();
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
        <Activity className="w-8 h-8 animate-spin text-blue-500" />
        <p className="text-sm text-gray-400 font-mono">Loading Security Posture Intelligence...</p>
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="rounded-xl border border-red-900/50 bg-red-950/20 p-6 text-center space-y-4">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto" />
        <h3 className="text-lg font-semibold text-white">Security Intelligence Unavailable</h3>
        <p className="text-sm text-gray-400">{error}</p>
        <button
          onClick={fetchStats}
          className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const comparison = stats?.comparison;
  const scoreDiff = comparison?.score_change ?? 0;

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

          <div className="flex items-center gap-3">
            <button
              onClick={fetchStats}
              disabled={loading}
              className="px-3 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 text-xs flex items-center gap-1.5 transition"
              title="Refresh Stats"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>

            {hasRole(['ADMIN', 'SECURITY_ANALYST']) && (
              <button
                onClick={triggerScan}
                disabled={scanning}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-2 shadow-lg shadow-blue-600/20 transition disabled:opacity-50"
              >
                <Radio className={`w-4 h-4 ${scanning ? 'animate-pulse text-yellow-300' : ''}`} />
                {scanning ? 'Running Posture Scan...' : 'Trigger Cloud Scan'}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Primary KPI Grid: Security Score + Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Security Posture Score Card */}
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-6 space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-blue-400" />
              Security Posture Score
            </span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-bold ${getRatingBadge(stats?.posture_rating || 'GOOD')}`}>
              {stats?.posture_rating || 'GOOD'}
            </span>
          </div>

          <div className="flex items-baseline gap-3">
            <span className={`text-4xl font-extrabold tracking-tight font-mono ${getScoreColor(stats?.security_score || 0)}`}>
              {stats?.security_score ?? '--'}
            </span>
            <span className="text-xs text-gray-500 font-mono">/ 100</span>

            {comparison?.has_previous_scan && (
              <div className={`ml-auto flex items-center text-xs font-semibold font-mono ${scoreDiff > 0 ? 'text-emerald-400' : scoreDiff < 0 ? 'text-red-400' : 'text-gray-400'}`}>
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

          <div className="pt-2 border-t border-gray-800 text-[11px] text-gray-400 flex items-center justify-between">
            <span>Scan Drift Baseline:</span>
            <span className="font-mono text-gray-200">
              {comparison?.has_previous_scan ? `${comparison.persistent_findings} persistent` : 'Initial Baseline'}
            </span>
          </div>
        </div>

        {/* Total Assets Scanned */}
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-6 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-emerald-400" />
              Discovered Inventory
            </span>
            <button 
              onClick={() => navigate('/resources')}
              className="text-[10px] text-blue-400 hover:underline flex items-center"
            >
              View Assets <ChevronRight className="w-3 h-3" />
            </button>
          </div>

          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-white font-mono">
              {stats?.total_resources ?? 0}
            </span>
            <span className="text-xs text-gray-400">monitored resources</span>
          </div>

          <div className="pt-2 border-t border-gray-800 text-[11px] text-gray-400 flex items-center justify-between">
            <span>Multi-Service Coverage:</span>
            <span className="text-emerald-400 font-medium">S3, IAM, EC2, VPC, CT, RDS</span>
          </div>
        </div>

        {/* Active Findings */}
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-6 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              Active Violations
            </span>
            <button 
              onClick={() => navigate('/findings')}
              className="text-[10px] text-blue-400 hover:underline flex items-center"
            >
              Inspect <ChevronRight className="w-3 h-3" />
            </button>
          </div>

          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-white font-mono">
              {stats?.total_findings ?? 0}
            </span>
            <span className="text-xs text-gray-400">unresolved issues</span>
          </div>

          <div className="pt-2 border-t border-gray-800 text-[11px] text-gray-400 flex items-center justify-between">
            <span>Critical Severity:</span>
            <span className="text-red-400 font-mono font-semibold">
              {stats?.severity_distribution.critical ?? 0} Critical
            </span>
          </div>
        </div>

        {/* Maximum Risk & Priority */}
        <div className="rounded-xl border border-gray-800 bg-[#111827] p-6 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
              <Flame className="w-4 h-4 text-red-400" />
              Peak Workload Risk
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-900/50">
              Avg: {stats?.risk_metrics.avg_risk ?? 0}/100
            </span>
          </div>

          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-red-400 font-mono">
              {stats?.risk_metrics.max_risk ?? 0}
            </span>
            <span className="text-xs text-gray-500 font-mono">/ 100 max risk</span>
          </div>

          <div className="pt-2 border-t border-gray-800 text-[11px] text-gray-400 flex items-center justify-between">
            <span>Immediate Actions:</span>
            <span className="text-red-400 font-mono font-bold">
              {stats?.priority_distribution.immediate ?? 0} Immediate
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
                <span className="font-mono text-gray-300">{stats?.severity_distribution.critical}</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="bg-red-500 h-2 rounded-full" 
                  style={{ width: `${stats?.total_findings ? (stats.severity_distribution.critical / stats.total_findings) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-orange-400 font-semibold">HIGH</span>
                <span className="font-mono text-gray-300">{stats?.severity_distribution.high}</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="bg-orange-500 h-2 rounded-full" 
                  style={{ width: `${stats?.total_findings ? (stats.severity_distribution.high / stats.total_findings) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-yellow-400 font-semibold">MEDIUM</span>
                <span className="font-mono text-gray-300">{stats?.severity_distribution.medium}</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="bg-yellow-500 h-2 rounded-full" 
                  style={{ width: `${stats?.total_findings ? (stats.severity_distribution.medium / stats.total_findings) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-blue-400 font-semibold">LOW</span>
                <span className="font-mono text-gray-300">{stats?.severity_distribution.low}</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div 
                  className="bg-blue-500 h-2 rounded-full" 
                  style={{ width: `${stats?.total_findings ? (stats.severity_distribution.low / stats.total_findings) * 100 : 0}%` }}
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
