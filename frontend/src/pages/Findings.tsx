import { useState, useEffect, FormEvent } from 'react';
import api from '../services/api';
import { Finding, FindingListResponse } from '../types/finding';
import { 
  RefreshCw, 
  X, 
  AlertTriangle, 
  Info, 
  CheckCircle2, 
  Sliders, 
  Code
} from 'lucide-react';
import { resolvePreferredAccountId, getStoredAccountId, setStoredAccountId } from '../utils/accountSelection';

interface CloudAccountOption {
  id: string;
  name: string;
  provider: string;
  is_active?: boolean;
  role_arn?: string | null;
  credential_mode?: string;
  account_identifier?: string;
}

export const Findings = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [accounts, setAccounts] = useState<CloudAccountOption[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<string>(getStoredAccountId());
  const [systemMode, setSystemMode] = useState<string>('mock');
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedRiskLevel, setSelectedRiskLevel] = useState<string>('');
  const [selectedPriority, setSelectedPriority] = useState<string>('');
  const [selectedStatus, setSelectedStatus] = useState<string>('OPEN');
  const [selectedService, setSelectedService] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Inspector
  const [inspectingFinding, setInspectingFinding] = useState<Finding | null>(null);
  const [inspectingLoading, setInspectingLoading] = useState<boolean>(false);

  const services = ['S3', 'IAM', 'EC2', 'VPC', 'CloudTrail', 'RDS'];

  useEffect(() => {
    // Fetch backend system mode
    api.get<{ mode: string }>('/health')
      .then((res) => {
        if (res.data?.mode) {
          setSystemMode(res.data.mode.toLowerCase());
        }
      })
      .catch(() => {});

    // Fetch cloud accounts for targeting
    api.get<any>('/cloud-accounts')
      .then((res) => {
        const items: CloudAccountOption[] = Array.isArray(res.data) ? res.data : (res.data?.items || []);
        setAccounts(items);
        const preferredId = resolvePreferredAccountId(items, getStoredAccountId());
        setSelectedAccountId(preferredId);
        setStoredAccountId(preferredId);
      })
      .catch(() => {});
  }, []);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      setError(null);
      let query = '/findings?limit=50';
      if (selectedAccountId) query += `&account_id=${encodeURIComponent(selectedAccountId)}`;
      if (selectedSeverity) query += `&severity=${encodeURIComponent(selectedSeverity)}`;
      if (selectedRiskLevel) query += `&risk_level=${encodeURIComponent(selectedRiskLevel)}`;
      if (selectedPriority) query += `&risk_priority=${encodeURIComponent(selectedPriority)}`;
      if (selectedStatus) query += `&status=${encodeURIComponent(selectedStatus)}`;
      if (selectedService) query += `&service=${encodeURIComponent(selectedService)}`;
      if (searchTerm) query += `&search=${encodeURIComponent(searchTerm)}`;

      const res = await api.get<FindingListResponse>(query);
      setFindings(res.data.items);
      setTotalCount(res.data.total);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load security findings.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [selectedAccountId, selectedSeverity, selectedRiskLevel, selectedPriority, selectedStatus, selectedService]);

  const handleSearchSubmit = (e: FormEvent) => {
    e.preventDefault();
    fetchFindings();
  };

  const handleInspect = async (f: Finding) => {
    try {
      setInspectingLoading(true);
      const detail = await api.get<Finding>(`/findings/${f.id}`);
      setInspectingFinding(detail.data);
    } catch (err: any) {
      setError('Failed to fetch detailed finding configuration evidence.');
    } finally {
      setInspectingLoading(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/70 text-rose-300 border border-rose-800/80 font-mono">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950/70 text-orange-300 border border-orange-800/80 font-mono">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-yellow-950/60 text-yellow-300 border border-yellow-800/70 font-mono">
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-blue-950/60 text-blue-300 border border-blue-800/70 font-mono">
            LOW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">
            {severity}
          </span>
        );
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 90) return 'text-rose-400';
    if (score >= 70) return 'text-orange-400';
    if (score >= 40) return 'text-yellow-400';
    return 'text-blue-400';
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white">Security Misconfiguration Findings</h1>
            {accounts.find(a => a.id === selectedAccountId)?.provider === 'AWS' || (!selectedAccountId && systemMode === 'aws') ? (
              <span className="px-2.5 py-1 text-xs font-mono font-semibold uppercase tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded-md flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                AWS FINDINGS
              </span>
            ) : (
              <span className="px-2.5 py-1 text-xs font-mono font-semibold uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 rounded-md">
                MOCK FINDINGS
              </span>
            )}
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Real-time evidence-backed misconfigurations evaluated across 6 risk dimensions with explainable scoring.
            {totalCount !== null && (
              <span className="ml-2 font-mono text-xs text-blue-400 font-semibold">({totalCount} Total Issues Identified)</span>
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {accounts.length > 0 && (
            <div className="flex items-center gap-2 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
              <span className="text-xs text-slate-400 font-medium">Target Account:</span>
              <select
                value={selectedAccountId}
                onChange={(e) => {
                  setSelectedAccountId(e.target.value);
                  setStoredAccountId(e.target.value);
                }}
                className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded px-2 py-1 focus:outline-none focus:border-blue-500 font-sans"
              >
                {accounts.map((acc) => (
                  <option key={acc.id} value={acc.id}>
                    {acc.name} ({acc.provider})
                  </option>
                ))}
              </select>
            </div>
          )}

          <button
            onClick={fetchFindings}
            disabled={loading}
            className="px-3.5 py-2 text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 self-start md:self-auto"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Findings
          </button>
        </div>
      </div>

      {/* Filter Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        {/* Row 1: Severity and Risk Level */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs font-medium text-slate-400 mr-1">Rule Severity:</span>
            {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev || 'all-sev'}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                  selectedSeverity === sev
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                }`}
              >
                {sev || 'All Severities'}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs font-medium text-slate-400 mr-1">Risk Level:</span>
            {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl || 'all-lvl'}
                onClick={() => setSelectedRiskLevel(lvl)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                  selectedRiskLevel === lvl
                    ? 'bg-purple-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                }`}
              >
                {lvl || 'All Levels'}
              </button>
            ))}
          </div>
        </div>

        {/* Row 2: Priority, Status, Service and Search */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/60">
          <div className="flex flex-wrap items-center gap-3">
            {/* Priority Selector */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-medium text-slate-400">Priority:</span>
              <select
                value={selectedPriority}
                onChange={(e) => setSelectedPriority(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1"
              >
                <option value="">All Priorities</option>
                <option value="IMMEDIATE">IMMEDIATE</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>

            {/* Service Selector */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-medium text-slate-400">Service:</span>
              <select
                value={selectedService}
                onChange={(e) => setSelectedService(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1"
              >
                <option value="">All Services</option>
                {services.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>

            {/* Status Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-medium text-slate-400">Status:</span>
              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1"
              >
                <option value="">All Statuses</option>
                <option value="OPEN">OPEN Only</option>
                <option value="RESOLVED">RESOLVED Only</option>
              </select>
            </div>
          </div>

          {/* Search Form */}
          <form onSubmit={handleSearchSubmit} className="flex items-center gap-2">
            <div className="relative">
              <input
                type="text"
                placeholder="Search rule, title, resource..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-52 md:w-64"
              />
            </div>
            <button
              type="submit"
              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium transition"
            >
              Search
            </button>
          </form>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 bg-rose-950/30 border border-rose-800/60 rounded-xl text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Findings Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        {loading && findings.length === 0 ? (
          <div className="p-12 text-center text-slate-400 text-sm">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto text-blue-500 mb-2" />
            Evaluating security findings and risk scores...
          </div>
        ) : findings.length === 0 ? (
          <div className="p-12 text-center text-slate-400 text-sm">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
            No security findings matching the specified criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-800/60 border-b border-slate-800 text-slate-400 uppercase font-mono text-[11px]">
                <tr>
                  <th className="px-4 py-3">Rule Severity</th>
                  <th className="px-4 py-3">Calculated Risk</th>
                  <th className="px-4 py-3">Priority</th>
                  <th className="px-4 py-3">Rule ID & Violation</th>
                  <th className="px-4 py-3">Affected Asset</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => handleInspect(f)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3 whitespace-nowrap">
                      {getSeverityBadge(f.severity)}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden hidden sm:block">
                          <div
                            className={`h-1.5 rounded-full ${
                              f.risk_score >= 90 ? 'bg-rose-500' :
                              f.risk_score >= 70 ? 'bg-orange-500' :
                              f.risk_score >= 40 ? 'bg-amber-400' : 'bg-cyan-400'
                            }`}
                            style={{ width: `${Math.min(f.risk_score, 100)}%` }}
                          />
                        </div>
                        <span className={`text-sm font-extrabold font-mono ${getRiskScoreColor(f.risk_score)}`}>
                          {f.risk_score}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400 uppercase font-semibold">
                          {f.risk_level}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border uppercase font-bold ${getPriorityBadge(f.risk_priority)}`}>
                        {f.risk_priority}
                      </span>
                    </td>
                    <td className="px-4 py-3 max-w-sm">
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <span className="font-mono font-bold text-slate-200">{f.rule_code || 'RULE'}</span>
                        <span className="text-[10px] text-blue-400 font-mono">[{f.service}]</span>
                      </div>
                      <div className="font-semibold text-slate-200 line-clamp-1">{f.title}</div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">{f.description}</div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-slate-300 font-mono">{f.resource_name || f.resource_identifier}</div>
                      <div className="font-mono text-[10px] text-slate-500 truncate max-w-[200px]">{f.resource_identifier}</div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {f.status === 'OPEN' ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950/60 text-rose-300 border border-rose-800/60">
                          OPEN
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
                          RESOLVED
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleInspect(f);
                        }}
                        className="text-blue-400 hover:text-blue-300 font-mono text-xs flex items-center gap-1"
                      >
                        Inspect Risk &rarr;
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Risk & Evidence Inspector Modal */}
      {inspectingFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-800/40">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                    {inspectingFinding.rule_code}
                  </span>
                  <span className="text-xs font-mono text-blue-400 uppercase font-semibold">
                    {inspectingFinding.service}
                  </span>
                  <h3 className="text-base font-semibold text-white">
                    {inspectingFinding.title}
                  </h3>
                </div>
                <p className="text-xs text-slate-400 font-mono">
                  Asset: {inspectingFinding.resource_name || inspectingFinding.resource_identifier} &bull; Status: {inspectingFinding.status}
                </p>
              </div>

              <button
                onClick={() => setInspectingFinding(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6">
              {/* Executive Risk Scorecard */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 rounded-xl border border-gray-800 bg-[#0E131F]">
                <div className="text-center md:border-r border-gray-800/80 p-2">
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-mono">
                    Calculated Risk Score
                  </div>
                  <div className={`text-4xl font-extrabold font-mono mt-1 ${getRiskScoreColor(inspectingFinding.risk_score)}`}>
                    {inspectingFinding.risk_score}
                    <span className="text-sm text-gray-500 font-normal"> / 100</span>
                  </div>
                  <div className="flex items-center justify-center gap-2 mt-1.5">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-bold uppercase">
                      {inspectingFinding.risk_level}
                    </span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border uppercase font-bold ${getPriorityBadge(inspectingFinding.risk_priority)}`}>
                      {inspectingFinding.risk_priority}
                    </span>
                  </div>
                </div>

                <div className="space-y-1.5 p-2">
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-mono">
                    Rule vs Risk Context
                  </div>
                  <div className="text-xs text-gray-300">
                    Rule Base Severity: <strong className="text-white">{inspectingFinding.severity}</strong>
                  </div>
                  <div className="text-xs text-gray-300">
                    Calculated Level: <strong className="text-white">{inspectingFinding.risk_level}</strong>
                  </div>
                  <div className="text-[11px] text-gray-400 italic">
                    The calculated risk reflects actual network exposure, asset criticality, and data sensitivity.
                  </div>
                </div>

                <div className="space-y-1.5 p-2 text-xs font-mono text-gray-400">
                  <div className="text-[10px] uppercase tracking-wider text-gray-400">Detection Timeline</div>
                  <div>First Seen: <span className="text-gray-200">{new Date(inspectingFinding.first_detected).toLocaleDateString()}</span></div>
                  <div>Last Detected: <span className="text-gray-200">{new Date(inspectingFinding.last_detected).toLocaleTimeString()}</span></div>
                  <div>Calculated At: <span className="text-emerald-400">{inspectingFinding.risk_calculated_at ? new Date(inspectingFinding.risk_calculated_at).toLocaleTimeString() : 'Current'}</span></div>
                </div>
              </div>

              {/* Explainable Risk Factor Progress Bars */}
              <div className="rounded-xl border border-gray-800 bg-slate-900/60 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Sliders className="w-4 h-4 text-blue-400" />
                    Explainable Risk Factor Breakdown
                  </h4>
                  <span className="text-[10px] font-mono text-gray-400">Deterministic Model: 100% Normalized</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
                  {/* Base Severity */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-gray-300">Base Severity (40% weight)</span>
                      <span className="text-white font-bold">{inspectingFinding.risk_factors?.severity ?? '--'}/100</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div className="bg-rose-500 h-2 rounded-full" style={{ width: `${inspectingFinding.risk_factors?.severity ?? 0}%` }} />
                    </div>
                  </div>

                  {/* Exposure */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-gray-300">Internet Exposure (20% weight)</span>
                      <span className="text-white font-bold">{inspectingFinding.risk_factors?.exposure ?? '--'}/100</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div className="bg-orange-500 h-2 rounded-full" style={{ width: `${inspectingFinding.risk_factors?.exposure ?? 0}%` }} />
                    </div>
                    {inspectingFinding.risk_factors?.reasons?.exposure && (
                      <p className="text-[10px] text-gray-400 italic">{inspectingFinding.risk_factors.reasons.exposure}</p>
                    )}
                  </div>

                  {/* Asset Criticality */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-gray-300">Asset Criticality (15% weight)</span>
                      <span className="text-white font-bold">{inspectingFinding.risk_factors?.asset_criticality ?? '--'}/100</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div className="bg-yellow-500 h-2 rounded-full" style={{ width: `${inspectingFinding.risk_factors?.asset_criticality ?? 0}%` }} />
                    </div>
                    {inspectingFinding.risk_factors?.reasons?.asset_criticality && (
                      <p className="text-[10px] text-gray-400 italic">{inspectingFinding.risk_factors.reasons.asset_criticality}</p>
                    )}
                  </div>

                  {/* Exploitability */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-gray-300">Exploitability (10% weight)</span>
                      <span className="text-white font-bold">{inspectingFinding.risk_factors?.exploitability ?? '--'}/100</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div className="bg-purple-500 h-2 rounded-full" style={{ width: `${inspectingFinding.risk_factors?.exploitability ?? 0}%` }} />
                    </div>
                    {inspectingFinding.risk_factors?.reasons?.exploitability && (
                      <p className="text-[10px] text-gray-400 italic">{inspectingFinding.risk_factors.reasons.exploitability}</p>
                    )}
                  </div>

                  {/* Data Sensitivity */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-gray-300">Data Sensitivity (10% weight)</span>
                      <span className="text-white font-bold">{inspectingFinding.risk_factors?.data_sensitivity ?? '--'}/100</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div className="bg-blue-500 h-2 rounded-full" style={{ width: `${inspectingFinding.risk_factors?.data_sensitivity ?? 0}%` }} />
                    </div>
                    {inspectingFinding.risk_factors?.reasons?.data_sensitivity && (
                      <p className="text-[10px] text-gray-400 italic">{inspectingFinding.risk_factors.reasons.data_sensitivity}</p>
                    )}
                  </div>

                  {/* Config Weakness */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-gray-300">Config Weakness (5% weight)</span>
                      <span className="text-white font-bold">{inspectingFinding.risk_factors?.config_weakness ?? '--'}/100</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div className="bg-emerald-500 h-2 rounded-full" style={{ width: `${inspectingFinding.risk_factors?.config_weakness ?? 0}%` }} />
                    </div>
                    {inspectingFinding.risk_factors?.reasons?.config_weakness && (
                      <p className="text-[10px] text-gray-400 italic">{inspectingFinding.risk_factors.reasons.config_weakness}</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Human-Readable Risk Explanation */}
              {inspectingFinding.risk_explanation && (
                <div className="p-3 bg-slate-800/60 rounded-lg border border-slate-700 text-xs space-y-1">
                  <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-blue-400" />
                    Human-Readable Risk Justification
                  </div>
                  <p className="text-slate-200 leading-relaxed font-sans">{inspectingFinding.risk_explanation}</p>
                </div>
              )}

              {/* Concrete Configuration Evidence */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Code className="w-3.5 h-3.5 text-emerald-400" />
                    Offending Configuration Evidence (SDK Snapshot)
                  </h4>
                  <span className="text-[11px] font-mono text-emerald-400">Verifiable JSON Payload</span>
                </div>
                {inspectingLoading ? (
                  <div className="p-4 text-center text-slate-400 text-xs">Loading evidence...</div>
                ) : (
                  <pre className="bg-slate-950 p-4 rounded-lg border border-slate-800 text-emerald-400 font-mono text-xs overflow-x-auto max-h-60">
                    {JSON.stringify(inspectingFinding.evidence || {}, null, 2)}
                  </pre>
                )}
              </div>

              {/* Remediation Guidance */}
              <div className="p-3 bg-blue-950/20 rounded-lg border border-blue-900/40 text-xs space-y-1">
                <div className="font-semibold text-blue-300 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Recommended Remediation Guidance
                </div>
                <p className="text-slate-300">{inspectingFinding.remediation || 'Review configuration against AWS security guidelines.'}</p>
              </div>

              {/* Status Update & Analyst Notes Workflow */}
              <div className="p-4 bg-slate-900/90 rounded-lg border border-slate-800 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2">
                  <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    Finding Lifecycle Management
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-slate-400">Current Status:</span>
                    <select
                      value={inspectingFinding.status}
                      onChange={async (e) => {
                        const newStatus = e.target.value;
                        try {
                          await api.patch(`/findings/${inspectingFinding.id}/status`, {
                            status: newStatus,
                            rationale: 'Updated via Security Inspector Console',
                          });
                          setInspectingFinding({ ...inspectingFinding, status: newStatus as Finding['status'] });
                          fetchFindings();
                        } catch (err: any) {
                          alert(err.response?.data?.detail || 'Failed to update finding status');
                        }
                      }}
                      className="px-2 py-1 text-xs bg-slate-800 border border-slate-700 rounded text-white font-mono"
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="IN_PROGRESS">IN_PROGRESS</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="ACCEPTED_RISK">ACCEPTED_RISK</option>
                      <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                    </select>
                  </div>
                </div>

                {/* Analyst Notes */}
                <div className="space-y-2">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Analyst Investigation Notes
                  </div>
                  <form
                    onSubmit={async (e) => {
                      e.preventDefault();
                      const input = (e.target as any).elements.noteText;
                      const text = input.value.trim();
                      if (!text) return;
                      try {
                        await api.post(`/findings/${inspectingFinding.id}/notes`, { note: text });
                        input.value = '';
                        alert('Note added successfully');
                      } catch (err: any) {
                        alert(err.response?.data?.detail || 'Failed to add note');
                      }
                    }}
                    className="flex gap-2"
                  >
                    <input
                      name="noteText"
                      type="text"
                      placeholder="Add investigation context, remediation ticket link, or risk waiver..."
                      className="flex-1 px-3 py-1.5 text-xs bg-slate-800 border border-slate-700 rounded text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                    />
                    <button
                      type="submit"
                      className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold"
                    >
                      Post Note
                    </button>
                  </form>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-800/20 flex justify-end">
              <button
                onClick={() => setInspectingFinding(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg border border-slate-700"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
