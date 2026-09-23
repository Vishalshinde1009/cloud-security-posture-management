import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Bell,
  AlertTriangle,
  CheckCircle2,
  Radio,
  Filter,
  RefreshCw,
  ExternalLink,
  Check,
  Loader2,
  TrendingUp,
  TrendingDown,
} from 'lucide-react';
import api from '../services/api';
import { SecurityAlert, AlertSummary } from '../types/alert';
import { getStoredAccountId, setStoredAccountId } from '../utils/accountSelection';

interface AccountOption {
  id: string;
  name: string;
  provider: string;
  account_identifier: string;
}

export const Alerts: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const [accounts, setAccounts] = useState<AccountOption[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedAccountId, setSelectedAccountId] = useState<string>(
    searchParams.get('account_id') || getStoredAccountId() || ''
  );
  const [statusFilter, setStatusFilter] = useState<string>(searchParams.get('status') || '');
  const [severityFilter, setSeverityFilter] = useState<string>(searchParams.get('severity') || '');
  const [typeFilter, setTypeFilter] = useState<string>(searchParams.get('type') || '');

  const fetchAccounts = async () => {
    try {
      const res = await api.get('/cloud-accounts');
      const items = Array.isArray(res.data) ? res.data : (res.data?.items || []);
      setAccounts(items);
    } catch {
      // Ignore
    }
  };

  const fetchSummary = async () => {
    try {
      const params = selectedAccountId ? `?cloud_account_id=${selectedAccountId}` : '';
      const res = await api.get<AlertSummary>(`/alerts/summary${params}`);
      setSummary(res.data);
    } catch {
      // Ignore
    }
  };

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const q = new URLSearchParams();
      if (selectedAccountId) q.set('cloud_account_id', selectedAccountId);
      if (statusFilter) q.set('status', statusFilter);
      if (severityFilter) q.set('severity', severityFilter);
      if (typeFilter) q.set('alert_type', typeFilter);
      q.set('limit', '100');

      const res = await api.get<{ items: SecurityAlert[]; total: number }>(`/alerts?${q.toString()}`);
      setAlerts(res.data.items);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load security alerts.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAccounts();
  }, []);

  useEffect(() => {
    fetchSummary();
    fetchAlerts();
  }, [selectedAccountId, statusFilter, severityFilter, typeFilter]);

  const handleAccountChange = (newAccId: string) => {
    setSelectedAccountId(newAccId);
    setStoredAccountId(newAccId);
    const params = new URLSearchParams(searchParams);
    if (newAccId) params.set('account_id', newAccId);
    else params.delete('account_id');
    setSearchParams(params);
  };

  const handleStatusUpdate = async (alertId: string, newStatus: 'ACKNOWLEDGED' | 'RESOLVED') => {
    setActionLoading(alertId);
    try {
      const res = await api.patch<SecurityAlert>(`/alerts/${alertId}`, { status: newStatus });
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: res.data.status, resolved_at: res.data.resolved_at } : a))
      );
      fetchSummary();
    } catch (err: any) {
      alert(err.response?.data?.detail || `Failed to update alert status.`);
    } finally {
      setActionLoading(null);
    }
  };

  const formatRelativeTime = (dateStr: string) => {
    const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return new Date(dateStr).toLocaleDateString();
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-500/15 text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30';
      case 'LOW':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
    }
  };

  const getTypeBadge = (type: string) => {
    switch (type) {
      case 'NEW_FINDING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950/60 text-rose-300 border border-rose-800/60">
            <AlertTriangle className="w-3 h-3 text-rose-400" /> NEW FINDING
          </span>
        );
      case 'RISK_INCREASED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-950/60 text-amber-300 border border-amber-800/60">
            <TrendingUp className="w-3 h-3 text-amber-400" /> RISK INCREASED
          </span>
        );
      case 'FINDING_RESOLVED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" /> RESOLVED
          </span>
        );
      case 'POSTURE_DEGRADED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-red-950/60 text-red-300 border border-red-800/60">
            <TrendingDown className="w-3 h-3 text-red-400" /> POSTURE DEGRADED
          </span>
        );
      case 'POSTURE_IMPROVED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950/60 text-cyan-300 border border-cyan-800/60">
            <TrendingUp className="w-3 h-3 text-cyan-400" /> POSTURE IMPROVED
          </span>
        );
      case 'SCAN_FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950/80 text-rose-400 border border-rose-700">
            <Radio className="w-3 h-3 text-rose-400" /> SCAN FAILED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700">
            {type}
          </span>
        );
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'OPEN':
        return (
          <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-rose-500/20 text-rose-400 border border-rose-500/40">
            OPEN
          </span>
        );
      case 'ACKNOWLEDGED':
        return (
          <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-cyan-500/20 text-cyan-400 border border-cyan-500/40">
            ACKNOWLEDGED
          </span>
        );
      case 'RESOLVED':
        return (
          <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
            RESOLVED
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-slate-800 text-slate-400">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
              <Bell className="w-6 h-6 text-cyan-400" />
              Security Alert Center
            </h1>
            <span className="px-2.5 py-1 text-xs font-mono font-semibold uppercase tracking-wider bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-md">
              Continuous Monitoring
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Real-time notifications on cloud drift, new vulnerabilities, escalated risk scores, and posture changes.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              fetchSummary();
              fetchAlerts();
            }}
            disabled={loading}
            className="px-3.5 py-2 text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-md">
          <span className="text-[10px] font-mono font-semibold text-slate-400 uppercase block">Total Open</span>
          <span className="text-2xl font-bold text-white font-mono mt-1 block">
            {summary?.total_open ?? 0}
          </span>
        </div>
        <div className="p-4 rounded-xl border border-rose-900/40 bg-rose-950/20 backdrop-blur-md">
          <span className="text-[10px] font-mono font-semibold text-rose-400 uppercase block">Critical</span>
          <span className="text-2xl font-bold text-rose-400 font-mono mt-1 block">
            {summary?.critical ?? 0}
          </span>
        </div>
        <div className="p-4 rounded-xl border border-amber-900/40 bg-amber-950/20 backdrop-blur-md">
          <span className="text-[10px] font-mono font-semibold text-amber-400 uppercase block">High</span>
          <span className="text-2xl font-bold text-amber-400 font-mono mt-1 block">
            {summary?.high ?? 0}
          </span>
        </div>
        <div className="p-4 rounded-xl border border-yellow-900/40 bg-yellow-950/20 backdrop-blur-md">
          <span className="text-[10px] font-mono font-semibold text-yellow-300 uppercase block">Medium</span>
          <span className="text-2xl font-bold text-yellow-300 font-mono mt-1 block">
            {summary?.medium ?? 0}
          </span>
        </div>
        <div className="p-4 rounded-xl border border-blue-900/40 bg-blue-950/20 backdrop-blur-md">
          <span className="text-[10px] font-mono font-semibold text-blue-400 uppercase block">Low</span>
          <span className="text-2xl font-bold text-blue-400 font-mono mt-1 block">
            {summary?.low ?? 0}
          </span>
        </div>
        <div className="p-4 rounded-xl border border-emerald-900/40 bg-emerald-950/20 backdrop-blur-md">
          <span className="text-[10px] font-mono font-semibold text-emerald-400 uppercase block">Resolved</span>
          <span className="text-2xl font-bold text-emerald-400 font-mono mt-1 block">
            {summary?.resolved ?? 0}
          </span>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900/70 border border-slate-800 rounded-xl">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="text-xs text-slate-400 font-medium flex items-center gap-1">
            <Filter className="w-3.5 h-3.5 text-cyan-400" /> Filters:
          </span>

          {/* Account Filter */}
          <select
            value={selectedAccountId}
            onChange={(e) => handleAccountChange(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-sans"
          >
            <option value="">All Cloud Accounts</option>
            {accounts.map((acc) => (
              <option key={acc.id} value={acc.id}>
                {acc.name} ({acc.provider})
              </option>
            ))}
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-sans"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="RESOLVED">Resolved</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-sans"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          {/* Alert Type Filter */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-sans"
          >
            <option value="">All Alert Types</option>
            <option value="NEW_FINDING">New Finding</option>
            <option value="RISK_INCREASED">Risk Increased</option>
            <option value="FINDING_RESOLVED">Finding Resolved</option>
            <option value="POSTURE_DEGRADED">Posture Degraded</option>
            <option value="POSTURE_IMPROVED">Posture Improved</option>
            <option value="SCAN_FAILED">Scan Failed</option>
          </select>
        </div>

        <div className="text-xs text-slate-400 font-mono">
          Showing {alerts.length} alerts
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs flex items-center justify-between">
          <span>{error}</span>
          <button onClick={fetchAlerts} className="underline text-rose-200 hover:text-white">
            Retry
          </button>
        </div>
      )}

      {/* Alerts Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden backdrop-blur-md shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-800/60 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Alert Type</th>
                <th className="px-4 py-3">Title & Description</th>
                <th className="px-4 py-3">Target Account</th>
                <th className="px-4 py-3">Detected</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {loading && alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-slate-500">
                    <Loader2 className="w-5 h-5 animate-spin mx-auto text-cyan-400 mb-2" />
                    Loading security alerts...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-slate-500">
                    <CheckCircle2 className="w-6 h-6 text-emerald-500 mx-auto mb-2 opacity-80" />
                    No security alerts matching current filters.
                  </td>
                </tr>
              ) : (
                alerts.map((al) => (
                  <tr key={al.id} className="hover:bg-slate-800/40 transition-colors">
                    {/* Severity */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono font-bold border uppercase ${getSeverityBadge(
                          al.severity
                        )}`}
                      >
                        {al.severity}
                      </span>
                    </td>

                    {/* Alert Type */}
                    <td className="px-4 py-3 whitespace-nowrap">{getTypeBadge(al.alert_type)}</td>

                    {/* Title & Description */}
                    <td className="px-4 py-3 max-w-sm">
                      <div className="font-semibold text-white text-xs truncate">{al.title}</div>
                      <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">{al.description}</div>
                      {al.previous_value && al.current_value && (
                        <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                          Value: {al.previous_value} &rarr;{' '}
                          <span className="text-cyan-300 font-semibold">{al.current_value}</span>
                        </div>
                      )}
                    </td>

                    {/* Target Account */}
                    <td className="px-4 py-3 whitespace-nowrap font-sans">
                      <div className="font-medium text-slate-200 text-xs">{al.account_name || 'Account'}</div>
                      <div className="text-[10px] font-mono text-slate-500">{al.account_identifier}</div>
                    </td>

                    {/* Detected Timestamp */}
                    <td className="px-4 py-3 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                      <div title={new Date(al.last_detected_at).toLocaleString()}>
                        {formatRelativeTime(al.last_detected_at)}
                      </div>
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3 whitespace-nowrap">{getStatusBadge(al.status)}</td>

                    {/* Actions */}
                    <td className="px-4 py-3 whitespace-nowrap text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {al.finding_id && (
                          <button
                            onClick={() => navigate(`/findings?finding_id=${al.finding_id}`)}
                            title="View Finding Details"
                            className="p-1.5 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                        )}

                        {al.status === 'OPEN' && (
                          <button
                            onClick={() => handleStatusUpdate(al.id, 'ACKNOWLEDGED')}
                            disabled={actionLoading === al.id}
                            title="Acknowledge Alert"
                            className="px-2.5 py-1 text-xs font-semibold text-cyan-300 hover:text-white bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 rounded-lg transition"
                          >
                            {actionLoading === al.id ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Acknowledge'}
                          </button>
                        )}

                        {al.status !== 'RESOLVED' && (
                          <button
                            onClick={() => handleStatusUpdate(al.id, 'RESOLVED')}
                            disabled={actionLoading === al.id}
                            title="Mark as Resolved"
                            className="px-2.5 py-1 text-xs font-semibold text-emerald-300 hover:text-white bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 rounded-lg transition flex items-center gap-1"
                          >
                            {actionLoading === al.id ? (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            ) : (
                              <>
                                <Check className="w-3 h-3" /> Resolve
                              </>
                            )}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
