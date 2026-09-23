import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Download, 
  PlusCircle, 
  AlertCircle,
  FileCheck,
  Cloud,
  RefreshCw,
  Server
} from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import { resolvePreferredAccountId, getStoredAccountId, setStoredAccountId } from '../utils/accountSelection';

interface CloudAccountOption {
  id: string;
  name: string;
  provider: string;
  is_active?: boolean;
  role_arn?: string | null;
  credential_mode?: string;
  account_identifier?: string;
  total_scans?: number;
  latest_scan?: {
    id: string;
    status: string;
    security_score: number | null;
    findings_count: number;
    completed_at: string | null;
  } | null;
}

interface ReportItem {
  id: string;
  cloud_account_id?: string;
  title: string;
  report_type: 'EXECUTIVE' | 'TECHNICAL';
  format: string;
  file_path?: string;
  created_at: string;
}

export function Reports() {
  const { user } = useAuth();
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [accounts, setAccounts] = useState<CloudAccountOption[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<string>(getStoredAccountId());
  const [systemMode, setSystemMode] = useState<string>('mock');
  const [loading, setLoading] = useState<boolean>(true);
  const [generating, setGenerating] = useState<boolean>(false);
  const [showModal, setShowModal] = useState<boolean>(false);
  const [reportType, setReportType] = useState<'EXECUTIVE' | 'TECHNICAL'>('EXECUTIVE');
  const [reportTitle, setReportTitle] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [hasCompletedScan, setHasCompletedScan] = useState<boolean>(false);

  const canGenerate = Boolean(user) && (
    (user?.roles && (user.roles.includes('ADMIN') || user.roles.includes('SECURITY_ANALYST'))) ||
    hasCompletedScan
  );

  useEffect(() => {
    // Fetch backend system mode
    api.get<{ mode: string }>('/health')
      .then((res) => {
        if (res.data?.mode) {
          setSystemMode(res.data.mode.toLowerCase());
        }
      })
      .catch(() => {});

    // Check if any completed scan exists for current user
    api.get<any>('/scans?limit=5')
      .then((res) => {
        const scans = Array.isArray(res.data) ? res.data : (res.data?.items || []);
        if (scans.some((s: any) => s.status === 'COMPLETED')) {
          setHasCompletedScan(true);
        }
      })
      .catch(() => {});

    // Fetch cloud accounts for targeting
    api.get<any>('/cloud-accounts')
      .then((res) => {
        const items: CloudAccountOption[] = Array.isArray(res.data) ? res.data : (res.data?.items || []);
        setAccounts(items);
        if (items.some((a) => (a.total_scans ?? 0) > 0 || a.latest_scan?.status === 'COMPLETED')) {
          setHasCompletedScan(true);
        }
        const preferredId = resolvePreferredAccountId(items, getStoredAccountId());
        setSelectedAccountId(preferredId);
        setStoredAccountId(preferredId);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchReports();
  }, [selectedAccountId]);

  const fetchReports = async () => {
    setLoading(true);
    try {
      let query = '/reports?limit=50';
      if (selectedAccountId) {
        query += `&account_id=${encodeURIComponent(selectedAccountId)}`;
      }
      const res = await api.get(query);
      setReports(res.data.items);
    } catch (err) {
      console.error('Failed to load reports', err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setGenerating(true);
    setError(null);
    try {
      await api.post('/reports', {
        account_id: selectedAccountId || undefined,
        report_type: reportType,
        title: reportTitle.trim() || undefined,
      });
      setShowModal(false);
      setReportTitle('');
      fetchReports();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (reportId: string, title: string) => {
    try {
      const res = await api.get(`/reports/${reportId}/download`, {
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${title.replace(/\s+/g, '_')}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert('Failed to download report file');
    }
  };

  const selectedAccount = accounts.find((a) => a.id === selectedAccountId);
  const isAwsTarget = selectedAccount?.provider === 'AWS' || (!selectedAccount && systemMode === 'aws');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <FileText className="w-6 h-6 text-blue-400" />
              Security Posture & Compliance Reports
            </h1>

            {/* Dynamic Environment Badge */}
            {isAwsTarget ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/30 shadow-[0_0_10px_rgba(245,158,11,0.15)] uppercase">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                AWS REPORTS
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 uppercase">
                <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                MOCK REPORTS
              </span>
            )}
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Export comprehensive server-generated PDF assessments for executive stakeholders and technical audit teams.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Target Account Selector */}
          {accounts.length > 0 && (
            <div className="flex items-center gap-2 bg-slate-900/80 border border-slate-700/80 rounded-xl px-3 py-1.5 text-xs shadow-sm">
              <Cloud className={`w-4 h-4 ${isAwsTarget ? 'text-amber-400' : 'text-cyan-400'}`} />
              <span className="text-slate-400 font-medium">Target:</span>
              <select
                value={selectedAccountId}
                onChange={(e) => {
                  setSelectedAccountId(e.target.value);
                  setStoredAccountId(e.target.value);
                }}
                className="bg-transparent text-white font-medium focus:outline-none cursor-pointer text-xs"
              >
                {accounts.map((acc) => (
                  <option key={acc.id} value={acc.id} className="bg-slate-900 text-white">
                    {acc.name} ({acc.provider})
                  </option>
                ))}
              </select>
            </div>
          )}

          <button
            onClick={fetchReports}
            disabled={loading}
            className="px-3 py-2 text-xs font-semibold text-slate-300 bg-slate-800/80 hover:bg-slate-700 border border-slate-700/80 rounded-xl transition-colors flex items-center gap-1.5 shadow-sm"
            title="Refresh reports"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>

          {canGenerate && (
            <button
              onClick={() => setShowModal(true)}
              className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-semibold shadow-glow-cyan transition"
            >
              <PlusCircle className="w-4 h-4" />
              Generate New Report
            </button>
          )}
        </div>
      </div>

      {/* Reports Grid / List */}
      <div className="glass-panel border border-slate-800/80 rounded-2xl overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400">Loading reports catalog...</div>
        ) : reports.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400 space-y-3">
            {hasCompletedScan ? (
              <>
                <p>No reports generated yet. Click "Generate New Report" to export a security assessment.</p>
                <div>
                  <button
                    onClick={() => setShowModal(true)}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-semibold shadow-glow-cyan transition"
                  >
                    <PlusCircle className="w-4 h-4" />
                    Generate New Report
                  </button>
                </div>
              </>
            ) : (
              <p>No completed security scans found. Run a scan on your cloud account first to generate posture reports.</p>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-800/60 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Report Document</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Format</th>
                  <th className="px-4 py-3">Generated Date</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {reports.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <FileCheck className="w-4 h-4 text-cyan-400" />
                        <div>
                          <div className="font-semibold text-white">{r.title}</div>
                          <div className="text-[10px] font-mono text-slate-500">{r.id}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold ${
                        r.report_type === 'EXECUTIVE'
                          ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                          : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                      }`}>
                        {r.report_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                      {r.format}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-[11px]">
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleDownload(r.id, r.title)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white rounded-xl border border-slate-700 text-xs transition shadow-sm"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Download PDF
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Generate Report Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-[#0F172A] border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl backdrop-blur-xl">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <FileText className="w-5 h-5 text-cyan-400" />
              Generate Security Assessment Report
            </h2>

            {/* Target Account Display in Modal */}
            <div className="p-3 bg-slate-800/60 border border-slate-700/60 rounded-lg flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-slate-400" />
                <span className="text-slate-400">Target Account:</span>
                <span className="font-semibold text-white">
                  {selectedAccount ? selectedAccount.name : 'Active Cloud Account'}
                </span>
              </div>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                isAwsTarget
                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                  : 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/30'
              }`}>
                {selectedAccount?.provider || systemMode.toUpperCase()}
              </span>
            </div>

            {error && (
              <div className="p-3 bg-red-950/40 border border-red-800 rounded-lg text-xs text-red-200 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleGenerate} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-1">
                  Report Type
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setReportType('EXECUTIVE')}
                    className={`p-3 text-left rounded-xl border text-xs transition ${
                      reportType === 'EXECUTIVE'
                        ? 'border-cyan-500 bg-cyan-500/10 text-white shadow-glow-cyan'
                        : 'border-slate-800 bg-slate-850/60 text-slate-400 hover:bg-slate-800'
                    }`}
                  >
                    <div className="font-semibold">Executive Summary</div>
                    <div className="text-[10px] text-slate-500 mt-1">High-level posture & risk overview for leadership</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => setReportType('TECHNICAL')}
                    className={`p-3 text-left rounded-xl border text-xs transition ${
                      reportType === 'TECHNICAL'
                        ? 'border-cyan-500 bg-cyan-500/10 text-white shadow-glow-cyan'
                        : 'border-slate-800 bg-slate-850/60 text-slate-400 hover:bg-slate-800'
                    }`}
                  >
                    <div className="font-semibold">Technical Deep Dive</div>
                    <div className="text-[10px] text-slate-500 mt-1">Full control gaps, resources & remediation steps</div>
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">
                  Custom Title (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. Q3 Cloud Security Posture Audit"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-950/80 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-xs text-slate-400 hover:text-white transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generating}
                  className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white rounded-xl text-xs font-semibold shadow-glow-cyan transition"
                >
                  {generating ? 'Generating PDF...' : 'Generate PDF'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
