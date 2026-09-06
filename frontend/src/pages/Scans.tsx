import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import { Scan, ScanListResponse } from '../types/scanner';

export const Scans = () => {
  const { user } = useAuth();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [triggering, setTriggering] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const canTrigger = user?.roles.some((r) => ['ADMIN', 'SECURITY_ANALYST'].includes(r));

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get<ScanListResponse>('/scans?limit=25');
      setScans(res.data.items);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load scan history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleStartScan = async () => {
    if (!canTrigger) return;
    try {
      setTriggering(true);
      setError(null);
      setSuccessMsg(null);
      const res = await api.post<Scan>('/scans', {});
      setSuccessMsg(`Scan initiated successfully! Discovered ${res.data.resources_scanned} cloud assets.`);
      await fetchScans();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to execute scan.');
    } finally {
      setTriggering(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/70 text-emerald-400 border border-emerald-800/60">
            COMPLETED
          </span>
        );
      case 'RUNNING':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/70 text-amber-300 border border-amber-800/60 animate-pulse">
            RUNNING
          </span>
        );
      case 'QUEUED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-950/70 text-blue-300 border border-blue-800/60">
            QUEUED
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/70 text-rose-400 border border-rose-800/60">
            FAILED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-300">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white">CSPM Cloud Scans</h1>
            <span className="px-2.5 py-1 text-xs font-mono font-medium uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 rounded-md">
              MOCK / DEMO MODE
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Trigger automated resource discovery and view posture assessment history.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchScans}
            disabled={loading}
            className="px-3.5 py-2 text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5"
          >
            <svg className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh
          </button>

          <button
            onClick={handleStartScan}
            disabled={!canTrigger || triggering}
            title={!canTrigger ? 'VIEWER role cannot trigger scans' : 'Execute discovery scan'}
            className={`px-4 py-2 text-xs font-semibold tracking-wide uppercase rounded-lg shadow-sm transition-all flex items-center gap-2 ${
              canTrigger
                ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-500/20 active:scale-95'
                : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
            }`}
          >
            {triggering ? (
              <>
                <svg className="animate-spin w-4 h-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                Scanning Assets...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Start Mock Scan
              </>
            )}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800/70 text-sm text-rose-300 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200 text-xs">Dismiss</button>
        </div>
      )}

      {successMsg && (
        <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-800/70 text-sm text-emerald-300 flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200 text-xs">Dismiss</button>
        </div>
      )}

      {!canTrigger && (
        <div className="p-3 bg-slate-800/60 border border-slate-700 rounded-lg text-xs text-slate-400">
          Note: Your current role (<strong>{user?.roles.join(', ')}</strong>) has read-only permissions. Contact an Administrator or Security Analyst to trigger scans.
        </div>
      )}

      {/* Scan History Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Execution Runs ({scans.length})</h2>
          <span className="text-xs text-slate-500">Historical records are strictly preserved</span>
        </div>

        {loading && scans.length === 0 ? (
          <div className="p-8 text-center text-slate-400 text-sm">
            <svg className="animate-spin w-6 h-6 mx-auto mb-2 text-blue-500" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
            Loading scan history...
          </div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <svg className="w-12 h-12 mx-auto text-slate-600 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            <p className="text-base font-medium text-slate-300">No scans executed yet</p>
            <p className="text-xs text-slate-500 mt-1">Click "Start Mock Scan" above to discover simulated cloud resources.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-800/50 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Scan ID</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Resources</th>
                  <th className="px-4 py-3">Posture Score</th>
                  <th className="px-4 py-3">Duration</th>
                  <th className="px-4 py-3">Started At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300 font-mono">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 text-slate-400 font-medium">
                      {scan.id.substring(0, 8)}...
                    </td>
                    <td className="px-4 py-3 font-sans">
                      {getStatusBadge(scan.status)}
                    </td>
                    <td className="px-4 py-3 font-sans text-slate-200 font-semibold">
                      {scan.resources_scanned} assets
                    </td>
                    <td className="px-4 py-3 font-sans">
                      {scan.security_score !== null ? (
                        <span className={`font-semibold ${
                          scan.security_score >= 80 ? 'text-emerald-400' : scan.security_score >= 50 ? 'text-amber-400' : 'text-rose-400'
                        }`}>
                          {scan.security_score}%
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {scan.duration !== null ? `${scan.duration}s` : '—'}
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-sans">
                      {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
