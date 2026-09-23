import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import { Scan, ScanListResponse } from '../types/scanner';
import { resolvePreferredAccountId, getStoredAccountId, setStoredAccountId, onAccountChanged } from '../utils/accountSelection';

interface CloudAccountOption {
  id: string;
  name: string;
  provider: string;
  account_identifier: string;
  default_region: string;
  role_arn?: string | null;
  credential_mode?: string;
  is_active: boolean;
}

export const Scans = () => {
  const { user } = useAuth();
  const location = useLocation();
  const [scans, setScans] = useState<Scan[]>([]);
  const [accounts, setAccounts] = useState<CloudAccountOption[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<string>('');
  const [systemMode, setSystemMode] = useState<string>('mock');
  const [loading, setLoading] = useState<boolean>(true);
  const [triggering, setTriggering] = useState<boolean>(false);
  const [scanStage, setScanStage] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const isAdmin = Boolean(user?.roles?.includes('ADMIN'));
  const hasAccounts = accounts.length > 0;
  const canTrigger = Boolean(user) && (isAdmin || (hasAccounts && Boolean(selectedAccountId)));

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
        const passedId = (location.state as any)?.accountId;
        const preferredId = resolvePreferredAccountId(items, passedId || getStoredAccountId());
        setSelectedAccountId(preferredId);
        const preferredAcc = items.find((a) => a.id === preferredId);
        setStoredAccountId(preferredId, preferredAcc);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const unsubscribe = onAccountChanged((newId) => {
      if (newId && newId !== selectedAccountId) {
        setSelectedAccountId(newId);
      }
    });
    return () => unsubscribe();
  }, [selectedAccountId]);

  const selectedAccount = accounts.find((a) => a.id === selectedAccountId);
  const isAwsRole = selectedAccount?.provider === 'AWS' && selectedAccount?.credential_mode === 'ROLE';
  const isAwsLive = selectedAccount?.provider === 'AWS' || (!selectedAccount && systemMode === 'aws');
  const isAwsTarget = isAwsLive;

  const handleStartScan = async () => {
    if (!canTrigger) return;
    setTriggering(true);
    setScanStage(1);
    setError(null);
    setSuccessMsg(null);

    const t1 = setTimeout(() => setScanStage(2), 600);
    const t2 = setTimeout(() => setScanStage(3), 1300);
    const t3 = setTimeout(() => setScanStage(4), 2100);
    const t4 = setTimeout(() => setScanStage(5), 2900);

    try {
      const payload = selectedAccountId
        ? { account_id: selectedAccountId, cloud_account_id: selectedAccountId }
        : {};
      const res = await api.post<Scan>('/scans', payload);
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
      setScanStage(6);
      setSuccessMsg(
        `Scan completed successfully! Discovered ${res.data.resources_scanned} cloud assets (${res.data.account_name || 'Target Account'}).`
      );
      await fetchScans();
    } catch (err: any) {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
      setScanStage(0);
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
            {isAwsRole ? (
              <span className="px-2.5 py-1 text-xs font-mono font-semibold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-md flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                AWS ROLE / LIVE
              </span>
            ) : isAwsLive ? (
              <span className="px-2.5 py-1 text-xs font-mono font-semibold uppercase tracking-wider bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-md flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                AWS / LIVE MODE
              </span>
            ) : (
              <span className="px-2.5 py-1 text-xs font-mono font-semibold uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 rounded-md">
                MOCK / DEMO MODE
              </span>
            )}
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Trigger automated resource discovery and view posture assessment history.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {accounts.length > 0 && (
            <div className="flex items-center gap-2 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
              <span className="text-xs text-slate-400 font-medium">Target:</span>
              <select
                value={selectedAccountId}
                onChange={(e) => {
                  const newId = e.target.value;
                  const acc = accounts.find((a) => a.id === newId);
                  setSelectedAccountId(newId);
                  setStoredAccountId(newId, acc);
                }}
                disabled={triggering}
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
            title={
              !user
                ? 'Please log in to trigger scans'
                : !hasAccounts && !isAdmin
                ? 'Please register a cloud account to trigger scans'
                : `Execute ${isAwsTarget ? 'AWS read-only' : 'mock'} discovery scan`
            }
            className={`px-4 py-2 text-xs font-semibold tracking-wide uppercase rounded-lg shadow-sm transition-all flex items-center gap-2 ${
              canTrigger
                ? isAwsTarget
                  ? 'bg-amber-600 hover:bg-amber-500 text-white shadow-amber-500/20 active:scale-95'
                  : 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-500/20 active:scale-95'
                : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
            }`}
          >
            {triggering ? (
              <>
                <svg className="animate-spin w-4 h-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                Scanning {isAwsTarget ? 'AWS' : 'Mock'} Assets...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {isAwsTarget ? 'Execute AWS Scan' : 'Start Mock Scan'}
              </>
            )}
          </button>
        </div>
      </div>

      {/* Live Scan Execution Stepper (Visual Feedback) */}
      {(triggering || scanStage > 0) && (
        <div className="p-6 rounded-2xl border border-cyan-500/40 bg-slate-900/90 backdrop-blur-md shadow-2xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-full ${scanStage === 6 ? 'bg-emerald-400' : 'bg-cyan-400 animate-ping'}`} />
              <h3 className="text-sm font-bold text-white tracking-tight">
                {scanStage === 6 ? 'Scan Assessment Completed' : 'Discovery & Audit Pipeline Executing...'}
              </h3>
            </div>
            <span className="text-xs font-mono text-cyan-400 font-semibold">
              Step {scanStage} of 6
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
            {[
              { id: 1, name: 'Initializing' },
              { id: 2, name: 'Connecting to AWS' },
              { id: 3, name: 'Discovering resources' },
              { id: 4, name: 'Evaluating security rules' },
              { id: 5, name: 'Calculating posture' },
              { id: 6, name: 'Completed' },
            ].map((st) => (
              <div
                key={st.id}
                className={`p-3 rounded-xl border text-center transition-all ${
                  scanStage === st.id
                    ? 'bg-cyan-950/70 border-cyan-500 text-cyan-300 shadow-glow-cyan font-bold scale-[1.02]'
                    : scanStage > st.id
                    ? 'bg-emerald-950/40 border-emerald-800 text-emerald-400'
                    : 'bg-slate-950/40 border-slate-800 text-slate-500'
                }`}
              >
                <div className="text-[10px] font-mono mb-1">
                  {scanStage > st.id ? '✓ DONE' : scanStage === st.id ? '● ACTIVE' : `0${st.id}`}
                </div>
                <div className="text-xs truncate">{st.name}</div>
              </div>
            ))}
          </div>
        </div>
      )}

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

      {!hasAccounts && !isAdmin && (
        <div className="p-3 bg-amber-950/30 border border-amber-800/50 rounded-lg text-xs text-amber-300 flex items-center justify-between">
          <span>No cloud account configured. Please connect your AWS account before triggering scans.</span>
          <a href="/cloud-accounts" className="text-amber-400 hover:underline font-semibold ml-2">Connect AWS &rarr;</a>
        </div>
      )}

      {hasAccounts && (
        <div className="p-3 bg-slate-800/60 border border-slate-700 rounded-lg text-xs text-slate-400">
          Note: Scans use read-only AWS access. You can scan your own registered cloud account.
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
                  <th className="px-4 py-3">Target Account</th>
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
                      <div className="flex items-center gap-1.5">
                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border uppercase font-semibold ${
                          scan.account_provider === 'AWS'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        }`}>
                          {scan.account_provider || 'MOCK'}
                        </span>
                        <span className="text-slate-200 text-xs truncate max-w-[140px]" title={scan.account_name || 'Demo Environment'}>
                          {scan.account_name || 'Demo Environment'}
                        </span>
                      </div>
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
