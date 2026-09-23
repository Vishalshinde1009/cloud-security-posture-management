import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Cloud, 
  Plus, 
  CheckCircle2, 
  XCircle, 
  Loader2, 
  Radio, 
  RefreshCw,
  Server,
  KeyRound,
  Globe,
  Copy,
  Check,
  ShieldCheck,
  Key,
  Trash2,
  AlertTriangle
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import { resolvePreferredAccountId, getStoredAccountId, setStoredAccountId, markAccountVerified } from '../utils/accountSelection';

interface LatestScanSummary {
  id: string;
  status: string;
  security_score: number | null;
  findings_count: number;
  completed_at: string | null;
}

interface CloudAccount {
  id: string;
  name: string;
  provider: string;
  account_identifier: string;
  default_region: string;
  credential_mode: string;
  role_arn?: string | null;
  external_id?: string | null;
  trust_policy_snippet?: string | null;
  is_active: boolean;
  created_at: string;
  total_scans: number;
  latest_scan: LatestScanSummary | null;
}

interface TestConnectionResult {
  status: 'CONNECTED' | 'ERROR';
  provider: string;
  account_id?: string;
  arn?: string;
  user_id?: string;
  message: string;
}

export const CloudAccounts = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, TestConnectionResult>>({});
  const [scanningId, setScanningId] = useState<string | null>(null);
  const [scanMsg, setScanMsg] = useState<string | null>(null);

  // Add Account Modal State
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [name, setName] = useState('');
  const [provider, setProvider] = useState('AWS');
  const [accountIdentifier, setAccountIdentifier] = useState('');
  const [defaultRegion, setDefaultRegion] = useState('us-east-1');
  const [credentialMode, setCredentialMode] = useState('ENVIRONMENT');
  const [roleArn, setRoleArn] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // IAM Role Configuration Modal State
  const [roleModalAccount, setRoleModalAccount] = useState<CloudAccount | null>(null);
  const [roleArnInput, setRoleArnInput] = useState('');
  const [savingRole, setSavingRole] = useState(false);
  const [roleError, setRoleError] = useState<string | null>(null);
  const [roleSuccess, setRoleSuccess] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Delete Account Modal State
  const [deleteModalAccount, setDeleteModalAccount] = useState<CloudAccount | null>(null);
  const [deletingAccount, setDeletingAccount] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleteSuccess, setDeleteSuccess] = useState<string | null>(null);

  // Continuous Monitoring State
  const [monitoringConfigs, setMonitoringConfigs] = useState<
    Record<string, { enabled: boolean; scan_interval_minutes: number; last_scan_at?: string | null; next_scan_at?: string | null }>
  >({});
  const [savingMonitoringId, setSavingMonitoringId] = useState<string | null>(null);
  const [runningMonitoringId, setRunningMonitoringId] = useState<string | null>(null);
  const [monitoringFeedback, setMonitoringFeedback] = useState<Record<string, string>>({});

  const canManage = Boolean(user);
  const canScan = Boolean(user);

  const copyToClipboard = (text: string, fieldId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldId);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const fetchAccounts = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get<CloudAccount[]>('/cloud-accounts');
      const data = Array.isArray(res.data) ? res.data : ((res.data as any)?.items || []);
      setAccounts(data);
      const currentStored = getStoredAccountId();
      const preferred = resolvePreferredAccountId(data, currentStored);
      setStoredAccountId(preferred);

      // Fetch monitoring configs for accounts
      data.forEach((acc: CloudAccount) => {
        api.get(`/monitoring/${acc.id}`)
          .then((mRes) => {
            setMonitoringConfigs((prev) => ({ ...prev, [acc.id]: mRes.data }));
          })
          .catch(() => {});
      });
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch registered cloud accounts.');
    } finally {
      setLoading(false);
    }
  };

  const handleToggleMonitoring = async (accountId: string) => {
    const current = monitoringConfigs[accountId];
    const newEnabled = !(current?.enabled ?? false);
    const interval = current?.scan_interval_minutes ?? 60;
    setSavingMonitoringId(accountId);
    try {
      const res = await api.put(`/monitoring/${accountId}`, {
        enabled: newEnabled,
        scan_interval_minutes: interval,
      });
      setMonitoringConfigs((prev) => ({ ...prev, [accountId]: res.data }));
      setMonitoringFeedback((prev) => ({
        ...prev,
        [accountId]: newEnabled ? 'Monitoring enabled.' : 'Monitoring disabled.',
      }));
      setTimeout(() => {
        setMonitoringFeedback((prev) => {
          const cp = { ...prev };
          delete cp[accountId];
          return cp;
        });
      }, 3000);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update monitoring config.');
    } finally {
      setSavingMonitoringId(null);
    }
  };

  const handleUpdateInterval = async (accountId: string, newInterval: number) => {
    const current = monitoringConfigs[accountId];
    const enabled = current?.enabled ?? false;
    setSavingMonitoringId(accountId);
    try {
      const res = await api.put(`/monitoring/${accountId}`, {
        enabled: enabled,
        scan_interval_minutes: newInterval,
      });
      setMonitoringConfigs((prev) => ({ ...prev, [accountId]: res.data }));
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update scan interval.');
    } finally {
      setSavingMonitoringId(null);
    }
  };

  const handleRunMonitoringNow = async (accountId: string) => {
    setRunningMonitoringId(accountId);
    try {
      const res = await api.post(`/monitoring/${accountId}/run`);
      setMonitoringFeedback((prev) => ({
        ...prev,
        [accountId]: `Run completed: ${res.data.new_findings} new, ${res.data.alerts_created} alerts generated.`,
      }));
      fetchAccounts();
      setTimeout(() => {
        setMonitoringFeedback((prev) => {
          const cp = { ...prev };
          delete cp[accountId];
          return cp;
        });
      }, 4000);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to execute continuous monitoring run.');
    } finally {
      setRunningMonitoringId(null);
    }
  };

  useEffect(() => {
    fetchAccounts();
  }, []);

  const handleTestConnection = async (id: string) => {
    try {
      setTestingId(id);
      const res = await api.post<TestConnectionResult>(`/cloud-accounts/${id}/test-connection`);
      setTestResults((prev) => ({ ...prev, [id]: res.data }));
      if (res.data?.status === 'CONNECTED') {
        markAccountVerified(id);
      }
    } catch (err: any) {
      setTestResults((prev) => ({
        ...prev,
        [id]: {
          status: 'ERROR',
          provider: 'UNKNOWN',
          message: err.response?.data?.detail || 'Connection test failed.',
        },
      }));
    } finally {
      setTestingId(null);
    }
  };

  const handleTriggerScan = async (accountId: string) => {
    try {
      setScanningId(accountId);
      setScanMsg(null);
      const res = await api.post('/scans', { account_id: accountId, cloud_account_id: accountId });
      setScanMsg(`Scan initiated for account! Resources discovered: ${res.data.resources_scanned}`);
      await fetchAccounts();
      navigate('/scans', { state: { accountId } });
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to trigger scan for cloud account.');
    } finally {
      setScanningId(null);
    }
  };

  const handleOpenDeleteModal = (account: CloudAccount) => {
    setDeleteModalAccount(account);
    setDeleteError(null);
  };

  const handleConfirmDelete = async () => {
    if (!deleteModalAccount) return;
    try {
      setDeletingAccount(true);
      setDeleteError(null);
      await api.delete(`/cloud-accounts/${deleteModalAccount.id}`);

      const remaining = accounts.filter((a) => a.id !== deleteModalAccount.id);
      setAccounts(remaining);

      // Smoothly update globally selected target account
      const currentStored = getStoredAccountId();
      if (currentStored === deleteModalAccount.id) {
        const nextId = resolvePreferredAccountId(remaining);
        setStoredAccountId(nextId);
      }

      setDeleteSuccess(`Cloud account "${deleteModalAccount.name}" and associated scan data removed successfully.`);
      setDeleteModalAccount(null);
      setTimeout(() => setDeleteSuccess(null), 5000);
    } catch (err: any) {
      setDeleteError(err.response?.data?.detail || 'Failed to delete cloud account.');
    } finally {
      setDeletingAccount(false);
    }
  };

  const handleCreateAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);
    try {
      const res = await api.post('/cloud-accounts', {
        name,
        provider,
        account_identifier: accountIdentifier,
        default_region: defaultRegion,
        credential_mode: roleArn ? 'ROLE' : credentialMode,
        role_arn: roleArn || undefined,
      });
      setShowAddModal(false);
      setName('');
      setAccountIdentifier('');
      setRoleArn('');
      if (res.data?.id) {
        setStoredAccountId(res.data.id, res.data);
      }
      await fetchAccounts();
    } catch (err: any) {
      setFormError(err.response?.data?.detail || 'Failed to register cloud account.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenRoleModal = (acc: CloudAccount) => {
    setRoleModalAccount(acc);
    setRoleArnInput(acc.role_arn || '');
    setRoleError(null);
    setRoleSuccess(null);
  };

  const handleSaveRole = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!roleModalAccount) return;
    setSavingRole(true);
    setRoleError(null);
    setRoleSuccess(null);

    try {
      const res = await api.patch<CloudAccount>(`/cloud-accounts/${roleModalAccount.id}`, {
        role_arn: roleArnInput.trim() || null,
        credential_mode: roleArnInput.trim() ? 'ROLE' : 'ENVIRONMENT',
      });
      setRoleSuccess('IAM Role configuration saved successfully.');
      setRoleModalAccount(res.data);
      if (res.data?.id) {
        setStoredAccountId(res.data.id, res.data);
      }
      await fetchAccounts();
    } catch (err: any) {
      setRoleError(err.response?.data?.detail || 'Failed to update IAM Role configuration.');
    } finally {
      setSavingRole(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono uppercase text-cyan-400 mb-1">
            <Server className="w-4 h-4" />
            Infrastructure & Accounts
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Cloud Accounts</h2>
          <p className="text-sm text-slate-400 mt-1">
            Manage target AWS and simulated cloud environments. Verified via read-only STS AssumeRole or provider chain.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchAccounts}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-xl border border-slate-700/80 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>

          {canManage && (
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold rounded-xl shadow-glow-cyan transition"
            >
              <Plus className="w-4 h-4" />
              Add Cloud Account
            </button>
          )}
        </div>
      </div>

      {/* Success Notifications */}
      {deleteSuccess && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-sm flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            {deleteSuccess}
          </div>
          <button onClick={() => setDeleteSuccess(null)} className="text-xs text-emerald-400 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {scanMsg && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            {scanMsg}
          </div>
          <button onClick={() => setScanMsg(null)} className="text-xs text-emerald-400 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-sm flex items-center gap-2">
          <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Accounts List */}
      {loading ? (
        <div className="flex flex-col items-center justify-center p-12 space-y-3 bg-slate-900/40 rounded-2xl border border-slate-800">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
          <p className="text-sm text-slate-400">Loading registered cloud accounts...</p>
        </div>
      ) : accounts.length === 0 ? (
        <div className="text-center p-12 bg-slate-900/40 rounded-2xl border border-slate-800">
          <Cloud className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-white">No Cloud Accounts Configured</h3>
          <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
            No cloud accounts are registered yet. Register your AWS account to begin scanning your cloud security posture.
          </p>
          {canManage && (
            <div className="mt-5">
              <button
                onClick={() => setShowAddModal(true)}
                className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold rounded-xl shadow-glow-cyan transition"
              >
                <Plus className="w-4 h-4" />
                Add Cloud Account
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {accounts.map((acc) => {
            const testRes = testResults[acc.id];
            const isTesting = testingId === acc.id;
            const isScanning = scanningId === acc.id;

            return (
              <div
                key={acc.id}
                className="glass-panel rounded-2xl border border-slate-800/80 p-5 space-y-4 hover:border-cyan-500/30 transition shadow-xl"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded-full border uppercase font-semibold ${
                          acc.provider === 'AWS'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        }`}
                      >
                        {acc.provider}
                      </span>
                      <span className="text-xs font-mono text-gray-400">ID: {acc.account_identifier}</span>
                    </div>
                    <h3 className="text-base font-bold text-white mt-1.5">{acc.name}</h3>
                  </div>

                  <span
                    className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold ${
                      acc.is_active
                        ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/40'
                        : 'bg-gray-800 text-gray-400'
                    }`}
                  >
                    {acc.is_active ? 'ACTIVE' : 'INACTIVE'}
                  </span>
                </div>

                {/* Metadata Grid */}
                <div className="grid grid-cols-2 gap-2 text-xs bg-slate-950/60 p-3 rounded-xl border border-slate-800/60">
                  <div>
                    <span className="text-slate-500 block text-[10px]">REGION</span>
                    <span className="font-mono text-slate-200 flex items-center gap-1 mt-0.5">
                      <Globe className="w-3 h-3 text-cyan-400" />
                      {acc.default_region}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">CREDENTIAL MODE</span>
                    <span className="font-mono text-slate-200 flex items-center gap-1 mt-0.5">
                      <KeyRound className="w-3 h-3 text-purple-400" />
                      {acc.credential_mode}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">TOTAL SCANS</span>
                    <span className="font-semibold text-white mt-0.5 block">{acc.total_scans}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">LATEST POSTURE</span>
                    <span className="font-semibold text-emerald-400 mt-0.5 block">
                      {acc.latest_scan?.security_score !== null && acc.latest_scan?.security_score !== undefined
                        ? `${acc.latest_scan.security_score}%`
                        : 'Not scanned'}
                    </span>
                  </div>
                </div>

                {/* AWS Cross-Account AssumeRole Info */}
                {acc.provider === 'AWS' && (
                  <div className="space-y-2 bg-slate-950/40 p-3 rounded-xl border border-slate-800/60 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-[11px] flex items-center gap-1">
                        <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                        Cross-Account STS Security:
                      </span>
                      {acc.role_arn ? (
                        <span className="text-[10px] text-emerald-400 bg-emerald-950/50 border border-emerald-800/50 px-2 py-0.5 rounded-md font-mono">
                          AssumeRole Configured
                        </span>
                      ) : (
                        <span className="text-[10px] text-amber-400 bg-amber-950/50 border border-amber-800/50 px-2 py-0.5 rounded-md font-mono">
                          Local Provider Chain
                        </span>
                      )}
                    </div>

                    {acc.external_id && (
                      <div className="flex items-center justify-between text-[11px] pt-1 border-t border-slate-900">
                        <span className="text-slate-500">External ID:</span>
                        <div className="flex items-center gap-1.5 font-mono text-slate-300">
                          <span>{acc.external_id}</span>
                          <button
                            onClick={() => copyToClipboard(acc.external_id!, `card-${acc.id}`)}
                            title="Copy External ID"
                            className="text-slate-400 hover:text-white transition"
                          >
                            {copiedField === `card-${acc.id}` ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </div>
                    )}

                    {acc.role_arn && (
                      <div className="text-[10px] text-slate-400 truncate font-mono">
                        Role: {acc.role_arn}
                      </div>
                    )}
                  </div>
                )}

                {/* Live Test Connection Result */}
                {testRes && (
                  <div
                    className={`p-3 rounded-xl text-xs space-y-1 ${
                      testRes.status === 'CONNECTED'
                        ? 'bg-emerald-950/30 border border-emerald-800/40 text-emerald-300'
                        : 'bg-rose-950/30 border border-rose-800/40 text-rose-300'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 font-semibold">
                      {testRes.status === 'CONNECTED' ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-rose-400" />
                      )}
                      <span>{testRes.message}</span>
                    </div>
                    {testRes.arn && (
                      <div className="font-mono text-[10px] text-slate-400 truncate">
                        Caller ARN: {testRes.arn}
                      </div>
                    )}
                  </div>
                )}

                {/* Continuous Monitoring Section */}
                <div className="bg-slate-950/40 p-3 rounded-xl border border-slate-800/60 text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[11px] flex items-center gap-1.5 font-medium">
                      <Radio className="w-3.5 h-3.5 text-blue-400" />
                      Continuous Monitoring:
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                        monitoringConfigs[acc.id]?.enabled
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {monitoringConfigs[acc.id]?.enabled ? '● ON' : 'OFF'}
                    </span>
                  </div>

                  {monitoringConfigs[acc.id]?.enabled ? (
                    /* When monitoring is ON: show timestamps + Run Now + Disable */
                    <div className="space-y-1.5 pt-1 border-t border-slate-900 text-[11px]">
                      {/* Last Scan timestamp */}
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Last Scan:</span>
                        <span className="font-mono text-slate-200">
                          {monitoringConfigs[acc.id]?.last_scan_at
                            ? new Date(monitoringConfigs[acc.id].last_scan_at!).toLocaleString()
                            : <span className="text-slate-500 italic">Not yet run</span>}
                        </span>
                      </div>
                      {/* Next Scan timestamp */}
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Next Scan:</span>
                        <span className="font-mono text-cyan-300">
                          {monitoringConfigs[acc.id]?.next_scan_at
                            ? new Date(monitoringConfigs[acc.id].next_scan_at!).toLocaleString()
                            : <span className="text-slate-500 italic">Pending</span>}
                        </span>
                      </div>
                      {/* Interval info */}
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Interval:</span>
                        <span className="font-mono text-slate-300">
                          {monitoringConfigs[acc.id]?.scan_interval_minutes >= 1440
                            ? '24 hours'
                            : monitoringConfigs[acc.id]?.scan_interval_minutes >= 60
                            ? `${(monitoringConfigs[acc.id]?.scan_interval_minutes / 60).toFixed(0)} hour(s)`
                            : `${monitoringConfigs[acc.id]?.scan_interval_minutes} min`}
                        </span>
                      </div>
                      {/* Action buttons */}
                      <div className="flex items-center gap-2 pt-1">
                        {canScan && (
                          <button
                            onClick={() => handleRunMonitoringNow(acc.id)}
                            disabled={runningMonitoringId === acc.id}
                            title="Trigger continuous monitoring evaluation now"
                            className="px-2.5 py-1 text-xs font-medium text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800/60 rounded-lg transition flex items-center gap-1"
                          >
                            {runningMonitoringId === acc.id ? (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            ) : (
                              'Run Now'
                            )}
                          </button>
                        )}
                        {canManage && (
                          <button
                            onClick={() => handleToggleMonitoring(acc.id)}
                            disabled={savingMonitoringId === acc.id}
                            className="px-2.5 py-1 text-xs font-semibold rounded-lg border bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700 transition flex items-center gap-1"
                          >
                            {savingMonitoringId === acc.id && <Loader2 className="w-3 h-3 animate-spin" />}
                            Disable
                          </button>
                        )}
                      </div>
                    </div>
                  ) : (
                    /* When monitoring is OFF: show interval selector + enable button */
                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-900 text-[11px]">
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-400">Interval:</span>
                        <select
                          value={monitoringConfigs[acc.id]?.scan_interval_minutes || 60}
                          onChange={(e) => handleUpdateInterval(acc.id, parseInt(e.target.value))}
                          disabled={savingMonitoringId === acc.id || !canManage}
                          className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded px-2 py-0.5 focus:outline-none focus:border-cyan-500 font-sans"
                        >
                          <option value={60}>60 minutes</option>
                          <option value={360}>6 hours</option>
                          <option value={1440}>24 hours</option>
                        </select>
                      </div>
                      {canManage && (
                        <button
                          onClick={() => handleToggleMonitoring(acc.id)}
                          disabled={savingMonitoringId === acc.id}
                          className="px-2.5 py-1 text-xs font-semibold rounded-lg border bg-blue-600 hover:bg-blue-500 text-white border-blue-500 shadow-sm transition flex items-center gap-1"
                        >
                          {savingMonitoringId === acc.id && <Loader2 className="w-3 h-3 animate-spin" />}
                          Enable Monitoring
                        </button>
                      )}
                    </div>
                  )}

                  {monitoringFeedback[acc.id] && (
                    <div className="text-[10px] text-cyan-300 font-mono bg-cyan-950/30 border border-cyan-800/40 p-1.5 rounded">
                      {monitoringFeedback[acc.id]}
                    </div>
                  )}

                  {acc.provider === 'MOCK' && (
                    <div className="text-[10px] text-amber-400/80 font-mono">
                      Simulated: Evaluates synthetic misconfiguration drift against MockProvider.
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800/80">
                  <div className="flex flex-wrap items-center gap-3">
                    {canManage && (
                      <button
                        onClick={() => handleTestConnection(acc.id)}
                        disabled={isTesting}
                        className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition"
                      >
                        {isTesting ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <RefreshCw className="w-3.5 h-3.5" />
                        )}
                        Test Connection
                      </button>
                    )}

                    {canManage && acc.provider === 'AWS' && (
                      <button
                        onClick={() => handleOpenRoleModal(acc)}
                        className="flex items-center gap-1.5 text-xs text-purple-400 hover:text-purple-300 transition"
                      >
                        <Key className="w-3.5 h-3.5" />
                        IAM Role Setup
                      </button>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {canScan && (
                      <button
                        onClick={() => handleTriggerScan(acc.id)}
                        disabled={isScanning}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-cyan-600/20 to-blue-600/20 hover:from-cyan-600/30 hover:to-blue-600/30 text-cyan-300 border border-cyan-500/30 text-xs font-semibold rounded-xl transition shadow-sm"
                      >
                        {isScanning ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Radio className="w-3.5 h-3.5" />
                        )}
                        Run Scan
                      </button>
                    )}

                    {canManage && (
                      <button
                        onClick={() => handleOpenDeleteModal(acc)}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-rose-400 hover:text-rose-300 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 rounded-xl transition shadow-sm"
                        title="Delete Cloud Account from CSPM"
                      >
                        <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                        Delete Account
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Add Cloud Account Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-[#0F172A] border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl backdrop-blur-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Cloud className="w-4 h-4 text-blue-400" />
                Register Cloud Account
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-gray-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-red-950/40 border border-red-800 text-red-300 text-xs rounded-lg">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreateAccount} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1">Account Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. AWS Production Workloads"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">Provider</label>
                  <select
                    value={provider}
                    onChange={(e) => setProvider(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="AWS">AWS</option>
                    <option value="MOCK">MOCK (Simulated)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">Account Identifier</label>
                  <input
                    type="text"
                    required
                    placeholder="12-digit AWS Account ID"
                    value={accountIdentifier}
                    onChange={(e) => setAccountIdentifier(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">Default Region</label>
                  <input
                    type="text"
                    required
                    value={defaultRegion}
                    onChange={(e) => setDefaultRegion(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">Credential Mode</label>
                  <select
                    value={credentialMode}
                    onChange={(e) => setCredentialMode(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="ENVIRONMENT">ENVIRONMENT (Default Provider Chain)</option>
                    <option value="ROLE">ROLE (Cross-Account AssumeRole)</option>
                    <option value="IAM_ROLE">IAM_ROLE (Instance/Task Profile)</option>
                    <option value="PROFILE">PROFILE (~/.aws/credentials)</option>
                    <option value="MOCK">MOCK (Demo)</option>
                  </select>
                </div>
              </div>

              {provider === 'AWS' && (
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">
                    IAM Role ARN <span className="text-gray-500 font-normal">(Optional — can be added later)</span>
                  </label>
                  <input
                    type="text"
                    placeholder="arn:aws:iam::123456789012:role/CSPM-ReadOnly-Role"
                    value={roleArn}
                    onChange={(e) => setRoleArn(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white placeholder-gray-500 font-mono focus:outline-none focus:border-blue-500"
                  />
                  <p className="text-[11px] text-gray-500 mt-1">
                    A unique External ID will be auto-generated for this account to secure the STS AssumeRole trust relationship.
                  </p>
                </div>
              )}

              {/* Zero Secret Storage Security Callout */}
              <div className="p-3 bg-blue-950/30 border border-blue-800/40 rounded-lg text-[11px] text-blue-300 space-y-1">
                <span className="font-semibold block text-blue-200">Zero-Secret Security Policy:</span>
                The CSPM platform never accepts or stores AWS access keys. Cross-account access uses temporary STS credentials via AssumeRole and unique External IDs.
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow transition flex items-center gap-1.5"
                >
                  {submitting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  Register Account
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* IAM Role Configuration & External ID Setup Drawer / Modal */}
      {roleModalAccount && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-gray-800 rounded-xl max-w-xl w-full p-6 space-y-5 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-purple-400" />
                  AWS Cross-Account IAM Role Setup
                </h3>
                <p className="text-xs text-gray-400 mt-0.5">
                  Target Account: <span className="font-mono text-gray-300">{roleModalAccount.account_identifier}</span> ({roleModalAccount.name})
                </p>
              </div>
              <button
                onClick={() => setRoleModalAccount(null)}
                className="text-gray-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            {roleError && (
              <div className="p-3 bg-red-950/40 border border-red-800 text-red-300 text-xs rounded-lg">
                {roleError}
              </div>
            )}

            {roleSuccess && (
              <div className="p-3 bg-emerald-950/40 border border-emerald-800 text-emerald-300 text-xs rounded-lg flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                {roleSuccess}
              </div>
            )}

            {/* Step 1: External ID */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-gray-200 flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-[11px] font-bold">1</span>
                  Generated External ID (Confused Deputy Safeguard)
                </label>
                {roleModalAccount.external_id && (
                  <button
                    onClick={() => copyToClipboard(roleModalAccount.external_id!, 'modal-ext-id')}
                    className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"
                  >
                    {copiedField === 'modal-ext-id' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                    {copiedField === 'modal-ext-id' ? 'Copied!' : 'Copy'}
                  </button>
                )}
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-lg p-2.5 font-mono text-xs text-amber-300 break-all select-all">
                {roleModalAccount.external_id || 'Not generated (legacy account)'}
              </div>
              <p className="text-[11px] text-gray-400">
                This unique identifier prevents unauthorized third-party cross-account confused deputy exploitation.
              </p>
            </div>

            {/* Step 2: Trust Policy Template */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-gray-200 flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-[11px] font-bold">2</span>
                  IAM Role Trust Policy Template
                </label>
                {roleModalAccount.trust_policy_snippet && (
                  <button
                    onClick={() => copyToClipboard(roleModalAccount.trust_policy_snippet!, 'modal-trust-policy')}
                    className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"
                  >
                    {copiedField === 'modal-trust-policy' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                    {copiedField === 'modal-trust-policy' ? 'Copied Policy!' : 'Copy Policy'}
                  </button>
                )}
              </div>
              <pre className="bg-gray-900 border border-gray-800 rounded-lg p-3 font-mono text-[11px] text-gray-300 overflow-x-auto select-all max-h-40">
                {roleModalAccount.trust_policy_snippet || 'No trust policy template available.'}
              </pre>
              <p className="text-[11px] text-gray-400">
                Paste this into the <strong>Trust Relationships</strong> tab of your IAM Role in the AWS Console. Attach AWS managed policy <code>SecurityAudit</code> for read-only scanner access.
              </p>
            </div>

            {/* Step 3: Role ARN Input & Save */}
            <form onSubmit={handleSaveRole} className="space-y-3 pt-2 border-t border-gray-800">
              <div>
                <label className="text-xs font-semibold text-gray-200 flex items-center gap-1.5 mb-1">
                  <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-[11px] font-bold">3</span>
                  Enter Created Role ARN
                </label>
                <input
                  type="text"
                  placeholder={`arn:aws:iam::${roleModalAccount.account_identifier}:role/CSPM-ReadOnly-Role`}
                  value={roleArnInput}
                  onChange={(e) => setRoleArnInput(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white placeholder-gray-500 font-mono focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex items-center justify-between pt-2">
                <button
                  type="button"
                  onClick={() => {
                    handleTestConnection(roleModalAccount.id);
                  }}
                  className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Test Live Connection
                </button>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setRoleModalAccount(null)}
                    className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium rounded-lg transition"
                  >
                    Close
                  </button>
                  <button
                    type="submit"
                    disabled={savingRole}
                    className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow transition flex items-center gap-1.5"
                  >
                    {savingRole && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    Save Role ARN
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteModalAccount && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-[#0F172A] border border-rose-900/50 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl backdrop-blur-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Trash2 className="w-5 h-5 text-rose-400" />
                Delete Cloud Account?
              </h3>
              <button
                onClick={() => setDeleteModalAccount(null)}
                className="text-slate-400 hover:text-white text-xs p-1"
                aria-label="Close"
              >
                ✕
              </button>
            </div>

            {deleteError && (
              <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-xl text-xs text-rose-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{deleteError}</span>
              </div>
            )}

            <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-800/80 space-y-2.5 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Account:</span>
                <span className="font-semibold text-white truncate max-w-[240px]">{deleteModalAccount.name}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400">AWS Account:</span>
                <span className="font-mono text-slate-200">{deleteModalAccount.account_identifier}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Region:</span>
                <span className="font-mono text-slate-200">{deleteModalAccount.default_region}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Credential Mode:</span>
                <span className="font-mono text-purple-300">{deleteModalAccount.credential_mode}</span>
              </div>
            </div>

            <div className="p-3.5 bg-amber-950/30 border border-amber-800/40 rounded-xl text-xs text-amber-200 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <p className="leading-relaxed">
                This removes this cloud account registration and its CSPM scan data. It does not delete or modify anything in AWS.
              </p>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setDeleteModalAccount(null)}
                disabled={deletingAccount}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-xl border border-slate-700 transition"
              >
                CANCEL
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                disabled={deletingAccount}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded-xl transition flex items-center gap-1.5 shadow-lg shadow-rose-900/30 disabled:opacity-50"
              >
                {deletingAccount ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    DELETING...
                  </>
                ) : (
                  <>
                    <Trash2 className="w-3.5 h-3.5" />
                    DELETE ACCOUNT
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
