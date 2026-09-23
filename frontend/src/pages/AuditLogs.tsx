import { useState, useEffect } from 'react';
import { 
  History, 
  Search, 
  CheckCircle2, 
  XCircle, 
  User, 
  Terminal,
  Eye,
  ShieldAlert,
  Shield
} from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

interface AuditLogItem {
  id: string;
  user_id?: string;
  username: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  result: string;
  metadata_json: Record<string, any>;
  ip_address?: string;
  created_at: string;
}

export function AuditLogs() {
  const { hasRole } = useAuth();
  const isViewer = !hasRole(['ADMIN', 'SECURITY_ANALYST']);

  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionFilter, setActionFilter] = useState<string>('');
  const [resultFilter, setResultFilter] = useState<string>('');
  const [selectedLog, setSelectedLog] = useState<AuditLogItem | null>(null);
  const [forbidden, setForbidden] = useState<boolean>(false);

  useEffect(() => {
    fetchLogs();
  }, [page, actionFilter, resultFilter]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      setForbidden(false);
      const res = await api.get('/audit-logs', {
        params: {
          action: actionFilter || undefined,
          result: resultFilter || undefined,
          page,
          limit: 25,
        },
      });
      setLogs(res.data.items);
      setTotal(res.data.total);
    } catch (err: any) {
      if (err.response?.status === 403) {
        setForbidden(true);
      } else {
        console.error('Failed to load audit logs', err);
      }
    } finally {
      setLoading(false);
    }
  };

  const getActionBadge = (action: string) => {
    if (action.includes('LOGIN') || action.includes('LOGOUT')) {
      return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
    }
    if (action.includes('SCAN')) {
      return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    }
    if (action.includes('FINDING')) {
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    }
    if (action.includes('RULE')) {
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    }
    return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <History className="w-6 h-6 text-blue-400" />
          System & Security Audit Trail
        </h1>
        <p className="text-xs text-gray-400 mt-1">
          Immutable audit record of user authentications, scan executions, finding workflow transitions, and administrative configurations.
        </p>
      </div>

      {/* Viewer Scope Informational Label */}
      {isViewer && !forbidden && (
        <div className="flex items-center gap-2 px-3.5 py-2.5 bg-blue-950/30 border border-blue-800/50 rounded-xl text-xs text-blue-300">
          <Shield className="w-4 h-4 text-blue-400 shrink-0" />
          <span>Showing audit activity for your account and registered cloud resources.</span>
        </div>
      )}

      {forbidden ? (
        <div className="bg-gray-900/40 border border-gray-800 rounded-xl p-12 text-center max-w-2xl mx-auto space-y-4 shadow-xl">
          <div className="w-12 h-12 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center mx-auto">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <h3 className="text-base font-bold text-white">Administrator Access Required</h3>
          <p className="text-xs text-gray-400 max-w-md mx-auto leading-relaxed">
            The platform audit trail is restricted to administrators and security analysts (<code className="text-blue-400">read:audit_logs</code>). Tenant activity (including authentications, scans, and account registrations) is securely captured for compliance, but viewing global system audit events requires elevated privileges.
          </p>
        </div>
      ) : (
        <>
          {/* Filters */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-gray-900/60 p-3 rounded-xl border border-gray-800">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Filter action (e.g. SCAN, FINDING, LOGIN)..."
                value={actionFilter}
                onChange={(e) => {
                  setActionFilter(e.target.value);
                  setPage(1);
                }}
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-gray-800/80 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <select
                value={resultFilter}
                onChange={(e) => {
                  setResultFilter(e.target.value);
                  setPage(1);
                }}
                className="px-3 py-1.5 text-xs bg-gray-800 border border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:border-blue-500"
              >
                <option value="">All Results</option>
                <option value="SUCCESS">Success Only</option>
                <option value="FAILURE">Failures / Denied</option>
              </select>
            </div>
          </div>

          {/* Audit Log Table */}
          <div className="bg-gray-900/40 border border-gray-800 rounded-xl overflow-hidden">
            {loading ? (
              <div className="p-12 text-center text-xs text-gray-400">Loading audit records...</div>
            ) : logs.length === 0 ? (
              <div className="p-12 text-center text-xs text-gray-400">No audit events match your filter criteria.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-gray-300">
                  <thead className="bg-gray-800/50 text-[11px] uppercase tracking-wider text-gray-400 border-b border-gray-800">
                    <tr>
                      <th className="px-4 py-3">Timestamp</th>
                      <th className="px-4 py-3">User</th>
                      <th className="px-4 py-3">Action</th>
                      <th className="px-4 py-3">Resource Target</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Client IP</th>
                      <th className="px-4 py-3 text-right">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/60">
                    {logs.map((log) => {
                      const isSuccess = log.result === 'SUCCESS';
                      return (
                        <tr key={log.id} className="hover:bg-gray-800/30 transition">
                          <td className="px-4 py-3 text-gray-400 font-mono text-[11px] whitespace-nowrap">
                            {new Date(log.created_at).toLocaleString()}
                          </td>
                          <td className="px-4 py-3 whitespace-nowrap">
                            <div className="flex items-center gap-1.5 text-white font-medium">
                              <User className="w-3.5 h-3.5 text-gray-400" />
                              {log.username}
                            </div>
                          </td>
                          <td className="px-4 py-3 whitespace-nowrap">
                            <span className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold ${getActionBadge(log.action)}`}>
                              {log.action}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-gray-400 font-mono text-[11px] whitespace-nowrap">
                            {log.resource_type ? `${log.resource_type} ${log.resource_id ? `(${log.resource_id.slice(0, 8)})` : ''}` : 'Global'}
                          </td>
                          <td className="px-4 py-3 whitespace-nowrap">
                            <div className="flex items-center gap-1">
                              {isSuccess ? (
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <XCircle className="w-3.5 h-3.5 text-red-400" />
                              )}
                              <span className={`text-[11px] font-semibold ${isSuccess ? 'text-emerald-400' : 'text-red-400'}`}>
                                {log.result}
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-gray-400 font-mono text-[11px] whitespace-nowrap">
                            {log.ip_address || '127.0.0.1'}
                          </td>
                          <td className="px-4 py-3 text-right whitespace-nowrap">
                            <button
                              onClick={() => setSelectedLog(log)}
                              className="text-blue-400 hover:text-blue-300 text-xs inline-flex items-center gap-1"
                            >
                              <Eye className="w-3.5 h-3.5" />
                              View
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Pagination */}
          {total > 25 && (
            <div className="flex items-center justify-between text-xs text-gray-400 px-1">
              <div>
                Showing {(page - 1) * 25 + 1} - {Math.min(page * 25, total)} of {total} events
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 bg-gray-800 rounded disabled:opacity-40 hover:bg-gray-700 text-gray-200"
                >
                  Previous
                </button>
                <span className="font-mono text-white">{page}</span>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  disabled={page * 25 >= total}
                  className="px-3 py-1 bg-gray-800 rounded disabled:opacity-40 hover:bg-gray-700 text-gray-200"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Metadata Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-blue-400" />
                Audit Event Metadata: {selectedLog.action}
              </h2>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-gray-400 hover:text-white text-xs"
              >
                Close
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-gray-800/60">
                <span className="text-gray-400">Event ID:</span>
                <span className="font-mono text-gray-200">{selectedLog.id}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-gray-800/60">
                <span className="text-gray-400">Actor:</span>
                <span className="text-white font-semibold">{selectedLog.username}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-gray-800/60">
                <span className="text-gray-400">Timestamp:</span>
                <span className="font-mono text-gray-300">{selectedLog.created_at}</span>
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">
                Context Payload:
              </div>
              <pre className="p-3 bg-gray-950 border border-gray-800 rounded-lg text-emerald-400 font-mono text-[11px] max-h-60 overflow-y-auto">
                {JSON.stringify(selectedLog.metadata_json, null, 2)}
              </pre>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
