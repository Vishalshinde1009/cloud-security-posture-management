import { useState, useEffect } from 'react';
import api from '../services/api';
import { SecurityRule, RuleListResponse } from '../types/finding';

export const Rules = () => {
  const [rules, setRules] = useState<SecurityRule[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedService, setSelectedService] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedRule, setSelectedRule] = useState<SecurityRule | null>(null);

  const services = ['S3', 'IAM', 'EC2', 'VPC', 'CloudTrail', 'RDS'];

  const fetchRules = async () => {
    try {
      setLoading(true);
      setError(null);
      let query = '/rules?limit=100';
      if (selectedService) query += `&service=${encodeURIComponent(selectedService)}`;
      if (selectedSeverity) query += `&severity=${encodeURIComponent(selectedSeverity)}`;

      const res = await api.get<RuleListResponse>(query);
      setRules(res.data.items);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load security rules catalog.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, [selectedService, selectedSeverity]);

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950/70 text-rose-300 border border-rose-800/80">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950/70 text-amber-300 border border-amber-800/80">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-yellow-950/60 text-yellow-300 border border-yellow-800/70">
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-blue-950/60 text-blue-300 border border-blue-800/70">
            LOW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-300">
            {severity}
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
            <h1 className="text-2xl font-bold tracking-tight text-white">CSPM Security Rules Catalog</h1>
            <span className="px-2.5 py-1 text-xs font-mono font-medium uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 rounded-md">
              26 RULES LOADED
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Modular cybersecurity detection rule definitions aligned with CIS AWS Foundations benchmarks.
          </p>
        </div>

        <button
          onClick={fetchRules}
          disabled={loading}
          className="px-3.5 py-2 text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 self-start md:self-auto"
        >
          <svg className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh Catalog
        </button>
      </div>

      {/* Filter Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        {/* Service filter */}
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setSelectedService('')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              selectedService === '' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            All Services
          </button>
          {services.map((srv) => (
            <button
              key={srv}
              onClick={() => setSelectedService(selectedService === srv ? '' : srv)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                selectedService === srv ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {srv}
            </button>
          ))}
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Severity:</span>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            aria-label="Filter by Severity"
            className="bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800/70 text-sm text-rose-300">
          {error}
        </div>
      )}

      {/* Rules Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Detection Catalog ({rules.length})</h2>
          <span className="text-xs text-slate-500">Pure detection logic &bull; Zero modification actions</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-400 text-sm">
            <svg className="animate-spin w-6 h-6 mx-auto mb-2 text-blue-500" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
            Loading security rules...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-800/50 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Rule ID</th>
                  <th className="px-4 py-3">Title & Detection Purpose</th>
                  <th className="px-4 py-3">Service</th>
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {rules.map((rule) => (
                  <tr
                    key={rule.id}
                    onClick={() => setSelectedRule(rule)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3 font-mono font-bold text-blue-400">
                      {rule.rule_id}
                    </td>
                    <td className="px-4 py-3 max-w-md">
                      <div className="font-semibold text-slate-200">{rule.title}</div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">{rule.description}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                        {rule.service}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300 font-sans">
                      {rule.category}
                    </td>
                    <td className="px-4 py-3">
                      {getSeverityBadge(rule.severity)}
                    </td>
                    <td className="px-4 py-3">
                      {rule.enabled ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
                          Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-500">
                          Disabled
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Rule Detail Modal */}
      {selectedRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-800/40">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-blue-400 bg-slate-800 px-2.5 py-1 rounded border border-slate-700">
                  {selectedRule.rule_id}
                </span>
                <h3 className="text-base font-semibold text-white">{selectedRule.title}</h3>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 text-xs">
              <div className="space-y-1">
                <div className="font-semibold uppercase tracking-wider text-slate-400 text-[11px]">Description & Detection Criteria</div>
                <p className="text-slate-300 leading-relaxed bg-slate-800/40 p-3 rounded-lg border border-slate-700/60">{selectedRule.description}</p>
              </div>

              <div className="space-y-1">
                <div className="font-semibold uppercase tracking-wider text-blue-400 text-[11px]">Remediation Guidance</div>
                <p className="text-slate-300 leading-relaxed bg-blue-950/20 p-3 rounded-lg border border-blue-900/40">{selectedRule.remediation}</p>
              </div>

              <div className="grid grid-cols-2 gap-3 p-3 bg-slate-800/30 rounded-lg font-mono">
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">Service Scope</span>
                  <span className="text-slate-200">{selectedRule.service} ({selectedRule.resource_type})</span>
                </div>
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">Category</span>
                  <span className="text-slate-200">{selectedRule.category}</span>
                </div>
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">Default Severity</span>
                  <span className="text-slate-200">{selectedRule.severity}</span>
                </div>
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">Execution Mode</span>
                  <span className="text-emerald-400">Pure Detection</span>
                </div>
              </div>

              {selectedRule.references && selectedRule.references.length > 0 && (
                <div className="space-y-1">
                  <div className="font-semibold uppercase tracking-wider text-slate-400 text-[11px]">Compliance & Industry References</div>
                  <ul className="space-y-1 text-slate-300 font-mono text-[11px]">
                    {selectedRule.references.map((ref, idx) => (
                      <li key={idx} className="flex items-center gap-2">
                        <span className="text-blue-400">&bull;</span>
                        {ref.startsWith('http') ? (
                          <a href={ref} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                            {ref}
                          </a>
                        ) : (
                          <span>{ref}</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-800/20 flex justify-end">
              <button
                onClick={() => setSelectedRule(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg border border-slate-700"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
