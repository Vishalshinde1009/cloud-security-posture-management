import { useState, useEffect, FormEvent } from 'react';
import api from '../services/api';
import { Finding, FindingListResponse } from '../types/finding';

export const Findings = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedStatus, setSelectedStatus] = useState<string>('OPEN');
  const [selectedService, setSelectedService] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Inspector
  const [inspectingFinding, setInspectingFinding] = useState<Finding | null>(null);
  const [inspectingLoading, setInspectingLoading] = useState<boolean>(false);

  const services = ['S3', 'IAM', 'EC2', 'VPC', 'CloudTrail', 'RDS'];

  const fetchFindings = async () => {
    try {
      setLoading(true);
      setError(null);
      let query = '/findings?limit=50';
      if (selectedSeverity) query += `&severity=${encodeURIComponent(selectedSeverity)}`;
      if (selectedStatus) query += `&status=${encodeURIComponent(selectedStatus)}`;
      if (selectedService) query += `&service=${encodeURIComponent(selectedService)}`;
      if (searchTerm) query += `&search=${encodeURIComponent(searchTerm)}`;

      const res = await api.get<FindingListResponse>(query);
      setFindings(res.data.items);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load security findings.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [selectedSeverity, selectedStatus, selectedService]);

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
            <h1 className="text-2xl font-bold tracking-tight text-white">Security Misconfiguration Findings</h1>
            <span className="px-2.5 py-1 text-xs font-mono font-medium uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 rounded-md">
              RULE ENGINE ACTIVE
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Evidence-backed security misconfigurations detected across discovered cloud assets.
          </p>
        </div>

        <button
          onClick={fetchFindings}
          disabled={loading}
          className="px-3.5 py-2 text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 self-start md:self-auto"
        >
          <svg className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh Findings
        </button>
      </div>

      {/* Filter Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Severity Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs font-medium text-slate-400 mr-1">Severity:</span>
            {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev || 'all'}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                  selectedSeverity === sev
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                }`}
              >
                {sev || 'All'}
              </button>
            ))}
          </div>

          {/* Status Pills */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-medium text-slate-400 mr-1">Status:</span>
            {['', 'OPEN', 'RESOLVED'].map((st) => (
              <button
                key={st || 'all'}
                onClick={() => setSelectedStatus(st)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                  selectedStatus === st
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                }`}
              >
                {st || 'All'}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/60">
          {/* Service filter */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs font-medium text-slate-400 mr-1">Service:</span>
            <button
              onClick={() => setSelectedService('')}
              className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                selectedService === '' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              All
            </button>
            {services.map((srv) => (
              <button
                key={srv}
                onClick={() => setSelectedService(selectedService === srv ? '' : srv)}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                  selectedService === srv ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {srv}
              </button>
            ))}
          </div>

          {/* Text Search */}
          <form onSubmit={handleSearchSubmit} className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Search finding or rule ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-slate-300 placeholder-slate-500 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500 w-52"
            />
            <button
              type="submit"
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs text-slate-300"
            >
              Search
            </button>
          </form>
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800/70 text-sm text-rose-300">
          {error}
        </div>
      )}

      {/* Findings Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Active Violations ({findings.length})</h2>
          <span className="text-xs text-slate-500">Every finding is supported by concrete configuration evidence</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-400 text-sm">
            <svg className="animate-spin w-6 h-6 mx-auto mb-2 text-blue-500" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
            Loading security findings...
          </div>
        ) : findings.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <p className="text-base font-medium text-slate-300">No security findings match the current filter criteria</p>
            <p className="text-xs text-slate-500 mt-1">
              Trigger a scan from the Cloud Scans tab or clear your filters.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-800/50 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Rule ID</th>
                  <th className="px-4 py-3">Finding Title & Technical Detail</th>
                  <th className="px-4 py-3">Affected Asset</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => handleInspect(f)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3">
                      {getSeverityBadge(f.severity)}
                    </td>
                    <td className="px-4 py-3 font-mono font-bold text-slate-300">
                      {f.rule_code || 'RULE'}
                    </td>
                    <td className="px-4 py-3 max-w-md">
                      <div className="font-semibold text-slate-200">{f.title}</div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">{f.description}</div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-slate-300">{f.resource_name || f.resource_identifier}</div>
                      <div className="font-mono text-[11px] text-slate-500">{f.service} &bull; {f.resource_identifier}</div>
                    </td>
                    <td className="px-4 py-3">
                      {f.status === 'OPEN' ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950/60 text-rose-300 border border-rose-800/60">
                          OPEN
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
                          RESOLVED
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleInspect(f);
                        }}
                        className="text-blue-400 hover:text-blue-300 underline font-mono text-xs"
                      >
                        Inspect Evidence &rarr;
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Evidence Inspector Modal */}
      {inspectingFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-800/40">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  {getSeverityBadge(inspectingFinding.severity)}
                  <span className="font-mono text-xs font-bold text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                    {inspectingFinding.rule_code}
                  </span>
                  <h3 className="text-base font-semibold text-white">
                    {inspectingFinding.title}
                  </h3>
                </div>
                <p className="text-xs text-slate-400 font-mono">
                  Asset: {inspectingFinding.resource_name || inspectingFinding.resource_identifier} ({inspectingFinding.service}) &bull; Status: {inspectingFinding.status}
                </p>
              </div>

              <button
                onClick={() => setInspectingFinding(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-4">
              {/* Reason / Details */}
              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700 text-xs space-y-1">
                <div className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">Technical Finding Explanation</div>
                <p className="text-slate-200">{inspectingFinding.description}</p>
              </div>

              {/* Concrete Configuration Evidence */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Offending Configuration Evidence (SDK Snapshot)</h4>
                  <span className="text-[11px] font-mono text-emerald-400">Verifiable JSON Payload</span>
                </div>
                {inspectingLoading ? (
                  <div className="p-4 text-center text-slate-400 text-xs">Loading evidence...</div>
                ) : (
                  <pre className="bg-slate-950 p-4 rounded-lg border border-slate-800 text-emerald-400 font-mono text-xs overflow-x-auto max-h-64">
                    {JSON.stringify(inspectingFinding.evidence || {}, null, 2)}
                  </pre>
                )}
              </div>

              {/* Remediation Guidance */}
              <div className="p-3 bg-blue-950/20 rounded-lg border border-blue-900/40 text-xs space-y-1">
                <div className="font-semibold text-blue-300 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Recommended Remediation Guidance
                </div>
                <p className="text-slate-300">{inspectingFinding.remediation || 'Review configuration against AWS security guidelines.'}</p>
              </div>

              {/* Timeline & Scoring Metadata */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3 p-3 bg-slate-800/30 rounded-lg text-xs font-mono text-slate-400">
                <div>
                  <div className="text-[10px] uppercase text-slate-500">Base Severity Score</div>
                  <div className="text-white font-semibold">{inspectingFinding.risk_score} / 100</div>
                  <div className="text-[9px] text-slate-500 italic">Phase 6 Contextual Scoring Pending</div>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-slate-500">First Detected</div>
                  <div className="text-slate-300">{new Date(inspectingFinding.first_detected).toLocaleDateString()}</div>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-slate-500">Last Detected</div>
                  <div className="text-slate-300">{new Date(inspectingFinding.last_detected).toLocaleString()}</div>
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
