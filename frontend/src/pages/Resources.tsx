import { useState, useEffect, FormEvent } from 'react';
import api from '../services/api';
import { CloudResource, ResourceListResponse } from '../types/scanner';

export const Resources = () => {
  const [resources, setResources] = useState<CloudResource[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  
  // Filter state
  const [selectedService, setSelectedService] = useState<string>('');
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState<string>('');
  
  // Inspector state
  const [inspectingResource, setInspectingResource] = useState<CloudResource | null>(null);
  const [inspectingLoading, setInspectingLoading] = useState<boolean>(false);

  const services = ['S3', 'IAM', 'EC2', 'VPC', 'CloudTrail', 'RDS'];

  const fetchResources = async () => {
    try {
      setLoading(true);
      setError(null);
      let query = '/resources?limit=50';
      if (selectedService) query += `&service=${encodeURIComponent(selectedService)}`;
      if (selectedStatus) query += `&security_status=${encodeURIComponent(selectedStatus)}`;
      if (searchTerm) query += `&search=${encodeURIComponent(searchTerm)}`;

      const res = await api.get<ResourceListResponse>(query);
      setResources(res.data.items);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load cloud resources.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResources();
  }, [selectedService, selectedStatus]);

  const handleSearchSubmit = (e: FormEvent) => {
    e.preventDefault();
    fetchResources();
  };

  const handleInspect = async (res: CloudResource) => {
    try {
      setInspectingLoading(true);
      const detail = await api.get<CloudResource>(`/resources/${res.id}`);
      setInspectingResource(detail.data);
    } catch (err: any) {
      setError('Failed to fetch detailed resource configuration.');
    } finally {
      setInspectingLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white">Discovered Cloud Resources</h1>
            <span className="px-2.5 py-1 text-xs font-mono font-medium uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 rounded-md">
              MOCK INVENTORY
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Unified normalized multi-service asset inventory discovered from cloud configurations.
          </p>
        </div>

        <button
          onClick={fetchResources}
          disabled={loading}
          className="px-3.5 py-2 text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 self-start md:self-auto"
        >
          <svg className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh Inventory
        </button>
      </div>

      {/* Filters Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        {/* Service pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setSelectedService('')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              selectedService === ''
                ? 'bg-blue-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
            }`}
          >
            All Services
          </button>
          {services.map((srv) => (
            <button
              key={srv}
              onClick={() => setSelectedService(srv === selectedService ? '' : srv)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                selectedService === srv
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
              }`}
            >
              {srv}
            </button>
          ))}
        </div>

        {/* Search & Status Filters */}
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            aria-label="Filter by Security Status"
            className="bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="">All Statuses</option>
            <option value="SECURE">Secure</option>
            <option value="AT_RISK">At Risk</option>
            <option value="PENDING_ANALYSIS">Pending Analysis</option>
          </select>

          <form onSubmit={handleSearchSubmit} className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Search resource..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-slate-300 placeholder-slate-500 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500 w-44"
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

      {/* Inventory Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Discovered Assets ({resources.length})</h2>
          <span className="text-xs text-slate-500">Click any row to inspect configuration JSON evidence</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-400 text-sm">
            <svg className="animate-spin w-6 h-6 mx-auto mb-2 text-blue-500" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
            Loading inventory...
          </div>
        ) : resources.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <p className="text-base font-medium text-slate-300">No resources found</p>
            <p className="text-xs text-slate-500 mt-1">
              Trigger a scan on the Scans page or adjust your search filters.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-800/50 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Service</th>
                  <th className="px-4 py-3">Resource Type</th>
                  <th className="px-4 py-3">Resource Identifier / Name</th>
                  <th className="px-4 py-3">Region</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {resources.map((res) => (
                  <tr
                    key={res.id}
                    onClick={() => handleInspect(res)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                        {res.service}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400">
                      {res.resource_type}
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-slate-200">{res.resource_name || res.resource_id}</div>
                      <div className="font-mono text-[11px] text-slate-500">{res.resource_id}</div>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400">
                      {res.region || 'global'}
                    </td>
                    <td className="px-4 py-3">
                      {res.security_status === 'SECURE' ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-950/70 text-emerald-400 border border-emerald-800/60">
                          SECURE
                        </span>
                      ) : res.security_status === 'AT_RISK' ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-950/70 text-rose-400 border border-rose-800/60">
                          AT RISK
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-slate-800 text-slate-400">
                          {res.security_status}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleInspect(res);
                        }}
                        className="text-blue-400 hover:text-blue-300 underline text-xs font-mono"
                      >
                        Inspect Config &rarr;
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Configuration Inspector Modal / Drawer */}
      {inspectingResource && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-800/40">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-blue-900/60 text-blue-300 border border-blue-700/50">
                    {inspectingResource.service}
                  </span>
                  <h3 className="text-base font-semibold text-white">
                    {inspectingResource.resource_name || inspectingResource.resource_id}
                  </h3>
                </div>
                <p className="text-xs font-mono text-slate-400 mt-1">
                  ID: {inspectingResource.resource_id} &bull; Region: {inspectingResource.region || 'global'} &bull; Provider: {inspectingResource.provider}
                </p>
              </div>

              <button
                onClick={() => setInspectingResource(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-4">
              {/* Tags */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Resource Tags</h4>
                {inspectingResource.tags && Object.keys(inspectingResource.tags).length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(inspectingResource.tags).map(([key, val]) => (
                      <span key={key} className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300">
                        <span className="text-slate-400">{key}:</span> {String(val)}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">No tags assigned</p>
                )}
              </div>

              {/* Raw Configuration JSON */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Configuration Evidence (SDK Response)</h4>
                  <span className="text-[11px] font-mono text-slate-500">Read-Only Evidence Snapshot</span>
                </div>
                {inspectingLoading ? (
                  <div className="p-4 text-center text-slate-400 text-xs">Loading configuration...</div>
                ) : (
                  <pre className="bg-slate-950 p-4 rounded-lg border border-slate-800 text-emerald-400 font-mono text-xs overflow-x-auto max-h-96">
                    {JSON.stringify(inspectingResource.configuration || {}, null, 2)}
                  </pre>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-800/20 flex justify-end">
              <button
                onClick={() => setInspectingResource(null)}
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
