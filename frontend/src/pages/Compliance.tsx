import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Search, 
  Info, 
  ChevronRight
} from 'lucide-react';
import api from '../services/api';
import { useCountUp } from '../hooks/useCountUp';
import { resolvePreferredAccountId, getStoredAccountId, setStoredAccountId } from '../utils/accountSelection';

interface FrameworkSummary {
  framework: string;
  framework_name: string;
  total_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  compliance_percentage: number;
  status_label: string;
  critical_findings_count: number;
  high_findings_count: number;
  total_findings_mapped: number;
}

interface ControlItem {
  id: string;
  framework: string;
  control_id: string;
  control_title: string;
  description: string;
  status: 'COMPLIANT' | 'NON_COMPLIANT';
  rule_id: string;
  rule_title: string;
  severity: string;
  service: string;
  remediation: string;
  open_findings_count: number;
  findings: Array<{
    id: string;
    finding_identifier: string;
    title: string;
    severity: string;
    risk_score: number;
    resource_name?: string;
  }>;
}

interface CloudAccountOption {
  id: string;
  name: string;
  provider: string;
  is_active?: boolean;
  role_arn?: string | null;
  credential_mode?: string;
  account_identifier?: string;
}

function FrameworkCard({
  framework,
  summary,
  isSelected,
  onSelect,
}: {
  framework: { id: string; name: string };
  summary?: FrameworkSummary | null;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const percentage = summary?.compliance_percentage ?? 0;
  const animatedPct = useCountUp(percentage, 1000, 1);
  const radius = 22;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <button
      onClick={onSelect}
      className={`p-4 rounded-2xl border text-left transition-all flex items-center justify-between gap-3 ${
        isSelected
          ? 'bg-slate-900 border-cyan-500 shadow-glow-cyan'
          : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
      }`}
    >
      <div className="space-y-1">
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-300 uppercase font-semibold">
          {framework.id.replace('_', ' ')}
        </span>
        <h4 className="text-xs font-bold text-white leading-tight line-clamp-1">
          {framework.name}
        </h4>
        <div className="text-[11px] text-slate-400">
          {summary ? `${summary.compliant_controls}/${summary.total_controls} controls passing` : 'Evaluating...'}
        </div>
      </div>

      {/* Radial Meter */}
      <div className="relative w-14 h-14 flex-shrink-0 flex items-center justify-center">
        <svg className="w-14 h-14 -rotate-90 transform" viewBox="0 0 56 56">
          <circle cx="28" cy="28" r={radius} stroke="currentColor" strokeWidth="4" className="text-slate-800" fill="transparent" />
          <circle
            cx="28"
            cy="28"
            r={radius}
            stroke="currentColor"
            strokeWidth="4"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className={`transition-all duration-700 ease-out ${
              percentage >= 80 ? 'text-emerald-400' :
              percentage >= 50 ? 'text-amber-400' : 'text-rose-500'
            }`}
            fill="transparent"
          />
        </svg>
        <span className="absolute text-[11px] font-mono font-bold text-white">
          {summary ? `${animatedPct}%` : '--'}
        </span>
      </div>
    </button>
  );
}

export function Compliance() {
  const frameworks = [
    { id: 'CIS_AWS', name: 'CIS AWS Foundations Benchmark v1.4.0' },
    { id: 'NIST', name: 'NIST SP 800-53 Rev. 5' },
    { id: 'ISO27001', name: 'ISO/IEC 27001:2022' },
    { id: 'PCI_DSS', name: 'PCI DSS v4.0' },
  ];
  const [selectedFramework, setSelectedFramework] = useState<string>('CIS_AWS');
  const [summary, setSummary] = useState<FrameworkSummary | null>(null);
  const [allSummaries, setAllSummaries] = useState<Record<string, FrameworkSummary>>({});
  const [controls, setControls] = useState<ControlItem[]>([]);
  const [accounts, setAccounts] = useState<CloudAccountOption[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<string>('');
  const [systemMode, setSystemMode] = useState<string>('mock');
  const [loading, setLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [serviceFilter, setServiceFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedControl, setExpandedControl] = useState<string | null>(null);

  useEffect(() => {
    Promise.all(
      frameworks.map((fw) =>
        api
          .get(`/compliance/${fw.id}/summary`, {
            params: { account_id: selectedAccountId || undefined },
          })
          .then((res) => ({ id: fw.id, data: res.data }))
          .catch(() => null)
      )
    ).then((results) => {
      const map: Record<string, FrameworkSummary> = {};
      results.forEach((r) => {
        if (r) map[r.id] = r.data;
      });
      setAllSummaries(map);
    });
  }, [selectedAccountId]);

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

  useEffect(() => {
    fetchFrameworkData(selectedFramework);
  }, [selectedFramework, selectedAccountId, statusFilter, serviceFilter]);

  const fetchFrameworkData = async (fw: string) => {
    setLoading(true);
    try {
      const [sumRes, ctrlRes] = await Promise.all([
        api.get(`/compliance/${fw}/summary`, {
          params: {
            account_id: selectedAccountId || undefined,
          },
        }),
        api.get(`/compliance/${fw}/controls`, {
          params: {
            account_id: selectedAccountId || undefined,
            status_filter: statusFilter || undefined,
            service: serviceFilter || undefined,
          },
        }),
      ]);
      setSummary(sumRes.data);
      setControls(ctrlRes.data);
    } catch (err) {
      console.error('Failed to load compliance data', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredControls = controls.filter((ctrl) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      ctrl.control_id.toLowerCase().includes(q) ||
      ctrl.control_title.toLowerCase().includes(q) ||
      ctrl.description.toLowerCase().includes(q) ||
      ctrl.rule_id.toLowerCase().includes(q)
    );
  });

  const selectedAccount = accounts.find((a) => a.id === selectedAccountId);
  const isAws = selectedAccount?.provider === 'AWS' || (!selectedAccount && systemMode === 'aws');

  return (
    <div className="space-y-6">
      {/* Header & Disclaimer */}
      <div>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-6 h-6 text-blue-400" />
                Security Control Compliance & Benchmarks
              </h1>
              {isAws ? (
                <span className="px-2.5 py-1 text-xs font-mono font-semibold uppercase tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded-md flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                  AWS COMPLIANCE ALIGNMENT
                </span>
              ) : (
                <span className="px-2.5 py-1 text-xs font-mono font-semibold uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 rounded-md">
                  MOCK COMPLIANCE ALIGNMENT
                </span>
              )}
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Automated mapping of discovered technical configurations against standard security frameworks.
            </p>
          </div>

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
        </div>

        {/* Academic / Non-certification Disclaimer Banner */}
        <div className="mt-3 p-3 bg-blue-950/40 border border-blue-800/60 rounded-lg flex items-start gap-2 text-xs text-blue-200">
          <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-white">Compliance Posture Note:</span> Control statuses represent internal security alignment and gap detection based on automated rule evaluations. This analysis does not constitute formal third-party regulatory certification or official compliance endorsement.
          </div>
        </div>
      </div>

      {/* Framework Cards with Circular Gauges */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {frameworks.map((fw) => (
          <FrameworkCard
            key={fw.id}
            framework={fw}
            summary={allSummaries[fw.id] || (selectedFramework === fw.id ? summary : null)}
            isSelected={selectedFramework === fw.id}
            onSelect={() => setSelectedFramework(fw.id)}
          />
        ))}
      </div>

      {/* Framework Summary Posture Cards */}
      {summary && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 bg-gray-900/60 border border-gray-800 rounded-xl">
            <div className="text-xs text-gray-400 font-medium">Control Coverage</div>
            <div className="flex items-baseline gap-2 mt-2">
              <div className="text-3xl font-extrabold text-white">
                {summary.compliance_percentage}%
              </div>
              <span className={`text-xs px-2 py-0.5 rounded font-semibold ${
                summary.compliance_percentage >= 80 ? 'bg-emerald-500/10 text-emerald-400' :
                summary.compliance_percentage >= 50 ? 'bg-amber-500/10 text-amber-400' :
                'bg-red-500/10 text-red-400'
              }`}>
                {summary.status_label}
              </span>
            </div>
            {/* Coverage Progress Bar */}
            <div className="w-full bg-gray-800 h-1.5 rounded-full mt-3 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  summary.compliance_percentage >= 80 ? 'bg-emerald-500' :
                  summary.compliance_percentage >= 50 ? 'bg-amber-500' : 'bg-red-500'
                }`}
                style={{ width: `${summary.compliance_percentage}%` }}
              />
            </div>
          </div>

          <div className="p-4 bg-gray-900/60 border border-gray-800 rounded-xl">
            <div className="text-xs text-gray-400 font-medium">Security Control Status</div>
            <div className="flex items-center gap-4 mt-2">
              <div>
                <div className="text-2xl font-bold text-emerald-400">{summary.compliant_controls}</div>
                <div className="text-[10px] text-gray-500 uppercase">Compliant</div>
              </div>
              <div className="h-8 w-px bg-gray-800" />
              <div>
                <div className="text-2xl font-bold text-red-400">{summary.non_compliant_controls}</div>
                <div className="text-[10px] text-gray-500 uppercase">Gaps / Non-Compliant</div>
              </div>
            </div>
          </div>

          <div className="p-4 bg-gray-900/60 border border-gray-800 rounded-xl">
            <div className="text-xs text-gray-400 font-medium">High Impact Gaps</div>
            <div className="flex items-center gap-4 mt-2">
              <div>
                <div className="text-2xl font-bold text-red-500">{summary.critical_findings_count}</div>
                <div className="text-[10px] text-gray-500 uppercase">Critical</div>
              </div>
              <div className="h-8 w-px bg-gray-800" />
              <div>
                <div className="text-2xl font-bold text-amber-400">{summary.high_findings_count}</div>
                <div className="text-[10px] text-gray-500 uppercase">High</div>
              </div>
            </div>
          </div>

          <div className="p-4 bg-gray-900/60 border border-gray-800 rounded-xl">
            <div className="text-xs text-gray-400 font-medium">Mapped Findings</div>
            <div className="text-3xl font-extrabold text-white mt-2">
              {summary.total_findings_mapped}
            </div>
            <div className="text-[11px] text-gray-400 mt-1">
              Active violations aligned to framework controls
            </div>
          </div>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-gray-900/60 p-3 rounded-xl border border-gray-800">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search controls, rules or IDs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-gray-800/80 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 text-xs bg-gray-800 border border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Control Statuses</option>
            <option value="COMPLIANT">Compliant Only</option>
            <option value="NON_COMPLIANT">Non-Compliant (Gaps)</option>
          </select>

          <select
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value)}
            className="px-3 py-1.5 text-xs bg-gray-800 border border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Services</option>
            <option value="S3">S3</option>
            <option value="IAM">IAM</option>
            <option value="EC2">EC2</option>
            <option value="VPC">VPC</option>
            <option value="CloudTrail">CloudTrail</option>
            <option value="RDS">RDS</option>
          </select>
        </div>
      </div>

      {/* Controls Table */}
      <div className="bg-gray-900/40 border border-gray-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs text-gray-400">Loading compliance controls...</div>
        ) : filteredControls.length === 0 ? (
          <div className="p-12 text-center text-xs text-gray-400">No controls matched the specified criteria.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-gray-800/50 text-[11px] uppercase tracking-wider text-gray-400 border-b border-gray-800">
                <tr>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Control ID</th>
                  <th className="px-4 py-3">Control Title & Description</th>
                  <th className="px-4 py-3">Service</th>
                  <th className="px-4 py-3">Detection Rule</th>
                  <th className="px-4 py-3">Mapped Findings</th>
                  <th className="px-4 py-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {filteredControls.map((ctrl) => {
                  const isExpanded = expandedControl === ctrl.control_id;
                  const isCompliant = ctrl.status === 'COMPLIANT';

                  return (
                    <React.Fragment key={ctrl.control_id}>
                      <tr 
                        onClick={() => setExpandedControl(isExpanded ? null : ctrl.control_id)}
                        className="hover:bg-gray-800/30 cursor-pointer transition"
                      >
                        <td className="px-4 py-3 whitespace-nowrap">
                          {isCompliant ? (
                            <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              <CheckCircle2 className="w-3 h-3" />
                              Compliant
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full font-semibold bg-red-500/10 text-red-400 border border-red-500/20">
                              <XCircle className="w-3 h-3" />
                              Non-Compliant
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 font-mono font-bold text-white whitespace-nowrap">
                          {ctrl.control_id}
                        </td>
                        <td className="px-4 py-3 max-w-md">
                          <div className="font-semibold text-gray-200">{ctrl.control_title}</div>
                          <div className="text-[11px] text-gray-400 mt-0.5 line-clamp-1">{ctrl.description}</div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono text-[10px]">
                            {ctrl.service}
                          </span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span className="font-mono text-blue-400">{ctrl.rule_id}</span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          {ctrl.open_findings_count > 0 ? (
                            <span className="px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 font-bold border border-red-500/20">
                              {ctrl.open_findings_count} violations
                            </span>
                          ) : (
                            <span className="text-gray-500">None (Secure)</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <ChevronRight className={`w-4 h-4 text-gray-400 inline transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                        </td>
                      </tr>

                      {/* Expandable Remediation & Finding Details */}
                      {isExpanded && (
                        <tr className="bg-gray-950/60 border-b border-gray-800">
                          <td colSpan={7} className="p-4 space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="p-3 bg-gray-900/90 rounded-lg border border-gray-800">
                                <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">
                                  Control Details
                                </div>
                                <p className="text-xs text-gray-300 leading-relaxed">{ctrl.description}</p>
                              </div>
                              <div className="p-3 bg-gray-900/90 rounded-lg border border-gray-800">
                                <div className="text-[11px] font-semibold text-blue-400 uppercase tracking-wider mb-1">
                                  Remediation Guidance
                                </div>
                                <p className="text-xs text-gray-300 leading-relaxed font-mono">
                                  {ctrl.remediation}
                                </p>
                              </div>
                            </div>

                            {ctrl.findings.length > 0 && (
                              <div className="mt-3">
                                <div className="text-[11px] font-semibold text-red-400 uppercase tracking-wider mb-2">
                                  Associated Non-Compliant Cloud Resources:
                                </div>
                                <div className="space-y-1.5">
                                  {ctrl.findings.map((f) => (
                                    <div key={f.id} className="flex items-center justify-between p-2 bg-gray-900/70 border border-gray-800 rounded text-xs">
                                      <div className="flex items-center gap-2">
                                        <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                                        <span className="font-semibold text-white">{f.title}</span>
                                        {f.resource_name && (
                                          <span className="text-gray-400 font-mono text-[11px]">({f.resource_name})</span>
                                        )}
                                      </div>
                                      <div className="flex items-center gap-2">
                                        <span className="text-xs font-mono font-bold text-red-400">Risk: {f.risk_score}</span>
                                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 font-semibold uppercase">
                                          {f.severity}
                                        </span>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
