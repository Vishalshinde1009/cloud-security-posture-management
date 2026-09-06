export interface SecurityRule {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  service: string;
  resource_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  remediation: string;
  references: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RuleListResponse {
  items: SecurityRule[];
  total: number;
  page: number;
  limit: number;
}

export interface Finding {
  id: string;
  rule_id: string;
  scan_id: string;
  cloud_account_id: string;
  resource_id: string;
  finding_identifier: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  risk_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  risk_priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
  risk_factors?: {
    severity: number;
    exposure: number;
    asset_criticality: number;
    exploitability: number;
    data_sensitivity: number;
    config_weakness: number;
    reasons?: Record<string, string>;
  };
  risk_explanation?: string;
  risk_calculated_at?: string;
  status: 'OPEN' | 'RESOLVED' | 'SUPPRESSED';
  remediation: string | null;
  first_detected: string;
  last_detected: string;
  resolved_at: string | null;
  created_at: string;
  rule_code?: string;
  service?: string;
  resource_name?: string;
  resource_identifier?: string;
  evidence?: Record<string, any>;
  references?: string[];
}

export interface FindingListResponse {
  items: Finding[];
  total: number;
  page: number;
  limit: number;
}
