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
