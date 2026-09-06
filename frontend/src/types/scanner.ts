export interface Scan {
  id: string;
  cloud_account_id: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  started_at: string | null;
  completed_at: string | null;
  duration: number | null;
  resources_scanned: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  security_score: number | null;
  posture_rating?: 'EXCELLENT' | 'GOOD' | 'MODERATE' | 'POOR' | 'CRITICAL' | null;
  risk_summary?: {
    avg_risk: number;
    max_risk: number;
    immediate_count: number;
    high_priority_count: number;
    medium_priority_count: number;
    low_priority_count: number;
  };
  error_message: string | null;
  created_at: string;
}

export interface ScanComparison {
  has_previous_scan: boolean;
  current_scan_id: string;
  previous_scan_id: string | null;
  score_change: number;
  risk_change: number;
  new_findings: number;
  resolved_findings: number;
  persistent_findings: number;
  previous_security_score: number | null;
  current_security_score: number | null;
  previous_posture_rating: string | null;
  current_posture_rating: string | null;
}

export interface ScanListResponse {
  items: Scan[];
  total: number;
  page: number;
  limit: number;
}

export interface CloudResource {
  id: string;
  cloud_account_id: string;
  scan_id: string | null;
  provider: string;
  service: string;
  resource_type: string;
  resource_id: string;
  resource_name: string | null;
  region: string | null;
  tags: Record<string, any>;
  security_status: 'SECURE' | 'AT_RISK' | 'UNKNOWN' | 'PENDING_ANALYSIS';
  first_seen: string;
  last_seen: string;
  configuration?: Record<string, any>;
}

export interface ResourceListResponse {
  items: CloudResource[];
  total: number;
  page: number;
  limit: number;
}
