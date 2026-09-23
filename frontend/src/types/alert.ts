export interface SecurityAlert {
  id: string;
  cloud_account_id: string;
  account_name?: string;
  account_identifier?: string;
  account_provider?: string;
  finding_id?: string | null;
  alert_type: string;
  severity: string;
  title: string;
  description: string;
  previous_value?: string | null;
  current_value?: string | null;
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';
  first_detected_at: string;
  last_detected_at: string;
  resolved_at?: string | null;
  created_at: string;
}

export interface AlertSummary {
  total_open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  resolved: number;
  new_findings: number;
  risk_increases: number;
}

export interface MonitoringConfig {
  id: string;
  cloud_account_id: string;
  enabled: boolean;
  scan_interval_minutes: number;
  last_scan_at?: string | null;
  next_scan_at?: string | null;
  created_at: string;
  updated_at: string;
}
