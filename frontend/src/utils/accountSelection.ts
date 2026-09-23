/**
 * Cloud Account Selection & Persistence Utility
 * 
 * Ensures consistent target selection across Dashboard, Scans, Findings,
 * Compliance, and Reports without hard-coding or falling back to legacy
 * mock accounts when real AWS accounts are configured.
 */

export interface CloudAccountOption {
  id: string;
  name: string;
  provider: string;
  account_identifier?: string;
  default_region?: string;
  credential_mode?: string;
  role_arn?: string | null;
  external_id?: string | null;
  is_active?: boolean;
  total_scans?: number;
  latest_scan?: {
    id: string;
    status: string;
    security_score: number | null;
    findings_count: number;
    completed_at: string | null;
  } | null;
}

const STORAGE_KEY = 'cspm_selected_account_id';
const VERIFIED_STORAGE_KEY = 'cspm_verified_accounts';

/**
 * Retrieves the currently saved account ID from localStorage.
 */
export function getStoredAccountId(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

/**
 * Saves the selected account ID to localStorage and dispatches a change event.
 */
export function setStoredAccountId(id: string, account?: CloudAccountOption): void {
  try {
    if (id) {
      localStorage.setItem(STORAGE_KEY, id);
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore storage quota or access errors
  }

  if (typeof window !== 'undefined') {
    try {
      window.dispatchEvent(
        new CustomEvent('cspm_account_changed', {
          detail: { id, account },
        })
      );
    } catch {
      // Ignore event dispatch errors
    }
  }
}

/**
 * Subscribes to target account selection changes across the app.
 */
export function onAccountChanged(
  callback: (id: string, account?: CloudAccountOption) => void
): () => void {
  if (typeof window === 'undefined') return () => {};

  const handler = (e: Event) => {
    const custom = e as CustomEvent;
    callback(custom.detail?.id || '', custom.detail?.account);
  };

  window.addEventListener('cspm_account_changed', handler);
  return () => window.removeEventListener('cspm_account_changed', handler);
}

/**
 * Retrieves the list of account IDs that have passed connection testing.
 */
export function getVerifiedAccountIds(): string[] {
  try {
    const raw = localStorage.getItem(VERIFIED_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

/**
 * Marks a cloud account as verified (passed connection test).
 */
export function markAccountVerified(id: string): void {
  try {
    const current = getVerifiedAccountIds();
    if (!current.includes(id)) {
      const updated = [...current, id];
      localStorage.setItem(VERIFIED_STORAGE_KEY, JSON.stringify(updated));
    }
  } catch {
    // Ignore storage errors
  }

  if (typeof window !== 'undefined') {
    try {
      window.dispatchEvent(
        new CustomEvent('cspm_account_verified', { detail: { id } })
      );
    } catch {}
  }
}

/**
 * Determines whether a given cloud account is verified and ready for scanning:
 * - MOCK accounts are always ready for simulated scans.
 * - AWS ROLE accounts require role_arn configured AND (have completed >= 1 scan OR passed connection test).
 * - AWS ENVIRONMENT accounts are ready if active.
 */
export function isAccountVerified(account?: CloudAccountOption | null): boolean {
  if (!account) return false;

  if (account.provider === 'MOCK') {
    return true;
  }

  if (account.provider === 'AWS') {
    if (account.credential_mode === 'ROLE') {
      if (!account.role_arn || !account.role_arn.trim()) {
        return false;
      }
      // If previously scanned, live connectivity was established
      if ((account.total_scans && account.total_scans > 0) || account.latest_scan?.status === 'COMPLETED') {
        return true;
      }
      // If connection test passed in this or prior session
      const verifiedList = getVerifiedAccountIds();
      return verifiedList.includes(account.id);
    }
    // ENVIRONMENT credential mode uses container/instance metadata
    return true;
  }

  return false;
}

/**
 * Formats the dynamic mode label based on the selected account:
 * - Real AWS ROLE account: 'AWS ROLE'
 * - Real AWS ENVIRONMENT account: 'AWS ENVIRONMENT'
 * - MOCK account: 'MOCK'
 */
export function getAccountModeLabel(
  account?: CloudAccountOption | null,
  fallbackMode?: string
): string {
  if (!account) {
    if (fallbackMode && fallbackMode.toLowerCase() === 'aws') {
      return 'AWS';
    }
    return 'MOCK';
  }

  if (account.provider === 'AWS') {
    if (account.credential_mode === 'ROLE') {
      return 'AWS ROLE';
    }
    if (account.credential_mode === 'ENVIRONMENT') {
      return 'AWS ENVIRONMENT';
    }
    return 'AWS';
  }

  return 'MOCK';
}

/**
 * Returns consistent enterprise styling for the mode badge.
 */
export function getAccountModeStyle(mode: string): {
  badge: string;
  dot: string;
  ping: string;
  text: string;
} {
  const upper = (mode || '').toUpperCase();
  if (upper.includes('ROLE')) {
    return {
      badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      dot: 'bg-emerald-500',
      ping: 'bg-emerald-400',
      text: 'text-emerald-400',
    };
  }
  if (upper.includes('AWS') || upper.includes('ENVIRONMENT')) {
    return {
      badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      dot: 'bg-cyan-500',
      ping: 'bg-cyan-400',
      text: 'text-cyan-400',
    };
  }
  // MOCK fallback: muted amber
  return {
    badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    dot: 'bg-amber-500',
    ping: 'bg-amber-400',
    text: 'text-amber-400',
  };
}

/**
 * Resolves the optimal account ID from a list of accounts.
 *
 * Rules:
 * 1. Never automatically selects the old MOCK "Audit Target" if a real AWS ROLE account exists.
 * 2. If a specific preferredId (e.g. from location state or storage) exists in accounts:
 *    - Check if preferredId points to a mock "Audit Target" while a real AWS ROLE account is available.
 *      If so, automatically upgrade to the real AWS ROLE account.
 *    - Otherwise, preserve the preferredId.
 * 3. If no valid preferredId exists:
 *    - Prioritize an AWS account with a configured IAM role (role_arn populated or credential_mode === 'ROLE').
 *    - Next, prioritize any AWS account not named "Audit Target".
 *    - Next, any AWS account.
 *    - Fallback to the first available account.
 * 4. If accounts list is empty, returns empty string.
 */
export function resolvePreferredAccountId(
  accounts: CloudAccountOption[],
  preferredId?: string | null
): string {
  if (!accounts || accounts.length === 0) {
    return '';
  }

  // 1. Identify real AWS ROLE accounts
  const realRoleAccounts = accounts.filter(
    (a) =>
      a.provider === 'AWS' &&
      a.name.trim().toLowerCase() !== 'audit target' &&
      ((a.role_arn && a.role_arn.trim().length > 0) || a.credential_mode === 'ROLE')
  );

  const realAwsAccounts = accounts.filter(
    (a) => a.provider === 'AWS' && a.name.trim().toLowerCase() !== 'audit target'
  );

  // 2. Evaluate currently preferred ID if given
  const currentId = preferredId || getStoredAccountId();
  if (currentId) {
    const existing = accounts.find((a) => a.id === currentId);
    if (existing) {
      const isMockAuditTarget =
        existing.provider === 'MOCK' ||
        existing.name.trim().toLowerCase() === 'audit target';

      // If user has a real AWS role account, do not stick to the mock target
      if (isMockAuditTarget && (realRoleAccounts.length > 0 || realAwsAccounts.length > 0)) {
        const bestRoleAcc = realRoleAccounts[0] || realAwsAccounts[0];
        setStoredAccountId(bestRoleAcc.id, bestRoleAcc);
        return bestRoleAcc.id;
      }

      // Valid current selection
      return existing.id;
    }
  }

  // 3. Priority 1: Real AWS ROLE account
  if (realRoleAccounts.length > 0) {
    const bestRoleAcc = realRoleAccounts[0];
    setStoredAccountId(bestRoleAcc.id, bestRoleAcc);
    return bestRoleAcc.id;
  }

  // 4. Priority 2: Other real AWS account
  if (realAwsAccounts.length > 0) {
    const bestRoleAcc = realAwsAccounts[0];
    setStoredAccountId(bestRoleAcc.id, bestRoleAcc);
    return bestRoleAcc.id;
  }

  // 5. Priority 3: Any AWS account
  const anyAws = accounts.find((a) => a.provider === 'AWS');
  if (anyAws) {
    setStoredAccountId(anyAws.id, anyAws);
    return anyAws.id;
  }

  // 6. Fallback to first available account (e.g. MOCK if no real accounts exist)
  const fallback = accounts[0];
  setStoredAccountId(fallback.id, fallback);
  return fallback.id;
}
