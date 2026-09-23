# In-App Notifications & Alerts System

## Overview

The CSPM in-app notification system provides real-time and persistent alerts to security personnel regarding critical events, posture degradation, and scan completions.

---

## Notification Types & Triggers

1. **Scan Completion & Summary (`SCAN_COMPLETED`)**:
   - Dispatched immediately upon the conclusion of a scan cycle.
   - Contains high-level metrics: total discovered resources, newly created findings, and updated security posture score.

2. **Critical Risk Alerts (`CRITICAL_FINDING`)**:
   - Fired when a scan detects one or more `CRITICAL` severity findings (e.g. root account usage without MFA, unrestricted inbound SSH/RDP from 0.0.0.0/0, or public S3 buckets with sensitive data).
   - Prompts immediate SOC triage.

3. **Posture Degradation Alert (`POSTURE_DROP`)**:
   - Triggered when the calculated Security Posture Score drops by 5 points or more compared to the previous scan baseline.

4. **Security Policy Modifications (`RULE_STATUS_CHANGE`)**:
   - Informs analysts when an administrator disables or reenables a detection rule in the rule registry.

---

## Data Model & Lifecycle

Notifications are stored in the `notifications` table:
- `id`: Integer primary key
- `user_id`: Integer or null (null targets all tenant analysts)
- `title`: Short descriptive title
- `message`: Detailed summary text
- `severity`: Alert severity (`INFO`, `WARNING`, `CRITICAL`)
- `is_read`: Boolean read status flag
- `link`: Optional deep-link URL pointing directly to the relevant resource or finding
- `created_at`: UTC timestamp

---

## Frontend Integration

- **Navigation Header Bell**:
  - Displays a dynamic badge with unread count.
  - Clicking the bell opens a popover drawer with recent notifications.
  - Analysts can mark individual alerts as read or use "Mark All as Read".
- **Real-Time Polling / Refresh**:
  - Automatically queries `GET /api/notifications/unread-count` and updates UI state.
