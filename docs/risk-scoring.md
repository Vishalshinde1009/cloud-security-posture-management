# Explainable Risk Scoring & Security Posture Assessment Model

This document specifies the mathematical formulas, scoring criteria, normalization techniques, and architectural design governing the Cloud Security Posture Management (CSPM) Risk Engine.

---

## 1. Executive Summary & Design Philosophy

The CSPM platform rejects "black-box" risk numbers and arbitrary severity overrides. Instead, it employs an **evidence-backed, deterministic, multi-factor scoring model**. Every finding score and overall posture rating can be mathematically decomposed, verified, and audited by security analysts and cloud auditors.

### Core Tenets
1. **Determinism:** Identical configuration evidence and asset metadata strictly yield identical risk scores and human-readable explanations.
2. **Contextual Risk vs. Rule Base Severity:** A static rule severity (e.g., `HIGH`) represents theoretical impact; the *calculated risk score* incorporates actual network exposure, asset criticality, exploitability, and data sensitivity.
3. **Read-Only / Detection-Only:** Risk calculation operates purely on normalized configuration evidence without mutating cloud assets, creating AWS access credentials, or generating external network traffic.
4. **Explainability:** Each score is accompanied by human-readable justifications referencing the exact evaluated values.

---

## 2. Finding-Level Risk Scoring Model (0–100)

Every detected finding is evaluated across **six normalized dimensions** ($0 \le F_k \le 100$). The final score is computed via a weighted linear combination rounded to the nearest stable integer:

$$\text{Risk Score} = \min\left(100, \, \max\left(0, \, \text{round}\left(\sum_{k=1}^6 W_k \cdot F_k\right)\right)\right)$$

### 2.1 Weight Distribution

| Factor ($k$) | Dimension | Weight ($W_k$) | Description |
| :--- | :--- | :---: | :--- |
| 1 | **Base Severity** | **40%** ($0.40$) | Inherent theoretical impact defined by the benchmark rule |
| 2 | **Internet Exposure** | **20%** ($0.20$) | Network accessibility and ingress boundaries from configuration |
| 3 | **Asset Criticality** | **15%** ($0.15$) | Environmental tier, workload purpose, and blast radius |
| 4 | **Exploitability** | **10%** ($0.10$) | Ease and directness of adversarial weaponization |
| 5 | **Data Sensitivity** | **10%** ($0.10$) | Presence or handling of databases, PII, credentials, or backups |
| 6 | **Configuration Weakness** | **5%** ($0.05$) | Compounded configuration failure or defense-in-depth absence |
| **Total** | | **100%** ($1.00$) | |

---

## 3. Detailed Factor Evaluators

### 3.1 Base Severity Factor ($F_1$, 40%)
Directly derived from the security rule definition:
- `CRITICAL`: **100**
- `HIGH`: **80**
- `MEDIUM`: **55**
- `LOW`: **25**
- `INFO`: **0**

### 3.2 Internet Exposure Factor ($F_2$, 20%)
Evaluates whether the resource is reachable from untrusted external networks based on configuration evidence:
- **Internet-wide (100):** Unrestricted ingress (`0.0.0.0/0` or `::/0`), S3 bucket policies permitting `Principal: "*"`, unrestricted SSH/RDP/database ingress, or public RDS instances with open security groups.
- **Broad Public Exposure (90):** Public IPv4 address assigned to compute instances, public IP with legacy IMDSv1 enabled, or S3 Public Access Block protections disabled.
- **Publicly Reachable (80):** Attached to Internet Gateway or public subnet; database instance configured with `publicly_accessible=True`.
- **Internal Network (40):** Isolated within private VPC subnets with RFC1918 CIDRs.
- **Private / Control Plane (10):** Management plane resources (IAM users/roles, CloudTrail trails) with no direct data-plane network ingress.
- **Unknown (30):** Baseline applied when network boundary metadata is indeterminate.

### 3.3 Asset Criticality Factor ($F_3$, 15%)
Evaluates the operational value and blast radius of the affected asset:
- **CRITICAL (100):** AWS Root account credentials (`IAM-005`), or relational production database instances.
- **HIGH (80):** Production compute, storage, or security boundary resources identified via tags (`env: prod`, `environment: production`) or naming conventions.
- **MEDIUM (60):** Staging or development workloads (`env: dev`, `env: stage`).
- **LOW (30):** Ephemeral sandbox, QA, or testing resources (`env: test`, `env: sandbox`).
- **UNKNOWN (50):** Baseline applied when environment tags or naming metadata are absent.

### 3.4 Exploitability Factor ($F_4$, 10%)
Evaluates the technical barrier to exploitation:
- **Direct Admin Exploitation (95):** Direct internet exposure of remote management protocols (SSH port 22, RDP port 3389) or database engines (3306, 5432).
- **Wildcard Authorization (90):** Overly permissive IAM policy with `Action: "*"` and `Resource: "*"`.
- **Public Data Exposure (85):** Anonymous unauthenticated reads/writes on S3 or unencrypted public endpoints.
- **SSRF Exploitation (80):** Public compute instance with legacy IMDSv1 enabled.
- **Authentication Weakness (70):** Missing Multi-Factor Authentication on administrative accounts.
- **Internal Config Weakness (50–55):** Unencrypted storage volumes or stale credentials requiring preexisting local or authenticated access.
- **Observability Gap (30–40):** Missing logging, disabled versioning, or disabled multi-region trails.

### 3.5 Data Sensitivity Factor ($F_5$, 10%)
Evaluates the data classification of the resource:
- **Confirmed Sensitive Data Workload (90):** Relational databases (RDS), storage buckets tagged or named with sensitive keywords (`customer`, `backup`, `finance`, `payment`, `pii`, `data`).
- **Standard Structured Data Store (80):** General relational database instances.
- **Security Credentials (70):** IAM users, access keys, and policy credentials.
- **General Storage Repository (50):** Unclassified S3 buckets, EBS block storage volumes.
- **Compute Workload (35):** Virtual machine compute instances without explicit data tags.
- **Network / Packet Infrastructure (20):** Security groups, VPCs, subnets, route tables (non-data resources).
- **Unknown (50):** Unclassified asset.

### 3.6 Configuration Weakness Factor ($F_6$, 5%)
Evaluates compounded security failure and defense-in-depth degradation:
- **Compounded Vulnerability (95):** Publicly accessible database combined with unencrypted storage at rest.
- **Perimeter Bypass (90):** Ingress security rules allowing all protocols and ports from `0.0.0.0/0`.
- **Cryptographic Failure (75):** Default server-side encryption disabled for EBS volumes, S3 buckets, or RDS databases.
- **Identity Failure (70):** Missing multi-factor authentication on privileged or console accounts.
- **Resilience Deficiency (50):** Object versioning disabled on S3 storage.
- **Observability Gap (30):** Optional access logging or CloudTrail log file validation disabled.

---

## 4. Risk Level and Remediation Priority Mapping

The calculated risk score maps deterministically to standardized operational tiers:

### 4.1 Risk Level Mapping
| Score Range | Risk Level | Operational Interpretation |
| :---: | :---: | :--- |
| **90 – 100** | `CRITICAL` | Severe exposure of critical infrastructure requiring immediate SOC intervention. |
| **70 – 89** | `HIGH` | Significant security gap threatening confidentiality, integrity, or availability. |
| **40 – 69** | `MEDIUM` | Policy violation, lack of defense-in-depth, or hygiene non-compliance. |
| **1 – 39** | `LOW` | Minor observational issue or best-practice divergence with limited exploitability. |
| **0** | `INFO` | Informational security observation without risk exposure. |

### 4.2 Remediation Priority Mapping
| Score Range | Risk Priority | Recommended SLA |
| :---: | :---: | :--- |
| **90 – 100** | `IMMEDIATE` | Mitigate within **4 hours**; disconnect exposed ports or revoke access keys. |
| **70 – 89** | `HIGH` | Remediate within **24 hours**. |
| **40 – 69** | `MEDIUM` | Remediate within **7 business days** (next sprint). |
| **0 – 39** | `LOW` | Remediate within **30 days** or next maintenance window. |

---

## 5. Security Posture Score (0–100) & Rating Model

The Security Posture Score reflects the overall resilience of the scanned cloud environment. It is formulated to satisfy two requirements:
1. **Asset Normalization:** Environments are not penalized simply for scaling resource counts.
2. **Critical Risk Sensitivity:** Severe vulnerabilities on critical production assets noticeably reduce the overall score even in large deployments.

### 5.1 Mathematical Posture Formula

Let $N$ be the total count of scanned resources. Let $\mathcal{F}_{\text{open}}$ be the set of active open findings. For each finding $i \in \mathcal{F}_{\text{open}}$, let $R_i$ be its calculated risk score ($0 \le R_i \le 100$) and $w_{\text{sev}(i)}$ be its severity weighting factor:
- $w_{\text{CRITICAL}} = 1.00$
- $w_{\text{HIGH}} = 0.75$
- $w_{\text{MEDIUM}} = 0.40$
- $w_{\text{LOW}} = 0.15$

The weighted sum of open finding risks is:
$$\text{Weighted Risk Sum} = \sum_{i \in \mathcal{F}_{\text{open}}} R_i \cdot w_{\text{sev}(i)}$$

The asset-normalized penalty combines normalized finding density with peak finding risk:
$$\text{Risk Penalty} = \min\left(100.0, \, 0.70 \cdot \frac{\text{Weighted Risk Sum}}{\max(1, N) \cdot 0.60} + 0.30 \cdot \max_{i}(R_i)\right)$$

The final Security Posture Score is:
$$\text{Security Posture Score} = \max\left(0.0, \, \text{round}(100.0 - \text{Risk Penalty}, 1)\right)$$

### 5.2 Posture Rating Boundaries
| Posture Score | Rating | Environment Condition |
| :---: | :---: | :--- |
| **90.0 – 100.0** | `EXCELLENT` | Exemplary adherence to CIS AWS Foundations and AWS security best practices. |
| **75.0 – 89.9** | `GOOD` | Strong perimeter and identity controls with minor hygiene observations. |
| **60.0 – 74.9** | `MODERATE` | Multiple unmitigated high/medium findings; perimeter hardening required. |
| **40.0 – 59.9** | `POOR` | Substantial attack surface exposed; unencrypted data or unrestricted network ingress. |
| **0.0 – 39.9** | `CRITICAL` | Imminent compromise risk; active root keys or unencrypted databases exposed to `0.0.0.0/0`. |

---

## 6. Historical Scan Comparison & Drift Analysis

The platform maintains immutable scan records and compares sequential executions for the same cloud account:

$$\Delta \text{Score} = \text{Security Score}_{\text{current}} - \text{Security Score}_{\text{previous}}$$
$$\Delta \text{Risk} = \overline{\text{Risk}}_{\text{current}} - \overline{\text{Risk}}_{\text{previous}}$$

- **New Findings:** Violations detected for the first time in the current scan ($\text{first\_detected} \ge \text{created\_at}_{\text{prev}}$).
- **Resolved Findings:** Previously open violations on scanned resources that cleared during the current scan ($\text{status} = \text{RESOLVED}$).
- **Persistent Findings:** Violations remaining open across consecutive scans ($\text{Total Open} - \text{New}$).

---

## 7. Worked Scoring Examples

### Example 1: Public Production Database (`RDS-001`)
- **Resource:** `orders-prod-db` (`AWS::RDS::DBInstance`), tags: `{"env": "prod"}`
- **Configuration:** `publicly_accessible=True`, `storage_encrypted=False`, SG allows port 5432 from `0.0.0.0/0`
- **Evaluator Scores:**
  - Base Severity: $100$ ($w = 0.40$) $\implies 40.0$
  - Internet Exposure: $100$ ($w = 0.20$) $\implies 20.0$
  - Asset Criticality: $100$ ($w = 0.15$) $\implies 15.0$
  - Exploitability: $85$ ($w = 0.10$) $\implies 8.5$
  - Data Sensitivity: $90$ ($w = 0.10$) $\implies 9.0$
  - Config Weakness: $95$ ($w = 0.05$) $\implies 4.75$
- **Calculated Risk Score:** $\text{round}(40.0 + 20.0 + 15.0 + 8.5 + 9.0 + 4.75) = \mathbf{97}$
- **Classification:** `Risk Level: CRITICAL`, `Priority: IMMEDIATE`
- **Generated Explanation:**
  > *"This finding received a risk score of 97/100 (CRITICAL - IMMEDIATE priority). Database is publicly accessible with unrestricted internet ingress. Production relational database instance hosting critical operational data. Database endpoint exposed directly or to broad external ingress."*

### Example 2: Missing Versioning on Development Bucket (`S3-003`)
- **Resource:** `dev-scratch-bucket` (`AWS::S3::Bucket`), tags: `{"env": "dev"}`
- **Configuration:** `versioning=False`, public access blocked
- **Evaluator Scores:**
  - Base Severity: $55$ ($w = 0.40$) $\implies 22.0$
  - Internet Exposure: $30$ ($w = 0.20$) $\implies 6.0$
  - Asset Criticality: $60$ ($w = 0.15$) $\implies 9.0$
  - Exploitability: $30$ ($w = 0.10$) $\implies 3.0$
  - Data Sensitivity: $50$ ($w = 0.10$) $\implies 5.0$
  - Config Weakness: $50$ ($w = 0.05$) $\implies 2.5$
- **Calculated Risk Score:** $\text{round}(22.0 + 6.0 + 9.0 + 3.0 + 5.0 + 2.5) = \mathbf{48}$
- **Classification:** `Risk Level: MEDIUM`, `Priority: MEDIUM`
