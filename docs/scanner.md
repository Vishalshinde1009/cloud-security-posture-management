# CSPM Scanner Architecture & Resource Discovery

## 1. Executive Summary

The Cloud Security Posture Management (CSPM) platform employs a modular, provider-agnostic scanner pipeline designed for automated asset discovery, configuration collection, data normalization, and continuous risk assessment.

The scanner architecture decouples cloud collection from detection rules and risk scoring, allowing the exact same core pipeline to seamlessly evaluate both simulated environments (in `MOCK` mode) and live cloud environments (in `AWS` mode) without modifying higher-level business logic.

---

## 2. Architecture & Data Flow

The scanning pipeline follows a unidirectional 5-stage lifecycle:

```mermaid
flowchart TD
    A[API Trigger / CLI / Cron] -->|POST /api/scans| B(ScanService)
    B -->|State: QUEUED| C[(Database: scans)]
    B -->|State: RUNNING| D[ScannerEngine]
    D -->|Provider Abstraction| E[CloudProvider Interface]
    E -.->|CSPM_MODE=mock| F[MockProvider]
    E -.->|CSPM_MODE=aws| G[AWSProvider Boto3]
    F -->|DiscoveredResource[]| D
    G -->|DiscoveredResource[]| D
    D -->|Baseline Classification| B
    B -->|Upsert Assets| H[(Database: resources)]
    B -->|State: COMPLETED + Metrics| C
    B -->|Audit Trail| I[(Database: audit_logs)]
```

### Discovery Lifecycle States
1. **QUEUED**: The scan request is authenticated, authorized against RBAC permissions (`scans:create` / `ADMIN` or `SECURITY_ANALYST`), and recorded in the database with a timestamp.
2. **RUNNING**: The scanner engine initializes the selected provider and begins query execution.
3. **COMPLETED**: Discovered resources are normalized and upserted into the `resources` table. Historical metrics (scanned count, posture score, duration) are saved.
4. **FAILED**: If network timeouts or authentication errors occur, the failure is trapped safely, logged to SOC audit logs, and recorded without corrupting existing historical data.

---

## 3. Provider Abstraction Interface (`CloudProvider`)

All cloud providers implement the abstract base class `CloudProvider` defined in `app.scanner.providers.base`:

```python
class CloudProvider(ABC):
    @abstractmethod
    def get_provider_name(self) -> str:
        """Returns provider identifier (e.g., 'MOCK', 'AWS')."""
        pass

    @abstractmethod
    def get_account_info(self) -> Dict[str, Any]:
        """Returns account metadata, ID, and default region."""
        pass

    @abstractmethod
    def discover_resources(self) -> List[DiscoveredResource]:
        """Discovers cloud inventory and returns normalized dataclass records."""
        pass

    @abstractmethod
    def collect_configuration(self, resource: DiscoveredResource) -> Dict[str, Any]:
        """Collects raw configuration evidence for a specific resource."""
        pass
```

---

## 4. Normalized Data Model (`DiscoveredResource`)

Regardless of the underlying cloud provider or service, discovered assets are normalized into a unified structure:

| Field | Type | Description |
| :--- | :--- | :--- |
| `provider` | `str` | Cloud identifier (`MOCK`, `AWS`) |
| `account_id` | `str` | Cloud account or AWS Account ID |
| `service` | `str` | AWS Service family (`S3`, `IAM`, `EC2`, `VPC`, `CloudTrail`, `RDS`) |
| `resource_type` | `str` | Canonical resource type (e.g. `aws_s3_bucket`, `aws_iam_user`) |
| `resource_id` | `str` | Unique cloud identifier (ARN, bucket name, instance ID) |
| `resource_name` | `str` | Human-readable name or alias |
| `region` | `str` | Cloud region or `global` |
| `tags` | `dict` | Key-value pairs extracted from resource metadata |
| `configuration` | `dict` | Raw configuration dictionary matching Boto3 SDK schemas |
| `security_status`| `str` | Baseline classification (`SECURE`, `AT_RISK`, `UNKNOWN`) |

---

## 5. Security & RBAC Enforcement

- **Scan Execution**: Restricted strictly to users possessing `ADMIN` or `SECURITY_ANALYST` roles. Requests from `VIEWER` users are rejected with HTTP 403 Forbidden.
- **Audit Logging**: Every scan trigger, completion, or failure automatically generates an immutable `AuditLog` entry detailing user ID, IP address, target account, duration, and asset count.
- **Preservation of History**: Repeated scans never delete previous scan records. Historical scans are preserved to enable posture drift analysis and compliance tracking.
