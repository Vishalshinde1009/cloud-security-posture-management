# AWS Read-Only Least-Privilege IAM Policy for CSPM

This document outlines the strict, least-privilege IAM policy required for the Cloud Security Posture Management (CSPM) platform.

---

## Security Principles
1. **100% Non-Mutating:** The policy grants strictly `Get*`, `List*`, and `Describe*` permissions.
2. **Zero Mutating Permissions:** No `Create*`, `Put*`, `Delete*`, `Update*`, `Modify*`, `Authorize*`, or `Attach*` actions are requested or permitted.
3. **Restricted Services:** Only services actively audited by the CSPM engine are included:
   - S3 (Object Storage configuration, encryption, bucket policies)
   - IAM (User posture, MFA status, access key age, account summary)
   - EC2 & VPC (Instance metadata IMDSv2, EBS encryption, security groups)
   - CloudTrail (Trail status, multi-region, log file validation)
   - RDS (Database engine, public exposure, storage encryption)
   - STS (Caller identity for connection verification)

---

## IAM Policy JSON

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CSPMCallerIdentityVerification",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMS3ReadOnlyAuditing",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketTagging"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMIAMReadOnlyAuditing",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies",
        "iam:GetAccountSummary"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMComputeAndNetworkReadOnlyAuditing",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMCloudTrailReadOnlyAuditing",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMRDSReadOnlyAuditing",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## AWS Setup Options

### Option A: Using AWS Managed `SecurityAudit` Policy (Recommended for Enterprise)
AWS provides a built-in managed policy named `arn:aws:iam::aws:policy/SecurityAudit`. This policy grants read-only access to configuration metadata across all AWS services without granting read access to underlying customer data or write privileges.

To attach via AWS CLI:
```bash
aws iam attach-role-policy \
  --role-name CSPM-ReadOnly-Role \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

### Option B: Creating the Custom Least-Privilege IAM Policy
1. Save the JSON above to a local file named `cspm-readonly-policy.json`.
2. Create the policy in your AWS account:
   ```bash
   aws iam create-policy \
     --policy-name CSPMReadOnlyAuditPolicy \
     --policy-document file://cspm-readonly-policy.json \
     --description "Least-privilege read-only policy for CSPM misconfiguration detection"
   ```
3. Attach this policy to your dedicated CSPM IAM Role or IAM Service User.
