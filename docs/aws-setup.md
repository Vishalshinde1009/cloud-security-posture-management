# AWS Setup & Least-Privilege IAM Policy for CSPM

## 1. Security Principle: Strict Read-Only Access
The CSPM platform is designed with zero-trust and least-privilege principles. The scanner:
- **NEVER** modifies cloud configurations.
- **NEVER** creates or deletes resources.
- **NEVER** modifies security groups, IAM policies, or credentials.
- **ONLY** requests configuration metadata via `Describe*`, `Get*`, and `List*` operations.

---

## 2. Recommended IAM Policy: `CSPMReadOnlyAuditorPolicy`

Attach the following customer-managed IAM policy to your IAM Role or IAM User dedicated to the scanner:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CSPMS3ReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketTagging"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMIAMReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:GetAccountPasswordPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMEC2AndVPCReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeRouteTables",
        "ec2:DescribeNetworkAcls"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMCloudTrailReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMRDSReadOnly",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBSubnetGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CSPMSTSIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 3. Alternative: AWS Managed Policy
For a rapid setup in a sandbox/testing account, you may attach the AWS-managed policy:
- `arn:aws:iam::aws:policy/SecurityAudit`

---

## 4. Configuring Credentials
Set the credentials in your local `.env` file (which is gitignored):
```env
CSPM_MODE=aws
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```
Or when deploying on AWS EC2 or ECS, leave these variables empty and let Boto3 automatically assume the attached IAM Instance Profile.
