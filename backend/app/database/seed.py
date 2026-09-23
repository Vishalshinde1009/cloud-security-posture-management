import logging
import uuid
from sqlalchemy.orm import Session
from app.database.session import SessionLocal
from app.core.config import settings
from app.core.security import get_password_hash
from app.models.auth import User, Role, Permission
from app.models.finding import SecurityRule
from app.models.compliance import ComplianceControl

logger = logging.getLogger("cspm.seed")


def seed_database(db: Session = None):
    """
    Populates initial safe non-sensitive development data:
    - Default RBAC Roles & Permissions
    - Initial Admin User (from settings)
    - Sample Security Rules catalog
    - Sample CIS Benchmark Compliance Controls
    """
    close_session = False
    if db is None:
        db = SessionLocal()
        close_session = True

    try:
        # 1. Seed Permissions
        permissions_data = [
            ("read:findings", "View detected security misconfigurations"),
            ("write:findings", "Update finding status and remediation notes"),
            ("run:scans", "Trigger on-demand cloud security scans"),
            ("read:scans", "View scan history and metrics"),
            ("cloud_accounts:manage", "Register, configure, and test cloud accounts"),
            ("read:accounts", "View cloud accounts"),
            ("manage:rules", "Enable or disable security detection rules"),
            ("read:rules", "View security detection rules"),
            ("download:reports", "Generate and export PDF security reports"),
            ("read:audit_logs", "View SOC security audit trail"),
        ]

        permission_objs = {}
        for name, desc in permissions_data:
            perm = db.query(Permission).filter(Permission.name == name).first()
            if not perm:
                perm = Permission(id=uuid.uuid4(), name=name, description=desc)
                db.add(perm)
                db.flush()
            permission_objs[name] = perm

        # 2. Seed Roles
        roles_data = [
            ("ADMIN", "Full platform administration and configuration access", list(permission_objs.values())),
            ("SECURITY_ANALYST", "Security operations, scanning, and finding remediation", [
                permission_objs["read:findings"],
                permission_objs["write:findings"],
                permission_objs["run:scans"],
                permission_objs["read:scans"],
                permission_objs["read:accounts"],
                permission_objs["read:rules"],
                permission_objs["download:reports"],
                permission_objs["read:audit_logs"],
            ]),
            ("VIEWER", "Read-only access to posture dashboard and reports", [
                permission_objs["read:findings"],
                permission_objs["read:scans"],
                permission_objs["read:accounts"],
                permission_objs["read:rules"],
                permission_objs["download:reports"],
            ]),
        ]

        role_objs = {}
        for role_name, role_desc, role_perms in roles_data:
            role = db.query(Role).filter(Role.name == role_name).first()
            if not role:
                role = Role(
                    id=uuid.uuid4(),
                    name=role_name,
                    description=role_desc,
                )
                db.add(role)
                db.flush()

            role.permissions = role_perms
            role.description = role_desc
            role_objs[role_name] = role

        # 3. Seed Default Users (Admin, Analyst, Viewer)
        admin_user = db.query(User).filter(User.email == settings.INITIAL_ADMIN_EMAIL).first()
        if not admin_user:
            admin_user = User(
                id=uuid.uuid4(),
                username="admin",
                email=settings.INITIAL_ADMIN_EMAIL,
                password_hash=get_password_hash(settings.INITIAL_ADMIN_PASSWORD),
                is_active=True,
            )
            admin_user.roles.append(role_objs["ADMIN"])
            db.add(admin_user)
            db.flush()
            logger.info(f"Created default admin user: {settings.INITIAL_ADMIN_EMAIL}")
        else:
            if role_objs["ADMIN"] not in admin_user.roles:
                admin_user.roles.append(role_objs["ADMIN"])

        analyst_user = db.query(User).filter(User.username == "analyst").first()
        if not analyst_user:
            analyst_user = User(
                id=uuid.uuid4(),
                username="analyst",
                email="analyst@cspm-security.local",
                password_hash=get_password_hash("AnalystPass123!"),
                is_active=True,
            )
            analyst_user.roles.append(role_objs["SECURITY_ANALYST"])
            db.add(analyst_user)
            db.flush()
            logger.info("Created default analyst user: analyst@cspm-security.local")
        else:
            if role_objs["SECURITY_ANALYST"] not in analyst_user.roles:
                analyst_user.roles.append(role_objs["SECURITY_ANALYST"])

        viewer_user = db.query(User).filter(User.username == "viewer").first()
        if not viewer_user:
            viewer_user = User(
                id=uuid.uuid4(),
                username="viewer",
                email="viewer@cspm-security.local",
                password_hash=get_password_hash("ViewerPass123!"),
                is_active=True,
            )
            viewer_user.roles.append(role_objs["VIEWER"])
            db.add(viewer_user)
            db.flush()
            logger.info("Created default viewer user: viewer@cspm-security.local")
        else:
            if role_objs["VIEWER"] not in viewer_user.roles:
                viewer_user.roles.append(role_objs["VIEWER"])

        # 4. Seed Standard Sample Security Rules
        sample_rules = [
            {
                "rule_id": "S3-001",
                "title": "S3 bucket allows public read/write access",
                "description": "Checks if S3 bucket ACL or public access block allows unrestricted public internet access.",
                "service": "S3",
                "resource_type": "aws_s3_bucket",
                "severity": "CRITICAL",
                "category": "Data Exposure",
                "remediation": "Enable S3 Block Public Access at bucket or account level, and review bucket policy.",
                "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
            },
            {
                "rule_id": "S3-002",
                "title": "S3 bucket missing default server-side encryption",
                "description": "Verifies that S3 buckets enforce server-side encryption using KMS or AES-256.",
                "service": "S3",
                "resource_type": "aws_s3_bucket",
                "severity": "HIGH",
                "category": "Encryption",
                "remediation": "Enable default server-side encryption (SSE-S3 or SSE-KMS) for the bucket.",
                "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"],
            },
            {
                "rule_id": "IAM-001",
                "title": "IAM user without Multi-Factor Authentication (MFA)",
                "description": "Checks if IAM users with console passwords have active MFA devices configured.",
                "service": "IAM",
                "resource_type": "aws_iam_user",
                "severity": "HIGH",
                "category": "Identity & Access",
                "remediation": "Enforce virtual or hardware MFA for all IAM users accessing the AWS Console.",
                "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"],
            },
            {
                "rule_id": "EC2-002",
                "title": "EC2 security group permits unrestricted inbound SSH (port 22)",
                "description": "Detects security groups allowing ingress to port 22 from 0.0.0.0/0 or ::/0.",
                "service": "EC2",
                "resource_type": "aws_security_group",
                "severity": "CRITICAL",
                "category": "Network Security",
                "remediation": "Restrict port 22 access to specific bastion host or authorized corporate IP ranges.",
                "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html"],
            },
            {
                "rule_id": "CT-001",
                "title": "CloudTrail logging is not enabled in all regions",
                "description": "Ensures that at least one multi-region CloudTrail trail is configured and actively logging.",
                "service": "CloudTrail",
                "resource_type": "aws_cloudtrail_trail",
                "severity": "HIGH",
                "category": "Logging & Audit",
                "remediation": "Create a multi-region CloudTrail trail and ensure log file validation is enabled.",
                "references": ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"],
            },
            {
                "rule_id": "RDS-001",
                "title": "RDS database instance is publicly accessible",
                "description": "Detects RDS DB instances configured with PubliclyAccessible flag set to true.",
                "service": "RDS",
                "resource_type": "aws_rds_instance",
                "severity": "CRITICAL",
                "category": "Data Exposure",
                "remediation": "Modify DB instance to disable PubliclyAccessible and place within private subnets.",
                "references": ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"],
            },
        ]

        for r_data in sample_rules:
            rule = db.query(SecurityRule).filter(SecurityRule.rule_id == r_data["rule_id"]).first()
            if not rule:
                rule = SecurityRule(
                    id=uuid.uuid4(),
                    rule_id=r_data["rule_id"],
                    title=r_data["title"],
                    description=r_data["description"],
                    service=r_data["service"],
                    resource_type=r_data["resource_type"],
                    severity=r_data["severity"],
                    category=r_data["category"],
                    remediation=r_data["remediation"],
                    references=r_data["references"],
                    enabled=True,
                )
                db.add(rule)

        # 5. Seed Sample CIS Benchmark Controls
        sample_controls = [
            ("CIS_AWS", "CIS-1.1", "Avoid the use of the 'root' account", "Root account has unrestricted administrative privileges and should not be used for daily tasks."),
            ("CIS_AWS", "CIS-1.5", "Ensure MFA is enabled for all IAM users that have a console password", "MFA adds a critical second layer of defense against credential stuffing."),
            ("CIS_AWS", "CIS-2.1", "Ensure CloudTrail is enabled in all regions", "Centralized audit logging across all regions is required for forensic visibility."),
            ("CIS_AWS", "CIS-4.1", "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", "Publicly exposed SSH invites automated brute force attacks."),
            ("CIS_AWS", "CIS-4.2", "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", "Publicly exposed RDP invites automated brute force and ransomware attacks."),
        ]

        for framework, cid, title, desc in sample_controls:
            ctrl = db.query(ComplianceControl).filter(
                ComplianceControl.framework == framework,
                ComplianceControl.control_id == cid,
            ).first()
            if not ctrl:
                ctrl = ComplianceControl(
                    id=uuid.uuid4(),
                    framework=framework,
                    control_id=cid,
                    title=title,
                    description=desc,
                )
                db.add(ctrl)

        db.commit()
        logger.info("Database seeding completed successfully.")

    except Exception as e:
        db.rollback()
        logger.error(f"Error seeding database: {e}")
        raise
    finally:
        if close_session:
            db.close()


if __name__ == "__main__":
    from app.core.logging import setup_logging
    setup_logging()
    print("Running database seed script...")
    seed_database()
    print("Seed finished.")
