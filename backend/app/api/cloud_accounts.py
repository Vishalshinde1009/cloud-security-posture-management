"""
Cloud Accounts Management API.
Supports listing, registering, and testing connection for AWS and Mock cloud environments.
Zero credential storage: relies on the standard AWS credential chain.
"""

import json
import re
import secrets
import uuid
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.session import get_db
from app.core.config import settings
from app.api.deps import (
    get_current_user,
    require_role,
    require_permission,
    is_admin,
    get_user_accessible_account_ids,
    verify_account_access,
    verify_account_ownership,
)
from app.models.auth import User
from app.models.cloud import CloudAccount, Scan, Resource
from app.models.finding import Finding
from app.models.report import Report
from app.models.audit import AuditLog
from app.scanner.providers.aws.client_factory import AWSClientFactory
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError

logger = logging.getLogger("cspm.api.cloud_accounts")

router = APIRouter(prefix="/cloud-accounts", tags=["Cloud Accounts"])

AWS_ROLE_ARN_REGEX = re.compile(
    r"^arn:aws[a-z-]*:iam::(?P<account_id>\d{12}):role\/(?P<role_name>[a-zA-Z0-9+=,.@\-_/]+)$"
)


def validate_role_arn_for_account(role_arn: str, account_identifier: str) -> None:
    """
    Validates AWS IAM Role ARN syntax and asserts account ID matches target account identifier.
    """
    match = AWS_ROLE_ARN_REGEX.match(role_arn.strip())
    if not match:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid AWS IAM Role ARN format. Expected format: arn:aws:iam::123456789012:role/RoleName",
        )
    arn_account_id = match.group("account_id")
    clean_acc_id = account_identifier.strip()
    if clean_acc_id.isdigit() and arn_account_id != clean_acc_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role ARN account ID ({arn_account_id}) does not match target account identifier ({clean_acc_id}).",
        )


def generate_trust_policy(external_id: Optional[str]) -> Optional[str]:
    """
    Generates the AWS IAM Trust Policy JSON snippet for the customer to paste into AWS.
    Enforces STS AssumeRole with sts:ExternalId condition to eliminate Confused Deputy risk.
    """
    if not external_id:
        return None
    assumer_arn = settings.AWS_BACKEND_ASSUMER_ROLE_ARN or "arn:aws:iam::<CSPM_BACKEND_ACCOUNT_ID>:root"
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": assumer_arn
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": external_id
                        }
                    }
                }
            ]
        },
        indent=2
    )


# =============================================================================
# Request & Response Schemas
# =============================================================================

class CloudAccountCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=150, json_schema_extra={"example": "AWS Production Environment"})
    provider: str = Field("AWS", description="Cloud provider identifier ('AWS' or 'MOCK')", json_schema_extra={"example": "AWS"})
    account_identifier: str = Field(..., min_length=3, max_length=100, json_schema_extra={"example": "123456789012"})
    default_region: str = Field("us-east-1", max_length=50, json_schema_extra={"example": "us-east-1"})
    credential_mode: str = Field("ENVIRONMENT", max_length=50, json_schema_extra={"example": "ENVIRONMENT"})
    role_arn: Optional[str] = Field(None, max_length=255, json_schema_extra={"example": "arn:aws:iam::123456789012:role/CSPM-ReadOnly-Role"})
    external_id: Optional[str] = Field(None, max_length=100, json_schema_extra={"example": "cspm-ext-a1b2c3d4e5f6"})


class CloudAccountUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=150)
    default_region: Optional[str] = Field(None, max_length=50)
    role_arn: Optional[str] = Field(None, max_length=255)
    credential_mode: Optional[str] = Field(None, max_length=50)


class LatestScanSummary(BaseModel):
    id: str
    status: str
    security_score: Optional[float] = None
    findings_count: int = 0
    completed_at: Optional[str] = None


class CloudAccountResponse(BaseModel):
    id: str
    name: str
    provider: str
    account_identifier: str
    default_region: str
    credential_mode: str
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    trust_policy_snippet: Optional[str] = None
    is_active: bool
    created_at: str
    total_scans: int = 0
    latest_scan: Optional[LatestScanSummary] = None


class TestConnectionResponse(BaseModel):
    status: str  # "CONNECTED" or "ERROR"
    provider: str
    account_id: Optional[str] = None
    arn: Optional[str] = None
    user_id: Optional[str] = None
    message: str


# =============================================================================
# Endpoints
# =============================================================================

@router.get("", response_model=List[CloudAccountResponse])
def list_cloud_accounts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read:accounts")),
):
    """
    Lists registered cloud accounts with their scan statistics.
    ADMIN: views all cloud accounts.
    Normal users: view ONLY cloud accounts they own.
    """
    query = db.query(CloudAccount)
    if not is_admin(current_user):
        query = query.filter(CloudAccount.user_id == current_user.id)

    accounts = query.order_by(desc(CloudAccount.created_at)).all()
    results = []

    for acc in accounts:
        # Guarantee external_id exists for AWS accounts
        if acc.provider == "AWS" and not acc.external_id:
            acc.external_id = f"cspm-ext-{secrets.token_hex(12)}"
            db.add(acc)
            db.commit()

        scans = db.query(Scan).filter(Scan.cloud_account_id == acc.id).order_by(desc(Scan.created_at)).all()
        total_scans = len(scans)
        latest_scan_summary = None

        if scans:
            latest = scans[0]
            latest_scan_summary = LatestScanSummary(
                id=str(latest.id),
                status=latest.status,
                security_score=latest.security_score,
                findings_count=latest.findings_count,
                completed_at=str(latest.completed_at) if latest.completed_at else None,
            )

        results.append(
            CloudAccountResponse(
                id=str(acc.id),
                name=acc.name,
                provider=acc.provider,
                account_identifier=acc.account_identifier,
                default_region=acc.default_region,
                credential_mode=acc.credential_mode,
                role_arn=acc.role_arn,
                external_id=acc.external_id,
                trust_policy_snippet=generate_trust_policy(acc.external_id),
                is_active=acc.is_active,
                created_at=str(acc.created_at),
                total_scans=total_scans,
                latest_scan=latest_scan_summary,
            )
        )

    return results


@router.post("", response_model=CloudAccountResponse, status_code=status.HTTP_201_CREATED)
def create_cloud_account(
    account_in: CloudAccountCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Registers a new cloud account in the CSPM system.
    Ownership is automatically set to current_user.id (cannot be overridden by client).
    Credentials are NEVER accepted via API; system relies on AWS provider chain or STS AssumeRole.
    Auto-generates a cryptographically random external_id for AWS accounts to prevent Confused Deputy attacks.
    """
    provider_clean = account_in.provider.strip().upper()
    if provider_clean not in ("AWS", "MOCK"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Supported providers are 'AWS' or 'MOCK'.",
        )

    # Check for duplicate per user (or globally for admin)
    existing_query = db.query(CloudAccount).filter(
        CloudAccount.provider == provider_clean,
        CloudAccount.account_identifier == account_in.account_identifier.strip(),
    )
    if not is_admin(current_user):
        existing_query = existing_query.filter(CloudAccount.user_id == current_user.id)

    existing = existing_query.first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cloud account '{account_in.account_identifier}' is already registered.",
        )

    # Resolve External ID and Role ARN
    external_id: Optional[str] = account_in.external_id.strip() if account_in.external_id else None
    role_arn: Optional[str] = account_in.role_arn.strip() if account_in.role_arn else None
    cred_mode = account_in.credential_mode.strip()

    if provider_clean == "MOCK":
        if role_arn:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Demo accounts use simulated mock data only and cannot be connected to real AWS IAM roles.",
            )
        cred_mode = "MOCK"

    if provider_clean == "AWS":
        if not external_id:
            external_id = f"cspm-ext-{secrets.token_hex(12)}"
        if role_arn:
            validate_role_arn_for_account(role_arn, account_in.account_identifier)
            if cred_mode == "ENVIRONMENT":
                cred_mode = "ROLE"

    account = CloudAccount(
        name=account_in.name.strip(),
        provider=provider_clean,
        account_identifier=account_in.account_identifier.strip(),
        default_region=account_in.default_region.strip(),
        credential_mode=cred_mode,
        role_arn=role_arn,
        external_id=external_id,
        user_id=current_user.id,
        is_active=True,
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    client_ip = request.client.host if request.client else None
    audit = AuditLog(
        user_id=current_user.id,
        action="CLOUD_ACCOUNT_CREATED",
        resource_type="cloud_account",
        resource_id=str(account.id),
        result="SUCCESS",
        metadata_json={
            "name": account.name,
            "provider": account.provider,
            "account_identifier": account.account_identifier,
            "role_arn": account.role_arn,
            "has_external_id": bool(account.external_id),
        },
        ip_address=client_ip,
    )
    db.add(audit)
    db.commit()

    logger.info(f"Cloud account created: '{account.name}' ({account.account_identifier}) by {current_user.username}")

    return CloudAccountResponse(
        id=str(account.id),
        name=account.name,
        provider=account.provider,
        account_identifier=account.account_identifier,
        default_region=account.default_region,
        credential_mode=account.credential_mode,
        role_arn=account.role_arn,
        external_id=account.external_id,
        trust_policy_snippet=generate_trust_policy(account.external_id),
        is_active=account.is_active,
        created_at=str(account.created_at),
        total_scans=0,
        latest_scan=None,
    )


@router.get("/{account_id}", response_model=CloudAccountResponse)
def get_cloud_account(
    account_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read:accounts")),
):
    """
    Retrieves metadata and status for a single cloud account.
    Enforces user isolation: returns 404 if account belongs to another user.
    """
    account = verify_account_access(db=db, user=current_user, account_id=account_id)

    # Guarantee external_id exists for AWS accounts
    if account.provider == "AWS" and not account.external_id:
        account.external_id = f"cspm-ext-{secrets.token_hex(12)}"
        db.add(account)
        db.commit()
        db.refresh(account)

    scans = db.query(Scan).filter(Scan.cloud_account_id == account.id).order_by(desc(Scan.created_at)).all()
    latest_scan_summary = None
    if scans:
        latest = scans[0]
        latest_scan_summary = LatestScanSummary(
            id=str(latest.id),
            status=latest.status,
            security_score=latest.security_score,
            findings_count=latest.findings_count,
            completed_at=str(latest.completed_at) if latest.completed_at else None,
        )

    return CloudAccountResponse(
        id=str(account.id),
        name=account.name,
        provider=account.provider,
        account_identifier=account.account_identifier,
        default_region=account.default_region,
        credential_mode=account.credential_mode,
        role_arn=account.role_arn,
        external_id=account.external_id,
        trust_policy_snippet=generate_trust_policy(account.external_id),
        is_active=account.is_active,
        created_at=str(account.created_at),
        total_scans=len(scans),
        latest_scan=latest_scan_summary,
    )


@router.patch("/{account_id}", response_model=CloudAccountResponse)
def update_cloud_account(
    account_id: uuid.UUID,
    account_in: CloudAccountUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Updates cloud account configuration such as IAM Role ARN, region, name, or credential mode.
    Enforces user isolation and validates Role ARN format and account matching.
    Supports switching credential_mode to ROLE before role_arn is entered.
    """
    account = verify_account_ownership(db=db, user=current_user, account_id=account_id)

    if account.provider == "MOCK":
        if account_in.role_arn:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Demo accounts use simulated mock data only and cannot be connected to real AWS IAM roles.",
            )
        if account_in.credential_mode and account_in.credential_mode != "MOCK":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Demo accounts use simulated mock data only and cannot be converted to AWS credential modes.",
            )

    if account_in.name is not None:
        account.name = account_in.name.strip()
    if account_in.default_region is not None:
        account.default_region = account_in.default_region.strip()
    if account_in.credential_mode is not None:
        account.credential_mode = account_in.credential_mode.strip()

    # Guarantee external_id exists for AWS account
    if account.provider == "AWS" and not account.external_id:
        account.external_id = f"cspm-ext-{secrets.token_hex(12)}"

    if account_in.role_arn is not None:
        clean_arn = account_in.role_arn.strip()
        if clean_arn:
            validate_role_arn_for_account(clean_arn, account.account_identifier)
            account.role_arn = clean_arn
            account.credential_mode = "ROLE"
        else:
            account.role_arn = None
            if account_in.credential_mode is None:
                account.credential_mode = "ENVIRONMENT"

    db.commit()
    db.refresh(account)

    client_ip = request.client.host if request.client else None
    audit = AuditLog(
        user_id=current_user.id,
        action="CLOUD_ACCOUNT_UPDATED",
        resource_type="cloud_account",
        resource_id=str(account.id),
        result="SUCCESS",
        metadata_json={
            "name": account.name,
            "role_arn": account.role_arn,
            "credential_mode": account.credential_mode,
        },
        ip_address=client_ip,
    )
    db.add(audit)
    db.commit()

    scans = db.query(Scan).filter(Scan.cloud_account_id == account.id).order_by(desc(Scan.created_at)).all()
    latest_scan_summary = None
    if scans:
        latest = scans[0]
        latest_scan_summary = LatestScanSummary(
            id=str(latest.id),
            status=latest.status,
            security_score=latest.security_score,
            findings_count=latest.findings_count,
            completed_at=str(latest.completed_at) if latest.completed_at else None,
        )

    return CloudAccountResponse(
        id=str(account.id),
        name=account.name,
        provider=account.provider,
        account_identifier=account.account_identifier,
        default_region=account.default_region,
        credential_mode=account.credential_mode,
        role_arn=account.role_arn,
        external_id=account.external_id,
        trust_policy_snippet=generate_trust_policy(account.external_id),
        is_active=account.is_active,
        created_at=str(account.created_at),
        total_scans=len(scans),
        latest_scan=latest_scan_summary,
    )


@router.post("/{account_id}/test-connection", response_model=TestConnectionResponse)
def test_cloud_account_connection(
    account_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Tests live connectivity to the cloud provider.
    Enforces user isolation: rejects access to other users' accounts.
    Supports both ENVIRONMENT credentials and cross-account STS AssumeRole with External ID.
    Rejects connection test if account is in ROLE mode without configured role_arn.
    """
    account = verify_account_ownership(db=db, user=current_user, account_id=account_id)

    if account.provider == "MOCK":
        return TestConnectionResponse(
            status="CONNECTED",
            provider="MOCK",
            account_id=account.account_identifier,
            arn=f"arn:aws:iam::{account.account_identifier}:root",
            user_id="MOCK_USER_ID",
            message="Simulated mock account connection verified successfully.",
        )

    # AWS Live Connection Test
    # If in ROLE mode, role_arn is strictly required to connect
    if account.credential_mode == "ROLE" and not account.role_arn:
        return TestConnectionResponse(
            status="ERROR",
            provider="AWS",
            account_id=None,
            arn=None,
            user_id=None,
            message="IAM Role ARN is not configured for ROLE credential mode. Please configure Role ARN in IAM Role Setup.",
        )

    try:
        factory = AWSClientFactory(
            region_name=account.default_region,
            role_arn=account.role_arn,
            external_id=account.external_id,
            target_account_id=account.account_identifier,
        )
        info = factory.test_sts_connection()
        return TestConnectionResponse(
            status="CONNECTED",
            provider="AWS",
            account_id=info.get("account_id"),
            arn=info.get("arn"),
            user_id=info.get("user_id"),
            message=f"Successfully authenticated to AWS Account {info.get('account_id')} via STS.",
        )
    except ValueError as e:
        logger.warning(f"AWS connection validation error for {account.account_identifier}: {e}")
        return TestConnectionResponse(
            status="ERROR",
            provider="AWS",
            account_id=None,
            arn=None,
            user_id=None,
            message=str(e),
        )
    except (ClientError, BotoCoreError, NoCredentialsError) as e:
        logger.warning(f"AWS connection test failed for {account.account_identifier}: {e}")
        return TestConnectionResponse(
            status="ERROR",
            provider="AWS",
            account_id=None,
            arn=None,
            user_id=None,
            message=f"AWS connection test failed: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Unexpected error testing connection for {account.account_identifier}: {e}")
        return TestConnectionResponse(
            status="ERROR",
            provider="AWS",
            account_id=None,
            arn=None,
            user_id=None,
            message=f"Unexpected connection error: {str(e)}",
        )


@router.delete("/{account_id}", status_code=status.HTTP_200_OK)
def delete_cloud_account(
    account_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Safely removes a cloud account registration and its associated CSPM scan data.
    Enforces tenant ownership (normal users delete only their own account, admins follow existing RBAC).
    Guaranteed zero external AWS mutations (no STS, IAM, or AWS resource deletion).
    Atomic transactional cleanup: cleans reports, findings, resources, scans, and account.
    """
    account = verify_account_ownership(db=db, user=current_user, account_id=account_id)

    # Capture metadata for audit logging before deletion
    acc_id_str = str(account.id)
    acc_name = account.name
    acc_identifier = account.account_identifier
    acc_provider = account.provider
    acc_region = account.default_region
    acc_cred_mode = account.credential_mode

    try:
        # 1. Identify all scans belonging strictly to this cloud account
        scan_records = db.query(Scan.id).filter(Scan.cloud_account_id == account.id).all()
        scan_ids = [s[0] for s in scan_records]

        # 2. Safely delete associated reports
        if scan_ids:
            db.query(Report).filter(Report.scan_id.in_(scan_ids)).delete(synchronize_session=False)

        # 3. Safely delete associated findings for this cloud account
        db.query(Finding).filter(Finding.cloud_account_id == account.id).delete(synchronize_session=False)

        # 4. Safely delete associated resources for this cloud account
        db.query(Resource).filter(Resource.cloud_account_id == account.id).delete(synchronize_session=False)

        # 5. Safely delete associated scans for this cloud account
        db.query(Scan).filter(Scan.cloud_account_id == account.id).delete(synchronize_session=False)

        # 6. Delete the cloud account record itself (specifically by primary key ID)
        db.delete(account)

        # 7. Record non-sensitive audit event
        client_ip = request.client.host if request.client else None
        audit = AuditLog(
            user_id=current_user.id,
            action="CLOUD_ACCOUNT_DELETED",
            resource_type="cloud_account",
            resource_id=acc_id_str,
            result="SUCCESS",
            metadata_json={
                "name": acc_name,
                "provider": acc_provider,
                "account_identifier": acc_identifier,
                "default_region": acc_region,
                "credential_mode": acc_cred_mode,
            },
            ip_address=client_ip,
        )
        db.add(audit)
        db.commit()

        logger.info(
            f"Cloud account '{acc_name}' (ID: {acc_id_str}, AWS ID: {acc_identifier}) and associated CSPM data "
            f"successfully deleted by {current_user.username}"
        )

        return {
            "status": "SUCCESS",
            "message": f"Cloud account '{acc_name}' and its associated CSPM scan data were removed successfully.",
            "account_id": acc_id_str,
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete cloud account {acc_id_str}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete cloud account: {str(e)}",
        )


