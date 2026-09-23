import uuid
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from pydantic import BaseModel
from datetime import datetime

from app.database.session import get_db
from app.models.auth import User
from app.models.audit import AuditLog
from app.models.cloud import CloudAccount, Scan
from app.models.finding import Finding
from app.models.monitoring import SecurityAlert
from app.api.deps import get_current_user

logger = logging.getLogger("cspm.api.audit")
router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    user_id: Optional[uuid.UUID]
    username: Optional[str] = None
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    result: str
    metadata_json: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    items: List[AuditLogResponse]
    total: int
    page: int
    limit: int


@router.get("", response_model=AuditLogListResponse)
def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action type (e.g. SCAN_TRIGGERED, USER_LOGIN)"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    result: Optional[str] = Query(None, description="Filter by result (SUCCESS, FAILURE)"),
    user_id: Optional[uuid.UUID] = Query(None, description="Filter by user UUID (Admin/Analyst only)"),
    account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves system audit logs with multi-criteria filtering.
    - ADMIN and SECURITY_ANALYST (users with 'read:audit_logs' permission) view global audit logs.
    - VIEWER (users without global permission) view strictly tenant-isolated audit logs belonging to their own user and registered cloud resources.
    """
    user_roles = [r.name for r in current_user.roles]
    user_perms = {p.name for r in current_user.roles for p in r.permissions}

    is_global_auditor = ("ADMIN" in user_roles or "read:audit_logs" in user_perms)

    query = db.query(AuditLog)

    if not is_global_auditor:
        # Strict tenant-isolation for VIEWER (or users without global read:audit_logs)
        # 1. Accounts owned by this viewer
        user_account_ids_uuid = [
            acc.id for acc in db.query(CloudAccount.id).filter(CloudAccount.user_id == current_user.id).all()
        ]

        # 2. Associated resources under viewer's accounts
        accessible_resource_ids = {str(aid) for aid in user_account_ids_uuid}
        if user_account_ids_uuid:
            scan_ids = [str(s.id) for s in db.query(Scan.id).filter(Scan.cloud_account_id.in_(user_account_ids_uuid)).all()]
            alert_ids = [str(a.id) for a in db.query(SecurityAlert.id).filter(SecurityAlert.cloud_account_id.in_(user_account_ids_uuid)).all()]
            finding_ids = [str(f.id) for f in db.query(Finding.id).filter(Finding.cloud_account_id.in_(user_account_ids_uuid)).all()]
            accessible_resource_ids.update(scan_ids)
            accessible_resource_ids.update(alert_ids)
            accessible_resource_ids.update(finding_ids)

        if accessible_resource_ids:
            query = query.filter(
                or_(
                    AuditLog.user_id == current_user.id,
                    AuditLog.resource_id.in_(list(accessible_resource_ids)),
                )
            )
        else:
            query = query.filter(AuditLog.user_id == current_user.id)

        # Ensure user_id param cannot be used to bypass tenant isolation
        if user_id and user_id != current_user.id:
            query = query.filter(AuditLog.id == uuid.uuid4())

        # Ensure account_id param cannot be used to inspect other tenants
        if account_id:
            if account_id not in user_account_ids_uuid:
                query = query.filter(AuditLog.id == uuid.uuid4())
            else:
                query = query.filter(AuditLog.resource_id == str(account_id))
    else:
        # Global auditor (ADMIN or SECURITY_ANALYST)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if account_id:
            query = query.filter(AuditLog.resource_id == str(account_id))

    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if result:
        query = query.filter(AuditLog.result == result.upper())

    total = query.count()
    offset = (page - 1) * limit
    logs = query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()

    items = []
    for log in logs:
        # For non-global auditor (VIEWER), mask other user identities
        if not is_global_auditor and log.user_id != current_user.id:
            log_user_id = None
            log_username = "System"
        else:
            log_user_id = log.user_id
            log_username = log.user.username if log.user else "System"

        # Sanitize metadata_json against credential / secret leakage
        meta = log.metadata_json or {}
        safe_meta = {}
        for k, v in meta.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ["password", "secret", "token", "key", "credential", "jwt"]):
                continue
            if not is_global_auditor and "email" in k_lower:
                if str(v).lower() != current_user.email.lower():
                    continue
            safe_meta[k] = v

        items.append(
            AuditLogResponse(
                id=log.id,
                user_id=log_user_id,
                username=log_username,
                action=log.action,
                resource_type=log.resource_type,
                resource_id=log.resource_id,
                result=log.result,
                metadata_json=safe_meta,
                ip_address=log.ip_address,
                created_at=log.timestamp,
            )
        )

    return AuditLogListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
    )
