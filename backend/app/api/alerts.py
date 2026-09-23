import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.database.session import get_db
from app.api.deps import (
    get_current_user,
    get_user_accessible_account_ids,
    require_role,
    is_admin,
)
from app.models.auth import User
from app.models.monitoring import SecurityAlert
from app.models.cloud import CloudAccount
from app.monitoring.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


class SecurityAlertResponse(BaseModel):
    id: uuid.UUID
    cloud_account_id: uuid.UUID
    account_name: Optional[str] = None
    account_identifier: Optional[str] = None
    account_provider: Optional[str] = None
    finding_id: Optional[uuid.UUID] = None
    alert_type: str
    severity: str
    title: str
    description: str
    previous_value: Optional[str] = None
    current_value: Optional[str] = None
    status: str
    first_detected_at: datetime
    last_detected_at: datetime
    resolved_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    items: List[SecurityAlertResponse]
    total: int
    limit: int
    offset: int


class AlertSummaryResponse(BaseModel):
    total_open: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    resolved: int = 0
    new_findings: int = 0
    risk_increases: int = 0


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(ACKNOWLEDGED|RESOLVED)$")


def _enrich_alert(alert: SecurityAlert) -> Dict[str, Any]:
    acc = alert.cloud_account
    return {
        "id": alert.id,
        "cloud_account_id": alert.cloud_account_id,
        "account_name": acc.name if acc else "Unknown",
        "account_identifier": acc.account_identifier if acc else "Unknown",
        "account_provider": acc.provider if acc else "AWS",
        "finding_id": alert.finding_id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "title": alert.title,
        "description": alert.description,
        "previous_value": alert.previous_value,
        "current_value": alert.current_value,
        "status": alert.status,
        "first_detected_at": alert.first_detected_at,
        "last_detected_at": alert.last_detected_at,
        "resolved_at": alert.resolved_at,
        "created_at": alert.created_at,
    }


@router.get("", response_model=AlertListResponse)
def list_alerts(
    cloud_account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account ID"),
    status: Optional[str] = Query(None, description="Filter by status (OPEN, ACKNOWLEDGED, RESOLVED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Lists security alerts with filtering and pagination.
    Strictly isolated to accounts accessible to the authenticated user.
    """
    accessible_account_ids = get_user_accessible_account_ids(db, current_user)
    if not accessible_account_ids:
        return {"items": [], "total": 0, "limit": limit, "offset": offset}

    if cloud_account_id:
        if cloud_account_id not in accessible_account_ids:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cloud account not found.",
            )
        target_account_ids = [cloud_account_id]
    else:
        target_account_ids = accessible_account_ids

    query = db.query(SecurityAlert).filter(
        SecurityAlert.cloud_account_id.in_(target_account_ids)
    )

    if status:
        query = query.filter(SecurityAlert.status == status.upper())
    if severity:
        query = query.filter(SecurityAlert.severity == severity.upper())
    if alert_type:
        query = query.filter(SecurityAlert.alert_type == alert_type.upper())

    total = query.count()
    alerts = query.order_by(
        desc(SecurityAlert.last_detected_at),
        desc(SecurityAlert.created_at)
    ).offset(offset).limit(limit).all()

    items = [_enrich_alert(a) for a in alerts]
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/summary", response_model=AlertSummaryResponse)
def get_alerts_summary(
    cloud_account_id: Optional[uuid.UUID] = Query(None, description="Optional target account filter"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns aggregated security alert statistics for dashboard KPI cards.
    """
    accessible_account_ids = get_user_accessible_account_ids(db, current_user)
    if not accessible_account_ids:
        return AlertSummaryResponse()

    if cloud_account_id:
        if cloud_account_id not in accessible_account_ids:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cloud account not found.",
            )
        target_ids = [cloud_account_id]
    else:
        target_ids = accessible_account_ids

    base_q = db.query(SecurityAlert).filter(SecurityAlert.cloud_account_id.in_(target_ids))

    total_open = base_q.filter(SecurityAlert.status == "OPEN").count()
    critical = base_q.filter(SecurityAlert.status == "OPEN", SecurityAlert.severity == "CRITICAL").count()
    high = base_q.filter(SecurityAlert.status == "OPEN", SecurityAlert.severity == "HIGH").count()
    medium = base_q.filter(SecurityAlert.status == "OPEN", SecurityAlert.severity == "MEDIUM").count()
    low = base_q.filter(SecurityAlert.status == "OPEN", SecurityAlert.severity == "LOW").count()
    resolved = base_q.filter(SecurityAlert.status == "RESOLVED").count()
    new_findings = base_q.filter(SecurityAlert.status == "OPEN", SecurityAlert.alert_type == "NEW_FINDING").count()
    risk_increases = base_q.filter(SecurityAlert.status == "OPEN", SecurityAlert.alert_type == "RISK_INCREASED").count()

    return AlertSummaryResponse(
        total_open=total_open,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        resolved=resolved,
        new_findings=new_findings,
        risk_increases=risk_increases,
    )


@router.get("/{alert_id}", response_model=SecurityAlertResponse)
def get_alert_detail(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves detailed attributes for a single security alert.
    Guarantees cross-tenant protection by blocking access to foreign tenant alerts.
    """
    accessible_account_ids = get_user_accessible_account_ids(db, current_user)
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()

    if not alert or alert.cloud_account_id not in accessible_account_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security alert not found.",
        )

    return _enrich_alert(alert)


@router.patch("/{alert_id}", response_model=SecurityAlertResponse)
def update_alert_status(
    alert_id: uuid.UUID,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Updates the lifecycle status of an alert (ACKNOWLEDGED or RESOLVED).
    Enforces authorization and records an audit log entry.
    """
    accessible_account_ids = get_user_accessible_account_ids(db, current_user)
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()

    if not alert or alert.cloud_account_id not in accessible_account_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security alert not found.",
        )

    # Allow ADMIN, SECURITY_ANALYST, or account owner
    acc = alert.cloud_account
    user_roles = [r.name for r in current_user.roles]
    is_owner = acc and acc.user_id == current_user.id
    can_modify = is_admin(current_user) or "SECURITY_ANALYST" in user_roles or is_owner

    if not can_modify:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to modify security alert status.",
        )

    if payload.status == "ACKNOWLEDGED":
        alert = AlertService.acknowledge_alert(db, alert, current_user)
    elif payload.status == "RESOLVED":
        alert = AlertService.resolve_alert(db, alert, current_user)

    return _enrich_alert(alert)
