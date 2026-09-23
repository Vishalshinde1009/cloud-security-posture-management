import uuid
from typing import Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.api.deps import (
    get_current_user,
    get_client_ip,
    require_role,
    verify_account_access,
    verify_account_ownership,
    is_admin,
)
from app.models.auth import User
from app.models.cloud import CloudAccount
from app.models.monitoring import MonitoringConfig
from app.monitoring.monitoring_service import MonitoringService

router = APIRouter(prefix="/monitoring", tags=["Continuous Monitoring"])


class MonitoringConfigResponse(BaseModel):
    id: uuid.UUID
    cloud_account_id: uuid.UUID
    enabled: bool
    scan_interval_minutes: int
    last_scan_at: Optional[datetime] = None
    next_scan_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class MonitoringConfigUpdate(BaseModel):
    enabled: bool
    scan_interval_minutes: int = Field(default=60, ge=5, le=10080)


class MonitoringRunResponse(BaseModel):
    cloud_account_id: str
    account_name: Optional[str] = None
    scan_id: str
    previous_scan_id: Optional[str] = None
    new_findings: int = 0
    risk_increases: int = 0
    resolved_findings: int = 0
    posture_change: float = 0.0
    alerts_created: int = 0
    status: Optional[str] = "COMPLETED"
    error: Optional[str] = None


@router.get("/{cloud_account_id}", response_model=MonitoringConfigResponse)
def get_monitoring_config(
    cloud_account_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves the monitoring configuration for an authorized cloud account.
    Returns default disabled configuration if not yet initialized.
    """
    account = verify_account_access(db, current_user, cloud_account_id)
    config = MonitoringService.get_or_create_config(db, account.id)
    return config


@router.put("/{cloud_account_id}", response_model=MonitoringConfigResponse)
def update_monitoring_config(
    cloud_account_id: uuid.UUID,
    payload: MonitoringConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Configures continuous monitoring preferences (enabled state, scan interval).
    Restricted to account owners or platform Administrators.
    """
    account = verify_account_ownership(db, current_user=current_user, account_id=cloud_account_id)
    config = MonitoringService.update_config(
        db=db,
        account=account,
        enabled=payload.enabled,
        scan_interval_minutes=payload.scan_interval_minutes,
        user=current_user,
    )
    return config


@router.post("/{cloud_account_id}/run", response_model=MonitoringRunResponse)
def trigger_manual_monitoring_run(
    cloud_account_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Manually triggers an immediate continuous monitoring evaluation cycle:
    1. Validates ownership and that monitoring is enabled
    2. Runs the read-only scan against AWS or Mock provider
    3. Detects drift/differences from previous scan
    4. Generates deduplicated security alerts
    5. Updates next execution timestamp
    """
    client_ip = get_client_ip(request)
    summary = MonitoringService.run_monitoring(
        db=db,
        account_id=cloud_account_id,
        user=current_user,
        client_ip=client_ip,
    )
    return summary
