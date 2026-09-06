import uuid
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.auth import User
from app.api.deps import get_current_user
from app.schemas.finding import FindingResponse, FindingDetailResponse, FindingListResponse
from app.services.finding_service import FindingService

logger = logging.getLogger("cspm.api.findings")
router = APIRouter(prefix="/findings", tags=["Security Findings"])


@router.get("", response_model=FindingListResponse)
def list_findings(
    account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    service: Optional[str] = Query(None, description="Filter by AWS service (S3, IAM, EC2, VPC, CloudTrail, RDS)"),
    status: Optional[str] = Query(None, description="Filter by status (OPEN, RESOLVED, SUPPRESSED)"),
    rule_id: Optional[str] = Query(None, description="Filter by canonical rule ID (e.g. S3-001)"),
    resource_id: Optional[uuid.UUID] = Query(None, description="Filter by resource UUID"),
    search: Optional[str] = Query(None, description="Search title, description, or resource identifier"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves paginated security findings with multi-criteria filtering.
    Accessible to all authenticated users (ADMIN, SECURITY_ANALYST, VIEWER).
    """
    offset = (page - 1) * limit
    items, total = FindingService.get_findings(
        db=db,
        account_id=account_id,
        severity=severity,
        service=service,
        status=status,
        rule_id=rule_id,
        resource_id=resource_id,
        search=search,
        limit=limit,
        offset=offset,
    )
    return FindingListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
    )


@router.get("/{finding_id}", response_model=FindingDetailResponse)
def get_finding(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves full details for a specific security finding including technical configuration evidence.
    """
    finding = FindingService.get_finding_by_id(db=db, finding_id=finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found.",
        )
    return finding
