import uuid
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.auth import User
from app.api.deps import get_current_user
from app.schemas.scanner import ResourceResponse, ResourceDetailResponse, ResourceListResponse
from app.services.scan_service import ScanService

logger = logging.getLogger("cspm.api.resources")
router = APIRouter(prefix="/resources", tags=["Cloud Resources"])


@router.get("", response_model=ResourceListResponse)
def list_resources(
    account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID"),
    service: Optional[str] = Query(None, description="Filter by AWS service (e.g. S3, IAM, EC2, VPC, CloudTrail, RDS)"),
    security_status: Optional[str] = Query(None, description="Filter by status (e.g. SECURE, AT_RISK)"),
    search: Optional[str] = Query(None, description="Search resource ID or name"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Lists discovered cloud assets across services with multi-criteria filtering.
    Accessible to all authenticated users (ADMIN, SECURITY_ANALYST, VIEWER).
    """
    offset = (page - 1) * limit
    items, total = ScanService.get_resources(
        db=db,
        account_id=account_id,
        service=service,
        security_status=security_status,
        search=search,
        limit=limit,
        offset=offset,
    )
    return ResourceListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
    )


@router.get("/{resource_id}", response_model=ResourceDetailResponse)
def get_resource(
    resource_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns granular configuration evidence, metadata, and tags for a specific cloud asset.
    """
    res = ScanService.get_resource_by_id(db=db, resource_id=resource_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource with ID '{resource_id}' not found.",
        )
    return res
