import uuid
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.auth import User
from app.api.deps import get_current_user, require_role, get_client_ip
from app.schemas.scanner import ScanCreate, ScanResponse, ScanListResponse, ScanComparisonResponse
from app.services.scan_service import ScanService

logger = logging.getLogger("cspm.api.scans")
router = APIRouter(prefix="/scans", tags=["CSPM Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def trigger_scan(
    request: Request,
    payload: Optional[ScanCreate] = None,
    current_user: User = Depends(require_role(["ADMIN", "SECURITY_ANALYST"])),
    db: Session = Depends(get_db),
):
    """
    Triggers an on-demand CSPM discovery and posture scan.
    RBAC: Restricted to ADMIN and SECURITY_ANALYST roles.
    In Phase 4, executes safe deterministic MockProvider pipeline.
    """
    account_id = payload.account_id if payload else None
    client_ip = get_client_ip(request)

    try:
        scan = ScanService.trigger_scan(
            db=db,
            user=current_user,
            account_id=account_id,
            client_ip=client_ip,
        )
        return scan
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(ve),
        )
    except Exception as e:
        logger.error(f"Failed to trigger scan: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while executing the cloud scan.",
        )


@router.get("", response_model=ScanListResponse)
def list_scans(
    account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves historical scan execution runs with pagination.
    Accessible to all authenticated users (ADMIN, SECURITY_ANALYST, VIEWER).
    """
    offset = (page - 1) * limit
    items, total = ScanService.get_scans(
        db=db,
        account_id=account_id,
        limit=limit,
        offset=offset,
    )
    return ScanListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves execution metrics and state for a specific scan.
    """
    scan = ScanService.get_scan_by_id(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )
    return scan


@router.get("/{scan_id}/comparison", response_model=ScanComparisonResponse)
def compare_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Computes historical security posture progression and drift between this scan
    and its immediate predecessor for the same cloud account.
    """
    try:
        comparison = ScanService.compare_scan_by_id(db=db, scan_id=scan_id)
        return comparison
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(ve),
        )
