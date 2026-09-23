import os
import uuid
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime

from app.database.session import get_db
from app.models.auth import User
from app.api.deps import get_current_user, verify_account_ownership
from app.services.report_service import ReportService

logger = logging.getLogger("cspm.api.reports")
router = APIRouter(prefix="/reports", tags=["Executive & Technical Reports"])


class ReportGenerateRequest(BaseModel):
    account_id: Optional[uuid.UUID] = None
    report_type: str = "EXECUTIVE"  # EXECUTIVE or TECHNICAL
    title: Optional[str] = None


class ReportResponse(BaseModel):
    id: uuid.UUID
    cloud_account_id: Optional[uuid.UUID]
    title: str
    report_type: str
    format: str
    file_path: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportListResponse(BaseModel):
    items: List[ReportResponse]
    total: int


@router.post("", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
def generate_report(
    payload: ReportGenerateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generates an Executive or Technical CSPM posture PDF report.
    Permitted for authenticated users (ADMIN, SECURITY_ANALYST, and VIEWER for their own accounts).
    Enforces tenant isolation: users can only generate reports for their owned accounts (returns 404 for cross-tenant).
    """
    if payload.account_id:
        verify_account_ownership(db=db, current_user=current_user, account_id=payload.account_id)

    try:
        report = ReportService.generate_report(
            db=db,
            user=current_user,
            account_id=payload.account_id,
            report_type=payload.report_type,
            title=payload.title,
            client_ip=request.client.host if request.client else None,
        )
        return report
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("", response_model=ReportListResponse)
def list_reports(
    account_id: Optional[uuid.UUID] = Query(None),
    cloud_account_id: Optional[uuid.UUID] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves generated report metadata records."""
    target_account = account_id or cloud_account_id
    items, total = ReportService.list_reports(
        db=db,
        account_id=target_account,
        limit=limit,
        offset=offset,
        user=current_user,
    )
    return ReportListResponse(items=items, total=total)


@router.get("/{report_id}", response_model=ReportResponse)
def get_report_metadata(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves metadata for a specific report.
    Enforces user isolation: returns 404 if report belongs to another user's account.
    """
    report = ReportService.get_report_by_id(db=db, report_id=report_id, user=current_user)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.get("/{report_id}/download")
def download_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Downloads the generated PDF report securely with strict path traversal checks.
    Enforces user isolation: returns 404 if report belongs to another user's account.
    """
    report = ReportService.get_report_by_id(db=db, report_id=report_id, user=current_user)
    if not report or not report.file_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found")

    abs_path = os.path.abspath(report.file_path)
    if not os.path.exists(abs_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file missing on server disk")

    filename = os.path.basename(abs_path)
    return FileResponse(
        path=abs_path,
        media_type="application/pdf",
        filename=filename,
    )

