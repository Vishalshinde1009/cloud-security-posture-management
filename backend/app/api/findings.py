import uuid
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.auth import User
from app.api.deps import get_current_user
from app.schemas.finding import (
    FindingResponse,
    FindingDetailResponse,
    FindingListResponse,
    FindingStatusUpdate,
    FindingNoteCreate,
    FindingNoteResponse,
)
from app.services.finding_service import FindingService

logger = logging.getLogger("cspm.api.findings")
router = APIRouter(prefix="/findings", tags=["Security Findings"])


@router.get("", response_model=FindingListResponse)
def list_findings(
    account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID"),
    cloud_account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID alias"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    service: Optional[str] = Query(None, description="Filter by AWS service (S3, IAM, EC2, VPC, CloudTrail, RDS)"),
    status: Optional[str] = Query(None, description="Filter by status (OPEN, RESOLVED, SUPPRESSED)"),
    rule_id: Optional[str] = Query(None, description="Filter by canonical rule ID (e.g. S3-001)"),
    resource_id: Optional[uuid.UUID] = Query(None, description="Filter by resource UUID"),
    risk_level: Optional[str] = Query(None, description="Filter by calculated risk level (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    risk_priority: Optional[str] = Query(None, description="Filter by remediation priority (IMMEDIATE, HIGH, MEDIUM, LOW)"),
    min_risk_score: Optional[float] = Query(None, ge=0, le=100, description="Filter by minimum risk score"),
    max_risk_score: Optional[float] = Query(None, ge=0, le=100, description="Filter by maximum risk score"),
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
    target_account_id = account_id or cloud_account_id
    offset = (page - 1) * limit
    items, total = FindingService.get_findings(
        db=db,
        account_id=target_account_id,
        severity=severity,
        service=service,
        status=status,
        rule_id=rule_id,
        resource_id=resource_id,
        risk_level=risk_level,
        risk_priority=risk_priority,
        min_risk_score=min_risk_score,
        max_risk_score=max_risk_score,
        search=search,
        limit=limit,
        offset=offset,
        user=current_user,
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
    Enforces user isolation: returns 404 if finding belongs to another user's account.
    """
    finding = FindingService.get_finding_by_id(db=db, finding_id=finding_id, user=current_user)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found.",
        )
    return finding


@router.patch("/{finding_id}/status")
def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Updates the status of a finding (OPEN, IN_PROGRESS, RESOLVED, ACCEPTED_RISK, FALSE_POSITIVE).
    Permitted for ADMIN and SECURITY_ANALYST.
    Enforces user isolation: rejects modification of another user's finding.
    """
    user_roles = [r.name for r in current_user.roles]
    if "ADMIN" not in user_roles and "SECURITY_ANALYST" not in user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Viewers are not permitted to update finding status.",
        )

    try:
        updated = FindingService.update_finding_status(
            db=db,
            finding_id=finding_id,
            new_status=payload.status,
            user=current_user,
            rationale=payload.rationale,
        )
        return {
            "message": "Finding status updated successfully",
            "finding_id": str(updated.id),
            "status": updated.status,
            "resolved_at": updated.resolved_at.isoformat() if updated.resolved_at else None,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{finding_id}/notes", response_model=FindingNoteResponse)
def add_finding_note(
    finding_id: uuid.UUID,
    payload: FindingNoteCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Adds an analyst investigation note to a finding.
    Permitted for ADMIN and SECURITY_ANALYST.
    Enforces user isolation: rejects note addition to another user's finding.
    """
    user_roles = [r.name for r in current_user.roles]
    if "ADMIN" not in user_roles and "SECURITY_ANALYST" not in user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Viewers are not permitted to add finding notes.",
        )

    try:
        note = FindingService.add_finding_note(
            db=db,
            finding_id=finding_id,
            note_text=payload.note,
            user=current_user,
        )
        return FindingNoteResponse(
            id=note.id,
            finding_id=note.finding_id,
            user_id=note.author_id,
            author_name=note.author_username,
            note=note.note,
            created_at=note.created_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{finding_id}/notes", response_model=list[FindingNoteResponse])
def get_finding_notes(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves all analyst notes for a specific finding with user isolation.
    """
    return FindingService.get_finding_notes(db=db, finding_id=finding_id, user=current_user)

