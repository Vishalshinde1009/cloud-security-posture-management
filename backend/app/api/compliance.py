import uuid
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database.session import get_db
from app.models.auth import User
from app.api.deps import get_current_user
from app.services.compliance_service import ComplianceService

logger = logging.getLogger("cspm.api.compliance")
router = APIRouter(prefix="/compliance", tags=["Compliance & Benchmarks"])


class ComplianceSummaryResponse(BaseModel):
    framework: str
    framework_name: str
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    compliance_percentage: float
    status_label: str
    critical_findings_count: int
    high_findings_count: int
    total_findings_mapped: int


@router.get("/frameworks")
def list_frameworks(
    current_user: User = Depends(get_current_user),
):
    """
    Returns list of supported security compliance benchmarks.
    Available to all authenticated users.
    """
    return ComplianceService.list_frameworks()


@router.get("/{framework}/summary", response_model=ComplianceSummaryResponse)
def get_framework_summary(
    framework: str,
    account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID"),
    cloud_account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID alias"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns security control status, coverage percentage, and gap metrics for a specific benchmark.
    Terminology strictly adheres to control status rather than regulatory certification.
    Enforces user isolation: normal users only evaluate compliance against their own accounts.
    """
    try:
        target_account_id = account_id or cloud_account_id
        raw = ComplianceService.get_framework_summary(
            db=db,
            framework=framework,
            account_id=target_account_id,
            user=current_user,
        )
        # Fetch open findings for severity breakdown
        framework_key = raw["framework"]
        controls = ComplianceService.get_framework_controls(
            db=db,
            framework=framework_key,
            account_id=target_account_id,
            user=current_user,
        )
        all_findings = [f for c in controls for f in c.get("findings", [])]
        crit_c = sum(1 for f in all_findings if f.get("severity", "").upper() == "CRITICAL")
        high_c = sum(1 for f in all_findings if f.get("severity", "").upper() == "HIGH")

        pct = raw["coverage_percentage"]
        status_label = (
            "EXCELLENT" if pct >= 90 else
            "GOOD" if pct >= 75 else
            "MODERATE" if pct >= 50 else
            "POOR" if pct >= 25 else "CRITICAL"
        )

        return ComplianceSummaryResponse(
            framework=raw["framework"],
            framework_name=raw["framework_name"],
            total_controls=raw["total_controls"],
            compliant_controls=raw["passing_controls"],
            non_compliant_controls=raw["failing_controls"],
            compliance_percentage=pct,
            status_label=status_label,
            critical_findings_count=crit_c,
            high_findings_count=high_c,
            total_findings_mapped=len(all_findings),
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{framework}/controls")
def get_framework_controls(
    framework: str,
    account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID"),
    cloud_account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID alias"),
    status_filter: Optional[str] = Query(None, description="Filter by status: COMPLIANT, NON_COMPLIANT"),
    service: Optional[str] = Query(None, description="Filter by cloud service (e.g. S3, IAM, EC2)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns detailed control coverage table with mapped findings, severity, and remediation guidance.
    Enforces user isolation: normal users only evaluate compliance against their own accounts.
    """
    try:
        target_account_id = account_id or cloud_account_id
        controls = ComplianceService.get_framework_controls(
            db=db,
            framework=framework,
            status_filter=status_filter,
            service_filter=service,
            account_id=target_account_id,
            user=current_user,
        )
        return controls
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

