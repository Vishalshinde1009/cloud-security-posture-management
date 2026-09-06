import uuid
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.auth import User
from app.api.deps import get_current_user
from app.schemas.finding import SecurityRuleResponse, RuleListResponse
from app.services.finding_service import FindingService

logger = logging.getLogger("cspm.api.rules")
router = APIRouter(prefix="/rules", tags=["Security Detection Rules"])


@router.get("", response_model=RuleListResponse)
def list_rules(
    service: Optional[str] = Query(None, description="Filter by AWS service (e.g. S3, IAM, EC2, VPC, CloudTrail, RDS)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled state"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns the comprehensive catalog of CSPM security misconfiguration detection rules.
    Accessible to all authenticated users.
    """
    # Ensure rules are synced to DB
    FindingService.sync_security_rules_to_db(db)

    offset = (page - 1) * limit
    items, total = FindingService.get_rules(
        db=db,
        service=service,
        category=category,
        severity=severity,
        enabled=enabled,
        limit=limit,
        offset=offset,
    )
    return RuleListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
    )


@router.get("/{rule_identifier}", response_model=SecurityRuleResponse)
def get_rule(
    rule_identifier: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves full metadata for a security rule by canonical ID (e.g., 'S3-001') or UUID.
    """
    FindingService.sync_security_rules_to_db(db)
    rule = FindingService.get_rule_by_id(db=db, identifier=rule_identifier)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security rule '{rule_identifier}' not found.",
        )
    return rule
