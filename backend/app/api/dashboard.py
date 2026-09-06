import uuid
import logging
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.auth import User
from app.api.deps import get_current_user
from app.services.scan_service import ScanService

logger = logging.getLogger("cspm.api.dashboard")
router = APIRouter(prefix="/dashboard", tags=["Security Posture Dashboard"])


@router.get("/stats")
def get_dashboard_stats(
    account_id: Optional[uuid.UUID] = Query(None, description="Filter by cloud account UUID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Retrieves aggregated, real-time security posture and risk analytics for the SOC dashboard:
    - Current security posture score and rating
    - Severity and priority distribution counts
    - Historical score trend across recent scans
    - Top 5 riskiest resources and highest risk findings
    - Historical scan comparison metrics (new, resolved, persistent findings)
    """
    return ScanService.get_dashboard_stats(db=db, account_id=account_id)
