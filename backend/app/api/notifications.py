import uuid
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime

from app.database.session import get_db
from app.models.auth import User
from app.api.deps import get_current_user
from app.services.notification_service import NotificationService

logger = logging.getLogger("cspm.api.notifications")
router = APIRouter(prefix="/notifications", tags=["In-App Notifications"])


class NotificationResponse(BaseModel):
    id: uuid.UUID
    user_id: Optional[uuid.UUID]
    title: Optional[str] = None
    message: str
    notification_type: str
    severity: Optional[str] = "MEDIUM"
    is_read: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class NotificationListResponse(BaseModel):
    items: List[NotificationResponse]
    total: int
    unread_count: int


@router.get("", response_model=NotificationListResponse)
def list_notifications(
    unread_only: bool = Query(False, description="Filter unread notifications only"),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves current user notifications with unread count."""
    items_raw, total = NotificationService.get_user_notifications(
        db=db,
        user_id=current_user.id,
        unread_only=unread_only,
        limit=limit,
    )
    unread_count = NotificationService.get_unread_count(db=db, user_id=current_user.id)
    items = [
        NotificationResponse(
            id=n.id,
            user_id=n.user_id,
            title=n.notification_type.replace("_", " ").title(),
            message=n.message,
            notification_type=n.notification_type,
            severity="CRITICAL" if "CRITICAL" in n.notification_type else "HIGH" if "HIGH" in n.notification_type else "INFO",
            is_read=(n.status == "READ"),
            created_at=n.created_at,
        )
        for n in items_raw
    ]
    return NotificationListResponse(
        items=items,
        total=total,
        unread_count=unread_count,
    )


@router.get("/unread-count")
def get_unread_count(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns number of unread alerts for badge counter."""
    count = NotificationService.get_unread_count(db=db, user_id=current_user.id)
    return {"unread_count": count}


@router.post("/{notification_id}/read")
def mark_as_read(
    notification_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Marks a single notification as read."""
    notif = NotificationService.mark_as_read(
        db=db,
        notification_id=notification_id,
        user_id=current_user.id,
    )
    if not notif:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found")
    return {"status": "success", "message": "Notification marked as read"}


@router.post("/read-all")
def mark_all_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Marks all notifications for current user as read."""
    updated = NotificationService.mark_all_as_read(db=db, user_id=current_user.id)
    return {"status": "success", "marked_read": updated}


class NotificationPreferencesUpdate(BaseModel):
    email_alerts_enabled: bool


class NotificationPreferencesResponse(BaseModel):
    email: str
    email_alerts_enabled: bool


@router.get("/preferences", response_model=NotificationPreferencesResponse)
def get_notification_preferences(
    current_user: User = Depends(get_current_user),
):
    """Retrieves current user email alert preferences."""
    return NotificationPreferencesResponse(
        email=current_user.email,
        email_alerts_enabled=current_user.email_alerts_enabled,
    )


@router.put("/preferences", response_model=NotificationPreferencesResponse)
def update_notification_preferences(
    payload: NotificationPreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Updates current user email alert preferences."""
    from app.models.audit import AuditLog
    current_user.email_alerts_enabled = payload.email_alerts_enabled
    db.add(AuditLog(
        user_id=current_user.id,
        action="NOTIFICATION_PREFERENCES_UPDATED",
        resource_type="user_preferences",
        resource_id=str(current_user.id),
        result="SUCCESS",
        metadata_json={
            "email_alerts_enabled": payload.email_alerts_enabled,
        }
    ))
    db.commit()
    db.refresh(current_user)
    return NotificationPreferencesResponse(
        email=current_user.email,
        email_alerts_enabled=current_user.email_alerts_enabled,
    )
