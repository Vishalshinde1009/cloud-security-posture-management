from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    UserResponse,
    UserMeResponse,
    MessageResponse,
)
from app.services.auth_service import AuthService
from app.api.deps import get_current_user, require_role, get_client_ip
from app.models.auth import User
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    """
    Authenticates user and returns JWT access token with role claims.
    Generic rejection error returned on invalid credentials.
    """
    client_ip = get_client_ip(request)
    user, error_message = AuthService.authenticate_user(
        db=db,
        username_or_email=payload.username_or_email,
        password=payload.password,
        client_ip=client_ip,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_message or "Invalid email/username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = AuthService.create_user_token(user)
    roles = [r.name for r in user.roles]

    user_resp = UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        roles=roles,
        is_active=user.is_active,
        created_at=user.created_at,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_resp,
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Logs out user and records audit trail event."""
    client_ip = get_client_ip(request)
    AuthService.record_logout(db=db, user=current_user, client_ip=client_ip)
    return MessageResponse(message="Successfully logged out.")


@router.get("/me", response_model=UserMeResponse)
def get_me(
    current_user: User = Depends(get_current_user),
):
    """Returns profile, assigned roles, and granular permissions of the authenticated user."""
    roles = [r.name for r in current_user.roles]
    permissions = AuthService.get_user_permissions(current_user)

    return UserMeResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        roles=roles,
        permissions=permissions,
        is_active=current_user.is_active,
        last_login=current_user.last_login,
    )


# Role-protected test routes verifying RBAC enforcement
@router.get("/admin-only", response_model=MessageResponse)
def admin_only_endpoint(
    current_user: User = Depends(require_role(["ADMIN"])),
):
    """Endpoint accessible exclusively to users with the ADMIN role."""
    return MessageResponse(
        message=f"Access granted to admin: {current_user.username}",
        detail="ADMIN authorization successful.",
    )


@router.get("/analyst-only", response_model=MessageResponse)
def analyst_only_endpoint(
    current_user: User = Depends(require_role(["ADMIN", "SECURITY_ANALYST"])),
):
    """Endpoint accessible to SECURITY_ANALYST or ADMIN roles."""
    return MessageResponse(
        message=f"Access granted to analyst/admin: {current_user.username}",
        detail="SECURITY_ANALYST authorization successful.",
    )
