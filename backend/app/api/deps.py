import uuid
from typing import List, Union, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.auth import User
from app.core.security import decode_access_token
from app.services.auth_service import AuthService

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/login",
    auto_error=False,
)


def get_client_ip(request: Request) -> str:
    """Extracts client IP address respecting reverse proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Validates JWT access token and returns authenticated active user.
    Raises HTTP 401 if missing, invalid, expired, or user not found/inactive.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise credentials_exception

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    user_id_str: Optional[str] = payload.get("sub")
    if not user_id_str:
        raise credentials_exception

    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_uuid).first()
    if not user:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account has been deactivated.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(roles: Union[str, List[str]]):
    """
    Factory creating a FastAPI dependency that verifies user possesses one of the allowed roles.
    Raises HTTP 403 and records audit log if unauthorized.
    """
    allowed = [roles] if isinstance(roles, str) else roles

    def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        user_role_names = [r.name for r in current_user.roles]
        if not any(r in allowed for r in user_role_names):
            client_ip = get_client_ip(request)
            AuthService.record_access_denied(
                db=db,
                user=current_user,
                endpoint=str(request.url.path),
                required_role_or_perm=f"Role: {allowed}",
                client_ip=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: requires one of roles {allowed}.",
            )
        return current_user

    return role_checker


def require_permission(permission: str):
    """
    Factory creating a FastAPI dependency that verifies user has specific permission.
    Raises HTTP 403 and records audit log if unauthorized.
    """
    def permission_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        user_perms = AuthService.get_user_permissions(current_user)
        if permission not in user_perms:
            client_ip = get_client_ip(request)
            AuthService.record_access_denied(
                db=db,
                user=current_user,
                endpoint=str(request.url.path),
                required_role_or_perm=f"Permission: {permission}",
                client_ip=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: missing required permission '{permission}'.",
            )
        return current_user

    return permission_checker
