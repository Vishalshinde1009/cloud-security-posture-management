import logging
from typing import Optional, Tuple, List
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models.auth import User
from app.models.audit import AuditLog
from app.models.base import utc_now
from app.core.security import verify_password, create_access_token
from app.core.config import settings

logger = logging.getLogger("cspm.auth")


class AuthService:
    @staticmethod
    def authenticate_user(
        db: Session,
        username_or_email: str,
        password: str,
        client_ip: Optional[str] = None
    ) -> Tuple[Optional[User], Optional[str]]:
        """
        Authenticates user with username or email against bcrypt password hash.
        Logs audit trail for success or failure with zero credential leakage.
        """
        clean_identifier = username_or_email.strip()
        user = db.query(User).filter(
            or_(
                User.username == clean_identifier,
                User.email == clean_identifier.lower(),
            )
        ).first()

        # Check user existence and verify password
        if not user or not verify_password(password, user.password_hash):
            logger.warning(f"Failed login attempt for identifier: {clean_identifier[:3]}*** from IP: {client_ip}")
            # Audit failure without revealing whether identifier exists
            audit = AuditLog(
                user_id=user.id if user else None,
                action="LOGIN_FAILURE",
                resource_type="auth",
                result="FAILURE",
                metadata_json={"attempted_identifier": clean_identifier[:30]},
                ip_address=client_ip,
            )
            db.add(audit)
            db.commit()
            return None, "Invalid email/username or password."

        # Check active status
        if not user.is_active:
            logger.warning(f"Login rejected for inactive user ID: {user.id}")
            audit = AuditLog(
                user_id=user.id,
                action="LOGIN_FAILURE",
                resource_type="auth",
                result="DENIED",
                metadata_json={"reason": "Account is inactive"},
                ip_address=client_ip,
            )
            db.add(audit)
            db.commit()
            return None, "User account is disabled. Please contact an administrator."

        # Update last login and audit success
        user.last_login = utc_now()
        audit = AuditLog(
            user_id=user.id,
            action="LOGIN_SUCCESS",
            resource_type="auth",
            result="SUCCESS",
            metadata_json={"roles": [r.name for r in user.roles]},
            ip_address=client_ip,
        )
        db.add(audit)
        db.commit()
        db.refresh(user)

        logger.info(f"Successful login for user: {user.username} (roles: {[r.name for r in user.roles]})")
        return user, None

    @staticmethod
    def create_user_token(user: User) -> str:
        """Generates a signed JWT with user id and role claims."""
        roles = [r.name for r in user.roles]
        claims = {
            "roles": roles,
            "username": user.username,
            "email": user.email,
        }
        return create_access_token(subject=str(user.id), claims=claims)

    @staticmethod
    def get_user_permissions(user: User) -> List[str]:
        """Extracts unique permission names associated with all of the user's roles."""
        perms = set()
        for role in user.roles:
            for perm in role.permissions:
                perms.add(perm.name)
        return sorted(list(perms))

    @staticmethod
    def record_logout(db: Session, user: User, client_ip: Optional[str] = None):
        """Records user logout in the audit trail."""
        audit = AuditLog(
            user_id=user.id,
            action="LOGOUT",
            resource_type="auth",
            result="SUCCESS",
            metadata_json={"username": user.username},
            ip_address=client_ip,
        )
        db.add(audit)
        db.commit()

    @staticmethod
    def record_access_denied(
        db: Session,
        user: User,
        endpoint: str,
        required_role_or_perm: str,
        client_ip: Optional[str] = None
    ):
        """Records RBAC authorization denial in audit logs."""
        audit = AuditLog(
            user_id=user.id,
            action="ACCESS_DENIED",
            resource_type="api_endpoint",
            resource_id=endpoint,
            result="DENIED",
            metadata_json={
                "username": user.username,
                "required": required_role_or_perm,
                "user_roles": [r.name for r in user.roles],
            },
            ip_address=client_ip,
        )
        db.add(audit)
        db.commit()
