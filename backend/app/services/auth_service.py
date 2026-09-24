import uuid
import logging
from typing import Optional, Tuple, List
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from app.models.auth import User, Role
from app.models.audit import AuditLog
from app.models.base import utc_now
from app.core.security import (
    verify_password,
    create_access_token,
    validate_password_strength,
    get_password_hash,
)
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
    def register_user(
        db: Session,
        username: str,
        email: str,
        password: str,
        password_confirm: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> Tuple[Optional[User], Optional[str]]:
        """
        Registers a new public user with safe default role (VIEWER).
        Validates password strength, email & username uniqueness, and hashes password.
        Logs an immutable audit event for account registration.
        """
        clean_username = username.strip()
        clean_email = email.strip().lower()

        # 1. Validate password confirmation if provided
        if password_confirm is not None and password != password_confirm:
            return None, "Passwords do not match."

        # 2. Validate password strength against NIST/OWASP rules
        is_strong, strength_err = validate_password_strength(password)
        if not is_strong:
            return None, strength_err

        # 3. Check for existing username (case-insensitive)
        existing_user = db.query(User).filter(
            func.lower(User.username) == clean_username.lower()
        ).first()
        if existing_user:
            return None, "Username is already registered."

        # 4. Check for existing email (case-insensitive)
        existing_email = db.query(User).filter(
            func.lower(User.email) == clean_email
        ).first()
        if existing_email:
            return None, "Email address is already registered."

        # 5. Resolve safe default role (VIEWER) - public registration NEVER grants ADMIN
        viewer_role = db.query(Role).filter(Role.name == "VIEWER").first()
        if not viewer_role:
            logger.warning("Default role VIEWER not found during user registration; attempting creation.")
            viewer_role = Role(id=uuid.uuid4(), name="VIEWER", description="Viewer role")
            db.add(viewer_role)
            db.flush()

        # Ensure VIEWER has read:accounts and baseline permissions assigned
        existing_perm_names = {p.name for p in viewer_role.permissions}
        if "read:accounts" not in existing_perm_names:
            from app.models.auth import Permission
            viewer_perms_data = [
                ("read:findings", "View detected security misconfigurations"),
                ("read:scans", "View scan history and metrics"),
                ("read:accounts", "View cloud accounts"),
                ("read:rules", "View security detection rules"),
                ("download:reports", "Generate and export PDF security reports"),
            ]
            for p_name, p_desc in viewer_perms_data:
                if p_name not in existing_perm_names:
                    perm = db.query(Permission).filter(Permission.name == p_name).first()
                    if not perm:
                        perm = Permission(id=uuid.uuid4(), name=p_name, description=p_desc)
                        db.add(perm)
                        db.flush()
                    viewer_role.permissions.append(perm)
            db.flush()

        # 6. Hash password securely with bcrypt
        password_hash = get_password_hash(password)

        # 7. Create new user
        new_user = User(
            id=uuid.uuid4(),
            username=clean_username,
            email=clean_email,
            password_hash=password_hash,
            is_active=True,
        )
        new_user.roles.append(viewer_role)
        db.add(new_user)
        db.flush()

        # 8. Record audit log entry
        audit = AuditLog(
            user_id=new_user.id,
            action="USER_REGISTER",
            resource_type="auth",
            result="SUCCESS",
            metadata_json={
                "username": new_user.username,
                "email": new_user.email,
                "assigned_role": viewer_role.name,
            },
            ip_address=client_ip,
        )
        db.add(audit)
        db.commit()
        db.refresh(new_user)

        logger.info(f"New user registered successfully: {new_user.username} with role {viewer_role.name}")
        return new_user, None

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
