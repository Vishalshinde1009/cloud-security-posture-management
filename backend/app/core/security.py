import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Union, Tuple
import jwt
import bcrypt
from app.core.config import settings


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validates password strength according to secure NIST/OWASP recommendations:
    - Length between 8 and 72 characters (72 is the bcrypt maximum).
    - At least one uppercase character.
    - At least one lowercase character.
    - At least one digit or symbol.
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password.encode("utf-8")) > 72:
        return False, "Password cannot exceed 72 bytes."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9\W_]", password):
        return False, "Password must contain at least one digit or special symbol."
    return True, None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Generates a secure bcrypt hash for the provided password."""
    # Truncate to 72 bytes strictly per bcrypt specification
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    claims: Optional[dict] = None
) -> str:
    """Creates a signed HMAC SHA-256 JWT access token with expiration."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "iat": datetime.now(timezone.utc),
    }
    if claims:
        to_encode.update(claims)
        
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """Decodes and validates a JWT access token."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "sub"]}
        )
        return payload
    except jwt.PyJWTError:
        return None
