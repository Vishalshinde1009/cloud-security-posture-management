import re
import uuid
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    username_or_email: str = Field(..., min_length=3, max_length=255, description="Username or email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")


class RegisterRequest(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Desired unique username (alphanumeric, underscores, hyphens)",
    )
    email: str = Field(..., min_length=5, max_length=255, description="User email address")
    password: str = Field(..., min_length=8, max_length=72, description="Password meeting security policy")
    password_confirm: Optional[str] = Field(None, min_length=8, max_length=72, description="Confirmation password")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        cleaned = v.strip()
        if not re.match(r"^[a-zA-Z0-9_-]+$", cleaned):
            raise ValueError("Username may only contain letters, numbers, underscores, and hyphens.")
        return cleaned

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(pattern, cleaned):
            raise ValueError("Invalid email address format.")
        return cleaned


class RegisterResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    roles: List[str]
    message: str = "Account successfully registered. You can now log in."

    model_config = {
        "from_attributes": True
    }


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    roles: List[str]
    is_active: bool
    email_alerts_enabled: bool = True
    created_at: datetime

    model_config = {
        "from_attributes": True
    }


class UserMeResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    roles: List[str]
    permissions: List[str]
    is_active: bool
    email_alerts_enabled: bool = True
    last_login: Optional[datetime] = None

    model_config = {
        "from_attributes": True
    }


class UserPreferencesUpdate(BaseModel):
    email_alerts_enabled: bool


class UserPreferencesResponse(BaseModel):
    email: str
    email_alerts_enabled: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None
