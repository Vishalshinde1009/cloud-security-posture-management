import uuid
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    username_or_email: str = Field(..., min_length=3, max_length=255, description="Username or email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    roles: List[str]
    is_active: bool
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
    last_login: Optional[datetime] = None

    model_config = {
        "from_attributes": True
    }


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None
