import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class SecurityRuleResponse(BaseModel):
    id: uuid.UUID
    rule_id: str
    title: str
    description: str
    service: str
    resource_type: str
    severity: str
    category: str
    remediation: str
    references: List[str]
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RuleListResponse(BaseModel):
    items: List[SecurityRuleResponse]
    total: int
    page: int
    limit: int


class FindingResponse(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID
    scan_id: uuid.UUID
    cloud_account_id: uuid.UUID
    resource_id: uuid.UUID
    finding_identifier: str
    title: str
    description: str
    severity: str
    risk_score: float
    risk_level: str = "MEDIUM"
    risk_priority: str = "MEDIUM"
    risk_factors: Dict[str, Any] = Field(default_factory=dict)
    risk_explanation: Optional[str] = None
    risk_calculated_at: Optional[datetime] = None
    status: str
    remediation: Optional[str] = None
    first_detected: datetime
    last_detected: datetime
    resolved_at: Optional[datetime] = None
    created_at: datetime

    # Denormalized context fields for UI convenience
    rule_code: Optional[str] = None
    service: Optional[str] = None
    resource_name: Optional[str] = None
    resource_identifier: Optional[str] = None

    model_config = {"from_attributes": True}


class FindingDetailResponse(FindingResponse):
    evidence: Dict[str, Any]
    references: Optional[List[str]] = None


class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int
    page: int
    limit: int


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="Target status: OPEN, IN_PROGRESS, RESOLVED, ACCEPTED_RISK, FALSE_POSITIVE")
    rationale: Optional[str] = Field(None, max_length=1000, description="Justification or context for the status update")


class FindingNoteCreate(BaseModel):
    note: str = Field(..., min_length=1, max_length=5000, description="Analyst note or investigation details")


class FindingNoteResponse(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    author_name: Optional[str] = "System Analyst"
    note: str
    created_at: datetime

    model_config = {"from_attributes": True}
