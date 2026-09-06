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
