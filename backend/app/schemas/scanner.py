import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    account_id: Optional[uuid.UUID] = None
    cloud_account_id: Optional[uuid.UUID] = None


class ScanResponse(BaseModel):
    id: uuid.UUID
    cloud_account_id: uuid.UUID
    account_name: Optional[str] = None
    account_provider: Optional[str] = None
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    resources_scanned: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    security_score: Optional[float] = None
    posture_rating: Optional[str] = None
    risk_summary: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanComparisonResponse(BaseModel):
    has_previous_scan: bool
    current_scan_id: str
    previous_scan_id: Optional[str] = None
    score_change: float
    risk_change: float
    new_findings: int
    resolved_findings: int
    persistent_findings: int
    previous_security_score: Optional[float] = None
    current_security_score: Optional[float] = None
    previous_posture_rating: Optional[str] = None
    current_posture_rating: Optional[str] = None


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    limit: int


class ResourceResponse(BaseModel):
    id: uuid.UUID
    cloud_account_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    provider: str
    service: str
    resource_type: str
    resource_id: str
    resource_name: Optional[str] = None
    region: Optional[str] = None
    tags: Dict[str, Any]
    security_status: str
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class ResourceDetailResponse(ResourceResponse):
    configuration: Dict[str, Any]


class ResourceListResponse(BaseModel):
    items: List[ResourceResponse]
    total: int
    page: int
    limit: int
