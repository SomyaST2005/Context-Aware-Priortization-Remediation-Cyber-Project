"""
Pydantic schemas for Finding entity.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
from enum import Enum

from backend.app.models.database import FindingStatus


class FindingStatusEnum(str, Enum):
    ACTIVE = "active"
    REMEDIATED = "remediated"
    SUPPRESSED = "suppressed"
    IN_PROGRESS = "in_progress"


class FindingBase(BaseModel):
    asset_id: str = Field(..., min_length=1, max_length=100)
    vulnerability_id: str = Field(..., min_length=1, max_length=100)
    port: Optional[int] = Field(None, ge=1, le=65535)
    service_name: Optional[str] = Field(None, max_length=255)
    status: FindingStatusEnum = FindingStatusEnum.ACTIVE
    discovered_at: Optional[datetime] = None


class FindingCreate(FindingBase):
    id: str = Field(..., min_length=1, max_length=100)


class FindingUpdate(BaseModel):
    asset_id: Optional[str] = Field(None, min_length=1, max_length=100)
    vulnerability_id: Optional[str] = Field(None, min_length=1, max_length=100)
    port: Optional[int] = Field(None, ge=1, le=65535)
    service_name: Optional[str] = Field(None, max_length=255)
    status: Optional[FindingStatusEnum] = None
    discovered_at: Optional[datetime] = None


class FindingResponse(FindingBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)