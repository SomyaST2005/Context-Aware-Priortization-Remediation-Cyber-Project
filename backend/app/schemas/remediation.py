"""
Pydantic schemas for RemediationAction entity.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
from enum import Enum

from backend.app.models.database import RemediationActionType


class RemediationActionTypeEnum(str, Enum):
    PATCH_VULNERABILITY = "PATCH_VULNERABILITY"
    REMOVE_VULNERABILITY = "REMOVE_VULNERABILITY"
    DISABLE_SERVICE = "DISABLE_SERVICE"
    REMOVE_NETWORK_PATH = "REMOVE_NETWORK_PATH"
    SEGMENT_NETWORK = "SEGMENT_NETWORK"
    RESTRICT_PORT = "RESTRICT_PORT"
    REMOVE_TRUST_RELATIONSHIP = "REMOVE_TRUST_RELATIONSHIP"
    REDUCE_PRIVILEGE = "REDUCE_PRIVILEGE"
    CHANGE_ACCESS_POLICY = "CHANGE_ACCESS_POLICY"
    ISOLATE_ASSET = "ISOLATE_ASSET"


class RemediationActionBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1)
    action_type: RemediationActionTypeEnum
    target_asset_id: Optional[str] = Field(None, max_length=100)
    target_finding_id: Optional[str] = Field(None, max_length=100)
    target_edge_id: Optional[str] = Field(None, max_length=100)
    estimated_cost: float = Field(..., ge=0.0)
    implementation_complexity: str = Field(..., pattern="^(LOW|MEDIUM|HIGH)$")
    downtime_required: bool = False


class RemediationActionCreate(RemediationActionBase):
    id: str = Field(..., min_length=1, max_length=100)


class RemediationActionUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, min_length=1)
    action_type: Optional[RemediationActionTypeEnum] = None
    target_asset_id: Optional[str] = Field(None, max_length=100)
    target_finding_id: Optional[str] = Field(None, max_length=100)
    target_edge_id: Optional[str] = Field(None, max_length=100)
    estimated_cost: Optional[float] = Field(None, ge=0.0)
    implementation_complexity: Optional[str] = Field(None, pattern="^(LOW|MEDIUM|HIGH)$")
    downtime_required: Optional[bool] = None


class RemediationActionResponse(RemediationActionBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)