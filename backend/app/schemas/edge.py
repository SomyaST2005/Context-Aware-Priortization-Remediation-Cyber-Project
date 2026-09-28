"""
Pydantic schemas for Edge entity.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
from enum import Enum

from backend.app.models.database import EdgeType


class EdgeTypeEnum(str, Enum):
    EXPLOITS = "EXPLOITS"
    CAN_REACH = "CAN_REACH"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    TRUSTED_ACCESS = "TRUSTED_ACCESS"


class EdgeBase(BaseModel):
    source_id: str = Field(..., min_length=1, max_length=100)
    target_id: str = Field(..., min_length=1, max_length=100)
    edge_type: EdgeTypeEnum
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, max_length=50)
    traversal_cost: float = Field(..., ge=0.0)
    probability: float = Field(..., ge=0.01, le=1.0)
    finding_id: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = None


class EdgeCreate(EdgeBase):
    id: str = Field(..., min_length=1, max_length=100)


class EdgeUpdate(BaseModel):
    source_id: Optional[str] = Field(None, min_length=1, max_length=100)
    target_id: Optional[str] = Field(None, min_length=1, max_length=100)
    edge_type: Optional[EdgeTypeEnum] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, max_length=50)
    traversal_cost: Optional[float] = Field(None, ge=0.0)
    probability: Optional[float] = Field(None, ge=0.01, le=1.0)
    finding_id: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = None


class EdgeResponse(EdgeBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)