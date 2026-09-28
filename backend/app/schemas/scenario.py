"""
Pydantic schemas for Scenario entity.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime


class ScenarioBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)


class ScenarioCreate(ScenarioBase):
    id: str = Field(..., min_length=1, max_length=100)


class ScenarioUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)


class ScenarioResponse(ScenarioBase):
    id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)