"""
Pydantic schemas for Asset entity.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
from enum import Enum

from backend.app.models.database import (
    AssetType, Environment, NetworkZone
)


class AssetTypeEnum(str, Enum):
    WORKSTATION = "workstation"
    WEB_SERVER = "web_server"
    APP_SERVER = "app_server"
    DATABASE = "database"
    IDENTITY_PROVIDER = "identity_provider"
    CLOUD_STORAGE = "cloud_storage"
    API_GATEWAY = "api_gateway"
    DOMAIN_CONTROLLER = "domain_controller"


class EnvironmentEnum(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    DMZ = "dmz"
    INTERNAL = "internal"


class NetworkZoneEnum(str, Enum):
    EXTERNAL = "external"
    DMZ = "dmz"
    APP_TIER = "app_tier"
    DB_TIER = "db_tier"
    MANAGEMENT = "management"


class AssetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: AssetTypeEnum
    criticality: float = Field(..., ge=1.0, le=10.0)
    environment: EnvironmentEnum
    network_zone: NetworkZoneEnum
    is_entry_point: bool = False
    is_crown_jewel: bool = False
    owner: str = Field(..., min_length=1, max_length=255)
    ip_address: Optional[str] = None
    description: Optional[str] = None


class AssetCreate(AssetBase):
    id: str = Field(..., min_length=1, max_length=100)


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    type: Optional[AssetTypeEnum] = None
    criticality: Optional[float] = Field(None, ge=1.0, le=10.0)
    environment: Optional[EnvironmentEnum] = None
    network_zone: Optional[NetworkZoneEnum] = None
    is_entry_point: Optional[bool] = None
    is_crown_jewel: Optional[bool] = None
    owner: Optional[str] = Field(None, min_length=1, max_length=255)
    ip_address: Optional[str] = None
    description: Optional[str] = None


class AssetResponse(AssetBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)