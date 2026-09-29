"""
Pydantic schemas for Blast Radius analysis.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
from datetime import datetime


class ReachabilityDetailResponse(BaseModel):
    """Aggregated reachability metrics for a single asset."""
    asset_id: str = Field(..., description="Asset identifier")
    depth: int = Field(..., ge=0, description="Minimum depth at which asset is reachable from source")
    min_traversal_cost: float = Field(..., ge=0.0, description="Minimum traversal cost across all paths")
    max_probability: float = Field(..., ge=0.0, le=1.0, description="Maximum path probability across all paths")

    model_config = ConfigDict(from_attributes=True)


class BlastRadiusResponse(BaseModel):
    """Complete blast radius result for a source asset."""
    source_asset: str = Field(..., description="Starting compromised asset")
    affected_assets: List[str] = Field(default_factory=list, description="Sorted list of affected asset IDs")
    affected_asset_count: int = Field(..., ge=0, description="Number of affected assets")
    crown_jewels_reached: List[str] = Field(default_factory=list, description="Sorted list of crown jewels reached")
    max_depth_reached: int = Field(..., ge=0, description="Maximum traversal depth actually processed")
    reachability_details: List[ReachabilityDetailResponse] = Field(
        default_factory=list,
        description="Per-asset reachability metrics sorted by asset_id"
    )

    model_config = ConfigDict(from_attributes=True)