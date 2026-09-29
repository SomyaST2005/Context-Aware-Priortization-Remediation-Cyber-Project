"""
Pydantic schemas for Chokepoint analysis.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Literal, Optional
from datetime import datetime


class ChokepointDetailResponse(BaseModel):
    """Chokepoint metrics for a single entity (asset or finding)."""
    entity_id: str = Field(..., description="Entity identifier")
    entity_type: Literal["asset", "finding"] = Field(..., description="Entity type")
    chokepoint_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Normalized chokepoint score [0, 1]"
    )
    path_feasibility_criticality: float = Field(
        ..., ge=0.0,
        description="Raw risk-weighted path criticality (sum of PathFeasibility)"
    )
    path_count: int = Field(
        ..., ge=0,
        description="Number of attack paths through this entity"
    )
    unique_entry_points: int = Field(
        ..., ge=0,
        description="Number of distinct entry points among paths through this entity"
    )
    unique_crown_jewels: int = Field(
        ..., ge=0,
        description="Number of distinct crown jewels among paths through this entity"
    )
    min_path_depth: int = Field(
        ..., ge=0,
        description="Minimum path depth (hops) among paths through this entity"
    )
    max_path_depth: int = Field(
        ..., ge=0,
        description="Maximum path depth (hops) among paths through this entity"
    )

    model_config = ConfigDict(from_attributes=True)


class ChokepointResponse(BaseModel):
    """Complete chokepoint analysis result."""
    chokepoints: List[ChokepointDetailResponse] = Field(
        default_factory=list,
        description="Chokepoints sorted by score descending, then entity_id"
    )
    total_entities_analyzed: int = Field(
        ..., ge=0,
        description="Number of entities with chokepoint score > 0"
    )
    max_chokepoint_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Maximum chokepoint score across all entities"
    )
    total_attack_paths_analyzed: int = Field(
        ..., ge=0,
        description="Number of attack paths analyzed"
    )
    max_depth_used: int = Field(
        ..., ge=0,
        description="Maximum depth parameter used"
    )
    max_paths_used: int = Field(
        ..., ge=0,
        description="Maximum paths parameter used"
    )

    model_config = ConfigDict(from_attributes=True)