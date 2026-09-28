"""
SQLAlchemy database models for the canonical security graph.
"""
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, Enum
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class AssetType(PyEnum):
    WORKSTATION = "workstation"
    WEB_SERVER = "web_server"
    APP_SERVER = "app_server"
    DATABASE = "database"
    IDENTITY_PROVIDER = "identity_provider"
    CLOUD_STORAGE = "cloud_storage"
    API_GATEWAY = "api_gateway"
    DOMAIN_CONTROLLER = "domain_controller"


class Environment(PyEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    DMZ = "dmz"
    INTERNAL = "internal"


class NetworkZone(PyEnum):
    EXTERNAL = "external"
    DMZ = "dmz"
    APP_TIER = "app_tier"
    DB_TIER = "db_tier"
    MANAGEMENT = "management"

class VulnerabilitySeverity(PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AttackVector(PyEnum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class AttackComplexity(PyEnum):
    LOW = "LOW"
    HIGH = "HIGH"


class PrivilegesRequired(PyEnum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class UserInteraction(PyEnum):
    NONE = "NONE"
    REQUIRED = "REQUIRED"


class FindingStatus(PyEnum):
    ACTIVE = "active"
    REMEDIATED = "remediated"
    SUPPRESSED = "suppressed"
    IN_PROGRESS = "in_progress"


class EdgeType(PyEnum):
    EXPLOITS = "EXPLOITS"
    CAN_REACH = "CAN_REACH"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    TRUSTED_ACCESS = "TRUSTED_ACCESS"


class RemediationActionType(PyEnum):
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


class Asset(Base):
    """Represents a compute node, service, server, database, or identity store."""
    __tablename__ = "assets"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    type = Column(Enum(AssetType), nullable=False)
    criticality = Column(Float, nullable=False)  # Range 1.0 to 10.0
    environment = Column(Enum(Environment), nullable=False)
    network_zone = Column(Enum(NetworkZone), nullable=False)
    is_entry_point = Column(Boolean, default=False, nullable=False)
    is_crown_jewel = Column(Boolean, default=False, nullable=False)
    owner = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    scenario_id = Column(String, ForeignKey("scenarios.id"), nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="asset")
    # For edges where this asset is the source
    # outgoing_edges = relationship("Edge", foreign_keys="[Edge.source_id]", back_populates="source_asset")
    # For edges where this asset is the target
    # incoming_edges = relationship("Edge", foreign_keys="[Edge.target_id]", back_populates="target_asset")


class Vulnerability(Base):
    """Represents a known software or configuration weakness (CVE)."""
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, index=True)
    cve_id = Column(String, nullable=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    cvss_score = Column(Float, nullable=False)  # Range 0.0 to 10.0
    severity = Column(Enum(VulnerabilitySeverity), nullable=False)
    epss_score = Column(Float, nullable=True)  # Range 0.0 to 1.0
    known_exploited = Column(Boolean, default=False, nullable=False)
    attack_vector = Column(Enum(AttackVector), nullable=True)
    attack_complexity = Column(Enum(AttackComplexity), nullable=True)
    privileges_required = Column(Enum(PrivilegesRequired), nullable=True)
    user_interaction = Column(Enum(UserInteraction), nullable=True)
    remediation_effort = Column(Float, nullable=True)  # Relative effort score 1.0 to 10.0
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    scenario_id = Column(String, ForeignKey("scenarios.id"), nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="vulnerability")


class Finding(Base):
    """Represents the specific presence/observation of a Vulnerability on a designated Asset."""
    __tablename__ = "findings"

    id = Column(String, primary_key=True, index=True)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=False)
    vulnerability_id = Column(String, ForeignKey("vulnerabilities.id"), nullable=False)
    port = Column(Integer, nullable=True)
    service_name = Column(String, nullable=True)
    status = Column(Enum(FindingStatus), default=FindingStatus.ACTIVE, nullable=False)
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    scenario_id = Column(String, ForeignKey("scenarios.id"), nullable=True)

    # Relationships
    asset = relationship("Asset", back_populates="findings")
    vulnerability = relationship("Vulnerability", back_populates="findings")
    # For edges where this finding is the source (if edge represents an exploit)
    # outgoing_edges_as_source = relationship("Edge", foreign_keys="[Edge.source_id]", primaryjoin="and_(Edge.source_id == Finding.id, Edge.finding_id == Finding.id)", back_populates="source_finding")
    # For edges where this finding is the target (if edge represents an exploit)
    # incoming_edges_as_target = relationship("Edge", foreign_keys="[Edge.target_id]", primaryjoin="and_(Edge.target_id == Finding.id, Edge.finding_id == Finding.id)", back_populates="target_finding")


class Edge(Base):
    """Defines how an attacker or traffic can move between nodes in the graph."""
    __tablename__ = "edges"

    id = Column(String, primary_key=True, index=True)
    source_id = Column(String, nullable=False)  # Can be Asset.id or Finding.id
    target_id = Column(String, nullable=False)  # Can be Asset.id or Finding.id
    edge_type = Column(Enum(EdgeType), nullable=False)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)  # e.g., TCP, HTTP, SSH, RDP, DATABASE
    traversal_cost = Column(Float, nullable=False)  # Computed cost/difficulty for pathfinding
    probability = Column(Float, nullable=False)  # Transition success likelihood 0.01 to 1.0
    finding_id = Column(String, ForeignKey("findings.id"), nullable=True)  # Associated finding if edge represents an exploit
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    scenario_id = Column(String, ForeignKey("scenarios.id"), nullable=True)

    # Relationships - Note: These are polymorphic since source/target can be Asset or Finding
    # We'll handle this in the application layer rather than with SQLAlchemy relationships
    # for simplicity in this implementation
    finding = relationship("Finding", foreign_keys=[finding_id])


class RemediationAction(Base):
    """Defines a concrete security countermeasure that can be applied to the environment."""
    __tablename__ = "remediation_actions"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    action_type = Column(Enum(RemediationActionType), nullable=False)
    target_asset_id = Column(String, ForeignKey("assets.id"), nullable=True)
    target_finding_id = Column(String, ForeignKey("findings.id"), nullable=True)
    target_edge_id = Column(String, ForeignKey("edges.id"), nullable=True)
    estimated_cost = Column(Float, nullable=False)  # Synthetic or modeled financial/effort units
    implementation_complexity = Column(String, nullable=False)  # Enum: LOW, MEDIUM, HIGH
    downtime_required = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    scenario_id = Column(String, ForeignKey("scenarios.id"), nullable=True)

    # Relationships
    target_asset = relationship("Asset", foreign_keys=[target_asset_id])
    target_finding = relationship("Finding", foreign_keys=[target_finding_id])
    target_edge = relationship("Edge", foreign_keys=[target_edge_id])


class Scenario(Base):
    """An encapsulated network and threat topology for analysis and comparison."""
    __tablename__ = "scenarios"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
