"""
Formal definitions of edge types for the canonical security graph.
"""
from enum import Enum as PyEnum


class EdgeType(str, PyEnum):
    """Types of attack transitions in the security graph."""
    EXPLOITS = "EXPLOITS"  # Exploiting a vulnerability to gain access
    CAN_REACH = "CAN_REACH"  # Network reachability (e.g., port access)
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"  # Moving between systems at same privilege level
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"  # Gaining higher privileges
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"  # Using stolen credentials
    TRUSTED_ACCESS = "TRUSTED_ACCESS"  # Access via trusted relationship (e.g., domain trust)


# Edge properties that contribute to traversal cost/risk
EDGE_TYPE_WEIGHTS = {
    EdgeType.EXPLOITS: 1.0,      # Base weight for exploit edges
    EdgeType.CAN_REACH: 0.5,     # Network reachability is easier than exploitation
    EdgeType.LATERAL_MOVEMENT: 0.7,  # Lateral movement moderate difficulty
    EdgeType.PRIVILEGE_ESCALATION: 1.5,  # Privilege escalation is harder
    EdgeType.CREDENTIAL_ACCESS: 0.3,     # Using credentials is relatively easy
    EdgeType.TRUSTED_ACCESS: 0.4,        # Trusted access is easier than exploitation
}

# Default probability values for edge types (can be overridden per edge)
EDGE_TYPE_PROBABILITIES = {
    EdgeType.EXPLOITS: 0.6,      # Moderate probability of successful exploit
    EdgeType.CAN_REACH: 0.8,     # High probability if network allows
    EdgeType.LATERAL_MOVEMENT: 0.7,  # Good probability for lateral movement
    EdgeType.PRIVILEGE_ESCALATION: 0.4,  # Lower probability for privilege escalation
    EdgeType.CREDENTIAL_ACCESS: 0.9,     # High probability if credentials valid
    EdgeType.TRUSTED_ACCESS: 0.85,       # High probability for trusted access
}

# Default traversal cost values for edge types (lower = easier/cheaper)
EDGE_TYPE_BASE_COSTS = {
    EdgeType.EXPLOITS: 2.0,      # Base cost for exploitation
    EdgeType.CAN_REACH: 1.0,     # Lower cost for network reachability
    EdgeType.LATERAL_MOVEMENT: 1.5,  # Moderate cost for lateral movement
    EdgeType.PRIVILEGE_ESCALATION: 3.0,  # Higher cost for privilege escalation
    EdgeType.CREDENTIAL_ACCESS: 0.8,     # Low cost for using credentials
    EdgeType.TRUSTED_ACCESS: 0.9,        # Low cost for trusted access
}