"""Data models for graph nodes and edges."""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum


class NodeType(Enum):
    """Supported node types in the vulnerability graph."""

    CONTAINER = "container"
    PACKAGE = "package"
    VULNERABILITY = "vulnerability"
    SERVICE = "service"
    HOST = "host"
    SBOM = "sbom"
    SCAN_RESULT = "scan_result"


class EdgeType(Enum):
    """Supported edge types in the vulnerability graph."""

    CONTAINS = "CONTAINS"  # Container -> Package
    HAS_VULNERABILITY = "HAS_VULNERABILITY"  # Package -> Vulnerability
    DEPENDS_ON = "DEPENDS_ON"  # Container -> Container, Service -> Service
    COMMUNICATES_WITH = "COMMUNICATES_WITH"  # Container -> Container
    RUNS_ON = "RUNS_ON"  # Container -> Host
    EXPOSES = "EXPOSES"  # Container -> Service
    AFFECTS = "AFFECTS"  # Vulnerability -> Package
    FIXED_BY = "FIXED_BY"  # Vulnerability -> Package (fixed version)
    SCANNED_BY = "SCANNED_BY"  # Container -> ScanResult
    GENERATED_FROM = "GENERATED_FROM"  # SBOM -> Container


@dataclass
class GraphNode:
    """
    Represents a node in the vulnerability graph.

    Attributes:
        node_id: Unique identifier for the node
        node_type: Type of the node (container, package, vulnerability, etc.)
        properties: Additional node attributes (name, version, severity, etc.)
    """

    node_id: str
    node_type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Ensure node_type is a NodeType enum."""
        if isinstance(self.node_type, str):
            self.node_type = NodeType(self.node_type)


@dataclass
class GraphEdge:
    """
    Represents an edge (relationship) in the vulnerability graph.

    Attributes:
        source_id: Node ID of the source node
        target_id: Node ID of the target node
        edge_type: Type of relationship (contains, depends_on, etc.)
        properties: Additional edge attributes (weight, timestamp, etc.)
    """

    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Ensure edge_type is an EdgeType enum and properties dict exists."""
        if isinstance(self.edge_type, str):
            self.edge_type = EdgeType(self.edge_type)
        if self.properties is None:
            self.properties = {}


@dataclass
class GraphMetadata:
    """
    Metadata about the graph structure.

    Attributes:
        node_count: Total number of nodes
        edge_count: Total number of edges
        node_type_counts: Count of nodes by type
        edge_type_counts: Count of edges by type
    """

    node_count: int = 0
    edge_count: int = 0
    node_type_counts: Dict[str, int] = field(default_factory=dict)
    edge_type_counts: Dict[str, int] = field(default_factory=dict)


class AttackStepType(Enum):
    """Types of attack steps in an attack path."""

    ENTRY_POINT = "entry_point"
    EXPLOIT_VULNERABILITY = "exploit_vulnerability"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    TARGET_ACCESS = "target_access"
    DATA_EXFILTRATION = "data_exfiltration"


class ThreatLevel(Enum):
    """Threat level classifications for attack paths."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AttackStep:
    """
    Represents a single step in an attack path.

    Attributes:
        node_id: Node involved in this step
        step_type: Type of attack step
        description: Human-readable description of the step
        vulnerabilities: CVE IDs exploited in this step
        cvss_score: Severity score (if applicable)
        prerequisites: Required conditions for this step
        impact: Impact description if successful
    """

    node_id: str
    step_type: AttackStepType
    description: str
    vulnerabilities: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    prerequisites: List[str] = field(default_factory=list)
    impact: Optional[str] = None


@dataclass
class AttackPath:
    """
    Represents a complete attack path from entry point to target.

    Attributes:
        path_id: Unique identifier for this path
        entry_point: Starting node (entry point)
        target: Ending node (high-value target)
        steps: Ordered list of attack steps
        total_cvss: Combined CVSS score
        threat_level: Overall threat level
        exploitability: Ease of exploitation (0.0-1.0)
        impact_score: Business impact score
        path_length: Number of steps
        requires_privileges: Whether privilege escalation is required
        description: Summary of the attack path
    """

    path_id: str
    entry_point: str
    target: str
    steps: List[AttackStep]
    total_cvss: float
    threat_level: ThreatLevel
    exploitability: float = 0.5
    impact_score: float = 0.0
    path_length: int = 0
    requires_privileges: bool = False
    description: str = ""

    def __post_init__(self):
        """Calculate derived fields."""
        if self.path_length == 0:
            self.path_length = len(self.steps)

        # Check if any step is privilege escalation
        if not self.requires_privileges:
            self.requires_privileges = any(
                step.step_type == AttackStepType.PRIVILEGE_ESCALATION
                for step in self.steps
            )


@dataclass
class PrivilegeEscalationPath:
    """
    Represents a privilege escalation opportunity.

    Attributes:
        from_privilege: Starting privilege level
        to_privilege: Target privilege level
        path: Attack path for escalation
        vulnerabilities: CVEs that enable escalation
        difficulty: Exploitation difficulty (easy/medium/hard)
        mitigation: Recommended mitigation steps
    """

    from_privilege: str
    to_privilege: str
    path: AttackPath
    vulnerabilities: List[str]
    difficulty: str = "medium"
    mitigation: List[str] = field(default_factory=list)


@dataclass
class LateralMovementOpportunity:
    """
    Represents a lateral movement opportunity between assets.

    Attributes:
        from_asset: Source asset ID
        to_asset: Target asset ID
        movement_type: Type of movement (network, credential, vulnerability)
        path: Attack path for movement
        vulnerabilities: CVEs that enable movement
        network_requirements: Network access requirements
        prerequisites: Required conditions
        detection_difficulty: How hard to detect (easy/medium/hard)
    """

    from_asset: str
    to_asset: str
    movement_type: str
    path: AttackPath
    vulnerabilities: List[str]
    network_requirements: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    detection_difficulty: str = "medium"


@dataclass
class AttackSurface:
    """
    Analysis of the attack surface.

    Attributes:
        entry_points: List of potential entry points
        high_value_targets: List of critical assets
        attack_paths: All discovered attack paths
        privilege_escalations: Privilege escalation opportunities
        lateral_movements: Lateral movement opportunities
        total_risk_score: Overall risk assessment
        recommendations: Security recommendations
    """

    entry_points: List[str]
    high_value_targets: List[str]
    attack_paths: List[AttackPath]
    privilege_escalations: List[PrivilegeEscalationPath]
    lateral_movements: List[LateralMovementOpportunity]
    total_risk_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
