"""Pydantic models for technology-agnostic environment configuration.

These models define the structure for infrastructure and business context
that enables AI-driven risk assessment with business impact analysis.
"""

from typing import Dict, List, Optional, Any
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


# ============================================================================
# Enums
# ============================================================================

class EnvironmentType(str, Enum):
    """Environment type classification."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    DR = "dr"  # Disaster Recovery


class CloudProvider(str, Enum):
    """Cloud infrastructure provider."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ON_PREMISE = "on-premise"
    HYBRID = "hybrid"
    MULTI_CLOUD = "multi-cloud"


class ComplianceFramework(str, Enum):
    """Compliance and regulatory frameworks."""
    HIPAA = "hipaa"
    PCI_DSS = "pci-dss"
    SOX = "sox"
    GDPR = "gdpr"
    ISO27001 = "iso27001"
    FEDRAMP = "fedramp"
    NONE = "none"


class AssetType(str, Enum):
    """Infrastructure asset types."""
    CONTAINER = "container"
    VM = "vm"
    BARE_METAL = "bare-metal"
    SERVERLESS = "serverless"
    SAAS = "saas"
    DATABASE = "database"
    LOAD_BALANCER = "load-balancer"
    API_GATEWAY = "api-gateway"
    SERVICE = "service"


class Criticality(str, Enum):
    """Business criticality levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataClassification(str, Enum):
    """Data sensitivity classification."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"  # Personally Identifiable Information
    PCI = "pci"  # Payment Card Industry
    PHI = "phi"  # Protected Health Information


class DependencyType(str, Enum):
    """Asset dependency relationship types."""
    DEPENDS_ON = "depends_on"
    COMMUNICATES_WITH = "communicates_with"
    READS_FROM = "reads_from"
    WRITES_TO = "writes_to"
    AUTHENTICATES_TO = "authenticates_to"


class TrustLevel(str, Enum):
    """Network zone trust levels."""
    UNTRUSTED = "untrusted"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    TRUSTED = "trusted"


class RiskTolerance(str, Enum):
    """Organization risk tolerance."""
    VERY_LOW = "very-low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ============================================================================
# Sub-Models
# ============================================================================

class Package(BaseModel):
    """Software package information."""
    name: str
    version: str
    ecosystem: Optional[str] = None

    class Config:
        extra = "allow"


class Software(BaseModel):
    """Software running on an asset."""
    image: Optional[str] = None
    os: Optional[str] = None
    runtime: Optional[str] = None
    packages: List[Package] = Field(default_factory=list)

    class Config:
        extra = "allow"


class ExposedPort(BaseModel):
    """Network port configuration."""
    port: int = Field(gt=0, lt=65536)
    protocol: str
    public: Optional[bool] = False
    description: Optional[str] = None

    class Config:
        extra = "allow"


class FirewallRule(BaseModel):
    """Firewall or security group rule."""
    source: str
    destination_port: int
    action: str

    class Config:
        extra = "allow"


class Network(BaseModel):
    """Network configuration for an asset."""
    internal_ip: Optional[str] = None
    public_ip: Optional[str] = None
    exposed_ports: List[ExposedPort] = Field(default_factory=list)
    firewall_rules: List[FirewallRule] = Field(default_factory=list)

    class Config:
        extra = "allow"


class BusinessContext(BaseModel):
    """Business criticality and context for an asset."""
    criticality: Criticality
    criticality_score: Optional[int] = Field(None, ge=0, le=100)
    function: Optional[str] = None
    data_classification: Optional[DataClassification] = None
    revenue_impact: Optional[Criticality] = None
    customer_facing: Optional[bool] = None
    sla_tier: Optional[str] = None
    compliance_scope: List[ComplianceFramework] = Field(default_factory=list)
    mttr_target: Optional[int] = Field(None, description="Mean time to remediate target (hours)")
    owner_team: Optional[str] = None
    cost_center: Optional[str] = None

    class Config:
        extra = "allow"

    @field_validator('criticality_score')
    @classmethod
    def validate_criticality_score(cls, v, info):
        """Ensure criticality_score aligns with criticality level if both provided."""
        if v is not None:
            criticality = info.data.get('criticality')
            if criticality == Criticality.CRITICAL and v < 80:
                raise ValueError("Critical assets should have criticality_score >= 80")
            elif criticality == Criticality.LOW and v > 40:
                raise ValueError("Low criticality assets should have criticality_score <= 40")
        return v


class AssetMetadata(BaseModel):
    """Additional metadata for an asset."""
    created_at: Optional[datetime] = None
    last_scanned: Optional[datetime] = None
    last_patched: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)

    class Config:
        extra = "allow"


# ============================================================================
# Main Models
# ============================================================================

class Asset(BaseModel):
    """Infrastructure asset definition."""
    id: str
    name: str
    type: AssetType
    host: Optional[str] = None
    software: Optional[Software] = None
    network: Optional[Network] = None
    business_context: BusinessContext
    metadata: Optional[AssetMetadata] = None

    class Config:
        extra = "allow"


class Dependency(BaseModel):
    """Dependency relationship between assets."""
    source: str
    target: str
    type: DependencyType
    protocol: Optional[str] = None
    port: Optional[int] = None
    criticality: Optional[Criticality] = None
    data_flow: Optional[DataClassification] = None
    encrypted: Optional[bool] = None

    class Config:
        extra = "allow"


class NetworkZone(BaseModel):
    """Network security zone definition."""
    id: str
    name: str
    trust_level: TrustLevel
    assets: List[str] = Field(default_factory=list)
    internet_accessible: Optional[bool] = False

    class Config:
        extra = "allow"


class SegmentationRule(BaseModel):
    """Network segmentation policy rule."""
    from_zone: str
    to_zone: str
    allowed: bool
    policy: Optional[str] = None

    class Config:
        extra = "allow"


class NetworkTopology(BaseModel):
    """Network segmentation and zones."""
    zones: List[NetworkZone] = Field(default_factory=list)
    segmentation_rules: List[SegmentationRule] = Field(default_factory=list)

    class Config:
        extra = "allow"


class IncidentCostEstimates(BaseModel):
    """Estimated costs of security incidents."""
    data_breach_per_record: Optional[float] = None
    downtime_per_hour: Optional[float] = None
    reputation_damage: Optional[float] = None

    class Config:
        extra = "allow"


class GlobalBusinessContext(BaseModel):
    """Global business context for the environment."""
    organization: Optional[str] = None
    business_unit: Optional[str] = None
    regulatory_requirements: List[str] = Field(default_factory=list)
    risk_tolerance: Optional[RiskTolerance] = None
    incident_cost_estimates: Optional[IncidentCostEstimates] = None

    class Config:
        extra = "allow"


class EnvironmentMetadata(BaseModel):
    """Environment metadata and classification."""
    name: str
    type: EnvironmentType
    cloud_provider: Optional[CloudProvider] = None
    region: Optional[str] = None
    compliance_requirements: List[ComplianceFramework] = Field(default_factory=list)
    owner: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)

    class Config:
        extra = "allow"


class Environment(BaseModel):
    """Complete environment configuration with business context."""
    environment: EnvironmentMetadata
    assets: List[Asset]
    dependencies: List[Dependency] = Field(default_factory=list)
    network_topology: Optional[NetworkTopology] = None
    business_context: Optional[GlobalBusinessContext] = None

    class Config:
        extra = "allow"

    @field_validator('assets')
    @classmethod
    def validate_unique_asset_ids(cls, v):
        """Ensure all asset IDs are unique."""
        ids = [asset.id for asset in v]
        if len(ids) != len(set(ids)):
            duplicates = [id for id in ids if ids.count(id) > 1]
            raise ValueError(f"Duplicate asset IDs found: {set(duplicates)}")
        return v

    @field_validator('dependencies')
    @classmethod
    def validate_dependency_references(cls, v, info):
        """Ensure dependencies reference valid assets."""
        if 'assets' not in info.data:
            return v

        asset_ids = {asset.id for asset in info.data['assets']}
        for dep in v:
            if dep.source not in asset_ids:
                raise ValueError(f"Dependency source '{dep.source}' not found in assets")
            if dep.target not in asset_ids:
                raise ValueError(f"Dependency target '{dep.target}' not found in assets")
        return v

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Get asset by ID."""
        for asset in self.assets:
            if asset.id == asset_id:
                return asset
        return None

    def get_dependencies_for_asset(self, asset_id: str) -> List[Dependency]:
        """Get all dependencies where asset is source or target."""
        return [
            dep for dep in self.dependencies
            if dep.source == asset_id or dep.target == asset_id
        ]

    def get_critical_assets(self) -> List[Asset]:
        """Get all critical assets."""
        return [
            asset for asset in self.assets
            if asset.business_context.criticality == Criticality.CRITICAL
        ]

    def get_internet_facing_assets(self) -> List[Asset]:
        """Get all assets with public IPs or internet-accessible zones."""
        internet_facing = []

        # Check for public IPs
        for asset in self.assets:
            if asset.network and asset.network.public_ip:
                internet_facing.append(asset)
                continue

            # Check if in internet-accessible zone
            if self.network_topology:
                for zone in self.network_topology.zones:
                    if zone.internet_accessible and asset.id in zone.assets:
                        internet_facing.append(asset)
                        break

        return internet_facing

    def get_pci_scope_assets(self) -> List[Asset]:
        """Get all assets in PCI-DSS scope."""
        return [
            asset for asset in self.assets
            if asset.business_context.data_classification == DataClassification.PCI
            or ComplianceFramework.PCI_DSS in asset.business_context.compliance_scope
        ]

    def calculate_total_risk_score(self) -> Dict[str, Any]:
        """Calculate aggregate risk metrics for the environment."""
        total_assets = len(self.assets)
        critical_assets = len(self.get_critical_assets())
        internet_facing = len(self.get_internet_facing_assets())
        pci_scope = len(self.get_pci_scope_assets())

        # Calculate weighted criticality
        criticality_weights = {
            Criticality.CRITICAL: 4,
            Criticality.HIGH: 3,
            Criticality.MEDIUM: 2,
            Criticality.LOW: 1,
        }

        total_weighted = sum(
            criticality_weights.get(asset.business_context.criticality, 0)
            for asset in self.assets
        )

        avg_criticality = total_weighted / total_assets if total_assets > 0 else 0

        return {
            "total_assets": total_assets,
            "critical_assets": critical_assets,
            "internet_facing_assets": internet_facing,
            "pci_scope_assets": pci_scope,
            "average_criticality": round(avg_criticality, 2),
            "high_risk_percentage": round((critical_assets / total_assets * 100), 1) if total_assets > 0 else 0,
        }
