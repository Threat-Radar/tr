# Environment Configuration Examples

This directory contains comprehensive examples for using Threat Radar's environment configuration module with business context for AI-driven vulnerability risk assessment.

## Overview

The environment configuration module enables you to define your infrastructure in a technology-agnostic way, enriched with business context. This allows Threat Radar's AI to provide intelligent risk assessments based on:

- **Business criticality** - Impact of compromise
- **Data classification** - PII, PCI, PHI, etc.
- **Network exposure** - Internet-facing vs internal
- **Compliance scope** - PCI-DSS, HIPAA, GDPR, SOX
- **Dependencies** - Asset relationships and data flows

## Quick Start

### Generate a Template

```bash
# Generate template via CLI
threat-radar env template -o my-environment.json

# Or via Python
python -c "from threat_radar.environment import EnvironmentParser; \
import json; \
print(json.dumps(EnvironmentParser.generate_template(), indent=2))"
```

### Validate Configuration

```bash
# Validate environment file
threat-radar env validate my-environment.json

# Show validation errors
threat-radar env validate my-environment.json --errors
```

### Analyze Environment

```bash
# Analyze risk and compliance posture
threat-radar env analyze my-environment.json

# List assets with filtering
threat-radar env list-assets my-environment.json --criticality critical
threat-radar env list-assets my-environment.json --internet-facing
```

### Build Graph

```bash
# Build graph for vulnerability analysis
threat-radar env build-graph my-environment.json --auto-save

# Build and merge with CVE scan results
threat-radar env build-graph my-environment.json \
  --merge-scan cve-results.json \
  --auto-save
```

## Example Files

### 1. Basic Usage (`01_basic_usage.py`)

Learn the fundamentals of environment configuration:

- **Example 1**: Create simple environment
- **Example 2**: Add business context
- **Example 3**: Validate configurations
- **Example 4**: Save and load environments
- **Example 5**: Query and filter assets
- **Example 6**: Calculate risk scores
- **Example 7**: Generate templates

```bash
python 01_basic_usage.py
```

**Key Concepts:**
- Environment metadata (name, type, cloud provider, compliance requirements)
- Asset definition with business context
- Criticality levels and scores
- Data classification
- Risk calculation

### 2. Advanced Configuration (`02_advanced_configuration.py`)

Master advanced features:

- **Example 1**: Network topology with security zones
- **Example 2**: Asset dependencies and data flows
- **Example 3**: Compliance scoping
- **Example 4**: Graph integration
- **Example 5**: Complete complex environment

```bash
python 02_advanced_configuration.py
```

**Key Concepts:**
- Network zones and trust levels
- Dependency types (depends_on, reads_from, communicates_with)
- Data flow tracking (PII, PCI, PHI)
- Segmentation rules
- Attack path analysis

### 3. Real-World Workflows (`03_real_world_workflows.py`)

End-to-end workflows for common use cases:

- **Workflow 1**: Security audit
- **Workflow 2**: Vulnerability prioritization with business context
- **Workflow 3**: Compliance reporting
- **Workflow 4**: CI/CD integration

```bash
python 03_real_world_workflows.py
```

**Key Concepts:**
- Complete security audits
- Business risk-based prioritization
- Compliance scope reporting
- Policy enforcement in CI/CD

## Environment Configuration Structure

### Minimal Configuration

```json
{
  "environment": {
    "name": "my-environment",
    "type": "production",
    "owner": "team@company.com"
  },
  "assets": [
    {
      "id": "asset-1",
      "name": "Web Server",
      "type": "container",
      "host": "10.0.1.10",
      "business_context": {
        "criticality": "high",
        "criticality_score": 75
      }
    }
  ],
  "dependencies": []
}
```

### Complete Configuration

```json
{
  "environment": {
    "name": "production-app",
    "type": "production",
    "cloud_provider": "aws",
    "region": "us-east-1",
    "compliance_requirements": ["pci-dss", "gdpr"],
    "owner": "platform@company.com",
    "tags": {
      "cost-center": "engineering"
    }
  },
  "assets": [
    {
      "id": "api-gateway",
      "name": "API Gateway",
      "type": "api-gateway",
      "host": "10.0.1.10",
      "software": {
        "image": "nginx:1.25-alpine",
        "os": "Alpine Linux 3.18",
        "runtime": "nginx/1.25.0"
      },
      "network": {
        "internal_ip": "10.0.1.10",
        "public_ip": "203.0.113.10",
        "exposed_ports": [
          {
            "port": 443,
            "protocol": "https",
            "public": true
          }
        ]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 85,
        "function": "api-gateway",
        "data_classification": "pii",
        "revenue_impact": "high",
        "customer_facing": true,
        "compliance_scope": ["pci-dss", "gdpr"],
        "sla_tier": "tier-1",
        "mttr_target": 60,
        "owner_team": "platform-team"
      },
      "metadata": {
        "last_scanned": "2025-01-10T10:00:00Z",
        "tags": {
          "environment": "production"
        }
      }
    }
  ],
  "dependencies": [
    {
      "source": "api-gateway",
      "target": "payment-service",
      "type": "depends_on",
      "protocol": "https",
      "port": 8443,
      "encrypted": true,
      "criticality": "critical",
      "data_flow": "pci"
    }
  ],
  "network_topology": {
    "zones": [
      {
        "id": "dmz",
        "name": "DMZ",
        "trust_level": "untrusted",
        "internet_accessible": true,
        "assets": ["api-gateway"]
      }
    ],
    "segmentation_rules": [
      {
        "from_zone": "dmz",
        "to_zone": "app-tier",
        "allowed": true
      }
    ]
  },
  "business_context": {
    "organization": "My Company",
    "business_unit": "Engineering",
    "risk_tolerance": "medium"
  }
}
```

## Asset Types

Threat Radar supports various asset types:

- `container` - Docker containers, Kubernetes pods
- `vm` - Virtual machines
- `bare-metal` - Physical servers
- `serverless` - Lambda functions, Cloud Functions
- `saas` - SaaS applications
- `database` - Databases (SQL, NoSQL)
- `load-balancer` - Load balancers
- `api-gateway` - API gateways
- `service` - Generic services

## Criticality Levels

Define asset criticality with scores (0-100):

- **CRITICAL** (score ≥ 80): Business-critical, requires immediate attention
- **HIGH** (score 60-79): Important assets, short MTTR required
- **MEDIUM** (score 30-59): Standard business assets
- **LOW** (score < 30): Non-critical, development/testing

## Data Classification

Track sensitive data handling:

- `pci` - Payment Card Industry data
- `phi` - Protected Health Information
- `pii` - Personally Identifiable Information
- `confidential` - Confidential business data
- `internal` - Internal use only
- `public` - Public data

## Compliance Frameworks

Supported compliance frameworks:

- `pci-dss` - Payment Card Industry Data Security Standard
- `hipaa` - Health Insurance Portability and Accountability Act
- `gdpr` - General Data Protection Regulation
- `sox` - Sarbanes-Oxley Act
- `iso27001` - ISO/IEC 27001
- `fedramp` - Federal Risk and Authorization Management Program

## Dependency Types

Define relationships between assets:

- `depends_on` - Service dependency
- `communicates_with` - Communication relationship
- `reads_from` - Read data from
- `writes_to` - Write data to
- `authenticates_to` - Authentication relationship

## Network Zones

Organize assets into security zones:

- **Trust Levels**:
  - `untrusted` - DMZ, internet-facing
  - `medium` - Application tier
  - `trusted` - Data tier, internal systems
  - `restricted` - High-security zones

## Use Cases

### 1. Security Audits

```python
from threat_radar.environment import EnvironmentParser

# Load environment
env = EnvironmentParser.load_from_file("production.json")

# Identify high-risk assets
critical_assets = env.get_critical_assets()
internet_facing = env.get_internet_facing_assets()
pci_scope = env.get_pci_scope_assets()

# Calculate risk
risk_scores = env.calculate_total_risk_score()
print(f"High-risk percentage: {risk_scores['high_risk_percentage']:.1f}%")
```

### 2. Vulnerability Prioritization

```python
from threat_radar.environment import EnvironmentParser, EnvironmentGraphBuilder
from threat_radar.graph import NetworkXClient

# Load environment
env = EnvironmentParser.load_from_file("production.json")

# Build graph
client = NetworkXClient()
builder = EnvironmentGraphBuilder(client)
builder.build_from_environment(env)

# Calculate business risk for each asset
risk_scores = builder.calculate_risk_scores(env)

# Find critical paths
paths = builder.find_critical_paths(env)
print(f"Found {len(paths)} attack paths to critical assets")
```

### 3. Compliance Reporting

```python
from threat_radar.environment import EnvironmentParser, ComplianceFramework

# Load environment
env = EnvironmentParser.load_from_file("production.json")

# Get PCI-DSS scope
pci_assets = env.get_pci_scope_assets()

# Generate compliance report
for asset in pci_assets:
    print(f"{asset.name}: {asset.business_context.data_classification.value}")
```

### 4. CI/CD Integration

```bash
#!/bin/bash
# Validate environment in CI pipeline

# Validate configuration
threat-radar env validate infrastructure/production.json

# Check for policy violations
# (Critical assets must not be internet-facing)
threat-radar env list-assets infrastructure/production.json \
  --criticality critical \
  --internet-facing > violations.txt

if [ -s violations.txt ]; then
  echo "❌ Policy violation: Critical internet-facing assets found"
  exit 1
fi

echo "✅ Environment validation passed"
```

## Integration with Vulnerability Scanning

Combine environment configuration with CVE scanning for business context-aware risk assessment:

```bash
# 1. Scan Docker image for vulnerabilities
threat-radar cve scan-image alpine:3.18 --auto-save -o cve-scan.json

# 2. Build graph with environment context
threat-radar env build-graph production-env.json \
  --merge-scan cve-scan.json \
  --auto-save

# 3. Analyze with AI (coming soon)
threat-radar ai analyze cve-scan.json \
  --environment production-env.json \
  --prioritize-by-business-context
```

## Best Practices

### 1. Criticality Scoring

- **Critical (90-100)**: Revenue-generating, customer data, compliance-critical
- **High (70-89)**: Customer-facing, important business functions
- **Medium (40-69)**: Internal tools, non-critical services
- **Low (0-39)**: Development, testing, non-production

### 2. Asset Naming

Use consistent naming conventions:
- Include environment: `prod-api-gateway`, `dev-database`
- Include function: `payment-service`, `user-auth`
- Include identifier: `web-1`, `db-primary`

### 3. Dependency Documentation

Document all data flows:
- Mark encrypted connections
- Specify data classification
- Note criticality for business-critical dependencies

### 4. Network Segmentation

Organize assets into trust zones:
- DMZ for internet-facing assets
- Application tier for business logic
- Data tier for databases
- Restrict cross-zone traffic

### 5. Regular Updates

Keep configuration current:
- Update after infrastructure changes
- Review criticality scores quarterly
- Audit compliance scope annually
- Validate after deployments

## Troubleshooting

### Validation Errors

**Error**: `Critical assets should have criticality_score >= 80`

**Solution**: Ensure criticality scores align with levels:
```json
{
  "criticality": "critical",
  "criticality_score": 95
}
```

**Error**: `Dependency target 'asset-id' not found in assets`

**Solution**: Ensure all dependency targets exist in assets list:
```json
{
  "dependencies": [
    {
      "source": "web-1",
      "target": "api-1"  // Must exist in assets
    }
  ]
}
```

### Common Issues

1. **Invalid enum values**: Use lowercase with hyphens (e.g., `load-balancer` not `load_balancer`)
2. **Missing required fields**: All assets need `id`, `name`, `type`, `business_context`
3. **NetworkZone requires `id`**: Add unique ID to each zone
4. **Segmentation rules**: Use `from_zone`/`to_zone`, not `source`/`target`

## Additional Resources

- [Main Documentation](../../README.md)
- [Graph Database Examples](../06_graph_database/)
- [AI Analysis Examples](../05_ai_analysis/)
- [CLI Features Documentation](../../docs/CLI_FEATURES.md)
- [API Documentation](../../docs/API.md)

## Questions or Issues?

- Report issues: https://github.com/threat-radar/threat-radar/issues
- Documentation: https://docs.threat-radar.com
- Examples repository: https://github.com/threat-radar/examples
