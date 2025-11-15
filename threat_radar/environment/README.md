# Technology-Agnostic Environment Configuration

## Overview

This module provides a **business-context-aware** environment configuration system that enables **AI-driven risk assessment** by combining:

1. **Infrastructure Topology** - What's running, where, and how it connects
2. **Vulnerability Data** - CVEs and security issues
3. **Business Context** - Criticality, data sensitivity, revenue impact
4. **Network Segmentation** - Trust zones and communication policies

## Why This Approach?

### Problem with CVE Severity Alone

Traditional vulnerability scanning provides technical severity (CVSS scores):
- CVE-2023-1234: CVSS 9.8 (Critical)
- CVE-2023-5678: CVSS 7.5 (High)

**But which matters more to YOUR business?**

### Solution: Business-Aware Risk Assessment

With environment context, AI can provide intelligent analysis:

```
CVE-2023-1234 (CVSS 9.8) in Redis Cache
  ├─ Asset: Low criticality (analytics caching)
  ├─ Network: Internal only, no internet exposure
  ├─ Data: Internal classification
  └─ AI Assessment: MEDIUM business risk
      Reason: Despite high CVSS, limited blast radius and non-critical function

CVE-2023-5678 (CVSS 7.5) in Payment API
  ├─ Asset: CRITICAL (payment processing)
  ├─ Network: Internet-accessible via load balancer
  ├─ Data: PCI-DSS scope, handles payment cards
  ├─ Dependencies: Connected to user database (PII)
  └─ AI Assessment: CRITICAL business risk ⚠️
      Reason: Lower CVSS but huge business impact
      - Direct revenue impact
      - PCI-DSS compliance violation
      - Can reach customer data (PII)
      - Internet-exposed attack surface
      - 1-hour MTTR requirement
```

## Schema Design

See `schema_v1.json` for complete JSON schema specification.

### Core Components

1. **Environment Metadata** - Context about the deployment
2. **Assets** - Infrastructure components with business context
3. **Dependencies** - Relationships and data flows
4. **Network Topology** - Segmentation and trust zones
5. **Business Context** - Organization-wide risk parameters

## Example Usage

### 1. Load and Validate Environment

```python
from threat_radar.environment import Environment
import json

# Load environment configuration
with open('ecommerce-production.json') as f:
    data = json.load(f)

# Validate with Pydantic
env = Environment(**data)

# Access assets
payment_api = env.get_asset('asset-payment-api')
print(f"Criticality: {payment_api.business_context.criticality}")
print(f"Data Class: {payment_api.business_context.data_classification}")
```

### 2. Find High-Risk Assets

```python
# Get critical assets
critical = env.get_critical_assets()

# Get internet-facing
internet_facing = env.get_internet_facing_assets()

# Get PCI scope
pci_scope = env.get_pci_scope_assets()

# Find HIGH RISK: Critical + Internet-Facing
high_risk = set(critical) & set(internet_facing)
```

### 3. Analyze Attack Paths

```python
from threat_radar.graph import NetworkXClient, GraphBuilder
from threat_radar.environment import EnvironmentGraphBuilder

# Build graph from environment
client = NetworkXClient()
builder = EnvironmentGraphBuilder(client)
builder.build_from_environment(env)

# Add vulnerability data
vuln_builder = GraphBuilder(client)
vuln_builder.build_from_scan(scan_result)

# Query: Attack path from internet to database
paths = analyzer.critical_path(
    source="asset-frontend-lb",  # Internet entry
    target="asset-user-db"       # Critical database
)

# AI analyzes each hop for vulnerabilities
for path in paths:
    print(f"Attack Path: {' → '.join(path)}")
    for hop in path:
        vulns = analyzer.get_vulnerabilities_for_asset(hop)
        if vulns:
            print(f"  ⚠️ {hop}: {len(vulns)} vulnerabilities")
```

### 4. AI-Powered Executive Summary

```python
from threat_radar.ai import RiskAnalyzer

analyzer = RiskAnalyzer(environment=env, vulnerabilities=scan_result)

executive_summary = analyzer.generate_executive_summary()
print(executive_summary)
```

**Output:**
```
🚨 EXECUTIVE RISK ASSESSMENT

Environment: ecommerce-production (Production)
Compliance: PCI-DSS, GDPR, SOX

CRITICAL FINDINGS:

1. Payment API (CRITICAL BUSINESS RISK) ⚠️
   - Vulnerability: CVE-2023-5678 (CVSS 7.5)
   - Business Impact: CRITICAL
     • Handles payment processing ($50K/hour revenue)
     • PCI-DSS compliance scope
     • Internet-accessible through load balancer
     • Connected to user database (PII)
   - Attack Path:
     Load Balancer → Frontend → API Gateway → Payment API → User DB
   - Recommendation: IMMEDIATE patching required (1-hour MTTR target)
   - Estimated Incident Cost: $1.5M (data breach + downtime + compliance)

2. Frontend Nginx (HIGH BUSINESS RISK)
   - Vulnerability: CVE-2023-1234 (CVSS 9.8)
   - Business Impact: HIGH
     • Customer-facing service
     • First hop from internet
     • Can reach payment and database systems
   - Recommendation: Patch within 24 hours
   - Estimated Incident Cost: $500K

ACCEPTABLE RISKS:

3. Redis Cache (LOW BUSINESS RISK)
   - Vulnerability: CVE-2023-9999 (CVSS 8.2)
   - Business Impact: LOW
     • Non-critical caching function
     • Internal network only
     • No sensitive data
   - Recommendation: Patch during next maintenance window
   - Estimated Incident Cost: $5K (minimal downtime)

COMPLIANCE IMPACTS:
- 2 vulnerabilities in PCI-DSS scope (URGENT)
- 1 vulnerability affects GDPR data (HIGH priority)

NETWORK EXPOSURE:
- 1 critical asset internet-facing with HIGH CVEs
- Network segmentation: COMPLIANT (no direct internet→database)
```

## Business Context Schema

### Asset Business Context

```json
{
  "criticality": "critical|high|medium|low",
  "criticality_score": 0-100,
  "function": "payment-processing",
  "data_classification": "pci|pii|phi|confidential|internal|public",
  "revenue_impact": "critical|high|medium|low",
  "customer_facing": true,
  "sla_tier": "tier-1",
  "compliance_scope": ["pci-dss", "gdpr"],
  "mttr_target": 1,
  "owner_team": "payments-team"
}
```

### Key Business Metrics

- **Criticality**: How important to business operations
- **Data Classification**: Type of data handled (drives compliance)
- **Revenue Impact**: Direct financial impact if compromised
- **Customer Facing**: Affects user experience
- **SLA Tier**: Service level agreement requirements
- **MTTR Target**: Mean Time To Remediate requirement
- **Compliance Scope**: Regulatory requirements

## AI Integration Points

### 1. Risk Scoring Algorithm

AI combines multiple factors:

```python
business_risk_score = (
    technical_severity * 0.2 +        # CVSS score
    criticality_score * 0.3 +         # Business criticality
    exposure_score * 0.2 +            # Network exposure
    data_sensitivity_score * 0.2 +    # Data classification
    compliance_score * 0.1            # Regulatory impact
)
```

### 2. Attack Path Analysis

AI identifies critical paths:
```
Internet → [Vulnerable Frontend] → [API Gateway] → [Critical Database]
         └─ CVE-2023-1234 (CRITICAL RISK due to path to sensitive data)
```

### 3. Remediation Prioritization

AI prioritizes fixes by **business impact**, not just technical severity:

```
Priority 1: Payment API CVE-2023-5678
  - Why: Critical business function + PCI scope + internet exposure
  - Impact: $50K/hour downtime + $150/record breach + compliance fines
  - MTTR: 1 hour (SLA requirement)

Priority 2: Frontend Nginx CVE-2023-1234
  - Why: Customer-facing + gateway to critical systems
  - Impact: $500K reputation + user trust
  - MTTR: 24 hours

Priority 10: Analytics Service CVE-2023-9999
  - Why: Non-critical function + internal only + low data sensitivity
  - Impact: Minimal
  - MTTR: Next maintenance window
```

### 4. Compliance Impact Analysis

AI highlights regulatory risks:

```
PCI-DSS Compliance Alert:
  - 2 vulnerabilities in card data environment
  - Risk: Compliance failure, potential fines ($5K-$100K per month)
  - Action: Must remediate before next audit (30 days)

GDPR Impact:
  - 1 vulnerability affects personal data processing
  - Risk: Data breach notification requirement
  - Action: Assess if breach occurred, notify within 72 hours if yes
```

## File Formats

### JSON (Recommended)

Human-readable, widely supported:
```json
{
  "environment": {...},
  "assets": [...],
  "dependencies": [...]
}
```

### YAML (Alternative)

More readable for manual editing:
```yaml
environment:
  name: production
  type: production

assets:
  - id: asset-web
    name: Frontend
    ...
```

## Generating Environment Files

Users can generate environment JSON from various sources:

### From Terraform

```bash
# Extract from Terraform state
terraform show -json | jq '{
  environment: {name: "production"},
  assets: [.values.root_module.resources[] | {
    id: .address,
    name: .name,
    type: .type,
    ...
  }]
}' > environment.json
```

### From Kubernetes

```bash
# Extract from K8s cluster
kubectl get all -o json | threat-radar env convert-k8s > environment.json
```

### From Docker Compose

```bash
# Convert docker-compose.yml
threat-radar env convert-compose docker-compose.yml > environment.json
```

### From CMDB/Asset Inventory

```python
# Custom script to query your CMDB
import requests
from threat_radar.environment import Environment

assets = requests.get('https://cmdb.company.com/api/assets').json()

env_config = {
    "environment": {...},
    "assets": [transform_asset(a) for a in assets],
    ...
}

# Validate
env = Environment(**env_config)
env.model_dump_json()
```

## Validation

Pydantic validates:
- ✅ Required fields present
- ✅ Enums match allowed values
- ✅ Asset IDs are unique
- ✅ Dependencies reference valid assets
- ✅ Criticality scores align with levels
- ✅ Port numbers in valid range
- ✅ Data types correct

```python
try:
    env = Environment(**data)
    print("✅ Valid environment configuration")
except ValidationError as e:
    print("❌ Validation errors:")
    print(e.json(indent=2))
```

## Best Practices

### 1. Start Small

Begin with critical assets only:
- Payment processing
- User authentication
- Database servers

### 2. Use Realistic Criticality

Don't mark everything as CRITICAL. Use the spectrum:
- **CRITICAL**: Revenue-generating, PCI/PHI/PII, customer-facing
- **HIGH**: Important but not critical
- **MEDIUM**: Standard services
- **LOW**: Analytics, monitoring, internal tools

### 3. Document Data Flows

Capture dependencies accurately:
```json
{
  "source": "api",
  "target": "database",
  "type": "reads_from",
  "data_flow": "pii",
  "encrypted": true
}
```

### 4. Update Regularly

Environment changes frequently:
- New services deployed
- Assets decommissioned
- Criticality changes
- Compliance requirements evolve

### 5. Integrate with CI/CD

Auto-generate environment files:
```yaml
# .github/workflows/update-environment.yml
- name: Generate Environment Config
  run: |
    threat-radar env generate-from-terraform > environment.json
    threat-radar env validate environment.json
```

## Roadmap

### Sprint 2 (Current)
- ✅ JSON schema design
- ✅ Pydantic models
- ✅ Example environment files
- 🚧 Environment graph builder
- 🚧 CLI commands
- 🚧 Validation tools

### Sprint 3 (Future)
- 🔮 AI risk analyzer with business context
- 🔮 Compliance impact calculator
- 🔮 Attack path analysis
- 🔮 Remediation cost estimator
- 🔮 Executive summary generator

### Sprint 4 (Future)
- 🔮 Auto-generation from Terraform
- 🔮 Auto-generation from Kubernetes
- 🔮 CMDB integration
- 🔮 Real-time monitoring integration

## See Also

- `schema_v1.json` - JSON Schema specification
- `models.py` - Pydantic validation models
- `../examples/10_attack_path_discovery/sample-environment.json` - Example environment configuration
- `../examples/07_environment_configuration/` - Environment configuration examples
- `../graph/` - Graph database integration
- `../ai/` - AI risk analysis

---

**Questions? See main documentation or open an issue.**
