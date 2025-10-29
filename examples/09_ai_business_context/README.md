# AI Business Context Analysis Examples

This directory contains examples for using Threat Radar's AI analysis with business context from environment configurations.

## Overview

Traditional vulnerability scanners provide technical severity scores (CVSS), but they lack business context. A CRITICAL vulnerability on a development server is different from the same vulnerability on an internet-facing payment gateway handling PCI data.

**Threat Radar's business context-aware AI analysis** enhances traditional CVE scanning by incorporating:

- **Asset Criticality**: Business importance (CRITICAL, HIGH, MEDIUM, LOW with 0-100 scores)
- **Data Classification**: PII, PCI (payment data), PHI (health data), Confidential, Internal, Public
- **Network Exposure**: Internet-facing vs internal assets
- **Compliance Requirements**: PCI-DSS, HIPAA, GDPR, SOX, ISO27001, FedRAMP
- **SLA Targets**: Tier-1/2/3 with MTTR (Mean Time To Remediation) requirements

## Quick Start

### Prerequisites

1. **Environment Configuration**: Define your infrastructure with business context
   ```bash
   # See examples/07_environment_configuration/
   threat-radar env template -o my-environment.json
   # Edit my-environment.json with your asset details
   ```

2. **AI Provider Setup**: Configure AI provider
   ```bash
   # OpenAI
   export AI_PROVIDER=openai
   export AI_MODEL=gpt-4o
   export OPENAI_API_KEY=sk-...

   # Or Anthropic Claude
   export AI_PROVIDER=anthropic
   export AI_MODEL=claude-3-5-sonnet-20241022
   export ANTHROPIC_API_KEY=sk-ant-...

   # Or local Ollama
   export AI_PROVIDER=ollama
   export AI_MODEL=llama2
   ollama serve  # Start Ollama service
   ```

3. **CVE Scan**: Scan your container/application
   ```bash
   threat-radar cve scan-image alpine:3.18 --auto-save -o scan.json
   ```

### Run Business Context Analysis

```bash
# Analyze with business context
threat-radar ai analyze-with-context scan.json my-environment.json

# Save results
threat-radar ai analyze-with-context scan.json my-environment.json -o analysis.json

# Specify which asset (if scan target doesn't match asset name/image)
threat-radar ai analyze-with-context scan.json my-environment.json --asset-id api-gateway-001
```

## Example Files

### 1. Business Context Analysis (`01_business_context_analysis.py`)

Comprehensive examples demonstrating:

- **Example 1**: Basic business context analysis with risk scoring
- **Example 2**: Business context-aware prioritization
- **Example 3**: Compliance-driven remediation timelines
- **Example 4**: Saving and loading analysis results

```bash
python 01_business_context_analysis.py
```

## Business Risk Score Calculation

The business risk score (0-100) is computed from multiple factors:

```
Business Risk Score = Base Score + CVSS + Criticality + Exposure + Data Sensitivity

Components:
- Base Score (0-40):        Technical severity
  * CRITICAL severity = 40 points
  * HIGH severity = 30 points
  * MEDIUM severity = 20 points
  * LOW severity = 10 points

- CVSS Contribution (0-30):  CVSS score * 3
  * CVSS 10.0 = 30 points
  * CVSS 7.0 = 21 points
  * CVSS 5.0 = 15 points

- Asset Criticality (0-20):  Criticality score * 0.2
  * Score 100 (CRITICAL) = 20 points
  * Score 75 (HIGH) = 15 points
  * Score 50 (MEDIUM) = 10 points

- Network Exposure (0-10):
  * Internet-facing = +10 points
  * Internal only = 0 points

- Data Sensitivity (0-10):
  * PCI/PHI data = 10 points
  * PII data = 8 points
  * Confidential = 6 points
  * Internal = 3 points
  * Public = 0 points

Total: 0-100 points
```

### Business Risk Levels

```
CRITICAL (≥80):  Immediate remediation required
HIGH (60-79):    Urgent remediation required
MEDIUM (40-59):  Standard remediation timeline
LOW (<40):       Can be deferred
```

## Use Cases

### 1. Security Team Prioritization

**Problem**: 100 CVEs found across 20 services. Which should we fix first?

**Solution**: Business context analysis shows:
- 5 CVEs are on internet-facing, PCI-scoped assets (IMMEDIATE)
- 15 CVEs are on critical internal services (URGENT)
- 80 CVEs are on development/testing environments (STANDARD/DEFERRED)

```bash
threat-radar ai analyze-with-context scan-results.json production-env.json \
  --show-top 20 -o prioritized-risks.json
```

### 2. Compliance Reporting

**Problem**: Need to demonstrate vulnerability management for PCI-DSS audit.

**Solution**: Business context analysis provides:
- All vulnerabilities in PCI scope
- Remediation timelines aligned with PCI requirements
- Risk-based prioritization justification
- Audit trail of analysis decisions

```bash
# Analyze PCI-scoped assets
threat-radar ai analyze-with-context payment-scan.json pci-environment.json \
  -o pci-compliance-report.json
```

### 3. Executive Risk Dashboard

**Problem**: C-level executives need business risk metrics, not technical CVE counts.

**Solution**: Business context analysis provides:
- Overall risk rating (CRITICAL/HIGH/MEDIUM/LOW)
- Business impact assessment
- Compliance implications
- Revenue impact analysis

```bash
# Generate executive summary
threat-radar ai analyze-with-context production-scan.json environment.json \
  --auto-save

# Results include:
# - Environment summary
# - Overall risk rating
# - Compliance summary
# - Prioritized actions for leadership
```

### 4. SLA-Driven Remediation

**Problem**: Different assets have different SLA requirements.

**Solution**: Business context incorporates:
- SLA tiers (Tier-1/2/3)
- MTTR targets (15min/30min/2hr/24hr)
- Customer-facing vs internal
- Revenue impact

Assets with Tier-1 SLA + customer-facing + high revenue impact get highest priority regardless of technical severity.

## Workflow Examples

### Complete Security Audit Workflow

```bash
#!/bin/bash
# 1. Define production environment with business context
cat > production-env.json << 'EOF'
{
  "environment": {
    "name": "production-api",
    "type": "production",
    "compliance_requirements": ["pci-dss", "gdpr"]
  },
  "assets": [
    {
      "id": "api-gateway",
      "name": "API Gateway",
      "type": "api-gateway",
      "software": {"image": "nginx:1.25-alpine"},
      "network": {"public_ip": "203.0.113.10"},
      "business_context": {
        "criticality": "critical",
        "criticality_score": 95,
        "data_classification": "pci",
        "customer_facing": true,
        "compliance_scope": ["pci-dss", "gdpr"]
      }
    }
  ]
}
EOF

# 2. Scan Docker image for vulnerabilities
threat-radar cve scan-image nginx:1.25-alpine --auto-save -o scan.json

# 3. Analyze with business context
threat-radar ai analyze-with-context scan.json production-env.json \
  --auto-save -o business-risk-analysis.json

# 4. Review results
cat business-risk-analysis.json | jq '.overall_risk_rating'
cat business-risk-analysis.json | jq '.prioritized_actions'
cat business-risk-analysis.json | jq '.business_assessments[] | select(.business_risk_level == "CRITICAL")'
```

### CI/CD Pipeline Integration

```yaml
# .github/workflows/security-scan-with-context.yml
name: Business Context Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -t app:${{ github.sha }} .

      - name: Install Threat Radar
        run: pip install threat-radar

      - name: Scan for vulnerabilities
        run: |
          threat-radar cve scan-image app:${{ github.sha }} \
            -o scan.json --auto-save --cleanup

      - name: Analyze with business context
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          threat-radar ai analyze-with-context \
            scan.json .threat-radar/production-env.json \
            -o business-risk.json

      - name: Check risk threshold
        run: |
          CRITICAL_COUNT=$(jq '[.business_assessments[] | select(.business_risk_level == "CRITICAL")] | length' business-risk.json)
          OVERALL_RISK=$(jq -r '.overall_risk_rating' business-risk.json)

          echo "Critical Business Risks: $CRITICAL_COUNT"
          echo "Overall Risk Rating: $OVERALL_RISK"

          if [ "$OVERALL_RISK" = "CRITICAL" ]; then
            echo "❌ CRITICAL business risk detected! Blocking deployment."
            jq '.prioritized_actions[]' business-risk.json
            exit 1
          elif [ $CRITICAL_COUNT -gt 5 ]; then
            echo "⚠️  Too many critical business risks ($CRITICAL_COUNT > 5)"
            exit 1
          fi

          echo "✅ Business risk acceptable for deployment"

      - name: Upload analysis
        uses: actions/upload-artifact@v3
        with:
          name: security-analysis
          path: |
            scan.json
            business-risk.json
```

## Comparison: Technical vs Business Risk

### Example Scenario

**CVE-2024-1234**: Remote Code Execution (RCE) vulnerability
- CVSS Score: 9.8 (CRITICAL)
- Package: libssl 3.0.0
- Fixed in: 3.0.10

### Traditional CVSS-Based Analysis

All assets get the same priority:
```
Priority: CRITICAL (fix immediately)
Reason: CVSS 9.8, RCE vulnerability
```

### Business Context-Aware Analysis

Different priorities based on asset context:

**Asset 1: API Gateway (Internet-facing, PCI data, Critical asset)**
```
Business Risk Score: 100/100 (CRITICAL)
Remediation Urgency: IMMEDIATE (within 24 hours)
Reason:
  - CVSS 9.8 (40 + 30 points)
  - Asset criticality 95/100 (19 points)
  - Internet-facing (+10 points)
  - PCI data handling (+10 points)
Compliance Impact: PCI-DSS, GDPR
Business Impact: Potential payment data breach, customer service disruption
```

**Asset 2: Payment Service (Internal, PCI data, Critical asset)**
```
Business Risk Score: 89/100 (CRITICAL)
Remediation Urgency: URGENT (within 7 days)
Reason:
  - CVSS 9.8 (40 + 30 points)
  - Asset criticality 98/100 (20 points)
  - Internal only (0 points)
  - PCI data handling (+10 points)
Compliance Impact: PCI-DSS
Business Impact: Potential payment data breach if internal network compromised
```

**Asset 3: Analytics Service (Internal, PII data, Medium asset)**
```
Business Risk Score: 78/100 (HIGH)
Remediation Urgency: STANDARD (within 30 days)
Reason:
  - CVSS 9.8 (40 + 30 points)
  - Asset criticality 55/100 (11 points)
  - Internal only (0 points)
  - PII data handling (+8 points)
Compliance Impact: GDPR
Business Impact: Potential PII exposure, lower business criticality
```

**Asset 4: Development Environment (Internal, Test data, Low asset)**
```
Business Risk Score: 70/100 (HIGH)
Remediation Urgency: DEFERRED (within 90 days)
Reason:
  - CVSS 9.8 (40 + 30 points)
  - Asset criticality 20/100 (4 points)
  - Internal only (0 points)
  - No sensitive data (0 points)
Compliance Impact: None
Business Impact: Development disruption only, no customer/business risk
```

## Best Practices

### 1. Accurate Environment Configuration

**Critical**: Business context analysis is only as good as your environment configuration.

```json
{
  "assets": [
    {
      "id": "api-gateway-001",
      "name": "API Gateway",
      "business_context": {
        "criticality": "critical",
        "criticality_score": 95,  // Be realistic: 90-100 for truly critical
        "data_classification": "pci",  // Accurate data handling classification
        "customer_facing": true,  // Affects prioritization
        "compliance_scope": ["pci-dss", "gdpr"],  // All applicable frameworks
        "sla_tier": "tier-1",  // Drives remediation timelines
        "mttr_target": 30  // Minutes - realistic based on team capacity
      }
    }
  ]
}
```

### 2. Regular Updates

Keep environment configuration current:
- Update after infrastructure changes
- Review criticality scores quarterly
- Audit compliance scope annually
- Validate after major deployments

### 3. Asset Mapping

Ensure CVE scans can be mapped to environment assets:
```bash
# Explicit mapping (recommended)
threat-radar ai analyze-with-context scan.json env.json --asset-id api-gateway-001

# Automatic inference (works if image names match)
# scan target: nginx:1.25-alpine
# asset software.image: nginx:1.25-alpine
# → Automatically mapped
```

### 4. Compliance Alignment

Align remediation urgency with compliance requirements:
- **PCI-DSS**: Critical ≤30 days, High ≤90 days
- **HIPAA**: Risk-based, document decisions
- **GDPR**: 72-hour breach notification, reasonable security
- **SOX**: Controls must be effective, document remediation

### 5. Integration with Existing Workflows

```bash
# Combine with existing security tools
threat-radar cve scan-image myapp:latest -o scan.json
threat-radar ai analyze-with-context scan.json production-env.json -o risks.json

# Feed into your ticketing system
cat risks.json | jq '.business_assessments[] | select(.remediation_urgency == "IMMEDIATE")' \
  | while read risk; do
      # Create Jira ticket for immediate risks
      create_jira_ticket "$risk"
    done

# Update security dashboard
curl -X POST https://dashboard.company.com/api/risks \
  -H "Content-Type: application/json" \
  -d @risks.json
```

## Troubleshooting

### Asset Mapping Failures

**Problem**: "Could not map scan target to environment asset"

**Solutions**:
```bash
# 1. Explicit mapping
threat-radar ai analyze-with-context scan.json env.json --asset-id my-asset-id

# 2. Match image names in environment config
{
  "assets": [{
    "software": {
      "image": "nginx:1.25-alpine"  // Must match scan target
    }
  }]
}

# 3. Match asset names
{
  "assets": [{
    "name": "nginx"  // Partial match with scan target "nginx:1.25-alpine"
  }]
}
```

### AI Provider Configuration

**Problem**: "AI provider not configured" or API errors

**Solutions**:
```bash
# Check environment variables
echo $AI_PROVIDER  # Should be: openai, anthropic, or ollama
echo $AI_MODEL     # Should be valid model name
echo $OPENAI_API_KEY  # Should be set if using OpenAI

# Test AI connection
threat-radar ai analyze small-scan.json  # Try simple analysis first

# Use local model (no API key needed)
export AI_PROVIDER=ollama
export AI_MODEL=llama2
ollama serve &
ollama pull llama2
```

### Large Scan Batching

For scans with >30 CVEs, batch processing is automatic:
```bash
# Auto-batch mode (default)
threat-radar ai analyze-with-context large-scan.json env.json

# Force batch mode
threat-radar ai analyze-with-context scan.json env.json --batch-mode enabled

# Adjust batch size
threat-radar ai analyze-with-context scan.json env.json --batch-size 20
```

## Additional Resources

- [Main Documentation](../../README.md)
- [Environment Configuration](../07_environment_configuration/)
- [AI Analysis](../05_ai_analysis/)
- [CLI Features](../../docs/CLI_FEATURES.md)
- [API Documentation](../../docs/API.md)

## Questions or Issues?

- Report issues: https://github.com/threat-radar/threat-radar/issues
- Documentation: https://docs.threat-radar.com
- Examples repository: https://github.com/threat-radar/examples
