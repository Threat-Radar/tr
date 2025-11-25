#!/bin/bash
# Demo: Environment Configuration & Business Context
# Shows infrastructure modeling with business risk assessment

set -e

# Load AI configuration from .env file
if [ -f "../../../.env" ]; then
    echo "Loading AI configuration from .env..."
    set -a  # Automatically export all variables
    source "../../../.env"
    set +a
    echo "✓ AI Provider: ${AI_PROVIDER:-not set}"
    echo "✓ AI Model: ${AI_MODEL:-not set}"
    echo ""
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Demo: Environment Configuration & Business Context       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Demonstrates: threat-radar env commands"
echo "Use case: Business-aware risk assessment and compliance tracking"
echo ""

mkdir -p demo-03-results

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Create Environment Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Creating production environment config with business context..."

cat > demo-03-results/production-environment.json << 'EOF'
{
  "environment": {
    "name": "microservices-demo-production",
    "type": "production",
    "cloud_provider": "gcp",
    "region": "us-central1",
    "compliance_requirements": ["pci-dss", "gdpr"],
    "owner": "platform-team@company.com"
  },
  "global_business_context": {
    "industry": "ecommerce",
    "company_size": "startup",
    "risk_tolerance": "low",
    "incident_cost_estimates": {
      "data_breach_per_record": 150.0,
      "downtime_per_hour": 25000.0,
      "reputation_damage": 500000.0,
      "regulatory_fine_range": [50000.0, 2000000.0]
    }
  },
  "assets": [
    {
      "id": "asset-payment-api",
      "name": "Payment Processing API",
      "type": "container",
      "software": {
        "image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/paymentservice:v0.10.3"
      },
      "network": {
        "zone": "internal",
        "internal_ip": "10.0.2.100",
        "exposed_ports": [
          {"port": 50051, "protocol": "grpc", "public": false}
        ]
      },
      "business_context": {
        "criticality": "critical",
        "criticality_score": 95,
        "function": "payment-processing",
        "data_classification": "pci",
        "revenue_impact": "critical",
        "customer_facing": false,
        "pci_scope": true,
        "sla_tier": "tier-1",
        "mttr_target": 1,
        "owner_team": "payments-team"
      }
    },
    {
      "id": "asset-frontend",
      "name": "Frontend Web Server",
      "type": "container",
      "software": {
        "image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/frontend:v0.10.3"
      },
      "network": {
        "zone": "dmz",
        "internal_ip": "10.0.1.50",
        "exposed_ports": [
          {"port": 8080, "protocol": "http", "public": true}
        ]
      },
      "business_context": {
        "criticality": "critical",
        "criticality_score": 90,
        "function": "web-interface",
        "data_classification": "internal",
        "revenue_impact": "critical",
        "customer_facing": true,
        "pci_scope": false,
        "sla_tier": "tier-1",
        "mttr_target": 2,
        "owner_team": "frontend-team"
      }
    },
    {
      "id": "asset-redis-cache",
      "name": "Redis Session Cache",
      "type": "container",
      "software": {
        "image": "redis:alpine"
      },
      "network": {
        "zone": "internal",
        "internal_ip": "10.0.3.10",
        "exposed_ports": [
          {"port": 6379, "protocol": "redis", "public": false}
        ]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 80,
        "function": "session-storage",
        "data_classification": "internal",
        "revenue_impact": "high",
        "customer_facing": false,
        "pci_scope": true,
        "sla_tier": "tier-1",
        "mttr_target": 2,
        "owner_team": "platform-team"
      }
    }
  ],
  "dependencies": [
    {
      "source": "asset-frontend",
      "target": "asset-payment-api",
      "type": "communicates_with",
      "protocol": "grpc",
      "criticality": "critical"
    },
    {
      "source": "asset-frontend",
      "target": "asset-redis-cache",
      "type": "reads_from",
      "protocol": "redis",
      "criticality": "critical"
    }
  ],
  "network_topology": {
    "zones": [
      {
        "id": "zone-dmz",
        "name": "dmz",
        "trust_level": "medium",
        "internet_accessible": true,
        "description": "Demilitarized zone for public-facing services"
      },
      {
        "id": "zone-internal",
        "name": "internal",
        "trust_level": "high",
        "internet_accessible": false,
        "description": "Internal application zone"
      }
    ],
    "segmentation_rules": [
      {
        "from_zone": "dmz",
        "to_zone": "internal",
        "allowed": true,
        "ports": [50051, 6379],
        "protocols": ["grpc", "redis"]
      }
    ]
  }
}
EOF

echo "✓ Environment configuration created"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Validate Environment Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar env validate demo-03-results/production-environment.json

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3: Build Infrastructure Graph"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Merging environment topology with vulnerability data..."

# Use ALL existing scans from demo-02-results (vulnerability scanning)
SCANS=""
SCAN_COUNT=0
for scan_file in demo-02-results/*_scan.json; do
    if [ -f "$scan_file" ]; then
        SCANS="$SCANS --merge-scan $scan_file"
        SCAN_COUNT=$((SCAN_COUNT + 1))
    fi
done

echo "Found $SCAN_COUNT vulnerability scans to merge with infrastructure topology"
echo ""
echo "Press Enter to build comprehensive infrastructure graph..."
read

threat-radar env build-graph demo-03-results/production-environment.json \
    $SCANS \
    -o demo-03-results/infrastructure-graph.graphml

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "BUSINESS CONTEXT BENEFITS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Risk Prioritization"
echo "   → Critical assets (paymentservice) prioritized over low-risk assets"
echo "   → PCI-scoped assets get higher urgency"
echo ""
echo "2. Impact Assessment"
echo "   → Downtime cost: \$25K/hour"
echo "   → Data breach: \$150/record"
echo "   → Regulatory fines: \$50K - \$2M"
echo ""
echo "3. Compliance Mapping"
echo "   → PCI-DSS requirements affected"
echo "   → GDPR data protection implications"
echo ""
echo "4. SLA-Driven Remediation"
echo "   → Tier-1 assets: 1-2 hour MTTR target"
echo "   → Automated timeline recommendations"
echo ""
echo "5. Team Ownership"
echo "   → Clear responsibility (payments-team, frontend-team)"
echo "   → Escalation paths defined"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ENVIRONMENT CONFIGURATION ELEMENTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "• Environment Metadata"
echo "  - Type: production/staging/development"
echo "  - Cloud provider and region"
echo "  - Compliance requirements"
echo ""
echo "• Global Business Context"
echo "  - Industry and company size"
echo "  - Risk tolerance"
echo "  - Incident cost estimates"
echo ""
echo "• Assets"
echo "  - Infrastructure components"
echo "  - Software inventory"
echo "  - Network configuration"
echo "  - Business criticality"
echo ""
echo "• Dependencies"
echo "  - Inter-asset relationships"
echo "  - Communication protocols"
echo ""
echo "• Network Topology"
echo "  - Security zones (DMZ, internal, trusted)"
echo "  - Segmentation rules"
echo ""

echo "Results saved to: demo-03-results/"
echo ""
echo "✓ Demo Complete"
