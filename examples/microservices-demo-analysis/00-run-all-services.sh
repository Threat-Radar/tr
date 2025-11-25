#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Complete Multi-Service Security Analysis
# Google Cloud Online Boutique Microservices Demo
# ═══════════════════════════════════════════════════════════════════
#
# USAGE:
#   Basic run (scans only):
#     ./00-run-all-services.sh
#
#   Enable specific features:
#     RUN_VISUALIZATIONS=true ./00-run-all-services.sh
#     RUN_RISK_ASSESSMENT=true ./00-run-all-services.sh
#     RUN_REMEDIATION=true ./00-run-all-services.sh
#     RUN_PRIORITIES=true ./00-run-all-services.sh
#     RUN_THREAT_MODEL=true ./00-run-all-services.sh
#
#   Enable all AI features:
#     RUN_RISK_ASSESSMENT=true \
#     RUN_REMEDIATION=true \
#     RUN_PRIORITIES=true \
#     RUN_THREAT_MODEL=true \
#     RUN_VISUALIZATIONS=true \
#     ./00-run-all-services.sh
#
#   Quick enable-all:
#     RUN_ALL=true ./00-run-all-services.sh
#
#   Skip stages (to jump to visualizations):
#     SKIP_SCANS=true SKIP_GRAPHS=true SKIP_ATTACK_PATHS=true \
#     RUN_VISUALIZATIONS=true ./00-run-all-services.sh
#
#   Only run visualizations (assumes data exists):
#     SKIP_SCANS=true SKIP_GRAPHS=true SKIP_ATTACK_PATHS=true SKIP_AI=true \
#     RUN_VISUALIZATIONS=true ./00-run-all-services.sh
#
# FEATURES:
#   • RUN_VISUALIZATIONS     - Generate interactive HTML visualizations
#   • RUN_RISK_ASSESSMENT    - AI risk assessment with business context
#   • RUN_REMEDIATION        - Generate detailed remediation plans
#   • RUN_PRIORITIES         - AI-powered priority rankings
#   • RUN_THREAT_MODEL       - Threat modeling and attack analysis
#
# STAGE CONTROL:
#   • SKIP_SCANS             - Skip Phase 1 (individual service scans)
#   • SKIP_GRAPHS            - Skip graph building
#   • SKIP_ATTACK_PATHS      - Skip attack path discovery
#   • SKIP_AI                - Skip all AI analysis
#   • SKIP_VISUALIZATIONS    - Skip visualizations (overrides RUN_VISUALIZATIONS)
#
# REQUIREMENTS:
#   • .env file configured with AI provider (for AI features)
#   • plotly installed (for visualizations)
#
# ═══════════════════════════════════════════════════════════════════

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Complete Multi-Service Security Analysis                 ║"
echo "║  Google Cloud Online Boutique Microservices Demo          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo ""

# Define all microservices with their Docker images
declare -A SERVICES
SERVICES=(
    ["frontend"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/frontend:v0.10.3"
    ["cartservice"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/cartservice:v0.10.3"
    ["productcatalogservice"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/productcatalogservice:v0.10.3"
    ["currencyservice"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/currencyservice:v0.10.3"
    ["paymentservice"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/paymentservice:v0.10.3"
    ["shippingservice"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/shippingservice:v0.10.3"
    ["emailservice"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/emailservice:v0.10.3"
    ["checkoutservice"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/checkoutservice:v0.10.3"
    ["recommendationservice"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/recommendationservice:v0.10.3"
    ["adservice"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/adservice:v0.10.3"
    ["loadgenerator"]="us-central1-docker.pkg.dev/google-samples/microservices-demo/loadgenerator:v0.10.3"
    ["redis-cart"]="redis:alpine"
)

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION TOGGLES
# ═══════════════════════════════════════════════════════════════════
# Set to "true" to enable, "false" to disable

# Check for RUN_ALL quick toggle
if [ "${RUN_ALL:-false}" = "true" ]; then
    RUN_VISUALIZATIONS="true"
    RUN_RISK_ASSESSMENT="true"
    RUN_REMEDIATION="true"
    RUN_PRIORITIES="true"
    RUN_THREAT_MODEL="true"
    echo "RUN_ALL enabled - activating all features"
    echo ""
fi

# Basic Configuration
ENTERPRISE_RESULTS_DIR="full-demo-results"
RUN_VISUALIZATIONS="${RUN_VISUALIZATIONS:-false}"

# AI-Powered Analysis Toggles (requires AI configuration in .env)
RUN_RISK_ASSESSMENT="${RUN_RISK_ASSESSMENT:-false}"        # AI risk assessment with business context
RUN_BUSINESS_ANALYSIS="${RUN_BUSINESS_ANALYSIS:-false}"   # Business context-aware analysis (deprecated, use RUN_RISK_ASSESSMENT)
RUN_REMEDIATION="${RUN_REMEDIATION:-false}"                # Generate remediation plans
RUN_PRIORITIES="${RUN_PRIORITIES:-false}"                  # Generate priority rankings
RUN_THREAT_MODEL="${RUN_THREAT_MODEL:-false}"             # AI threat modeling analysis

# Stage Control (skip specific phases)
SKIP_SCANS="${SKIP_SCANS:-false}"                          # Skip individual service scanning
SKIP_GRAPHS="${SKIP_GRAPHS:-false}"                        # Skip graph building
SKIP_ATTACK_PATHS="${SKIP_ATTACK_PATHS:-false}"           # Skip attack path discovery
SKIP_AI="${SKIP_AI:-false}"                                # Skip all AI analysis
SKIP_VISUALIZATIONS="${SKIP_VISUALIZATIONS:-false}"       # Skip visualizations

# Backward compatibility: if RUN_BUSINESS_ANALYSIS is set, use RUN_RISK_ASSESSMENT
if [ "$RUN_BUSINESS_ANALYSIS" = "true" ]; then
    RUN_RISK_ASSESSMENT="true"
fi

# Override visualizations if explicitly skipped
if [ "$SKIP_VISUALIZATIONS" = "true" ]; then
    RUN_VISUALIZATIONS="false"
fi

# Override AI features if explicitly skipped
if [ "$SKIP_AI" = "true" ]; then
    RUN_RISK_ASSESSMENT="false"
    RUN_REMEDIATION="false"
    RUN_PRIORITIES="false"
    RUN_THREAT_MODEL="false"
fi

echo "Configuration:"
echo "  Features:"
echo "    • Visualizations:      $RUN_VISUALIZATIONS"
echo "    • Risk Assessment:     $RUN_RISK_ASSESSMENT"
echo "    • Remediation Plans:   $RUN_REMEDIATION"
echo "    • Priority Rankings:   $RUN_PRIORITIES"
echo "    • Threat Modeling:     $RUN_THREAT_MODEL"
echo "  Stage Control:"
echo "    • Skip Scans:          $SKIP_SCANS"
echo "    • Skip Graphs:         $SKIP_GRAPHS"
echo "    • Skip Attack Paths:   $SKIP_ATTACK_PATHS"
echo "    • Skip AI Analysis:    $SKIP_AI"
echo ""

# Create enterprise results directory structure
mkdir -p "$ENTERPRISE_RESULTS_DIR"/{02-scans,01-sboms,03-graphs,04-attack-paths,06-ai-analysis,08-reports,07-visualizations}

if [ "$SKIP_SCANS" = "false" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "PHASE 1: Individual Service Analysis (12 services)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Counter for progress tracking
    TOTAL_SERVICES=${#SERVICES[@]}
    CURRENT_SERVICE=0

    # Process each service
    for SERVICE_NAME in "${!SERVICES[@]}"; do
        CURRENT_SERVICE=$((CURRENT_SERVICE + 1))
        IMAGE="${SERVICES[$SERVICE_NAME]}"

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[$CURRENT_SERVICE/$TOTAL_SERVICES] Processing: $SERVICE_NAME"
        echo "Image: $IMAGE"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        # Step 1: Generate SBOM
        echo "  [1/4] Generating SBOM..."
        threat-radar sbom docker "$IMAGE" \
            -o "$ENTERPRISE_RESULTS_DIR/01-sboms/${SERVICE_NAME}_sbom.json" \
            2>/dev/null || echo "    ⚠️  SBOM generation failed for $SERVICE_NAME"

        # Step 2: Scan for vulnerabilities
        echo "  [2/4] Scanning for vulnerabilities..."
        threat-radar cve scan-image "$IMAGE" \
            -o "$ENTERPRISE_RESULTS_DIR/02-scans/${SERVICE_NAME}_scan.json" \
            --cleanup \
            2>/dev/null || echo "    ⚠️  Vulnerability scan failed for $SERVICE_NAME"

        # Step 3: Build vulnerability graph
        echo "  [3/4] Building vulnerability graph..."
        if [ -f "$ENTERPRISE_RESULTS_DIR/02-scans/${SERVICE_NAME}_scan.json" ]; then
            threat-radar graph build "$ENTERPRISE_RESULTS_DIR/02-scans/${SERVICE_NAME}_scan.json" \
                -o "$ENTERPRISE_RESULTS_DIR/03-graphs/${SERVICE_NAME}_graph.graphml" \
                2>/dev/null || echo "    ⚠️  Graph building failed for $SERVICE_NAME"
        fi

        # Step 4: Quick vulnerability summary
        echo "  [4/4] Vulnerability summary:"
        if [ -f "$ENTERPRISE_RESULTS_DIR/02-scans/${SERVICE_NAME}_scan.json" ]; then
            CRITICAL=$(jq -r '[.vulnerabilities[] | select(.severity=="critical")] | length' "$ENTERPRISE_RESULTS_DIR/02-scans/${SERVICE_NAME}_scan.json" 2>/dev/null || echo "0")
            HIGH=$(jq -r '[.vulnerabilities[] | select(.severity=="high")] | length' "$ENTERPRISE_RESULTS_DIR/02-scans/${SERVICE_NAME}_scan.json" 2>/dev/null || echo "0")
            MEDIUM=$(jq -r '[.vulnerabilities[] | select(.severity=="medium")] | length' "$ENTERPRISE_RESULTS_DIR/02-scans/${SERVICE_NAME}_scan.json" 2>/dev/null || echo "0")
            TOTAL=$(jq -r '.vulnerabilities | length' "$ENTERPRISE_RESULTS_DIR/02-scans/${SERVICE_NAME}_scan.json" 2>/dev/null || echo "0")

            echo "    Total: $TOTAL vulnerabilities"
            echo "    Critical: $CRITICAL | High: $HIGH | Medium: $MEDIUM"
        else
            echo "    ⚠️  No scan results available"
        fi

        echo "  ✓ $SERVICE_NAME analysis complete"
    done
else
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "PHASE 1: Individual Service Analysis - SKIPPED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  Using existing scan results from: $ENTERPRISE_RESULTS_DIR/02-scans/"
    echo ""
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 2: Enterprise-Wide Consolidated Analysis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if AI configuration is available
# Try multiple paths to find .env file (works from different execution contexts)
if [ -f "../../.env" ]; then
    echo "Loading AI configuration from .env..."
    set -a
    source "../../.env"
    set +a
    AI_AVAILABLE=true
    echo "✓ AI Provider: ${AI_PROVIDER:-not set}"
    echo ""
elif [ -f ".env" ]; then
    echo "Loading AI configuration from .env (project root)..."
    set -a
    source ".env"
    set +a
    AI_AVAILABLE=true
    echo "✓ AI Provider: ${AI_PROVIDER:-not set}"
    echo ""
else
    AI_AVAILABLE=false
    echo "⚠️  No .env file found - AI analysis will be skipped"
    echo "   (Searched: ../../.env and ./.env)"
    echo ""
fi

# Step 1: Build consolidated infrastructure graph
if [ "$SKIP_GRAPHS" = "false" ]; then
    echo "Step 1: Building consolidated infrastructure graph..."
    echo ""
else
    echo "Step 1: Building consolidated infrastructure graph - SKIPPED"
    echo ""
fi

# Create environment configuration with all services (always create for reference)
cat > "$ENTERPRISE_RESULTS_DIR/microservices-environment.json" << 'EOF'
{
  "environment": {
    "name": "microservices-demo-production",
    "type": "production",
    "cloud_provider": "gcp",
    "region": "us-central1",
    "compliance_requirements": ["pci-dss", "gdpr"],
    "owner": "platform-team@example.com"
  },
  "global_business_context": {
    "industry": "ecommerce",
    "company_size": "enterprise",
    "risk_tolerance": "low",
    "incident_cost_estimates": {
      "data_breach_per_record": 150.0,
      "downtime_per_hour": 50000.0,
      "reputation_damage": 1000000.0,
      "regulatory_fine_range": [100000.0, 5000000.0]
    }
  },
  "assets": [
    {
      "id": "asset-frontend",
      "name": "Frontend Web Application",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/frontend:v0.10.3"},
      "network": {
        "zone": "dmz",
        "exposed_ports": [{"port": 8080, "protocol": "http", "public": true}]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 85,
        "function": "customer-interface",
        "data_classification": "public",
        "customer_facing": true,
        "sla_tier": "tier-1"
      }
    },
    {
      "id": "asset-payment",
      "name": "Payment Processing Service",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/paymentservice:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 50051, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "critical",
        "criticality_score": 95,
        "function": "payment-processing",
        "data_classification": "pci",
        "pci_scope": true,
        "sla_tier": "tier-1"
      }
    },
    {
      "id": "asset-checkout",
      "name": "Checkout Service",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/checkoutservice:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 5050, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "critical",
        "criticality_score": 90,
        "function": "order-processing",
        "data_classification": "pci",
        "pci_scope": true,
        "sla_tier": "tier-1"
      }
    },
    {
      "id": "asset-cart",
      "name": "Cart Service",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/cartservice:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 7070, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 80,
        "function": "shopping-cart",
        "data_classification": "internal",
        "pci_scope": true,
        "sla_tier": "tier-2"
      }
    },
    {
      "id": "asset-product-catalog",
      "name": "Product Catalog Service",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/productcatalogservice:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 3550, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 75,
        "function": "product-catalog",
        "data_classification": "internal",
        "customer_facing": false,
        "sla_tier": "tier-2"
      }
    },
    {
      "id": "asset-currency",
      "name": "Currency Service",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/currencyservice:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 7000, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "medium",
        "criticality_score": 65,
        "function": "currency-conversion",
        "data_classification": "internal",
        "customer_facing": false,
        "sla_tier": "tier-2"
      }
    },
    {
      "id": "asset-shipping",
      "name": "Shipping Service",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/shippingservice:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 50051, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 75,
        "function": "shipping-calculation",
        "data_classification": "internal",
        "customer_facing": false,
        "sla_tier": "tier-2"
      }
    },
    {
      "id": "asset-email",
      "name": "Email Service",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/emailservice:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 8080, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "medium",
        "criticality_score": 60,
        "function": "email-notifications",
        "data_classification": "confidential",
        "customer_facing": false,
        "gdpr_scope": true,
        "sla_tier": "tier-3"
      }
    },
    {
      "id": "asset-recommendation",
      "name": "Recommendation Service",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/recommendationservice:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 8080, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "low",
        "criticality_score": 40,
        "function": "product-recommendations",
        "data_classification": "internal",
        "customer_facing": false,
        "sla_tier": "tier-3"
      }
    },
    {
      "id": "asset-ad",
      "name": "Ad Service",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/adservice:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 9555, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "low",
        "criticality_score": 35,
        "function": "advertisements",
        "data_classification": "public",
        "customer_facing": false,
        "sla_tier": "tier-3"
      }
    },
    {
      "id": "asset-loadgen",
      "name": "Load Generator",
      "type": "container",
      "software": {"image": "us-central1-docker.pkg.dev/google-samples/microservices-demo/loadgenerator:v0.10.3"},
      "network": {
        "zone": "internal",
        "exposed_ports": []
      },
      "business_context": {
        "criticality": "low",
        "criticality_score": 20,
        "function": "testing",
        "data_classification": "internal",
        "customer_facing": false,
        "sla_tier": "tier-3"
      }
    },
    {
      "id": "asset-redis",
      "name": "Redis Cache",
      "type": "container",
      "software": {"image": "redis:alpine"},
      "network": {
        "zone": "internal",
        "exposed_ports": [{"port": 6379, "protocol": "redis", "public": false}]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 75,
        "function": "caching",
        "data_classification": "internal",
        "sla_tier": "tier-2"
      }
    }
  ],
  "dependencies": [
    {"source": "asset-frontend", "target": "asset-checkout", "type": "communicates_with", "protocol": "grpc", "criticality": "critical"},
    {"source": "asset-frontend", "target": "asset-cart", "type": "communicates_with", "protocol": "grpc", "criticality": "high"},
    {"source": "asset-frontend", "target": "asset-product-catalog", "type": "communicates_with", "protocol": "grpc", "criticality": "high"},
    {"source": "asset-frontend", "target": "asset-currency", "type": "communicates_with", "protocol": "grpc", "criticality": "medium"},
    {"source": "asset-frontend", "target": "asset-recommendation", "type": "communicates_with", "protocol": "grpc", "criticality": "low"},
    {"source": "asset-frontend", "target": "asset-ad", "type": "communicates_with", "protocol": "grpc", "criticality": "low"},
    {"source": "asset-checkout", "target": "asset-payment", "type": "communicates_with", "protocol": "grpc", "criticality": "critical"},
    {"source": "asset-checkout", "target": "asset-shipping", "type": "communicates_with", "protocol": "grpc", "criticality": "high"},
    {"source": "asset-checkout", "target": "asset-email", "type": "communicates_with", "protocol": "grpc", "criticality": "medium"},
    {"source": "asset-checkout", "target": "asset-currency", "type": "communicates_with", "protocol": "grpc", "criticality": "medium"},
    {"source": "asset-checkout", "target": "asset-cart", "type": "communicates_with", "protocol": "grpc", "criticality": "critical"},
    {"source": "asset-checkout", "target": "asset-product-catalog", "type": "communicates_with", "protocol": "grpc", "criticality": "high"},
    {"source": "asset-cart", "target": "asset-redis", "type": "communicates_with", "protocol": "redis", "criticality": "high"},
    {"source": "asset-recommendation", "target": "asset-product-catalog", "type": "communicates_with", "protocol": "grpc", "criticality": "medium"},
    {"source": "asset-loadgen", "target": "asset-frontend", "type": "communicates_with", "protocol": "http", "criticality": "low"}
  ],
  "network_topology": {
    "zones": [
      {"id": "zone-dmz", "name": "dmz", "trust_level": "medium", "internet_accessible": true},
      {"id": "zone-internal", "name": "internal", "trust_level": "high", "internet_accessible": false}
    ],
    "segmentation_rules": [
      {"from_zone": "dmz", "to_zone": "internal", "allowed": true, "ports": [50051, 5050, 7070], "protocols": ["grpc"]}
    ]
  }
}
EOF

echo "✓ Environment configuration created"
echo ""

# Merge all scan results into infrastructure graph
if [ "$SKIP_GRAPHS" = "false" ]; then
    echo "Merging vulnerability data into infrastructure graph..."
    MERGE_ARGS=""
    for SCAN_FILE in "$ENTERPRISE_RESULTS_DIR/02-scans"/*.json; do
        if [ -f "$SCAN_FILE" ]; then
            MERGE_ARGS="$MERGE_ARGS --merge-scan $SCAN_FILE"
        fi
    done

    threat-radar env build-graph "$ENTERPRISE_RESULTS_DIR/microservices-environment.json" \
        $MERGE_ARGS \
        -o "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" \
        2>/dev/null || echo "⚠️  Infrastructure graph building failed"

    echo "✓ Infrastructure graph created"
    echo ""
else
    echo "Using existing infrastructure graph: $ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml"
    echo ""
fi

# Step 2: Attack path analysis
if [ "$SKIP_ATTACK_PATHS" = "false" ]; then
    echo "Step 2: Discovering attack paths across infrastructure..."
    echo ""

    if [ -f "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" ]; then
        threat-radar graph attack-paths "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" \
            --max-paths 50 \
            -o "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-paths.json" \
            2>/dev/null || echo "⚠️  Attack path discovery failed"

        threat-radar graph privilege-escalation "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" \
            --max-paths 30 \
            -o "$ENTERPRISE_RESULTS_DIR/04-attack-paths/privilege-escalation.json" \
            2>/dev/null || echo "⚠️  Privilege escalation analysis failed"

        threat-radar graph lateral-movement "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" \
            --max-opportunities 30 \
            -o "$ENTERPRISE_RESULTS_DIR/04-attack-paths/lateral-movement.json" \
            2>/dev/null || echo "⚠️  Lateral movement analysis failed"

        threat-radar graph attack-surface "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" \
            -o "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" \
            2>/dev/null || echo "⚠️  Attack surface analysis failed"

        echo "✓ Attack path analysis complete"
        echo ""

        # Show attack surface summary
        if [ -f "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" ]; then
            echo "Attack Surface Summary:"
            TOTAL_PATHS=$(jq -r '.attack_paths | length' "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" 2>/dev/null || echo "0")
            RISK_SCORE=$(jq -r '.total_risk_score' "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" 2>/dev/null || echo "N/A")
            ENTRY_POINTS=$(jq -r '.entry_points | length' "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" 2>/dev/null || echo "0")
            HIGH_VALUE_TARGETS=$(jq -r '.high_value_targets | length' "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" 2>/dev/null || echo "0")
            PRIV_ESC=$(jq -r '.privilege_escalations | length' "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" 2>/dev/null || echo "0")

            # Count threat levels
            CRITICAL_PATHS=$(jq -r '[.attack_paths[] | select(.threat_level=="critical")] | length' "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" 2>/dev/null || echo "0")
            HIGH_PATHS=$(jq -r '[.attack_paths[] | select(.threat_level=="high")] | length' "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" 2>/dev/null || echo "0")

            echo "  Total Risk Score: $RISK_SCORE/100"
            echo "  Entry Points: $ENTRY_POINTS"
            echo "  High-Value Targets: $HIGH_VALUE_TARGETS"
            echo "  Attack Paths: $TOTAL_PATHS (Critical: $CRITICAL_PATHS, High: $HIGH_PATHS)"
            echo "  Privilege Escalation Opportunities: $PRIV_ESC"
            echo ""
        fi
    else
        echo "⚠️  Infrastructure graph not found - cannot analyze attack paths"
        echo ""
    fi
else
    echo "Step 2: Attack path analysis - SKIPPED"
    echo ""
    echo "Using existing attack path data from: $ENTERPRISE_RESULTS_DIR/04-attack-paths/"
    echo ""
fi

# Step 3: AI-powered analysis (if available)
if [ "$SKIP_AI" = "false" ] && [ "$AI_AVAILABLE" = true ]; then
    echo "Step 3: Running AI-powered analysis on consolidated results..."
    echo ""

    # Check which analyses are enabled
    ANY_AI_ENABLED=false
    if [ "$RUN_RISK_ASSESSMENT" = "true" ] || [ "$RUN_REMEDIATION" = "true" ] || \
       [ "$RUN_PRIORITIES" = "true" ] || [ "$RUN_THREAT_MODEL" = "true" ]; then
        ANY_AI_ENABLED=true
    fi

    if [ "$ANY_AI_ENABLED" = false ]; then
        echo "  ℹ️  All AI analysis features are disabled"
        echo "     Enable with: RUN_RISK_ASSESSMENT=true, RUN_REMEDIATION=true, etc."
        echo ""
    else
        # Use consolidated scan for enterprise-wide AI analysis
        CONSOLIDATED_SCAN="$ENTERPRISE_RESULTS_DIR/08-reports/consolidated-scan.json"

        if [ ! -f "$CONSOLIDATED_SCAN" ]; then
            echo "  ⚠️  Consolidated scan not found, creating it now..."
            # Create consolidated scan (same logic as report generation)
            python3 << 'EOF'
import json
from pathlib import Path

scan_dir = Path("full-demo-results/02-scans")
scan_files = sorted(scan_dir.glob("*_scan.json"))

if not scan_files:
    print("  ⚠️  No scan files found")
    exit(1)

all_vulnerabilities = []
all_targets = []
severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}

for scan_file in scan_files:
    with open(scan_file) as f:
        scan_data = json.load(f)
        if "vulnerabilities" in scan_data:
            all_vulnerabilities.extend(scan_data["vulnerabilities"])
        if "severity_counts" in scan_data:
            for severity, count in scan_data["severity_counts"].items():
                if severity in severity_counts:
                    severity_counts[severity] += count
        if "target" in scan_data:
            all_targets.append(scan_data["target"])

consolidated = {
    "target": "microservices-demo (consolidated)",
    "targets": all_targets,
    "total_vulnerabilities": len(all_vulnerabilities),
    "severity_counts": severity_counts,
    "vulnerabilities": all_vulnerabilities
}

output_file = Path("full-demo-results/08-reports/consolidated-scan.json")
output_file.parent.mkdir(parents=True, exist_ok=True)
with open(output_file, "w") as f:
    json.dump(consolidated, f, indent=2)

print(f"  ✓ Created consolidated scan: {len(all_vulnerabilities)} vulnerabilities")
EOF
        fi

        if [ -f "$CONSOLIDATED_SCAN" ]; then
            # Count total vulnerabilities for progress tracking
            TOTAL_VULNS=$(jq -r '.total_vulnerabilities // (.vulnerabilities | length)' "$CONSOLIDATED_SCAN" 2>/dev/null || echo "unknown")
            CRITICAL_COUNT=$(jq -r '.severity_counts.critical // 0' "$CONSOLIDATED_SCAN" 2>/dev/null || echo "0")
            HIGH_COUNT=$(jq -r '.severity_counts.high // 0' "$CONSOLIDATED_SCAN" 2>/dev/null || echo "0")

            echo "  Running enterprise-wide AI analysis..."
            echo "  Total vulnerabilities: $TOTAL_VULNS (Critical: $CRITICAL_COUNT, High: $HIGH_COUNT)"
            echo ""

            # AI Vulnerability Analysis
            # Note: For consolidated multi-service scans, we use basic ai analyze
            # For individual services, use analyze-with-context with specific asset-id
            if [ "$RUN_RISK_ASSESSMENT" = "true" ]; then
                echo "  → [1/4] AI vulnerability analysis (consolidated)..."
                echo "     Filtering to HIGH+ severity for cost optimization..."

                # Create filtered scan with only HIGH+ vulnerabilities
                FILTERED_SCAN="$ENTERPRISE_RESULTS_DIR/08-reports/consolidated-scan-high.json"
                python3 << 'EOF'
import json
from pathlib import Path

# Load consolidated scan
scan_file = Path("full-demo-results/08-reports/consolidated-scan.json")
with open(scan_file) as f:
    scan_data = json.load(f)

# Filter to HIGH and CRITICAL only
high_severity = ["critical", "high"]
filtered_vulns = [v for v in scan_data.get("vulnerabilities", [])
                  if v.get("severity", "").lower() in high_severity]

# Recalculate severity counts
severity_counts = {"critical": 0, "high": 0}
for v in filtered_vulns:
    sev = v.get("severity", "").lower()
    if sev in severity_counts:
        severity_counts[sev] += 1

# Create filtered scan
filtered_scan = {
    "target": scan_data.get("target", "microservices-demo (consolidated)"),
    "targets": scan_data.get("targets", []),
    "total_vulnerabilities": len(filtered_vulns),
    "severity_counts": severity_counts,
    "vulnerabilities": filtered_vulns
}

# Save filtered scan
output_file = Path("full-demo-results/08-reports/consolidated-scan-high.json")
with open(output_file, "w") as f:
    json.dump(filtered_scan, f, indent=2)

print(f"     Filtered to {len(filtered_vulns)} HIGH+ vulnerabilities (Critical: {severity_counts['critical']}, High: {severity_counts['high']})")
EOF

                echo "     Analyzing exploitability, attack vectors, and business impact..."
                echo "     Estimated time: ~2-4 minutes (batch processing)"
                START_TIME=$(date +%s)

                threat-radar ai analyze "$FILTERED_SCAN" \
                    -o "$ENTERPRISE_RESULTS_DIR/06-ai-analysis/enterprise_vulnerability-analysis.json" \
                    --auto-save \
                    || echo "    ⚠️  Vulnerability analysis failed"

                END_TIME=$(date +%s)
                DURATION=$((END_TIME - START_TIME))
                echo "     ✓ Completed in ${DURATION}s"
                echo ""
            fi

            # Priority Rankings
            if [ "$RUN_PRIORITIES" = "true" ]; then
                echo "  → [2/4] Priority rankings..."
                echo "     Generating prioritized remediation list (HIGH+ severity only)"
                echo "     Analyzing Critical: $CRITICAL_COUNT, High: $HIGH_COUNT vulnerabilities"
                echo "     Estimated time: ~1-2 minutes"
                START_TIME=$(date +%s)

                threat-radar ai prioritize "$CONSOLIDATED_SCAN" \
                    --severity high \
                    -o "$ENTERPRISE_RESULTS_DIR/06-ai-analysis/enterprise_priorities.json" \
                    --auto-save \
                    || echo "    ⚠️  Priority ranking failed"

                END_TIME=$(date +%s)
                DURATION=$((END_TIME - START_TIME))
                echo "     ✓ Completed in ${DURATION}s"
                echo ""
            fi

            # Remediation Plans
            if [ "$RUN_REMEDIATION" = "true" ]; then
                echo "  → [3/4] Remediation plans..."
                echo "     Creating actionable fix recommendations (HIGH+ severity only)"
                echo "     Estimated time: ~1-2 minutes"
                START_TIME=$(date +%s)

                threat-radar ai remediate "$CONSOLIDATED_SCAN" \
                    --severity high \
                    -o "$ENTERPRISE_RESULTS_DIR/06-ai-analysis/enterprise_remediation.json" \
                    --auto-save \
                    || echo "    ⚠️  Remediation planning failed"

                END_TIME=$(date +%s)
                DURATION=$((END_TIME - START_TIME))
                echo "     ✓ Completed in ${DURATION}s"
                echo ""
            fi

            # AI-Powered Threat Modeling on Infrastructure Graph
            if [ "$RUN_THREAT_MODEL" = "true" ]; then
                INFRA_GRAPH="$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml"
                if [ -f "$INFRA_GRAPH" ]; then
                    echo "  → [4/4] AI threat modeling on infrastructure graph..."
                    echo "     Analyzing realistic attack scenarios with threat actor personas"
                    echo "     Estimated time: ~3-6 minutes (2 threat actors × 15 scenarios each)"
                    echo ""

                    # Run threat modeling for different threat actors
                    echo "     → Threat Actor 1/2: Ransomware (encryption/exfiltration scenarios)..."
                    START_TIME=$(date +%s)

                    threat-radar ai threat-model "$INFRA_GRAPH" \
                        -e "$ENTERPRISE_RESULTS_DIR/microservices-environment.json" \
                        -t ransomware \
                        -s 15 \
                        -o "$ENTERPRISE_RESULTS_DIR/06-ai-analysis/enterprise_threat-model-ransomware.json" \
                        --auto-save \
                        || echo "       ⚠️  Ransomware threat modeling failed"

                    END_TIME=$(date +%s)
                    DURATION=$((END_TIME - START_TIME))
                    echo "       ✓ Completed in ${DURATION}s"
                    echo ""

                    echo "     → Threat Actor 2/2: APT28 (advanced persistent threat scenarios)..."
                    START_TIME=$(date +%s)

                    threat-radar ai threat-model "$INFRA_GRAPH" \
                        -e "$ENTERPRISE_RESULTS_DIR/microservices-environment.json" \
                        -t apt28 \
                        -s 15 \
                        -o "$ENTERPRISE_RESULTS_DIR/06-ai-analysis/enterprise_threat-model-apt.json" \
                        --auto-save \
                        || echo "       ⚠️  APT threat modeling failed"

                    END_TIME=$(date +%s)
                    DURATION=$((END_TIME - START_TIME))
                    echo "       ✓ Completed in ${DURATION}s"
                    echo ""
                else
                    echo "    ⚠️  Infrastructure graph not found - skipping threat modeling"
                    echo ""
                fi
            fi

            echo "✓ Enterprise-wide AI analysis complete"
            echo ""
        else
            echo "  ⚠️  Could not create consolidated scan - skipping AI analysis"
            echo ""
        fi
    fi
elif [ "$SKIP_AI" = "true" ]; then
    echo "Step 3: AI-powered analysis - SKIPPED"
    echo ""
    echo "Using existing AI analysis from: $ENTERPRISE_RESULTS_DIR/06-ai-analysis/"
    echo ""
else
    echo "Step 3: Skipping AI analysis (no .env configuration)"
    echo ""
fi

# Step 4: Generate visualizations
if [ "$RUN_VISUALIZATIONS" = "true" ]; then
    echo "Step 4: Generating visualizations..."
    echo ""

    # Check if plotly is installed
    if python3 -c "import plotly" 2>/dev/null; then
        # Part 1: Infrastructure-level visualizations
        if [ -f "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" ]; then
            echo "  Infrastructure Visualizations:"
            echo "  ─────────────────────────────"

            echo "    → Creating infrastructure topology visualization..."
            threat-radar visualize topology "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" \
                -o "$ENTERPRISE_RESULTS_DIR/07-visualizations/topology.html" \
                --view topology \
                2>/dev/null || echo "      ⚠️  Topology visualization failed"

            echo "    → Creating critical-only infrastructure view..."
            threat-radar visualize filter "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" \
                -o "$ENTERPRISE_RESULTS_DIR/07-visualizations/infrastructure-critical.html" \
                --type severity \
                --value critical \
                2>/dev/null || echo "      ⚠️  Critical infrastructure visualization failed"

            echo "    → Creating composite critical view (hierarchical)..."
            threat-radar visualize graph "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" \
                -o "$ENTERPRISE_RESULTS_DIR/07-visualizations/infrastructure-critical-hierarchical.html" \
                --layout hierarchical \
                --color-by severity \
                2>/dev/null || echo "      ⚠️  Hierarchical critical view failed"

            echo "    → Creating attack paths visualization..."
            threat-radar visualize attack-paths "$ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml" \
                -o "$ENTERPRISE_RESULTS_DIR/07-visualizations/attack-paths.html" \
                --paths "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-paths.json" \
                --max-paths 15 \
                2>/dev/null || echo "      ⚠️  Attack paths visualization failed"

            echo ""
        fi

        # Part 2: Individual service visualizations
        echo "  Individual Service Visualizations:"
        echo "  ───────────────────────────────────"

        SERVICES_VISUALIZED=0
        for SERVICE_NAME in "${!SERVICES[@]}"; do
            GRAPH_FILE="$ENTERPRISE_RESULTS_DIR/03-graphs/${SERVICE_NAME}_graph.graphml"

            if [ -f "$GRAPH_FILE" ]; then
                echo "    Processing $SERVICE_NAME..."

                # 1. Basic graph visualization (hierarchical layout, colored by severity)
                echo "      → Creating basic graph visualization..."
                threat-radar visualize graph "$GRAPH_FILE" \
                    -o "$ENTERPRISE_RESULTS_DIR/07-visualizations/${SERVICE_NAME}_graph.html" \
                    --layout hierarchical \
                    --color-by severity \
                    2>/dev/null || echo "        ⚠️  Basic visualization failed"

                # 2. Critical-only filtered visualization (HIGH+ severity)
                echo "      → Creating critical-only filtered view..."
                threat-radar visualize filter "$GRAPH_FILE" \
                    -o "$ENTERPRISE_RESULTS_DIR/07-visualizations/${SERVICE_NAME}_critical.html" \
                    --type severity \
                    --value high \
                    2>/dev/null || echo "        ⚠️  Filtered visualization failed"

                # 3. Spring layout visualization (natural clustering)
                echo "      → Creating spring layout visualization..."
                threat-radar visualize graph "$GRAPH_FILE" \
                    -o "$ENTERPRISE_RESULTS_DIR/07-visualizations/${SERVICE_NAME}_spring.html" \
                    --layout spring \
                    --color-by node_type \
                    2>/dev/null || echo "        ⚠️  Spring layout visualization failed"

                # 4. Circular layout PNG export (for reports)
                echo "      → Creating circular layout PNG export..."
                threat-radar visualize export "$GRAPH_FILE" \
                    -o "$ENTERPRISE_RESULTS_DIR/07-visualizations/${SERVICE_NAME}_export" \
                    --format png \
                    --layout circular \
                    2>/dev/null || echo "        ⚠️  PNG export failed"

                SERVICES_VISUALIZED=$((SERVICES_VISUALIZED + 1))
                echo "      ✓ $SERVICE_NAME visualizations complete"
                echo ""
            fi
        done

        if [ $SERVICES_VISUALIZED -gt 0 ]; then
            echo "✓ Generated visualizations for $SERVICES_VISUALIZED services"
            echo ""

            # Create visualization index for easy navigation
            echo "  Creating visualization index..."
            bash "$(dirname "$0")/create-viz-index.sh" "$ENTERPRISE_RESULTS_DIR" 2>/dev/null || echo "    ⚠️  Index creation failed"
            echo ""
            echo "  📂 View all visualizations: $ENTERPRISE_RESULTS_DIR/07-visualizations/index.html"
        else
            echo "⚠️  No service graphs found - cannot generate individual service visualizations"
        fi
        echo ""
    else
        echo "  ⚠️  Plotly not installed - skipping visualizations"
        echo "     Install with: pip install plotly kaleido"
        echo ""
    fi
else
    echo "Step 4: Skipping visualizations (RUN_VISUALIZATIONS=false)"
    echo ""
fi

# Step 5: Generate consolidated reports
echo "Step 5: Generating consolidated reports..."
echo ""

# Merge all scan results into a consolidated JSON file
echo "  Merging scan results into consolidated file..."
CONSOLIDATED_SCAN="$ENTERPRISE_RESULTS_DIR/08-reports/consolidated-scan.json"

# Create consolidated scan by merging all individual scans
python3 << 'EOF'
import json
import sys
from pathlib import Path

# Find all scan files
scan_dir = Path("full-demo-results/02-scans")
scan_files = sorted(scan_dir.glob("*_scan.json"))

if not scan_files:
    print("  ⚠️  No scan files found", file=sys.stderr)
    sys.exit(1)

# Load and merge all scans
all_vulnerabilities = []
all_targets = []
severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}

for scan_file in scan_files:
    with open(scan_file) as f:
        scan_data = json.load(f)

        # Merge vulnerabilities (processed format)
        if "vulnerabilities" in scan_data:
            all_vulnerabilities.extend(scan_data["vulnerabilities"])

        # Update severity counts
        if "severity_counts" in scan_data:
            for severity, count in scan_data["severity_counts"].items():
                if severity in severity_counts:
                    severity_counts[severity] += count

        # Collect target info
        if "target" in scan_data:
            all_targets.append(scan_data["target"])

# Create consolidated result (in processed Threat Radar format)
consolidated = {
    "target": "microservices-demo (consolidated)",
    "targets": all_targets,
    "total_vulnerabilities": len(all_vulnerabilities),
    "severity_counts": severity_counts,
    "vulnerabilities": all_vulnerabilities
}

# Write consolidated file
output_file = Path("full-demo-results/08-reports/consolidated-scan.json")
output_file.parent.mkdir(parents=True, exist_ok=True)
with open(output_file, "w") as f:
    json.dump(consolidated, f, indent=2)

print(f"  ✓ Merged {len(scan_files)} scan files ({len(all_vulnerabilities)} total vulnerabilities)")
EOF

if [ $? -eq 0 ] && [ -f "$CONSOLIDATED_SCAN" ]; then
    # Generate executive summary (HTML) with AI-powered insights
    if [ "$AI_AVAILABLE" = true ]; then
        echo "  Generating executive summary (HTML) with AI-powered insights..."
        threat-radar report generate "$CONSOLIDATED_SCAN" \
            -o "$ENTERPRISE_RESULTS_DIR/08-reports/executive-summary.html" \
            -f html \
            --level executive \
            --attack-paths "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" \
            --executive \
            --ai-provider "${AI_PROVIDER:-openai}" \
            || echo "    ⚠️  Executive report generation failed"
    else
        echo "  Generating executive summary (HTML) without AI..."
        threat-radar report generate "$CONSOLIDATED_SCAN" \
            -o "$ENTERPRISE_RESULTS_DIR/08-reports/executive-summary.html" \
            -f html \
            --level executive \
            --attack-paths "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" \
            --no-executive \
            || echo "    ⚠️  Executive report generation failed"
    fi

    # Generate detailed technical report (JSON) with AI
    if [ "$AI_AVAILABLE" = true ]; then
        echo "  Generating detailed technical report (JSON) with AI summary..."
        threat-radar report generate "$CONSOLIDATED_SCAN" \
            -o "$ENTERPRISE_RESULTS_DIR/08-reports/detailed-report.json" \
            -f json \
            --level detailed \
            --attack-paths "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" \
            --executive \
            --ai-provider "${AI_PROVIDER:-openai}" \
            || echo "    ⚠️  Detailed report generation failed"
    else
        echo "  Generating detailed technical report (JSON)..."
        threat-radar report generate "$CONSOLIDATED_SCAN" \
            -o "$ENTERPRISE_RESULTS_DIR/08-reports/detailed-report.json" \
            -f json \
            --level detailed \
            --attack-paths "$ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json" \
            --no-executive \
            || echo "    ⚠️  Detailed report generation failed"
    fi

    # Generate critical-only report for incident response
    echo "  Generating critical-only report..."
    threat-radar report generate "$CONSOLIDATED_SCAN" \
        -o "$ENTERPRISE_RESULTS_DIR/08-reports/critical-only.json" \
        -f json \
        --level critical_only \
        || echo "    ⚠️  Critical-only report generation failed"

    # Export dashboard data
    echo "  Exporting dashboard data..."
    threat-radar report dashboard-export "$CONSOLIDATED_SCAN" \
        -o "$ENTERPRISE_RESULTS_DIR/08-reports/dashboard-data.json" \
        || echo "    ⚠️  Dashboard export failed"

    echo "✓ Reports generated"
    echo ""
else
    echo "  ⚠️  Could not create consolidated scan file, skipping reports"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ANALYSIS COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Count total vulnerabilities across all services
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
SERVICES_SCANNED=0

for SCAN_FILE in "$ENTERPRISE_RESULTS_DIR/02-scans"/*.json; do
    if [ -f "$SCAN_FILE" ]; then
        ((SERVICES_SCANNED++))
        CRITICAL=$(jq -r '[.vulnerabilities[] | select(.severity=="critical")] | length' "$SCAN_FILE" 2>/dev/null || echo "0")
        HIGH=$(jq -r '[.vulnerabilities[] | select(.severity=="high")] | length' "$SCAN_FILE" 2>/dev/null || echo "0")
        MEDIUM=$(jq -r '[.vulnerabilities[] | select(.severity=="medium")] | length' "$SCAN_FILE" 2>/dev/null || echo "0")
        LOW=$(jq -r '[.vulnerabilities[] | select(.severity=="low")] | length' "$SCAN_FILE" 2>/dev/null || echo "0")

        TOTAL_CRITICAL=$((TOTAL_CRITICAL + CRITICAL))
        TOTAL_HIGH=$((TOTAL_HIGH + HIGH))
        TOTAL_MEDIUM=$((TOTAL_MEDIUM + MEDIUM))
        TOTAL_LOW=$((TOTAL_LOW + LOW))
    fi
done

TOTAL_VULNS=$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW))

echo "Services Analyzed: $SERVICES_SCANNED/$TOTAL_SERVICES"
echo ""
echo "Total Vulnerabilities: $TOTAL_VULNS"
echo "  Critical: $TOTAL_CRITICAL"
echo "  High:     $TOTAL_HIGH"
echo "  Medium:   $TOTAL_MEDIUM"
echo "  Low:      $TOTAL_LOW"
echo ""

echo "Results saved to: $ENTERPRISE_RESULTS_DIR/"
echo ""
echo "Key files:"
echo "  • Executive Summary:     $ENTERPRISE_RESULTS_DIR/08-reports/executive-summary.html"
echo "  • Detailed Report:       $ENTERPRISE_RESULTS_DIR/08-reports/detailed-report.json"
echo "  • Infrastructure Graph:  $ENTERPRISE_RESULTS_DIR/03-graphs/infrastructure-graph.graphml"
echo "  • Attack Surface:        $ENTERPRISE_RESULTS_DIR/04-attack-paths/attack-surface.json"
echo "  • Dashboard Data:        $ENTERPRISE_RESULTS_DIR/08-reports/dashboard-data.json"

if [ "$RUN_VISUALIZATIONS" = "true" ] && python3 -c "import plotly" 2>/dev/null; then
    echo "  • Topology Viz:          $ENTERPRISE_RESULTS_DIR/07-visualizations/topology.html"
    echo "  • Attack Paths Viz:      $ENTERPRISE_RESULTS_DIR/07-visualizations/attack-paths.html"
fi
echo ""

if [ "$RUN_VISUALIZATIONS" = "true" ] && python3 -c "import plotly" 2>/dev/null; then
    echo "Quick view commands:"
    echo "  open $ENTERPRISE_RESULTS_DIR/08-reports/executive-summary.html"
    echo "  open $ENTERPRISE_RESULTS_DIR/07-visualizations/topology.html"
    echo "  open $ENTERPRISE_RESULTS_DIR/07-visualizations/attack-paths.html"
else
    echo "To view executive summary:"
    echo "  open $ENTERPRISE_RESULTS_DIR/08-reports/executive-summary.html"
fi
echo ""

echo "✓ Multi-Service Analysis Complete"
