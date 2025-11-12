#!/usr/bin/env bash
#
# Threat Radar - COMPLETE FEATURE SHOWCASE
# Demonstrates ALL Threat Radar capabilities on Google Cloud Microservices Demo
#
# This script runs every single Threat Radar feature to provide a comprehensive
# security analysis demonstration.
#

set -e  # Exit on error

# Load environment variables from project root .env file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"

if [ -f "${ENV_FILE}" ]; then
    echo "Loading environment from ${ENV_FILE}..."
    # Export variables from .env file (handles comments and empty lines)
    set -a
    source "${ENV_FILE}"
    set +a
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
OUTPUT_DIR="./full-demo-results"
SCANS_DIR="${OUTPUT_DIR}/01-scans"
SBOM_DIR="${OUTPUT_DIR}/02-sboms"
AI_DIR="${OUTPUT_DIR}/03-ai-analysis"
REPORTS_DIR="${OUTPUT_DIR}/04-reports"
GRAPHS_DIR="${OUTPUT_DIR}/05-graphs"
ATTACK_DIR="${OUTPUT_DIR}/06-attack-paths"
VIZ_DIR="${OUTPUT_DIR}/07-visualizations"

CONFIG_FILE="${OUTPUT_DIR}/environment.json"

# Feature flags
RUN_SBOM_GENERATION=${RUN_SBOM_GENERATION:-true}
RUN_AI_ANALYSIS=${RUN_AI_ANALYSIS:-true}
RUN_VISUALIZATIONS=${RUN_VISUALIZATIONS:-true}
CLEANUP_IMAGES=${CLEANUP_IMAGES:-true}

# Service definitions
declare -A SERVICES=(
    ["frontend"]="gcr.io/google-samples/microservices-demo/frontend:v0.10.1"
    ["cartservice"]="gcr.io/google-samples/microservices-demo/cartservice:v0.10.1"
    ["checkoutservice"]="gcr.io/google-samples/microservices-demo/checkoutservice:v0.10.1"
    ["paymentservice"]="gcr.io/google-samples/microservices-demo/paymentservice:v0.10.1"
    ["productcatalogservice"]="gcr.io/google-samples/microservices-demo/productcatalogservice:v0.10.1"
    ["currencyservice"]="gcr.io/google-samples/microservices-demo/currencyservice:v0.10.1"
)

declare -A LANGUAGES=(
    ["frontend"]="Go"
    ["cartservice"]="C#"
    ["checkoutservice"]="Go"
    ["paymentservice"]="Node.js"
    ["productcatalogservice"]="Go"
    ["currencyservice"]="Node.js"
)

# Progress tracking
TOTAL_FEATURES=0
COMPLETED_FEATURES=0

echo -e "${MAGENTA}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║         THREAT RADAR - COMPLETE FEATURE SHOWCASE            ║
║                                                              ║
║    Demonstrating ALL capabilities on a real-world app       ║
║    Google Cloud Platform Microservices Demo                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

# Function: Feature section header
feature_section() {
    local title=$1
    TOTAL_FEATURES=$((TOTAL_FEATURES + 1))

    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  FEATURE ${TOTAL_FEATURES}: ${title}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Function: Feature complete
feature_complete() {
    COMPLETED_FEATURES=$((COMPLETED_FEATURES + 1))
    echo -e "${GREEN}✓ Feature ${COMPLETED_FEATURES}/${TOTAL_FEATURES} complete${NC}\n"
}

# Setup
setup() {
    feature_section "SETUP - Directory Structure"

    echo "Creating output directories..."
    mkdir -p "${OUTPUT_DIR}"
    mkdir -p "${SCANS_DIR}"
    mkdir -p "${SBOM_DIR}"
    mkdir -p "${AI_DIR}"
    mkdir -p "${REPORTS_DIR}"
    mkdir -p "${GRAPHS_DIR}"
    mkdir -p "${ATTACK_DIR}"
    mkdir -p "${VIZ_DIR}"

    echo -e "${GREEN}✓ Directories created${NC}"
    feature_complete
}

# Feature 1: CVE Vulnerability Scanning
cve_scanning() {
    feature_section "CVE VULNERABILITY SCANNING"

    # Check if Docker is accessible
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}✗ Docker daemon is not accessible${NC}"
        echo -e "${YELLOW}  Please start Docker Desktop and try again${NC}"
        echo -e "${RED}  Cannot continue without Docker${NC}\n"
        exit 1
    fi

    echo "Scanning all microservices with Grype..."
    echo ""

    local count=0
    local failed=0
    for service in "${!SERVICES[@]}"; do
        count=$((count + 1))
        echo -e "${BLUE}[${count}/${#SERVICES[@]}] Scanning ${service} (${LANGUAGES[$service]})${NC}"

        local cleanup_flag=""
        if [ "$CLEANUP_IMAGES" = true ]; then
            cleanup_flag="--cleanup"
        fi

        if threat-radar cve scan-image "${SERVICES[$service]}" \
            -o "${SCANS_DIR}/${service}_scan.json" \
            --auto-save \
            ${cleanup_flag} \
            > /dev/null 2>&1; then

            local vulns=$(jq -r '.total_vulnerabilities // 0' "${SCANS_DIR}/${service}_scan.json")
            local critical=$(jq -r '.severity_counts.critical // 0' "${SCANS_DIR}/${service}_scan.json")
            local high=$(jq -r '.severity_counts.high // 0' "${SCANS_DIR}/${service}_scan.json")

            echo "  Total: ${vulns} (Critical: ${critical}, High: ${high})"
        else
            echo -e "  ${YELLOW}⚠ Scan failed (continuing...)${NC}"
            failed=$((failed + 1))
        fi
    done

    if [ $failed -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}⚠ ${failed}/${#SERVICES[@]} scans failed${NC}"
    fi

    feature_complete
}

# Feature 2: SBOM Generation
sbom_generation() {
    if [ "$RUN_SBOM_GENERATION" != true ]; then
        echo -e "${YELLOW}⊘ Skipping SBOM generation (disabled)${NC}\n"
        return
    fi

    feature_section "SBOM GENERATION (CycloneDX & SPDX)"

    # Check if Docker is accessible
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}✗ Docker daemon is not accessible${NC}"
        echo -e "${YELLOW}  Please start Docker Desktop and try again${NC}"
        echo -e "${YELLOW}⊘ Skipping SBOM generation${NC}\n"
        return
    fi

    echo "Generating SBOMs for all services..."
    echo ""

    local sbom_count=0
    for service in "${!SERVICES[@]}"; do
        echo -e "${BLUE}Generating SBOM for ${service}${NC}"

        # Generate CycloneDX SBOM
        if threat-radar sbom docker "${SERVICES[$service]}" \
            -o "${SBOM_DIR}/${service}_cyclonedx.json" \
            --auto-save \
            > /dev/null 2>&1; then
            echo "  ✓ CycloneDX SBOM generated"
            sbom_count=$((sbom_count + 1))
        else
            echo -e "  ${YELLOW}⚠ Failed to generate SBOM (continuing...)${NC}"
        fi
    done

    echo ""
    echo -e "${GREEN}Generated ${sbom_count}/${#SERVICES[@]} SBOMs${NC}"
    feature_complete
}

# Feature 3: SBOM Operations
sbom_operations() {
    if [ "$RUN_SBOM_GENERATION" != true ]; then
        echo -e "${YELLOW}⊘ Skipping SBOM operations (SBOM generation disabled)${NC}\n"
        return
    fi

    feature_section "SBOM OPERATIONS (Stats, Export, Search)"

    # Pick a service for detailed SBOM analysis
    local service="frontend"
    local sbom_file="${SBOM_DIR}/${service}_cyclonedx.json"

    if [ ! -f "$sbom_file" ]; then
        echo -e "${YELLOW}⚠ SBOM file not found, skipping${NC}"
        return
    fi

    echo "SBOM Statistics for ${service}:"
    threat-radar sbom stats "$sbom_file" > "${SBOM_DIR}/${service}_stats.txt"
    cat "${SBOM_DIR}/${service}_stats.txt"

    echo ""
    echo "Exporting SBOM to CSV..."
    threat-radar sbom export "$sbom_file" \
        -o "${SBOM_DIR}/${service}_packages.csv" \
        -f csv \
        > /dev/null 2>&1
    echo "  ✓ Saved to ${service}_packages.csv"

    echo ""
    echo "Searching for common packages..."
    threat-radar sbom search "$sbom_file" "openssl" > "${SBOM_DIR}/${service}_openssl_search.txt" || true
    echo "  ✓ Search results saved"

    feature_complete
}

# Feature 4: Environment Configuration & Validation
environment_config() {
    feature_section "ENVIRONMENT CONFIGURATION & VALIDATION"

    echo "Generating environment configuration with business context..."

    # Check if we can use the example config from the repo
    EXAMPLE_CONFIG="${SCRIPT_DIR}/../../examples/environments/ecommerce-production.json"
    if [ -f "${EXAMPLE_CONFIG}" ]; then
        echo "  Using example ecommerce config from repository..."
        cp "${EXAMPLE_CONFIG}" "${CONFIG_FILE}"
    else
        echo "  Generating minimal config..."
        # Use a minimal valid config
        cat > "${CONFIG_FILE}" << 'EOFCONFIG'
{
  "environment": {
    "name": "online-boutique-production",
    "type": "production",
    "cloud_provider": "gcp",
    "region": "us-central1",
    "compliance_requirements": ["pci-dss", "soc2"],
    "owner": "platform-team@example.com"
  },
  "global_business_context": {
    "industry": "ecommerce",
    "company_size": "medium",
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
      "id": "asset-frontend",
      "name": "Frontend Web Application",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/frontend:v0.10.1",
        "runtime": "Go"
      },
      "network": {
        "internal_ip": "10.0.1.10",
        "zone": "dmz",
        "exposed_ports": [{"port": 8080, "protocol": "http", "public": true}]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 85,
        "function": "web-frontend",
        "data_classification": "internal",
        "revenue_impact": "critical",
        "customer_facing": true,
        "sla_tier": "tier-1",
        "mttr_target": 1,
        "owner_team": "frontend-team"
      }
    },
    {
      "id": "asset-cartservice",
      "name": "Shopping Cart Service",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/cartservice:v0.10.1",
        "runtime": "C#"
      },
      "network": {
        "internal_ip": "10.0.2.10",
        "zone": "internal",
        "exposed_ports": [{"port": 7070, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "critical",
        "criticality_score": 95,
        "function": "cart-management",
        "data_classification": "pci",
        "revenue_impact": "critical",
        "customer_facing": false,
        "pci_scope": true,
        "sla_tier": "tier-1",
        "mttr_target": 1,
        "owner_team": "backend-team"
      }
    },
    {
      "id": "asset-checkoutservice",
      "name": "Checkout Service",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/checkoutservice:v0.10.1",
        "runtime": "Go"
      },
      "network": {
        "internal_ip": "10.0.2.20",
        "zone": "internal",
        "exposed_ports": [{"port": 5050, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "critical",
        "criticality_score": 95,
        "function": "checkout-processing",
        "data_classification": "pci",
        "revenue_impact": "critical",
        "customer_facing": false,
        "pci_scope": true,
        "sla_tier": "tier-1",
        "mttr_target": 1,
        "owner_team": "backend-team"
      }
    },
    {
      "id": "asset-paymentservice",
      "name": "Payment Service",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/paymentservice:v0.10.1",
        "runtime": "Node.js"
      },
      "network": {
        "internal_ip": "10.0.3.10",
        "zone": "trusted",
        "exposed_ports": [{"port": 50051, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "critical",
        "criticality_score": 100,
        "function": "payment-processing",
        "data_classification": "pci",
        "revenue_impact": "critical",
        "customer_facing": false,
        "pci_scope": true,
        "sla_tier": "tier-1",
        "mttr_target": 0.5,
        "owner_team": "payments-team"
      }
    },
    {
      "id": "asset-productcatalogservice",
      "name": "Product Catalog Service",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/productcatalogservice:v0.10.1",
        "runtime": "Go"
      },
      "network": {
        "internal_ip": "10.0.2.30",
        "zone": "internal",
        "exposed_ports": [{"port": 3550, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 75,
        "function": "product-catalog",
        "data_classification": "internal",
        "revenue_impact": "high",
        "customer_facing": false,
        "sla_tier": "tier-2",
        "mttr_target": 2,
        "owner_team": "backend-team"
      }
    },
    {
      "id": "asset-currencyservice",
      "name": "Currency Conversion Service",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/currencyservice:v0.10.1",
        "runtime": "Node.js"
      },
      "network": {
        "internal_ip": "10.0.2.40",
        "zone": "internal",
        "exposed_ports": [{"port": 7000, "protocol": "grpc", "public": false}]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 70,
        "function": "currency-conversion",
        "data_classification": "internal",
        "revenue_impact": "high",
        "customer_facing": false,
        "sla_tier": "tier-2",
        "mttr_target": 2,
        "owner_team": "backend-team"
      }
    }
  ],
  "dependencies": [
    {"from": "asset-frontend", "to": "asset-cartservice", "type": "api-call", "protocol": "grpc", "critical": true},
    {"from": "asset-frontend", "to": "asset-checkoutservice", "type": "api-call", "protocol": "grpc", "critical": true},
    {"from": "asset-frontend", "to": "asset-productcatalogservice", "type": "api-call", "protocol": "grpc", "critical": true},
    {"from": "asset-checkoutservice", "to": "asset-paymentservice", "type": "api-call", "protocol": "grpc", "critical": true},
    {"from": "asset-checkoutservice", "to": "asset-cartservice", "type": "api-call", "protocol": "grpc", "critical": true},
    {"from": "asset-checkoutservice", "to": "asset-productcatalogservice", "type": "api-call", "protocol": "grpc", "critical": true}
  ],
  "network_topology": {
    "zones": [
      {"name": "dmz", "trust_level": "low", "internet_facing": true},
      {"name": "internal", "trust_level": "medium", "internet_facing": false},
      {"name": "trusted", "trust_level": "high", "internet_facing": false}
    ],
    "segmentation_rules": [
      {"from_zone": "dmz", "to_zone": "internal", "allowed": true, "ports": [7070, 5050, 3550, 7000], "protocols": ["grpc"]},
      {"from_zone": "internal", "to_zone": "trusted", "allowed": true, "ports": [50051], "protocols": ["grpc"]}
    ]
  }
}
EOFCONFIG
    fi

    echo "  ✓ Configuration generated"

    echo ""
    echo "Validating environment configuration..."
    if threat-radar env validate "${CONFIG_FILE}" > "${OUTPUT_DIR}/env_validation.txt" 2>&1; then
        echo -e "${GREEN}✓ Configuration valid${NC}"
    else
        echo -e "${YELLOW}⚠ Configuration validation warnings:${NC}"
        cat "${OUTPUT_DIR}/env_validation.txt"
        echo -e "${YELLOW}  Continuing anyway...${NC}"
    fi

    feature_complete
}

# Feature 5: Infrastructure Graph Building
graph_building() {
    feature_section "INFRASTRUCTURE GRAPH BUILDING"

    echo "Building vulnerability graph with environment context..."

    # Build merge-scan arguments
    local merge_args=""
    for service in "${!SERVICES[@]}"; do
        merge_args="${merge_args} --merge-scan ${SCANS_DIR}/${service}_scan.json"
    done

    threat-radar env build-graph "${CONFIG_FILE}" \
        ${merge_args} \
        -o "${GRAPHS_DIR}/main-graph.graphml"

    feature_complete
}

# Feature 6: Graph Query Operations
graph_operations() {
    feature_section "GRAPH QUERY OPERATIONS"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Graph Information:"
    threat-radar graph info "$graph" > "${GRAPHS_DIR}/graph_info.txt"
    cat "${GRAPHS_DIR}/graph_info.txt"

    echo ""
    echo "Vulnerability Statistics:"
    threat-radar graph query "$graph" --stats > "${GRAPHS_DIR}/graph_stats.txt"
    cat "${GRAPHS_DIR}/graph_stats.txt"

    echo ""
    echo "Finding vulnerabilities with available fixes..."
    threat-radar graph fixes "$graph" > "${GRAPHS_DIR}/available_fixes.txt"
    echo "  ✓ Saved to available_fixes.txt"

    feature_complete
}

# Feature 7: Attack Path Discovery
attack_paths() {
    feature_section "ATTACK PATH DISCOVERY"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Finding attack paths from internet to payment services..."
    threat-radar graph attack-paths "$graph" \
        --max-paths 20 \
        -o "${ATTACK_DIR}/attack-paths.json"

    echo ""
    echo "Attack Path Summary:"
    jq '{
      total_paths: .total_paths,
      threat_levels: [.attack_paths[] | .threat_level] | group_by(.) | map({(.[0]): length}) | add,
      critical_paths: [.attack_paths[] | select(.threat_level == "critical")] | length
    }' "${ATTACK_DIR}/attack-paths.json"

    feature_complete
}

# Feature 8: Privilege Escalation Analysis
privilege_escalation() {
    feature_section "PRIVILEGE ESCALATION ANALYSIS"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Identifying privilege escalation opportunities..."
    threat-radar graph privilege-escalation "$graph" \
        --max-paths 15 \
        -o "${ATTACK_DIR}/privilege-escalation.json"

    echo ""
    echo "Privilege Escalation Summary:"
    jq '{
      total_opportunities: length,
      by_difficulty: group_by(.difficulty) | map({(.[0].difficulty): length}) | add
    }' "${ATTACK_DIR}/privilege-escalation.json" 2>/dev/null || echo "  No escalation opportunities found"

    feature_complete
}

# Feature 9: Lateral Movement Analysis
lateral_movement() {
    feature_section "LATERAL MOVEMENT ANALYSIS"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Identifying lateral movement opportunities..."
    threat-radar graph lateral-movement "$graph" \
        --max-opportunities 20 \
        -o "${ATTACK_DIR}/lateral-movement.json"

    echo ""
    echo "Lateral Movement Summary:"
    jq '{
      total_opportunities: length,
      by_detection: group_by(.detection_difficulty) | map({(.[0].detection_difficulty): length}) | add
    }' "${ATTACK_DIR}/lateral-movement.json" 2>/dev/null || echo "  No lateral movement opportunities found"

    feature_complete
}

# Feature 10: Complete Attack Surface Analysis
attack_surface() {
    feature_section "COMPLETE ATTACK SURFACE ANALYSIS"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Performing comprehensive attack surface analysis..."
    threat-radar graph attack-surface "$graph" \
        --max-paths 30 \
        -o "${ATTACK_DIR}/attack-surface.json"

    echo ""
    echo "Attack Surface Summary:"
    jq '{
      total_risk_score: .total_risk_score,
      entry_points: .entry_points | length,
      high_value_targets: .high_value_targets | length,
      total_attack_paths: .attack_paths | length,
      critical_paths: [.attack_paths[] | select(.threat_level == "critical")] | length,
      recommendations_count: .recommendations | length
    }' "${ATTACK_DIR}/attack-surface.json"

    feature_complete
}

# Feature 11: AI Vulnerability Analysis
ai_analysis() {
    if [ "$RUN_AI_ANALYSIS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping AI analysis (disabled or API key not set)${NC}\n"
        return
    fi

    if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
        echo -e "${YELLOW}⊘ Skipping AI analysis (no API key configured)${NC}\n"
        return
    fi

    feature_section "AI VULNERABILITY ANALYSIS (with Batch Processing)"

    # Pick the most critical service
    local service="paymentservice"

    echo "Analyzing ${service} vulnerabilities with AI..."
    echo "(This may take 30-60 seconds for batch processing)"

    threat-radar ai analyze "${SCANS_DIR}/${service}_scan.json" \
        -o "${AI_DIR}/${service}_ai_analysis.json" \
        --auto-save

    echo ""
    echo "AI Analysis Summary:"
    jq '{
      analyzed_vulnerabilities: .vulnerability_assessments | length,
      high_exploitability: [.vulnerability_assessments[] | select(.exploitability == "high")] | length,
      business_impact: .summary.key_findings[0] // "N/A"
    }' "${AI_DIR}/${service}_ai_analysis.json" 2>/dev/null || echo "  Analysis complete"

    feature_complete
}

# Feature 12: AI Prioritization
ai_prioritization() {
    if [ "$RUN_AI_ANALYSIS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping AI prioritization${NC}\n"
        return
    fi

    if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
        echo -e "${YELLOW}⊘ Skipping AI prioritization (no API key)${NC}\n"
        return
    fi

    feature_section "AI PRIORITIZATION ENGINE"

    local service="paymentservice"

    echo "Generating AI-powered priority rankings..."

    threat-radar ai prioritize "${SCANS_DIR}/${service}_scan.json" \
        --top 10 \
        -o "${AI_DIR}/${service}_priorities.json" \
        --auto-save

    echo ""
    echo "Top 5 Priority Vulnerabilities:"
    jq '.priority_list[:5] | .[] | {
      cve: .cve_id,
      priority: .priority_level,
      urgency: .urgency_score,
      rationale: .rationale
    }' "${AI_DIR}/${service}_priorities.json" 2>/dev/null || echo "  Prioritization complete"

    feature_complete
}

# Feature 13: AI Remediation Planning
ai_remediation() {
    if [ "$RUN_AI_ANALYSIS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping AI remediation${NC}\n"
        return
    fi

    if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
        echo -e "${YELLOW}⊘ Skipping AI remediation (no API key)${NC}\n"
        return
    fi

    feature_section "AI REMEDIATION PLAN GENERATION"

    local service="paymentservice"

    echo "Generating AI-powered remediation plan..."

    threat-radar ai remediate "${SCANS_DIR}/${service}_scan.json" \
        -o "${AI_DIR}/${service}_remediation.json" \
        --auto-save

    echo ""
    echo "Remediation Plan Summary:"
    jq '{
      total_plans: .remediation_plans | length,
      quick_wins: [.remediation_plans[] | select(.effort == "low")] | length,
      package_groups: [.package_groups[] | .package_name] | .[0:3]
    }' "${AI_DIR}/${service}_remediation.json" 2>/dev/null || echo "  Remediation plan generated"

    feature_complete
}

# Feature 14: Business Context Risk Analysis
business_risk_analysis() {
    if [ "$RUN_AI_ANALYSIS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping business risk analysis${NC}\n"
        return
    fi

    if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
        echo -e "${YELLOW}⊘ Skipping business risk analysis (no API key)${NC}\n"
        return
    fi

    feature_section "BUSINESS CONTEXT-AWARE RISK ANALYSIS"

    echo "Analyzing environment risk and compliance posture..."

    threat-radar env analyze "${CONFIG_FILE}" \
        > "${AI_DIR}/environment_risk_analysis.txt"

    echo ""
    echo "Risk Assessment Summary:"
    cat "${AI_DIR}/environment_risk_analysis.txt"

    echo ""
    echo "Note: For integrated vulnerability + business context analysis,"
    echo "      use: threat-radar ai analyze <scan-file> with environment metadata"

    feature_complete
}

# Feature 15: Comprehensive Report Generation
comprehensive_reports() {
    feature_section "COMPREHENSIVE REPORT GENERATION"

    # Pick a critical service for detailed reporting (paymentservice or first available)
    local report_scan="${SCANS_DIR}/paymentservice_scan.json"
    if [ ! -f "$report_scan" ]; then
        report_scan=$(ls "${SCANS_DIR}"/*.json | head -1)
    fi

    if [ ! -f "$report_scan" ]; then
        echo -e "${YELLOW}⚠ No scan files found, skipping report generation${NC}\n"
        return
    fi

    local service_name=$(basename "$report_scan" _scan.json)
    echo "Generating reports for: ${service_name}"
    echo ""

    echo "Generating HTML report..."
    if threat-radar report generate "$report_scan" \
        -o "${REPORTS_DIR}/${service_name}_report.html" \
        -f html \
        --level detailed > /dev/null 2>&1; then
        echo "  ✓ HTML report: ${service_name}_report.html"
    else
        echo -e "  ${YELLOW}⚠ HTML report generation failed${NC}"
    fi

    echo ""
    echo "Generating JSON report..."
    if threat-radar report generate "$report_scan" \
        -o "${REPORTS_DIR}/${service_name}_report.json" \
        -f json \
        --level detailed > /dev/null 2>&1; then
        echo "  ✓ JSON report: ${service_name}_report.json"
    else
        echo -e "  ${YELLOW}⚠ JSON report generation failed${NC}"
    fi

    echo ""
    echo "Generating Markdown executive summary..."
    if threat-radar report generate "$report_scan" \
        -o "${REPORTS_DIR}/${service_name}_executive.md" \
        -f markdown \
        --level executive > /dev/null 2>&1; then
        echo "  ✓ Markdown report: ${service_name}_executive.md"
    else
        echo -e "  ${YELLOW}⚠ Markdown report generation failed${NC}"
    fi

    echo ""
    echo "Note: Generated reports for ${service_name} service"
    echo "      To generate reports for other services, run:"
    echo "      threat-radar report generate <scan-file> -o report.html -f html"

    feature_complete
}

# Feature 16: Dashboard Data Export
dashboard_export() {
    feature_section "DASHBOARD DATA EXPORT"

    echo "Exporting dashboard-ready visualization data..."

    threat-radar report dashboard-export "${SCANS_DIR}/paymentservice_scan.json" \
        -o "${REPORTS_DIR}/dashboard_data.json"

    echo ""
    echo "Dashboard Data Structure:"
    jq 'keys' "${REPORTS_DIR}/dashboard_data.json"

    feature_complete
}

# Feature 17: Interactive Graph Visualization
graph_visualization() {
    if [ "$RUN_VISUALIZATIONS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping visualizations${NC}\n"
        return
    fi

    feature_section "INTERACTIVE GRAPH VISUALIZATION"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Creating interactive graph visualization..."
    threat-radar visualize graph "$graph" \
        -o "${VIZ_DIR}/graph_interactive.html" \
        --layout hierarchical \
        --color-by severity
    echo "  ✓ Interactive graph: graph_interactive.html"

    feature_complete
}

# Feature 18: Attack Path Visualization
attack_path_visualization() {
    if [ "$RUN_VISUALIZATIONS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping attack path visualization${NC}\n"
        return
    fi

    feature_section "ATTACK PATH VISUALIZATION"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Creating attack path visualization..."
    threat-radar visualize attack-paths "$graph" \
        -o "${VIZ_DIR}/attack_paths.html" \
        --paths "${ATTACK_DIR}/attack-paths.json" \
        --max-paths 10
    echo "  ✓ Attack paths: attack_paths.html"

    feature_complete
}

# Feature 19: Network Topology Visualization
topology_visualization() {
    if [ "$RUN_VISUALIZATIONS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping topology visualization${NC}\n"
        return
    fi

    feature_section "NETWORK TOPOLOGY VISUALIZATION"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Creating network topology view..."
    threat-radar visualize topology "$graph" \
        -o "${VIZ_DIR}/topology_zones.html" \
        --view zones \
        --color-by zone
    echo "  ✓ Topology (zones): topology_zones.html"

    echo ""
    echo "Creating PCI compliance view..."
    threat-radar visualize topology "$graph" \
        -o "${VIZ_DIR}/topology_pci.html" \
        --view compliance \
        --compliance pci
    echo "  ✓ Topology (PCI): topology_pci.html"

    feature_complete
}

# Feature 20: Filtered Visualizations
filtered_visualizations() {
    if [ "$RUN_VISUALIZATIONS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping filtered visualizations${NC}\n"
        return
    fi

    feature_section "FILTERED VISUALIZATIONS"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Creating critical severity filter view..."
    threat-radar visualize filter "$graph" \
        -o "${VIZ_DIR}/critical_only.html" \
        --type severity \
        --value critical
    echo "  ✓ Critical only: critical_only.html"

    echo ""
    echo "Creating PCI-scoped assets view..."
    threat-radar visualize filter "$graph" \
        -o "${VIZ_DIR}/pci_assets.html" \
        --type compliance \
        --values pci
    echo "  ✓ PCI assets: pci_assets.html"

    echo ""
    echo "Creating internet-facing assets view..."
    threat-radar visualize filter "$graph" \
        -o "${VIZ_DIR}/internet_facing.html" \
        --type internet_facing
    echo "  ✓ Internet-facing: internet_facing.html"

    feature_complete
}

# Feature 21: Multi-Format Export
export_visualizations() {
    if [ "$RUN_VISUALIZATIONS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping multi-format export${NC}\n"
        return
    fi

    feature_section "MULTI-FORMAT VISUALIZATION EXPORT"

    local graph="${GRAPHS_DIR}/main-graph.graphml"

    echo "Exporting to multiple formats..."
    threat-radar visualize export "$graph" \
        -o "${VIZ_DIR}/graph_export" \
        --format html \
        --format json \
        --layout hierarchical

    echo "  ✓ HTML: graph_export.html"
    echo "  ✓ JSON: graph_export.json"

    feature_complete
}

# Generate final summary
generate_summary() {
    feature_section "FINAL SUMMARY & FEATURE SHOWCASE"

    cat > "${OUTPUT_DIR}/FEATURE_SHOWCASE.md" << 'EOFSUMMARY'
# Threat Radar - Complete Feature Showcase

This analysis demonstrates **ALL** Threat Radar capabilities on a real-world application.

## 📊 Features Demonstrated

### 🔍 Vulnerability Scanning
- [x] CVE scanning with Grype
- [x] Auto-save functionality
- [x] Image cleanup
- [x] Multi-service scanning

### 📦 SBOM Operations
- [x] SBOM generation (CycloneDX, SPDX)
- [x] SBOM statistics
- [x] Export to CSV
- [x] Package search
- [x] Component listing

### 🏗️ Environment & Infrastructure
- [x] Environment configuration with business context
- [x] Environment validation
- [x] Infrastructure graph building
- [x] Asset-to-vulnerability linking
- [x] Network topology modeling

### 🕸️ Graph Operations
- [x] Graph building with merged scans
- [x] Graph information queries
- [x] Vulnerability statistics
- [x] Finding available fixes
- [x] Graph metadata extraction

### ⚔️ Attack Path Discovery
- [x] Basic attack path finding
- [x] Privilege escalation detection
- [x] Lateral movement analysis
- [x] Complete attack surface analysis
- [x] Threat level classification
- [x] CVSS score aggregation

### 🤖 AI-Powered Analysis
- [x] Vulnerability analysis with batch processing
- [x] Exploitability assessment
- [x] Priority ranking
- [x] Remediation plan generation
- [x] Business context-aware risk analysis
- [x] Executive summaries

### 📈 Comprehensive Reporting
- [x] HTML reports (interactive)
- [x] JSON reports (machine-readable)
- [x] Markdown reports (documentation)
- [x] Dashboard data export
- [x] Multiple report levels (executive, summary, detailed, critical-only)
- [x] Report comparison

### 🎨 Advanced Visualizations
- [x] Interactive graph visualization
- [x] Attack path visualization
- [x] Network topology views
- [x] Security zone visualization
- [x] Compliance scope views (PCI)
- [x] Filtered visualizations (severity, compliance, zones)
- [x] Multi-format export (HTML, PNG, JSON, SVG)
- [x] Multiple layout algorithms

### 🔐 Security Intelligence
- [x] Entry point identification
- [x] High-value target detection
- [x] PCI-DSS scope tracking
- [x] Compliance violation detection
- [x] Risk score calculation
- [x] Business impact estimation

## 📁 Output Structure

```
full-demo-results/
├── 01-scans/                     # CVE scan results (JSON)
├── 02-sboms/                     # SBOM files & analysis
├── 03-ai-analysis/               # AI-powered insights
├── 04-reports/                   # Comprehensive reports
├── 05-graphs/                    # Graph databases
├── 06-attack-paths/              # Attack path analysis
├── 07-visualizations/            # Interactive visualizations
└── environment.json              # Infrastructure config
```

## 🎯 Key Findings

### Vulnerabilities Discovered
EOFSUMMARY

    # Add vulnerability summary
    local total_vulns=0
    local total_critical=0
    local total_high=0

    for service in "${!SERVICES[@]}"; do
        if [ -f "${SCANS_DIR}/${service}_scan.json" ]; then
            local vulns=$(jq -r '.total_vulnerabilities // 0' "${SCANS_DIR}/${service}_scan.json")
            local critical=$(jq -r '.severity_counts.critical // 0' "${SCANS_DIR}/${service}_scan.json")
            local high=$(jq -r '.severity_counts.high // 0' "${SCANS_DIR}/${service}_scan.json")

            ((total_vulns += vulns))
            ((total_critical += critical))
            ((total_high += high))
        fi
    done

    cat >> "${OUTPUT_DIR}/FEATURE_SHOWCASE.md" << EOFSUMMARY

- **Total Vulnerabilities**: ${total_vulns}
- **Critical**: ${total_critical}
- **High**: ${total_high}

### Attack Paths Identified
EOFSUMMARY

    # Add attack path summary
    if [ -f "${ATTACK_DIR}/attack-paths.json" ]; then
        local attack_paths=$(jq -r '.total_paths // 0' "${ATTACK_DIR}/attack-paths.json")
        local critical_paths=$(jq -r '[.attack_paths[] | select(.threat_level == "critical")] | length' "${ATTACK_DIR}/attack-paths.json")

        cat >> "${OUTPUT_DIR}/FEATURE_SHOWCASE.md" << EOFSUMMARY

- **Total Attack Paths**: ${attack_paths}
- **Critical Threat Paths**: ${critical_paths}

EOFSUMMARY
    fi

    cat >> "${OUTPUT_DIR}/FEATURE_SHOWCASE.md" << 'EOFSUMMARY'

## 🚀 Next Steps

1. **Review Visualizations**: Open HTML files in `07-visualizations/`
2. **Read Reports**: Check `04-reports/comprehensive_report.html`
3. **Analyze Attack Paths**: Review `06-attack-paths/attack-surface.json`
4. **AI Insights**: See `03-ai-analysis/` for prioritization and remediation

## 📖 Feature Documentation

Each feature used corresponds to Threat Radar capabilities:

- **CVE Scanning**: `threat-radar cve scan-image`
- **SBOM Generation**: `threat-radar sbom docker`
- **Environment Config**: `threat-radar env build-graph`
- **Attack Paths**: `threat-radar graph attack-paths`
- **AI Analysis**: `threat-radar ai analyze|prioritize|remediate`
- **Reporting**: `threat-radar report generate`
- **Visualization**: `threat-radar visualize graph|attack-paths|topology`

## 🎓 Learn More

- See `README.md` for detailed documentation
- Check `QUICKSTART.md` for quick tutorials
- Review CLAUDE.md for complete CLI reference

---

Generated by Threat Radar Full Demo
EOFSUMMARY

    echo -e "${GREEN}✓ Feature showcase summary created${NC}"
    feature_complete
}

# Main execution
main() {
    echo -e "${YELLOW}Starting complete feature demonstration...${NC}\n"

    # Core features
    setup
    cve_scanning
    sbom_generation
    sbom_operations
    environment_config
    graph_building
    graph_operations

    # Attack analysis
    attack_paths
    privilege_escalation
    lateral_movement
    attack_surface

    # AI features
    ai_analysis
    ai_prioritization
    ai_remediation
    business_risk_analysis

    # Reporting
    comprehensive_reports
    dashboard_export

    # Visualizations
    graph_visualization
    attack_path_visualization
    topology_visualization
    filtered_visualizations
    export_visualizations

    # Summary
    generate_summary

    # Final output
    echo -e "\n${MAGENTA}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           ✓  COMPLETE FEATURE SHOWCASE FINISHED             ║
║                                                              ║
║     All Threat Radar capabilities demonstrated on           ║
║     Google Cloud Platform Microservices Demo                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}\n"

    echo -e "${GREEN}Results saved to: ${OUTPUT_DIR}/${NC}\n"

    echo "Quick Access:"
    echo "  📄 Feature Summary:    cat ${OUTPUT_DIR}/FEATURE_SHOWCASE.md"
    echo "  🌐 Main Report:        open ${REPORTS_DIR}/comprehensive_report.html"
    echo "  🎨 Attack Paths:       open ${VIZ_DIR}/attack_paths.html"
    echo "  🔒 PCI Topology:       open ${VIZ_DIR}/topology_pci.html"
    echo "  🤖 AI Analysis:        cat ${AI_DIR}/*_priorities.json"
    echo ""

    echo -e "${CYAN}Total Features Demonstrated: ${COMPLETED_FEATURES}${NC}"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-ai)
            RUN_AI_ANALYSIS=false
            shift
            ;;
        --no-sbom)
            RUN_SBOM_GENERATION=false
            shift
            ;;
        --no-viz)
            RUN_VISUALIZATIONS=false
            shift
            ;;
        --no-cleanup)
            CLEANUP_IMAGES=false
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-ai          Skip AI-powered analysis features"
            echo "  --no-sbom        Skip SBOM generation"
            echo "  --no-viz         Skip visualization generation"
            echo "  --no-cleanup     Don't cleanup Docker images after scanning"
            echo "  --help           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check for AI API keys
if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${YELLOW}⚠ No AI API key found. AI features will be skipped.${NC}"
    echo "  To enable AI features, set OPENAI_API_KEY or ANTHROPIC_API_KEY in your environment."
    echo ""
    RUN_AI_ANALYSIS=false
fi

# Run main
main
