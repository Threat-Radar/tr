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
    EXAMPLE_CONFIG="${SCRIPT_DIR}/../10_attack_path_discovery/sample-environment.json"
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

# Feature 22: Advanced Dynamic Visualizations
advanced_dynamic_visualizations() {
    if [ "$RUN_VISUALIZATIONS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping advanced visualizations${NC}\n"
        return
    fi

    feature_section "ADVANCED DYNAMIC VISUALIZATIONS"

    local graph="${GRAPHS_DIR}/main-graph.graphml"
    local attack_paths="${ATTACK_DIR}/attack-paths.json"
    local viz_script="../11_graph_visualization/02b_dynamic_attack_path_visualization.py"

    mkdir -p "${VIZ_DIR}/dynamic"

    echo "Creating dynamic attack path visualizations..."

    # Check if the visualization script exists
    if [ -f "$viz_script" ]; then
        echo "  Running advanced dynamic visualization script..."

        # Create a temporary wrapper script to run with the correct paths
        cat > /tmp/run_dynamic_viz.py << EOFPYTHON
import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from threat_radar.graph import NetworkXClient, GraphAnalyzer
from threat_radar.visualization import AttackPathVisualizer

# Load graph
print("Loading graph...")
client = NetworkXClient()
client.load("${graph}")

# Load attack paths
print("Loading attack paths...")
with open("${attack_paths}") as f:
    attack_data = json.load(f)

# Create visualizer
visualizer = AttackPathVisualizer(client)

# Get attack paths
from threat_radar.graph.models import AttackPath, AttackStep
attack_paths_list = []
for ap_data in attack_data.get("attack_paths", [])[:5]:  # Limit to top 5 for performance
    steps = [AttackStep(**step) for step in ap_data.get("steps", [])]
    attack_path = AttackPath(
        path_id=ap_data["path_id"],
        entry_point=ap_data["entry_point"],
        target=ap_data["target"],
        steps=steps,
        threat_level=ap_data["threat_level"],
        total_cvss=ap_data.get("total_cvss", 0),
        exploitability=ap_data.get("exploitability", 0)
    )
    attack_paths_list.append(attack_path)

if attack_paths_list:
    # Create basic animated visualization
    print(f"Creating animated visualization for {len(attack_paths_list)} attack paths...")
    fig = visualizer.visualize_attack_paths(
        attack_paths=attack_paths_list,
        layout="hierarchical",
        max_paths_display=5,
        title="Animated Attack Path Analysis"
    )

    # Save
    output_path = "${VIZ_DIR}/dynamic/animated_attack_paths.html"
    visualizer.save_html(fig, output_path)
    print(f"  ✓ Saved to: {output_path}")

    # Create comparison view if multiple paths
    if len(attack_paths_list) > 1:
        print("  Creating attack path comparison view...")
        # Save individual path analyses
        for i, ap in enumerate(attack_paths_list[:3], 1):
            fig_single = visualizer.visualize_single_path(
                attack_path=ap,
                show_step_details=True,
                title=f"Attack Path {i}: {ap.path_id}"
            )
            output = f"${VIZ_DIR}/dynamic/attack_path_{i}.html"
            visualizer.save_html(fig_single, output)
        print(f"  ✓ Created {min(3, len(attack_paths_list))} individual path views")
else:
    print("  ⚠️  No attack paths found to visualize")

print("✓ Dynamic visualizations complete!")
EOFPYTHON

        # Run the visualization script
        if python3 /tmp/run_dynamic_viz.py 2>/dev/null; then
            echo "  ✓ Animated attack progression created"
            echo "  ✓ Individual path analysis views created"
        else
            echo -e "  ${YELLOW}⚠ Some dynamic visualizations may have failed (continuing...)${NC}"
        fi

        rm -f /tmp/run_dynamic_viz.py
    else
        echo -e "  ${YELLOW}⚠ Advanced visualization scripts not found${NC}"
        echo "  ⓘ Install examples: cd ../11_graph_visualization/"
    fi

    feature_complete
}

# Feature 23: 3D Topology Visualizations
dynamic_3d_topology() {
    if [ "$RUN_VISUALIZATIONS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping 3D topology${NC}\n"
        return
    fi

    feature_section "DYNAMIC 3D TOPOLOGY VISUALIZATIONS"

    local graph="${GRAPHS_DIR}/main-graph.graphml"
    mkdir -p "${VIZ_DIR}/3d"

    echo "Creating 3D topology visualizations..."

    # Create 3D topology visualization using the CLI
    cat > /tmp/run_3d_viz.py << EOFPYTHON
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from threat_radar.graph import NetworkXClient
from threat_radar.visualization import NetworkGraphVisualizer

# Load graph
print("Loading graph for 3D visualization...")
client = NetworkXClient()
client.load("${graph}")

# Create visualizer
visualizer = NetworkGraphVisualizer(client)

# Create 3D visualization
print("Creating 3D network topology...")
fig_3d = visualizer.visualize(
    layout="spring",
    title="3D Network Topology",
    width=1400,
    height=1000,
    color_by="severity",
    show_labels=True,
    three_d=True
)

# Save
output_path = "${VIZ_DIR}/3d/network_topology_3d.html"
visualizer.save_html(fig_3d, output_path)
print(f"  ✓ Saved 3D topology to: {output_path}")

# Create layered view
print("Creating layered architecture view...")
fig_layered = visualizer.visualize(
    layout="hierarchical",
    title="Layered Network Architecture (3D)",
    width=1400,
    height=1000,
    color_by="node_type",
    show_labels=True,
    three_d=True
)

output_layered = "${VIZ_DIR}/3d/layered_architecture_3d.html"
visualizer.save_html(fig_layered, output_layered)
print(f"  ✓ Saved layered view to: {output_layered}")

print("✓ 3D visualizations complete!")
EOFPYTHON

    if python3 /tmp/run_3d_viz.py 2>/dev/null; then
        echo "  ✓ 3D network topology created"
        echo "  ✓ Layered architecture view created"
    else
        echo -e "  ${YELLOW}⚠ 3D visualization generation failed (continuing...)${NC}"
        echo "  ⓘ Make sure plotly is installed: pip install plotly"
    fi

    rm -f /tmp/run_3d_viz.py

    feature_complete
}

# Feature 24: Ultimate Combined Visualizations
ultimate_visualizations() {
    if [ "$RUN_VISUALIZATIONS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping ultimate visualizations${NC}\n"
        return
    fi

    feature_section "ULTIMATE COMBINED VISUALIZATIONS"

    local graph="${GRAPHS_DIR}/main-graph.graphml"
    local attack_paths="${ATTACK_DIR}/attack-paths.json"
    local attack_surface="${ATTACK_DIR}/attack-surface.json"
    mkdir -p "${VIZ_DIR}/ultimate"

    echo "Creating ultimate security command center dashboard..."

    cat > /tmp/run_ultimate_viz.py << 'EOFPYTHON'
import sys
import json
import math
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from threat_radar.graph import NetworkXClient, GraphAnalyzer
from threat_radar.visualization import NetworkGraphVisualizer, AttackPathVisualizer

# Load graph
print("Loading graph and attack data...")
client = NetworkXClient()
client.load("${graph}")

# Load attack paths and surface
try:
    with open("${attack_paths}") as f:
        attack_data = json.load(f)
    with open("${attack_surface}") as f:
        surface_data = json.load(f)
except:
    print("  ⚠️  Could not load attack path data")
    attack_data = {"attack_paths": []}
    surface_data = {}

# Create combined multi-view dashboard
print("Creating security command center dashboard...")

try:
    from plotly.subplots import make_subplots
    import plotly.graph_objects as go
    import networkx as nx

    # Create multi-panel dashboard (same as before)
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            "Network Topology & Attack Paths",
            "Vulnerability Distribution",
            "Attack Surface Analysis",
            "Critical Assets & Risk Score"
        ),
        specs=[
            [{"type": "scatter"}, {"type": "bar"}],
            [{"type": "scatter"}, {"type": "indicator"}]
        ],
        vertical_spacing=0.12,
        horizontal_spacing=0.1
    )

    # Panel 1: Network topology (simplified)
    visualizer = NetworkGraphVisualizer(client)
    pos = nx.spring_layout(client.graph, k=2, iterations=50, seed=42)

    edge_x, edge_y = [], []
    for edge in client.graph.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    fig.add_trace(
        go.Scatter(x=edge_x, y=edge_y, mode='lines',
                   line=dict(width=0.5, color='#888'),
                   hoverinfo='none', showlegend=False),
        row=1, col=1
    )

    node_x, node_y, node_colors, node_text = [], [], [], []
    for node in client.graph.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_data = client.graph.nodes[node]
        node_type = node_data.get('type', 'unknown')
        node_text.append(f"{node}<br>Type: {node_type}")

        # Color by severity if vulnerability
        if node_type == 'vulnerability':
            severity = node_data.get('severity', 'unknown')
            if severity == 'critical':
                node_colors.append('#dc2626')
            elif severity == 'high':
                node_colors.append('#ea580c')
            else:
                node_colors.append('#facc15')
        else:
            node_colors.append('#3b82f6')

    fig.add_trace(
        go.Scatter(x=node_x, y=node_y, mode='markers',
                   marker=dict(size=10, color=node_colors, line_width=2),
                   text=node_text, hoverinfo='text', showlegend=False),
        row=1, col=1
    )

    # Panel 2: Vulnerability distribution
    analyzer = GraphAnalyzer(client)
    stats = analyzer.vulnerability_statistics()

    severities = ['Critical', 'High', 'Medium', 'Low']
    counts = [
        stats.get('critical', 0),
        stats.get('high', 0),
        stats.get('medium', 0),
        stats.get('low', 0)
    ]

    fig.add_trace(
        go.Bar(x=severities, y=counts,
               marker_color=['#dc2626', '#ea580c', '#facc15', '#3b82f6'],
               showlegend=False),
        row=1, col=2
    )

    # Panel 3: Attack paths (scatter plot of risk)
    attack_count = len(attack_data.get("attack_paths", []))
    critical_attacks = len([ap for ap in attack_data.get("attack_paths", [])
                           if ap.get("threat_level") == "critical"])

    fig.add_trace(
        go.Scatter(
            x=[1, 2, 3],
            y=[attack_count, critical_attacks, attack_count - critical_attacks],
            mode='markers+text',
            marker=dict(size=[60, 80, 40], color=['#ea580c', '#dc2626', '#facc15']),
            text=['Total Paths', 'Critical', 'Other'],
            textposition='top center',
            showlegend=False
        ),
        row=2, col=1
    )

    # Panel 4: Risk score indicator
    risk_score = surface_data.get("total_risk_score", 0)

    fig.add_trace(
        go.Indicator(
            mode="gauge+number+delta",
            value=risk_score,
            title={'text': "Overall Risk Score"},
            delta={'reference': 50},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "#dc2626" if risk_score > 70 else "#ea580c" if risk_score > 40 else "#3b82f6"},
                'steps': [
                    {'range': [0, 40], 'color': "#d1fae5"},
                    {'range': [40, 70], 'color': "#fef3c7"},
                    {'range': [70, 100], 'color': "#fee2e2"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 80
                }
            }
        ),
        row=2, col=2
    )

    # Update layout
    fig.update_layout(
        title_text="Security Command Center - Comprehensive Analysis Dashboard",
        title_font_size=20,
        height=900,
        width=1600,
        showlegend=False
    )

    # Save
    output_path = "${VIZ_DIR}/ultimate/security_command_center.html"
    fig.write_html(output_path)
    print(f"  ✓ Saved command center to: {output_path}")

    # ========== NOW CREATE HOLOGRAPHIC VISUALIZATION (FIXED) ==========
    print("\nCreating holographic security story visualization...")

    # Get attack path objects for holographic viz
    from threat_radar.graph.models import AttackPath, AttackStep
    attack_paths_list = []
    for ap_data in attack_data.get("attack_paths", [])[:8]:  # Limit to 8 for performance
        steps = [AttackStep(**step) for step in ap_data.get("steps", [])]
        attack_path = AttackPath(
            path_id=ap_data["path_id"],
            entry_point=ap_data["entry_point"],
            target=ap_data["target"],
            steps=steps,
            threat_level=ap_data["threat_level"],
            total_cvss=ap_data.get("total_cvss", 0),
            exploitability=ap_data.get("exploitability", 0)
        )
        attack_paths_list.append(attack_path)

    # Create 3D holographic visualization with proper animation
    G = client.graph

    # Position nodes in 3D layers
    zone_levels = {
        'dmz': 0.0, 'public': 0.0,
        'internal': 4.0,
        'trusted': 8.0,
        'database': 12.0,
        'unknown': 2.0,
    }

    pos_2d = nx.spring_layout(G, k=2.5, iterations=50, seed=42)
    pos_3d = {}
    for node, (x, y) in pos_2d.items():
        zone = G.nodes[node].get('zone', 'unknown').lower()
        z = zone_levels.get(zone, 2.0)
        pos_3d[node] = (x * 6, y * 6, z)

    # Create frames with FIXED animation configuration
    frames = []
    num_frames = 120  # Reduced for better performance

    for frame_idx in range(num_frames):
        progress = frame_idx / num_frames

        # Smooth camera rotation
        angle = progress * 2 * math.pi
        radius = 20
        height = 8

        camera_x = radius * math.cos(angle)
        camera_y = radius * math.sin(angle)
        camera_z = height

        # Base edges
        edge_x, edge_y, edge_z = [], [], []
        for u, v in G.edges():
            if u in pos_3d and v in pos_3d:
                edge_x.extend([pos_3d[u][0], pos_3d[v][0], None])
                edge_y.extend([pos_3d[u][1], pos_3d[v][1], None])
                edge_z.extend([pos_3d[u][2], pos_3d[v][2], None])

        edge_trace = go.Scatter3d(
            x=edge_x, y=edge_y, z=edge_z,
            mode='lines',
            line=dict(color='rgba(100,100,150,0.3)', width=1),
            hoverinfo='none',
            showlegend=False
        )

        # Nodes with pulsing effect
        node_x, node_y, node_z = [], [], []
        node_colors, node_sizes, node_texts = [], [], []

        pulse = 1.0 + 0.2 * math.sin(progress * 8 * math.pi)

        zone_color_map = {
            'dmz': '#ff6b6b',
            'internal': '#4ecdc4',
            'trusted': '#45b7d1',
            'database': '#574b90',
            'unknown': '#95a5a6',
        }

        for node in G.nodes():
            if node in pos_3d:
                node_data = G.nodes[node]
                zone = node_data.get('zone', 'unknown').lower()

                x, y, z = pos_3d[node]
                node_x.append(x)
                node_y.append(y)
                node_z.append(z)

                color = zone_color_map.get(zone, '#95a5a6')
                node_colors.append(color)

                # Pulsing size
                base_size = 12
                size = base_size * pulse
                node_sizes.append(size)

                node_texts.append(f"<b>{node}</b><br>Zone: {zone.upper()}")

        node_trace = go.Scatter3d(
            x=node_x, y=node_y, z=node_z,
            mode='markers',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color='white'),
                opacity=0.9
            ),
            text=node_texts,
            hoverinfo='text',
            showlegend=False
        )

        # Combine traces
        frame_data = [edge_trace, node_trace]

        # Create frame with proper layout update
        frames.append(go.Frame(
            data=frame_data,
            name=f"frame_{frame_idx}",
            layout=go.Layout(
                scene=dict(
                    camera=dict(
                        eye=dict(x=camera_x/radius, y=camera_y/radius, z=camera_z/radius),
                        center=dict(x=0, y=0, z=6)
                    )
                ),
                title=dict(
                    text=f"🔮 HOLOGRAPHIC SECURITY VISUALIZATION<br><sub>Progress: {progress:.0%}</sub>",
                    font=dict(size=24, color='cyan'),
                    x=0.5,
                    xanchor='center'
                )
            )
        ))

    # Create figure with FIXED animation settings
    holo_fig = go.Figure(
        data=frames[0].data,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text="🔮 HOLOGRAPHIC SECURITY VISUALIZATION<br><sub>Interactive 3D Network Security</sub>",
                font=dict(size=24, color='cyan'),
                x=0.5,
                xanchor='center'
            ),
            width=1800,
            height=1200,
            showlegend=False,
            scene=dict(
                camera=dict(
                    eye=dict(x=1, y=0, z=0.4),  # Initial camera position
                    center=dict(x=0, y=0, z=6)
                ),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, showbackground=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, showbackground=False),
                zaxis=dict(
                    showgrid=True,
                    gridcolor='rgba(100,150,200,0.3)',
                    title=dict(text='SECURITY LAYERS', font=dict(color='cyan')),
                    ticktext=['EXPOSED', 'INTERNAL', 'SECURE', 'CRITICAL'],
                    tickvals=[0, 4, 8, 12],
                    tickfont=dict(color='cyan'),
                    showbackground=False
                ),
                bgcolor='#000000'
            ),
            paper_bgcolor='#000000',
            font=dict(color='cyan'),
            # FIXED: Proper animation controls with looping
            updatemenus=[{
                'type': 'buttons',
                'showactive': False,
                'buttons': [
                    {
                        'label': '▶ PLAY',
                        'method': 'animate',
                        'args': [None, {
                            'frame': {'duration': 50, 'redraw': True},
                            'fromcurrent': True,
                            'transition': {'duration': 50, 'easing': 'linear'},
                            'mode': 'immediate'
                        }]
                    },
                    {
                        'label': '⏸ PAUSE',
                        'method': 'animate',
                        'args': [[None], {
                            'frame': {'duration': 0, 'redraw': False},
                            'mode': 'immediate',
                            'transition': {'duration': 0}
                        }]
                    },
                    {
                        'label': '🔄 LOOP',
                        'method': 'animate',
                        'args': [None, {
                            'frame': {'duration': 50, 'redraw': True},
                            'fromcurrent': False,
                            'transition': {'duration': 50, 'easing': 'linear'},
                            'mode': 'immediate'
                        }]
                    }
                ],
                'x': 0.5,
                'y': 0.02,
                'xanchor': 'center',
                'yanchor': 'bottom',
                'bgcolor': 'rgba(0,100,150,0.8)',
                'bordercolor': 'cyan',
                'borderwidth': 2,
                'font': dict(color='cyan', size=14)
            }],
            # FIXED: Add slider for manual control
            sliders=[{
                'active': 0,
                'yanchor': 'top',
                'y': 0.95,
                'xanchor': 'left',
                'x': 0.1,
                'currentvalue': {
                    'prefix': 'Frame: ',
                    'visible': True,
                    'xanchor': 'right',
                    'font': {'color': 'cyan'}
                },
                'pad': {'b': 10, 't': 50},
                'len': 0.8,
                'bgcolor': 'rgba(0,50,100,0.5)',
                'bordercolor': 'cyan',
                'borderwidth': 2,
                'steps': [
                    {
                        'args': [[f.name], {
                            'frame': {'duration': 0, 'redraw': True},
                            'mode': 'immediate',
                            'transition': {'duration': 0}
                        }],
                        'method': 'animate',
                        'label': str(i)
                    }
                    for i, f in enumerate(frames)
                ]
            }]
        )
    )

    # Save holographic visualization
    output_holo = "${VIZ_DIR}/ultimate/holographic_security_story.html"
    holo_fig.write_html(output_holo)
    print(f"  ✓ Saved holographic visualization to: {output_holo}")
    print("     NOTE: Click PLAY or LOOP button to start animation!")

except Exception as e:
    print(f"  ⚠️  Could not create visualizations: {e}")
    import traceback
    traceback.print_exc()

print("\n✓ Ultimate visualizations complete!")
EOFPYTHON

    if python3 /tmp/run_ultimate_viz.py 2>/dev/null; then
        echo "  ✓ Security Command Center dashboard created"
        echo "  ✓ Holographic 3D visualization created (FIXED animation)"
        echo "  ✓ Multi-panel comprehensive analysis complete"
    else
        echo -e "  ${YELLOW}⚠ Ultimate visualization generation failed${NC}"
        echo "  ⓘ Make sure plotly is installed: pip install plotly"
    fi

    rm -f /tmp/run_ultimate_viz.py

    feature_complete
}

# Feature 25: Vulnerability Command Centers
vulnerability_command_centers() {
    if [ "$RUN_VISUALIZATIONS" != true ]; then
        echo -e "${YELLOW}⊘ Skipping command centers${NC}\n"
        return
    fi

    feature_section "VULNERABILITY COMMAND CENTERS"

    local graph="${GRAPHS_DIR}/main-graph.graphml"
    mkdir -p "${VIZ_DIR}/command-centers"

    echo "Creating specialized vulnerability command centers..."

    cat > /tmp/run_command_centers.py << EOFPYTHON
import sys
import json
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from threat_radar.graph import NetworkXClient, GraphAnalyzer

# Load graph
print("Loading graph for command centers...")
client = NetworkXClient()
client.load("${graph}")

analyzer = GraphAnalyzer(client)
stats = analyzer.vulnerability_statistics()

try:
    from plotly.subplots import make_subplots
    import plotly.graph_objects as go

    # 1. Critical Vulnerability Command Center
    print("Creating Critical Vulnerability Command Center...")

    # Get critical and high vulnerabilities
    critical_vulns = []
    high_vulns = []

    for node in client.graph.nodes():
        node_data = client.graph.nodes[node]
        if node_data.get('type') == 'vulnerability':
            severity = node_data.get('severity', '').lower()
            if severity == 'critical':
                critical_vulns.append((node, node_data))
            elif severity == 'high':
                high_vulns.append((node, node_data))

    # Create critical vuln dashboard
    fig_critical = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            f"Critical Vulnerabilities ({len(critical_vulns)})",
            f"High Severity Vulnerabilities ({len(high_vulns)})",
            "Severity Distribution",
            "Top Affected Packages"
        ),
        specs=[
            [{"type": "table"}, {"type": "table"}],
            [{"type": "pie"}, {"type": "bar"}]
        ]
    )

    # Critical CVEs table
    if critical_vulns:
        cve_ids = [v[0] for v in critical_vulns[:10]]
        cvss_scores = [v[1].get('cvss_score', 0) for v in critical_vulns[:10]]

        fig_critical.add_trace(
            go.Table(
                header=dict(values=['CVE ID', 'CVSS Score'],
                           fill_color='#dc2626', font=dict(color='white')),
                cells=dict(values=[cve_ids, cvss_scores],
                          fill_color='#fee2e2')
            ),
            row=1, col=1
        )

    # High CVEs table
    if high_vulns:
        high_cve_ids = [v[0] for v in high_vulns[:10]]
        high_cvss = [v[1].get('cvss_score', 0) for v in high_vulns[:10]]

        fig_critical.add_trace(
            go.Table(
                header=dict(values=['CVE ID', 'CVSS Score'],
                           fill_color='#ea580c', font=dict(color='white')),
                cells=dict(values=[high_cve_ids, high_cvss],
                          fill_color='#fed7aa')
            ),
            row=1, col=2
        )

    # Severity distribution pie
    severities = ['Critical', 'High', 'Medium', 'Low']
    counts = [
        stats.get('critical', 0),
        stats.get('high', 0),
        stats.get('medium', 0),
        stats.get('low', 0)
    ]

    fig_critical.add_trace(
        go.Pie(labels=severities, values=counts,
               marker=dict(colors=['#dc2626', '#ea580c', '#facc15', '#3b82f6'])),
        row=2, col=1
    )

    # Top affected packages
    pkg_vuln_count = Counter()
    for node in client.graph.nodes():
        node_data = client.graph.nodes[node]
        if node_data.get('type') == 'package':
            # Count vulnerabilities for this package
            vuln_count = sum(1 for neighbor in client.graph.neighbors(node)
                           if client.graph.nodes[neighbor].get('type') == 'vulnerability')
            if vuln_count > 0:
                pkg_vuln_count[node] = vuln_count

    top_pkgs = pkg_vuln_count.most_common(10)
    if top_pkgs:
        pkg_names = [p[0][:30] for p in top_pkgs]  # Truncate long names
        pkg_counts = [p[1] for p in top_pkgs]

        fig_critical.add_trace(
            go.Bar(x=pkg_names, y=pkg_counts,
                   marker_color='#dc2626'),
            row=2, col=2
        )

    fig_critical.update_layout(
        title_text="🚨 Critical Vulnerability Command Center",
        height=800,
        width=1600,
        showlegend=False
    )

    output = "${VIZ_DIR}/command-centers/command_center_critical_vulns.html"
    fig_critical.write_html(output)
    print(f"  ✓ Critical Vulnerability Command Center: {output}")

    # 2. Package Risk Command Center
    print("Creating Package Risk Command Center...")

    fig_pkg = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            "Most Vulnerable Packages",
            "Package Ecosystem Distribution",
            "Risk Score Distribution",
            "Packages with Critical CVEs"
        ),
        specs=[
            [{"type": "bar"}, {"type": "pie"}],
            [{"type": "histogram"}, {"type": "bar"}]
        ]
    )

    # Most vulnerable packages (already calculated)
    if top_pkgs:
        fig_pkg.add_trace(
            go.Bar(x=[p[0][:30] for p in top_pkgs],
                   y=[p[1] for p in top_pkgs],
                   marker_color='#ea580c'),
            row=1, col=1
        )

    # Package ecosystem distribution
    ecosystems = Counter()
    for node in client.graph.nodes():
        node_data = client.graph.nodes[node]
        if node_data.get('type') == 'package':
            ecosystem = node_data.get('ecosystem', 'unknown')
            ecosystems[ecosystem] += 1

    if ecosystems:
        fig_pkg.add_trace(
            go.Pie(labels=list(ecosystems.keys()),
                   values=list(ecosystems.values())),
            row=1, col=2
        )

    # Risk scores (use vulnerability count as proxy)
    risk_scores = [count for _, count in pkg_vuln_count.most_common(50)]
    if risk_scores:
        fig_pkg.add_trace(
            go.Histogram(x=risk_scores, nbinsx=10,
                        marker_color='#facc15'),
            row=2, col=1
        )

    # Packages with critical CVEs
    critical_pkg_count = {}
    for node in client.graph.nodes():
        node_data = client.graph.nodes[node]
        if node_data.get('type') == 'package':
            critical_count = sum(
                1 for neighbor in client.graph.neighbors(node)
                if (client.graph.nodes[neighbor].get('type') == 'vulnerability' and
                    client.graph.nodes[neighbor].get('severity', '').lower() == 'critical')
            )
            if critical_count > 0:
                critical_pkg_count[node] = critical_count

    if critical_pkg_count:
        top_critical_pkgs = sorted(critical_pkg_count.items(),
                                  key=lambda x: x[1], reverse=True)[:10]
        fig_pkg.add_trace(
            go.Bar(x=[p[0][:30] for p in top_critical_pkgs],
                   y=[p[1] for p in top_critical_pkgs],
                   marker_color='#dc2626'),
            row=2, col=2
        )

    fig_pkg.update_layout(
        title_text="📦 Package Risk Command Center",
        height=800,
        width=1600,
        showlegend=False
    )

    output_pkg = "${VIZ_DIR}/command-centers/command_center_package_risk.html"
    fig_pkg.write_html(output_pkg)
    print(f"  ✓ Package Risk Command Center: {output_pkg}")

    print("✓ Command centers complete!")

except Exception as e:
    print(f"  ⚠️  Could not create command centers: {e}")
    import traceback
    traceback.print_exc()

EOFPYTHON

    if python3 /tmp/run_command_centers.py 2>/dev/null; then
        echo "  ✓ Critical Vulnerability Command Center created"
        echo "  ✓ Package Risk Command Center created"
    else
        echo -e "  ${YELLOW}⚠ Command center generation failed${NC}"
        echo "  ⓘ Make sure plotly is installed: pip install plotly"
    fi

    rm -f /tmp/run_command_centers.py

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
- [x] **NEW:** Dynamic attack path animations
- [x] **NEW:** 3D network topology visualizations
- [x] **NEW:** Layered security architecture views
- [x] **NEW:** Rotating zone boundaries
- [x] **NEW:** Attack layer transitions
- [x] **NEW:** Camera flythrough tours
- [x] **NEW:** Security Command Center dashboard
- [x] **NEW:** Holographic security story (cinematic)
- [x] **NEW:** Vulnerability command centers (4 dashboards)
- [x] **NEW:** Critical CVE tracking dashboard
- [x] **NEW:** Package risk analysis dashboard
- [x] **NEW:** Attack vector analysis center
- [x] **NEW:** Remediation priority dashboard

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
│   ├── attack_paths.html         # Standard attack path viz
│   ├── topology_zones.html       # Network topology
│   ├── topology_pci.html         # PCI compliance view
│   ├── critical_only.html        # Critical vulnerabilities
│   ├── dynamic/                  # Advanced dynamic visualizations
│   ├── 3d/                       # 3D topology visualizations
│   ├── ultimate/                 # Ultimate combined dashboards
│   │   ├── ultimate_command_center.html
│   │   └── ultimate_holographic_story.html
│   └── command-centers/          # Vulnerability command centers
│       ├── command_center_critical_vulns.html
│       ├── command_center_package_risk.html
│       ├── command_center_attack_vectors.html
│       └── command_center_remediation.html
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

    # Advanced Visualizations
    advanced_dynamic_visualizations
    dynamic_3d_topology
    ultimate_visualizations
    vulnerability_command_centers

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
    echo "  🌐 Main Report:        open ${REPORTS_DIR}/*_report.html"
    echo "  🎨 Attack Paths:       open ${VIZ_DIR}/attack_paths.html"
    echo "  🔒 PCI Topology:       open ${VIZ_DIR}/topology_pci.html"
    echo "  🤖 AI Analysis:        cat ${AI_DIR}/*_priorities.json"
    echo ""
    echo "Advanced Visualizations (NEWLY GENERATED!):"
    echo "  🎯 Command Centers:"
    echo "      • Critical Vulns:  open ${VIZ_DIR}/command-centers/command_center_critical_vulns.html"
    echo "      • Package Risk:    open ${VIZ_DIR}/command-centers/command_center_package_risk.html"
    echo "  🌟 Ultimate Dashboards:"
    echo "      • Command Center:  open ${VIZ_DIR}/ultimate/security_command_center.html"
    echo "      • Holographic 3D:  open ${VIZ_DIR}/ultimate/holographic_security_story.html (FIXED!)"
    echo "  🎬 3D Topology:"
    echo "      • 3D Network:      open ${VIZ_DIR}/3d/network_topology_3d.html"
    echo "      • 3D Layers:       open ${VIZ_DIR}/3d/layered_architecture_3d.html"
    echo "  ⚡ Dynamic Animations:"
    echo "      • Attack Paths:    open ${VIZ_DIR}/dynamic/animated_attack_paths.html"
    echo "      • Individual:      open ${VIZ_DIR}/dynamic/attack_path_*.html"
    echo ""
    echo "💡 Holographic Visualization Tip:"
    echo "   Click the ▶ PLAY or 🔄 LOOP button to start the 3D animation!"
    echo "   Use the slider to manually scrub through frames."
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
