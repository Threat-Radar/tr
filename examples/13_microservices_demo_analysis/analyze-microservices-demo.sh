#!/usr/bin/env bash
#
# Threat Radar Analysis for Google Cloud Microservices Demo
# https://github.com/GoogleCloudPlatform/microservices-demo
#
# This script performs comprehensive vulnerability and attack path analysis
# on the Online Boutique microservices application.
#

set -e  # Exit on error

# Load environment variables from project root .env file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"

if [ -f "${ENV_FILE}" ]; then
    # Export variables from .env file (handles comments and empty lines)
    set -a
    source "${ENV_FILE}"
    set +a
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/GoogleCloudPlatform/microservices-demo"
OUTPUT_DIR="./microservices-demo-data"
SCANS_DIR="${OUTPUT_DIR}/scans"
CONFIG_FILE="${OUTPUT_DIR}/online-boutique-environment.json"
GRAPH_FILE="${OUTPUT_DIR}/online-boutique-graph.graphml"
ATTACK_PATHS_FILE="${OUTPUT_DIR}/attack-paths.json"

# Microservices in the demo (image names from the repo)
# These are the official Google Cloud images
declare -A SERVICES=(
    ["frontend"]="gcr.io/google-samples/microservices-demo/frontend:v0.10.1"
    ["cartservice"]="gcr.io/google-samples/microservices-demo/cartservice:v0.10.1"
    ["productcatalogservice"]="gcr.io/google-samples/microservices-demo/productcatalogservice:v0.10.1"
    ["currencyservice"]="gcr.io/google-samples/microservices-demo/currencyservice:v0.10.1"
    ["paymentservice"]="gcr.io/google-samples/microservices-demo/paymentservice:v0.10.1"
    ["shippingservice"]="gcr.io/google-samples/microservices-demo/shippingservice:v0.10.1"
    ["emailservice"]="gcr.io/google-samples/microservices-demo/emailservice:v0.10.1"
    ["checkoutservice"]="gcr.io/google-samples/microservices-demo/checkoutservice:v0.10.1"
    ["recommendationservice"]="gcr.io/google-samples/microservices-demo/recommendationservice:v0.10.1"
    ["adservice"]="gcr.io/google-samples/microservices-demo/adservice:v0.10.1"
    ["loadgenerator"]="gcr.io/google-samples/microservices-demo/loadgenerator:v0.10.1"
)

# Service languages (for context)
declare -A LANGUAGES=(
    ["frontend"]="Go"
    ["cartservice"]="C#"
    ["productcatalogservice"]="Go"
    ["currencyservice"]="Node.js"
    ["paymentservice"]="Node.js"
    ["shippingservice"]="Go"
    ["emailservice"]="Python"
    ["checkoutservice"]="Go"
    ["recommendationservice"]="Python"
    ["adservice"]="Java"
    ["loadgenerator"]="Python"
)

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Threat Radar - Microservices Demo Security Analysis      ║${NC}"
echo -e "${BLUE}║  Repository: GoogleCloudPlatform/microservices-demo        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}\n"

# Function: Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    local missing_tools=()

    # Check for required tools
    if ! command -v threat-radar &> /dev/null; then
        missing_tools+=("threat-radar")
    fi

    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi

    if ! command -v grype &> /dev/null; then
        missing_tools+=("grype")
    fi

    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}✗ Missing required tools: ${missing_tools[*]}${NC}"
        echo ""
        echo "Installation instructions:"
        echo "  - threat-radar: pip install threat-radar"
        echo "  - docker: https://docs.docker.com/get-docker/"
        echo "  - grype: brew install grype  (or see https://github.com/anchore/grype)"
        exit 1
    fi

    # Check Docker is running
    if ! docker info &> /dev/null; then
        echo -e "${RED}✗ Docker daemon is not running${NC}"
        echo "Please start Docker and try again."
        exit 1
    fi

    echo -e "${GREEN}✓ All prerequisites met${NC}\n"
}

# Function: Setup directories
setup_directories() {
    echo -e "${YELLOW}Setting up directories...${NC}"
    mkdir -p "${OUTPUT_DIR}"
    mkdir -p "${SCANS_DIR}"
    echo -e "${GREEN}✓ Directories created${NC}\n"
}

# Function: Scan a single service
scan_service() {
    local service_name=$1
    local image=$2
    local scan_file="${SCANS_DIR}/${service_name}_scan.json"

    echo -e "${BLUE}Scanning ${service_name} (${LANGUAGES[$service_name]})...${NC}"
    echo "  Image: ${image}"

    # Pull image if not exists
    if ! docker image inspect "${image}" &> /dev/null; then
        echo "  Pulling image..."
        docker pull "${image}" || {
            echo -e "${RED}  ✗ Failed to pull image${NC}"
            return 1
        }
    fi

    # Scan with Threat Radar
    threat-radar cve scan-image "${image}" \
        -o "${scan_file}" \
        --cleanup &> /dev/null || {
        echo -e "${RED}  ✗ Scan failed${NC}"
        return 1
    }

    # Show summary
    local total_vulns=$(jq -r '.total_vulnerabilities // 0' "${scan_file}")
    local critical=$(jq -r '.severity_counts.critical // 0' "${scan_file}")
    local high=$(jq -r '.severity_counts.high // 0' "${scan_file}")

    echo -e "  ${GREEN}✓ Complete${NC} - Total: ${total_vulns} (Critical: ${critical}, High: ${high})"
}

# Function: Scan all services
scan_all_services() {
    echo -e "${YELLOW}Scanning all microservices...${NC}\n"

    local total_services=${#SERVICES[@]}
    local current=0
    local failed=0

    for service in "${!SERVICES[@]}"; do
        current=$((current + 1))
        echo -e "${BLUE}[${current}/${total_services}]${NC}"

        if ! scan_service "${service}" "${SERVICES[$service]}"; then
            failed=$((failed + 1))
        fi
        echo ""
    done

    if [ $failed -gt 0 ]; then
        echo -e "${YELLOW}⚠ ${failed} service(s) failed to scan${NC}"
    else
        echo -e "${GREEN}✓ All services scanned successfully${NC}"
    fi
    echo ""
}

# Function: Generate environment configuration
generate_environment_config() {
    echo -e "${YELLOW}Generating environment configuration...${NC}"

    cat > "${CONFIG_FILE}" << 'EOF'
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
        "exposed_ports": [
          {
            "port": 8080,
            "protocol": "http",
            "public": true,
            "description": "Public web interface"
          }
        ]
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
        "exposed_ports": [
          {
            "port": 7070,
            "protocol": "grpc",
            "public": false,
            "description": "gRPC API"
          }
        ]
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
        "exposed_ports": [
          {
            "port": 5050,
            "protocol": "grpc",
            "public": false,
            "description": "gRPC API"
          }
        ]
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
        "exposed_ports": [
          {
            "port": 50051,
            "protocol": "grpc",
            "public": false,
            "description": "gRPC API"
          }
        ]
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
        "exposed_ports": [
          {
            "port": 3550,
            "protocol": "grpc",
            "public": false,
            "description": "gRPC API"
          }
        ]
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
        "exposed_ports": [
          {
            "port": 7000,
            "protocol": "grpc",
            "public": false,
            "description": "gRPC API"
          }
        ]
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
    },
    {
      "id": "asset-shippingservice",
      "name": "Shipping Service",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/shippingservice:v0.10.1",
        "runtime": "Go"
      },
      "network": {
        "internal_ip": "10.0.2.50",
        "zone": "internal",
        "exposed_ports": [
          {
            "port": 50051,
            "protocol": "grpc",
            "public": false,
            "description": "gRPC API"
          }
        ]
      },
      "business_context": {
        "criticality": "high",
        "criticality_score": 70,
        "function": "shipping-calculation",
        "data_classification": "internal",
        "revenue_impact": "medium",
        "customer_facing": false,
        "sla_tier": "tier-2",
        "mttr_target": 4,
        "owner_team": "backend-team"
      }
    },
    {
      "id": "asset-emailservice",
      "name": "Email Notification Service",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/emailservice:v0.10.1",
        "runtime": "Python"
      },
      "network": {
        "internal_ip": "10.0.2.60",
        "zone": "internal",
        "exposed_ports": [
          {
            "port": 8080,
            "protocol": "grpc",
            "public": false,
            "description": "gRPC API"
          }
        ]
      },
      "business_context": {
        "criticality": "medium",
        "criticality_score": 50,
        "function": "email-notifications",
        "data_classification": "internal",
        "revenue_impact": "low",
        "customer_facing": false,
        "sla_tier": "tier-3",
        "mttr_target": 8,
        "owner_team": "platform-team"
      }
    },
    {
      "id": "asset-recommendationservice",
      "name": "Product Recommendation Service",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/recommendationservice:v0.10.1",
        "runtime": "Python"
      },
      "network": {
        "internal_ip": "10.0.2.70",
        "zone": "internal",
        "exposed_ports": [
          {
            "port": 8080,
            "protocol": "grpc",
            "public": false,
            "description": "gRPC API"
          }
        ]
      },
      "business_context": {
        "criticality": "medium",
        "criticality_score": 60,
        "function": "product-recommendations",
        "data_classification": "internal",
        "revenue_impact": "medium",
        "customer_facing": false,
        "sla_tier": "tier-2",
        "mttr_target": 4,
        "owner_team": "ml-team"
      }
    },
    {
      "id": "asset-adservice",
      "name": "Advertisement Service",
      "type": "container",
      "software": {
        "image": "gcr.io/google-samples/microservices-demo/adservice:v0.10.1",
        "runtime": "Java"
      },
      "network": {
        "internal_ip": "10.0.2.80",
        "zone": "internal",
        "exposed_ports": [
          {
            "port": 9555,
            "protocol": "grpc",
            "public": false,
            "description": "gRPC API"
          }
        ]
      },
      "business_context": {
        "criticality": "medium",
        "criticality_score": 55,
        "function": "advertising",
        "data_classification": "internal",
        "revenue_impact": "medium",
        "customer_facing": false,
        "sla_tier": "tier-3",
        "mttr_target": 8,
        "owner_team": "ads-team"
      }
    }
  ],
  "dependencies": [
    {
      "from": "asset-frontend",
      "to": "asset-cartservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": true
    },
    {
      "from": "asset-frontend",
      "to": "asset-checkoutservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": true
    },
    {
      "from": "asset-frontend",
      "to": "asset-productcatalogservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": true
    },
    {
      "from": "asset-frontend",
      "to": "asset-currencyservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": false
    },
    {
      "from": "asset-frontend",
      "to": "asset-recommendationservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": false
    },
    {
      "from": "asset-frontend",
      "to": "asset-adservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": false
    },
    {
      "from": "asset-checkoutservice",
      "to": "asset-paymentservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": true
    },
    {
      "from": "asset-checkoutservice",
      "to": "asset-shippingservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": true
    },
    {
      "from": "asset-checkoutservice",
      "to": "asset-emailservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": false
    },
    {
      "from": "asset-checkoutservice",
      "to": "asset-cartservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": true
    },
    {
      "from": "asset-checkoutservice",
      "to": "asset-productcatalogservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": true
    },
    {
      "from": "asset-checkoutservice",
      "to": "asset-currencyservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": false
    },
    {
      "from": "asset-recommendationservice",
      "to": "asset-productcatalogservice",
      "type": "api-call",
      "protocol": "grpc",
      "critical": false
    }
  ],
  "network_topology": {
    "zones": [
      {
        "name": "dmz",
        "trust_level": "low",
        "internet_facing": true,
        "description": "DMZ zone for public-facing services"
      },
      {
        "name": "internal",
        "trust_level": "medium",
        "internet_facing": false,
        "description": "Internal application zone"
      },
      {
        "name": "trusted",
        "trust_level": "high",
        "internet_facing": false,
        "description": "Trusted zone for payment processing"
      }
    ],
    "segmentation_rules": [
      {
        "from_zone": "dmz",
        "to_zone": "internal",
        "allowed": true,
        "ports": [7070, 5050, 3550, 7000, 8080, 9555],
        "protocols": ["grpc", "http"]
      },
      {
        "from_zone": "internal",
        "to_zone": "trusted",
        "allowed": true,
        "ports": [50051],
        "protocols": ["grpc"]
      }
    ]
  }
}
EOF

    echo -e "${GREEN}✓ Environment configuration created: ${CONFIG_FILE}${NC}\n"
}

# Function: Build infrastructure graph
build_graph() {
    echo -e "${YELLOW}Building infrastructure graph with vulnerability data...${NC}\n"

    # Build list of scan files
    local merge_scans=""
    for service in "${!SERVICES[@]}"; do
        local scan_file="${SCANS_DIR}/${service}_scan.json"
        if [ -f "${scan_file}" ]; then
            merge_scans="${merge_scans} --merge-scan ${scan_file}"
        fi
    done

    # Build graph
    threat-radar env build-graph \
        "${CONFIG_FILE}" \
        ${merge_scans} \
        -o "${GRAPH_FILE}"

    echo -e "\n${GREEN}✓ Graph built: ${GRAPH_FILE}${NC}\n"
}

# Function: Analyze attack paths
analyze_attack_paths() {
    echo -e "${YELLOW}Analyzing attack paths...${NC}\n"

    threat-radar graph attack-paths \
        "${GRAPH_FILE}" \
        --max-paths 20 \
        -o "${ATTACK_PATHS_FILE}"

    echo -e "\n${GREEN}✓ Attack paths saved: ${ATTACK_PATHS_FILE}${NC}\n"
}

# Function: Generate summary report
generate_summary() {
    echo -e "${YELLOW}Generating summary report...${NC}\n"

    local total_services=${#SERVICES[@]}
    local scanned_services=0
    local total_vulns=0
    local total_critical=0
    local total_high=0

    for service in "${!SERVICES[@]}"; do
        local scan_file="${SCANS_DIR}/${service}_scan.json"
        if [ -f "${scan_file}" ]; then
            scanned_services=$((scanned_services + 1))

            local vulns=$(jq -r '.total_vulnerabilities // 0' "${scan_file}")
            local critical=$(jq -r '.severity_counts.critical // 0' "${scan_file}")
            local high=$(jq -r '.severity_counts.high // 0' "${scan_file}")

            total_vulns=$((total_vulns + vulns))
            total_critical=$((total_critical + critical))
            total_high=$((total_high + high))
        fi
    done

    local attack_paths=$(jq -r '.total_paths // 0' "${ATTACK_PATHS_FILE}" 2>/dev/null || echo "0")
    local critical_paths=$(jq -r '[.attack_paths[] | select(.threat_level == "critical")] | length' "${ATTACK_PATHS_FILE}" 2>/dev/null || echo "0")

    cat > "${OUTPUT_DIR}/SUMMARY.md" << EOF
# Online Boutique - Security Analysis Summary

Generated: $(date)

## Overview

Analyzed the Google Cloud Platform microservices-demo (Online Boutique) e-commerce application.

- **Repository**: https://github.com/GoogleCloudPlatform/microservices-demo
- **Services Analyzed**: ${scanned_services}/${total_services}
- **Architecture**: Microservices (gRPC)

## Vulnerability Summary

| Metric | Count |
|--------|-------|
| **Total Vulnerabilities** | ${total_vulns} |
| **Critical Severity** | ${total_critical} |
| **High Severity** | ${total_high} |

## Attack Path Analysis

| Metric | Count |
|--------|-------|
| **Total Attack Paths** | ${attack_paths} |
| **Critical Paths** | ${critical_paths} |

## Service Breakdown

| Service | Language | Vulnerabilities | Critical | High |
|---------|----------|----------------|----------|------|
EOF

    for service in $(echo "${!SERVICES[@]}" | tr ' ' '\n' | sort); do
        local scan_file="${SCANS_DIR}/${service}_scan.json"
        if [ -f "${scan_file}" ]; then
            local vulns=$(jq -r '.total_vulnerabilities // 0' "${scan_file}")
            local critical=$(jq -r '.severity_counts.critical // 0' "${scan_file}")
            local high=$(jq -r '.severity_counts.high // 0' "${scan_file}")

            echo "| ${service} | ${LANGUAGES[$service]} | ${vulns} | ${critical} | ${high} |" >> "${OUTPUT_DIR}/SUMMARY.md"
        fi
    done

    cat >> "${OUTPUT_DIR}/SUMMARY.md" << EOF

## PCI-DSS Scoped Services

The following services handle payment card data and are in PCI-DSS scope:

- **Cart Service** - Stores cart items with payment info
- **Checkout Service** - Processes checkout transactions
- **Payment Service** - Handles payment processing

## Attack Surface

### Entry Points
- **Frontend Service** - Internet-facing on port 8080 (HTTP)

### High-Value Targets
- **Payment Service** - PCI-scoped, processes payments
- **Cart Service** - PCI-scoped, stores cart data
- **Checkout Service** - PCI-scoped, processes orders

## Files Generated

- \`scans/*.json\` - Vulnerability scan results for each service
- \`online-boutique-environment.json\` - Infrastructure configuration
- \`online-boutique-graph.graphml\` - Vulnerability graph database
- \`attack-paths.json\` - Attack path analysis results

## Next Steps

1. **Review Attack Paths**: Examine critical attack paths to payment services
   \`\`\`bash
   jq '.attack_paths[] | select(.threat_level == "critical")' attack-paths.json
   \`\`\`

2. **Visualize Graph**: Create interactive visualization
   \`\`\`bash
   threat-radar visualize attack-paths online-boutique-graph.graphml -o viz.html --open
   \`\`\`

3. **Generate Comprehensive Report**: AI-powered analysis
   \`\`\`bash
   threat-radar report generate scans/*.json -o report.html -f html
   \`\`\`

4. **Prioritize Remediation**: Focus on PCI-scoped services
   \`\`\`bash
   threat-radar ai prioritize scans/paymentservice_scan.json --auto-save
   \`\`\`
EOF

    echo -e "${GREEN}✓ Summary report created: ${OUTPUT_DIR}/SUMMARY.md${NC}\n"
}

# Function: Display results
display_results() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    Analysis Complete!                      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}\n"

    echo -e "${GREEN}Results saved to: ${OUTPUT_DIR}/${NC}\n"

    echo "Next steps:"
    echo "  1. View summary:    cat ${OUTPUT_DIR}/SUMMARY.md"
    echo "  2. View graph:      threat-radar graph info ${GRAPH_FILE}"
    echo "  3. Visualize:       threat-radar visualize attack-paths ${GRAPH_FILE} -o viz.html --open"
    echo "  4. AI analysis:     threat-radar ai analyze ${SCANS_DIR}/*.json --auto-save"
    echo ""
}

# Main execution
main() {
    check_prerequisites
    setup_directories
    scan_all_services
    generate_environment_config
    build_graph
    analyze_attack_paths
    generate_summary
    display_results
}

# Parse command line arguments
SKIP_SCANS=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-scans)
            SKIP_SCANS=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-scans    Skip vulnerability scanning (use existing scans)"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main function (or skip scans if requested)
if [ "$SKIP_SCANS" = true ]; then
    echo -e "${YELLOW}Skipping scans, using existing data...${NC}\n"
    check_prerequisites
    setup_directories
    if [ ! -f "${CONFIG_FILE}" ]; then
        generate_environment_config
    fi
    build_graph
    analyze_attack_paths
    generate_summary
    display_results
else
    main
fi
