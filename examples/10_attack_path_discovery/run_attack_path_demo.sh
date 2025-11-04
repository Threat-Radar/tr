#!/bin/bash
#
# Complete Attack Path Discovery Demo
#
# This script demonstrates the full workflow:
# 1. Build environment graph with vulnerability data
# 2. Discover attack paths
# 3. Detect privilege escalations
# 4. Identify lateral movements
# 5. Generate comprehensive assessment
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "======================================================================"
echo "THREAT RADAR - ATTACK PATH DISCOVERY DEMO"
echo "======================================================================"

# Check prerequisites
echo -e "\n${BLUE}Checking prerequisites...${NC}"

if ! command -v threat-radar &> /dev/null; then
    echo -e "${RED}✗ threat-radar not found${NC}"
    echo "  Install: pip install -e ."
    exit 1
fi
echo -e "${GREEN}✓ threat-radar installed${NC}"

if [ ! -f "sample-environment.json" ]; then
    echo -e "${RED}✗ sample-environment.json not found${NC}"
    echo "  Run this script from examples/10_attack_path_discovery/"
    exit 1
fi
echo -e "${GREEN}✓ Sample environment found${NC}"

# Step 1: Build environment graph
echo -e "\n${BLUE}Step 1: Building environment graph...${NC}"
if [ -f "environment-graph.graphml" ]; then
    echo -e "${YELLOW}Graph already exists, rebuilding...${NC}"
    rm -f environment-graph.graphml
fi

threat-radar env build-graph sample-environment.json \
    -o environment-graph.graphml

if [ -f "environment-graph.graphml" ]; then
    echo -e "${GREEN}✓ Graph built successfully${NC}"
else
    echo -e "${RED}✗ Failed to build graph${NC}"
    exit 1
fi

# Step 2: Basic attack path discovery
echo -e "\n${BLUE}Step 2: Discovering attack paths...${NC}"
python3 01_basic_attack_path.py
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Attack paths discovered${NC}"
else
    echo -e "${YELLOW}⚠ Attack path discovery had issues (continuing...)${NC}"
fi

# Step 3: Privilege escalation detection
echo -e "\n${BLUE}Step 3: Detecting privilege escalations...${NC}"
python3 02_privilege_escalation.py
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Privilege escalations analyzed${NC}"
else
    echo -e "${YELLOW}⚠ Privilege escalation detection had issues (continuing...)${NC}"
fi

# Step 4: Lateral movement identification
echo -e "\n${BLUE}Step 4: Identifying lateral movements...${NC}"
python3 03_lateral_movement.py
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Lateral movements identified${NC}"
else
    echo -e "${YELLOW}⚠ Lateral movement identification had issues (continuing...)${NC}"
fi

# Step 5: Complete assessment
echo -e "\n${BLUE}Step 5: Running complete attack surface assessment...${NC}"
python3 04_complete_assessment.py
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Complete assessment finished${NC}"
else
    echo -e "${YELLOW}⚠ Assessment had issues (continuing...)${NC}"
fi

# Display results summary
echo -e "\n======================================================================"
echo "RESULTS SUMMARY"
echo "======================================================================"

if [ -f "attack-surface.json" ]; then
    RISK_SCORE=$(cat attack-surface.json | jq -r '.total_risk_score // "N/A"')
    ATTACK_PATHS=$(cat attack-surface.json | jq -r '.summary.attack_paths // "N/A"')
    CRITICAL=$(cat attack-surface.json | jq -r '.threat_distribution.critical // 0')
    PRIV_ESC=$(cat attack-surface.json | jq -r '.summary.privilege_escalations // "N/A"')
    LATERAL=$(cat attack-surface.json | jq -r '.summary.lateral_movements // "N/A"')

    echo -e "\n📊 Attack Surface Metrics:"
    echo "   • Risk Score: $RISK_SCORE/100"
    echo "   • Attack Paths: $ATTACK_PATHS"
    echo "   • Critical Paths: $CRITICAL"
    echo "   • Privilege Escalations: $PRIV_ESC"
    echo "   • Lateral Movements: $LATERAL"

    if [ "$CRITICAL" -gt 0 ]; then
        echo -e "\n${RED}⚠️  WARNING: $CRITICAL critical attack paths detected!${NC}"
    fi

    # Show top recommendation
    echo -e "\n🛡️  Top Security Recommendation:"
    cat attack-surface.json | jq -r '.recommendations[0] // "No recommendations available"' | sed 's/^/   /'
fi

# Show generated files
echo -e "\n📁 Generated Files:"
ls -lh *.json *.graphml 2>/dev/null | awk '{print "   • " $9 " (" $5 ")"}'

# CLI command examples
echo -e "\n======================================================================"
echo "CLI USAGE EXAMPLES"
echo "======================================================================"
echo ""
echo "Re-run individual analyses:"
echo ""
echo "  # Attack paths"
echo "  threat-radar graph attack-paths environment-graph.graphml -o paths.json"
echo ""
echo "  # Privilege escalation"
echo "  threat-radar graph privilege-escalation environment-graph.graphml -o privesc.json"
echo ""
echo "  # Lateral movement"
echo "  threat-radar graph lateral-movement environment-graph.graphml -o lateral.json"
echo ""
echo "  # Complete assessment"
echo "  threat-radar graph attack-surface environment-graph.graphml -o surface.json"
echo ""

echo -e "${GREEN}✅ Demo complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Review JSON files for detailed results"
echo "  2. Customize sample-environment.json for your infrastructure"
echo "  3. Integrate into CI/CD pipeline"
echo "  4. Set up continuous monitoring"
echo ""
