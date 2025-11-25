#!/bin/bash
# Demo: Graph Database Analysis
# Shows vulnerability relationship modeling and querying

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Demo: Graph Database Analysis                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Demonstrates: threat-radar graph commands"
echo "Use case: Vulnerability relationship analysis and blast radius"
echo ""

mkdir -p demo-04-results

# Use pre-scanned results or scan now
SERVICE="paymentservice"
if [ ! -f "demo-02-results/${SERVICE}_scan.json" ]; then
    echo "Running CVE scan first..."
    IMAGE="us-central1-docker.pkg.dev/google-samples/microservices-demo/paymentservice:v0.10.3"
    mkdir -p demo-02-results
    threat-radar cve scan-image "$IMAGE" -o "demo-02-results/${SERVICE}_scan.json"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Build Vulnerability Graph"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Converting scan results to graph database..."
echo "Press Enter to continue..."
read

threat-radar graph build "demo-02-results/${SERVICE}_scan.json" \
    -o "demo-04-results/${SERVICE}_graph.graphml"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Graph Statistics"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar graph query "demo-04-results/${SERVICE}_graph.graphml" --stats

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3: Top Vulnerable Packages"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Finding packages with the most vulnerabilities..."

threat-radar graph query "demo-04-results/${SERVICE}_graph.graphml" \
    --top-packages 10

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4: CVE Blast Radius (Example)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Finding which packages are affected by specific CVEs..."

# Get a sample CVE from the scan
SAMPLE_CVE=$(jq -r '.vulnerabilities[0].id' demo-02-results/${SERVICE}_scan.json)

if [ -n "$SAMPLE_CVE" ] && [ "$SAMPLE_CVE" != "null" ]; then
    echo "Querying CVE: $SAMPLE_CVE"
    threat-radar graph query "demo-04-results/${SERVICE}_graph.graphml" \
        --cve "$SAMPLE_CVE" --stats
else
    echo "No CVEs found in scan results"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 5: Available Fixes"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Finding vulnerabilities with available patches..."

threat-radar graph fixes "demo-04-results/${SERVICE}_graph.graphml" \
    --severity high

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 6: Graph Information"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar graph info "demo-04-results/${SERVICE}_graph.graphml"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "GRAPH DATABASE BENEFITS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Relationship Analysis"
echo "   → Understand connections between packages and vulnerabilities"
echo ""
echo "2. Blast Radius Queries"
echo "   → Find all assets affected by a specific CVE"
echo ""
echo "3. Fix Discovery"
echo "   → Identify which vulnerabilities have patches available"
echo ""
echo "4. Package Risk Scoring"
echo "   → Rank packages by vulnerability count"
echo ""
echo "5. Attack Path Analysis"
echo "   → Map potential exploitation routes (shown in later demos)"
echo ""
echo "6. Historical Analysis"
echo "   → Store and compare graphs over time"
echo ""

echo "Graph Format: GraphML (compatible with NetworkX, Gephi, Neo4j)"
echo ""
echo "Results saved to: demo-04-results/"
echo ""
echo "✓ Demo Complete"

