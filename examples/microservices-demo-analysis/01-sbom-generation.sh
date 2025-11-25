#!/bin/bash
# Demo: SBOM Generation & Management
# Shows software bill of materials generation and analysis

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Demo: SBOM Generation & Management                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Demonstrates: threat-radar sbom commands"
echo "Use case: Software supply chain transparency and tracking"
echo ""

mkdir -p demo-01-results

SERVICE="paymentservice"
IMAGE="us-central1-docker.pkg.dev/google-samples/microservices-demo/paymentservice:v0.10.3"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Generate SBOM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Generating SBOM for: $SERVICE"
echo "Press Enter to continue..."
read

threat-radar sbom docker "$IMAGE" \
    -o "demo-01-results/${SERVICE}_sbom.json"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Read SBOM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar sbom read "demo-01-results/${SERVICE}_sbom.json"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3: SBOM Statistics"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar sbom stats "demo-01-results/${SERVICE}_sbom.json"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4: Search SBOM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Searching for 'node' packages..."

threat-radar sbom search "demo-01-results/${SERVICE}_sbom.json" "node"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 5: List Components"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Showing all npm packages..."

threat-radar sbom components "demo-01-results/${SERVICE}_sbom.json" \
    --type library \
    --language javascript

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 6: Export SBOM to CSV"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar sbom export "demo-01-results/${SERVICE}_sbom.json" \
    -o "demo-01-results/${SERVICE}_packages.csv" \
    -f csv

echo "Exported to CSV: demo-01-results/${SERVICE}_packages.csv"
echo ""
echo "First 5 lines of CSV:"
head -5 "demo-01-results/${SERVICE}_packages.csv"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 7: SBOM Comparison (Simulated)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Comparing with another service to show differences..."

# Generate second SBOM for comparison
SERVICE2="frontend"
IMAGE2="us-central1-docker.pkg.dev/google-samples/microservices-demo/frontend:v0.10.3"

echo "Generating SBOM for $SERVICE2..."
threat-radar sbom docker "$IMAGE2" \
    -o "demo-01-results/${SERVICE2}_sbom.json"

echo ""
echo "Comparing $SERVICE vs $SERVICE2..."
threat-radar sbom compare \
    "demo-01-results/${SERVICE}_sbom.json" \
    "demo-01-results/${SERVICE2}_sbom.json"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "USE CASES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Supply Chain Transparency"
echo "   → Know exactly what's in your containers"
echo ""
echo "2. Version Tracking"
echo "   → Compare SBOMs across releases to track changes"
echo ""
echo "3. Compliance & Auditing"
echo "   → Meet SBOM requirements (Executive Order 14028)"
echo ""
echo "4. Vulnerability Management"
echo "   → Scan SBOMs instead of images (faster, offline-capable)"
echo ""
echo "5. License Compliance"
echo "   → Track open-source licenses in your dependencies"
echo ""

echo "Results saved to: demo-01-results/"
echo ""
echo "✓ Demo Complete"
