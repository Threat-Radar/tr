#!/bin/bash
# Demo: Interactive Visualizations
# Shows graph visualization and attack path exploration

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Demo: Interactive Visualizations                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Demonstrates: threat-radar visualize commands"
echo "Use case: Visual exploration and stakeholder communication"
echo ""

# Check if plotly is installed
if ! python3 -c "import plotly" 2>/dev/null; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "⚠ PLOTLY NOT INSTALLED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "To enable visualizations, install plotly:"
    echo ""
    echo "  pip install plotly kaleido"
    echo ""
    echo "This demo will show the commands without executing them."
    echo ""
    DEMO_MODE="show"
else
    echo "✓ Plotly installed"
    echo ""
    DEMO_MODE="run"
fi

mkdir -p demo-07-results

# Ensure we have graphs to visualize
if [ ! -f "demo-04-results/paymentservice_graph.graphml" ]; then
    echo "Creating vulnerability graph first..."
    bash demo-scripts/03-graph-analysis.sh
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Basic Graph Visualization"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

CMD="threat-radar visualize graph demo-04-results/paymentservice_graph.graphml \
    -o demo-07-results/paymentservice_graph.html \
    --layout hierarchical \
    --color-by severity"

if [ "$DEMO_MODE" = "run" ]; then
    echo "Creating interactive graph visualization..."
    eval $CMD
    echo ""
    echo "✓ Visualization created: demo-07-results/paymentservice_graph.html"
    echo "  Open in browser to explore interactively"
else
    echo "Command (not executed):"
    echo "  $CMD"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Filtered Visualization (Critical Only)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

CMD="threat-radar visualize filter demo-04-results/paymentservice_graph.graphml \
    -o demo-07-results/paymentservice_critical.html \
    --type severity \
    --value high"

if [ "$DEMO_MODE" = "run" ]; then
    echo "Creating filtered view (HIGH+ severity only)..."
    eval $CMD
    echo ""
    echo "✓ Filtered visualization created"
else
    echo "Command (not executed):"
    echo "  $CMD"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3: Network Topology Visualization"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "demo-03-results/infrastructure-graph.graphml" ]; then
    CMD="threat-radar visualize topology demo-03-results/infrastructure-graph.graphml \
        -o demo-07-results/network-topology.html \
        --view topology \
        --color-by zone"

    if [ "$DEMO_MODE" = "run" ]; then
        echo "Creating network topology view..."
        eval $CMD
        echo ""
        echo "✓ Topology visualization created"
    else
        echo "Command (not executed):"
        echo "  $CMD"
    fi
else
    echo "Infrastructure graph not found. Skipping topology visualization."
    echo "Run Demo 3 first to create environment graph."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4: Attack Path Visualization"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "demo-05-results/attack-paths.json" ] && [ -f "demo-03-results/infrastructure-graph.graphml" ]; then
    CMD="threat-radar visualize attack-paths demo-03-results/infrastructure-graph.graphml \
        -o demo-07-results/attack-paths-viz.html \
        --paths demo-05-results/attack-paths.json \
        --max-paths 10"

    if [ "$DEMO_MODE" = "run" ]; then
        echo "Creating attack path visualization..."
        eval $CMD
        echo ""
        echo "✓ Attack paths visualization created"
    else
        echo "Command (not executed):"
        echo "  $CMD"
    fi
else
    echo "Attack paths not found. Skipping attack path visualization."
    echo "Run prior Demos first to discover attack paths."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 5: Multi-Format Export"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

CMD="threat-radar visualize export demo-04-results/paymentservice_graph.graphml \
    -o demo-07-results/paymentservice_export \
    --format html --format png"

if [ "$DEMO_MODE" = "run" ]; then
    echo "Exporting visualization in multiple formats..."
    eval $CMD
    echo ""
    echo "✓ Exported formats: HTML, PNG"
else
    echo "Command (not executed):"
    echo "  $CMD"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "VISUALIZATION FEATURES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Interactive Exploration"
echo "   → Zoom, pan, hover for details"
echo "   → Click nodes to explore"
echo "   → Search and filter in real-time"
echo ""
echo "2. Layout Algorithms"
echo "   → Hierarchical (great for dependency trees)"
echo "   → Spring (force-directed, natural clustering)"
echo "   → Circular (shows connections clearly)"
echo "   → Spectral (mathematical optimization)"
echo ""
echo "3. Color Schemes"
echo "   → By severity (red=critical, orange=high, etc.)"
echo "   → By node type (vulnerability, package, container)"
echo "   → By zone (DMZ, internal, trusted)"
echo "   → By criticality (business importance)"
echo ""
echo "4. Filtering Options"
echo "   → By severity (critical, high, medium, low)"
echo "   → By CVE ID"
echo "   → By package name"
echo "   → By security zone"
echo "   → By compliance scope (PCI, HIPAA, etc.)"
echo ""
echo "5. Export Formats"
echo "   → HTML (interactive, standalone)"
echo "   → PNG (static image for reports)"
echo "   → SVG (scalable vector graphics)"
echo "   → PDF (print-ready documents)"
echo "   → JSON (custom web applications)"
echo "   → DOT (Graphviz processing)"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "VISUALIZATION USE CASES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Executive Presentations"
echo "   → Visual attack path demonstrations"
echo "   → Network topology with security overlays"
echo ""
echo "2. Security Team Analysis"
echo "   → Explore vulnerability relationships"
echo "   → Identify vulnerability clusters"
echo ""
echo "3. Developer Education"
echo "   → Show impact of dependency choices"
echo "   → Visualize fix propagation"
echo ""
echo "4. Compliance Audits"
echo "   → Demonstrate PCI/HIPAA scope"
echo "   → Show security zone segregation"
echo ""
echo "5. Incident Response"
echo "   → Map potential attack vectors"
echo "   → Identify blast radius quickly"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ADVANCED OPTIONS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "• 3D Visualization:"
echo "  threat-radar visualize graph graph.graphml --3d"
echo ""
echo "• Custom Dimensions:"
echo "  threat-radar visualize graph graph.graphml --width 1920 --height 1080"
echo ""
echo "• Hide Labels (cleaner view):"
echo "  threat-radar visualize graph graph.graphml --no-labels"
echo ""
echo "• Auto-open in browser:"
echo "  threat-radar visualize graph graph.graphml --open"
echo ""

if [ "$DEMO_MODE" = "run" ]; then
    echo "Results saved to: demo-07-results/"
    echo ""
    echo "To view visualizations:"
    echo "  open demo-07-results/*.html"
else
    echo "Install plotly to generate visualizations:"
    echo "  pip install plotly kaleido"
fi

echo ""
echo "✓ Demo Complete"
