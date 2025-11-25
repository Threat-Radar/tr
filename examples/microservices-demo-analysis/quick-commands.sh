#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Quick Commands for Microservices Demo Analysis
# ═══════════════════════════════════════════════════════════════════
#
# This file provides quick shortcut commands for common workflows.
# Source this file or run commands directly.
#
# USAGE:
#   # Run a specific shortcut
#   ./quick-commands.sh viz-only
#
#   # Or source it for aliases in your shell
#   source quick-commands.sh
#   demo-viz
#
# ═══════════════════════════════════════════════════════════════════

# Change to the demo-scripts directory
cd "$(dirname "$0")"

# Full analysis with all features
demo-full() {
    echo "🚀 Running full analysis with all features..."
    RUN_ALL=true ./00-run-all-services.sh
}

# Only visualizations (fastest - assumes data exists)
demo-viz() {
    echo "📊 Generating visualizations only..."
    SKIP_SCANS=true SKIP_GRAPHS=true SKIP_ATTACK_PATHS=true SKIP_AI=true \
    RUN_VISUALIZATIONS=true ./00-run-all-services.sh
}

# Rebuild graphs and attack paths (skip scans)
demo-graphs() {
    echo "🕸️  Rebuilding graphs and attack paths..."
    SKIP_SCANS=true RUN_VISUALIZATIONS=true ./00-run-all-services.sh
}

# AI analysis only
demo-ai() {
    echo "🤖 Running AI analysis only..."
    SKIP_SCANS=true SKIP_GRAPHS=true SKIP_ATTACK_PATHS=true \
    RUN_RISK_ASSESSMENT=true \
    RUN_REMEDIATION=true \
    RUN_PRIORITIES=true \
    RUN_THREAT_MODEL=true \
    ./00-run-all-services.sh
}

# Scans only (no AI, no visualizations)
demo-scans() {
    echo "🔍 Running scans only..."
    ./00-run-all-services.sh
}

# Full analysis without AI (faster)
demo-no-ai() {
    echo "🚀 Running full analysis (no AI)..."
    SKIP_AI=true RUN_VISUALIZATIONS=true ./00-run-all-services.sh
}

# Attack paths only
demo-attacks() {
    echo "⚔️  Analyzing attack paths only..."
    SKIP_SCANS=true SKIP_GRAPHS=true RUN_VISUALIZATIONS=true ./00-run-all-services.sh
}

# Show help
demo-help() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║  Microservices Demo - Quick Commands                      ║
╚══════════════════════════════════════════════════════════════╝

Available commands:

  demo-full       Full analysis with all features (~15-20 min)
                  - Scans + Graphs + Attacks + AI + Visualizations

  demo-viz        Visualizations only (~30-60 sec)
                  - Uses existing data, regenerates visualizations
                  - Fastest option!

  demo-graphs     Rebuild graphs and attack paths (~2-3 min)
                  - Skip scans, rebuild everything else
                  - Useful after config changes

  demo-ai         AI analysis only (~5-8 min)
                  - Risk assessment, remediation, priorities
                  - Requires AI provider configured

  demo-scans      Scans only (~10-12 min)
                  - Just scan services, no analysis

  demo-no-ai      Full analysis without AI (~8-10 min)
                  - Faster than full, skips AI features

  demo-attacks    Attack path analysis only (~1-2 min)
                  - Skip scans and graphs, find attack paths

  demo-help       Show this help message

USAGE:

  Option 1: Run directly
    ./quick-commands.sh demo-viz

  Option 2: Source and use as functions
    source quick-commands.sh
    demo-viz

  Option 3: Add to ~/.bashrc or ~/.zshrc
    echo 'source /path/to/quick-commands.sh' >> ~/.bashrc

For more details, see STAGE_SKIP_GUIDE.md

EOF
}

# If script is run with an argument, execute that command
if [ -n "$1" ]; then
    case "$1" in
        demo-full|full)
            demo-full
            ;;
        demo-viz|viz)
            demo-viz
            ;;
        demo-graphs|graphs)
            demo-graphs
            ;;
        demo-ai|ai)
            demo-ai
            ;;
        demo-scans|scans)
            demo-scans
            ;;
        demo-no-ai|no-ai)
            demo-no-ai
            ;;
        demo-attacks|attacks)
            demo-attacks
            ;;
        demo-help|help|--help|-h)
            demo-help
            ;;
        *)
            echo "Unknown command: $1"
            echo "Run './quick-commands.sh help' for usage"
            exit 1
            ;;
    esac
else
    # If no argument, show help
    demo-help
fi
