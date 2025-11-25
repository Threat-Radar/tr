#!/bin/bash
# Demo: AI-Powered Vulnerability Analysis
# Shows intelligent vulnerability analysis, prioritization, and remediation

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
echo "║  Demo: AI-Powered Vulnerability Analysis                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Demonstrates: threat-radar ai commands"
echo "Use case: Intelligent prioritization and remediation guidance"
echo ""

# Check for AI provider
if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ] && [ "$AI_PROVIDER" != "ollama" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "⚠ AI PROVIDER NOT CONFIGURED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "To use AI features, configure one of the following:"
    echo ""
    echo "Option 1: OpenAI"
    echo "  export OPENAI_API_KEY=sk-your-key-here"
    echo "  export AI_PROVIDER=openai"
    echo "  export AI_MODEL=gpt-4o"
    echo ""
    echo "Option 2: Anthropic Claude"
    echo "  export ANTHROPIC_API_KEY=sk-ant-your-key-here"
    echo "  export AI_PROVIDER=anthropic"
    echo "  export AI_MODEL=claude-3-5-sonnet-20241022"
    echo ""
    echo "Option 3: OpenRouter (multiple providers)"
    echo "  export OPENROUTER_API_KEY=sk-or-v1-your-key-here"
    echo "  export AI_PROVIDER=openrouter"
    echo "  export AI_MODEL=anthropic/claude-3.5-sonnet"
    echo ""
    echo "Option 4: Ollama (local, free)"
    echo "  brew install ollama"
    echo "  ollama pull llama2"
    echo "  export AI_PROVIDER=ollama"
    echo "  export AI_MODEL=llama2"
    echo ""
    echo "This demo will show the commands without executing them."
    echo ""
    DEMO_MODE="show"
else
    echo "✓ AI Provider configured: $AI_PROVIDER"
    echo ""
    DEMO_MODE="run"
fi

mkdir -p demo-06-results

SERVICE="paymentservice"
if [ ! -f "demo-02-results/${SERVICE}_scan.json" ]; then
    echo "Running CVE scan first..."
    IMAGE="us-central1-docker.pkg.dev/google-samples/microservices-demo/paymentservice:v0.10.3"
    mkdir -p demo-02-results
    threat-radar cve scan-image "$IMAGE" -o "demo-02-results/${SERVICE}_scan.json"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: AI Vulnerability Analysis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Analyzes: Exploitability, attack vectors, business impact"
echo ""

CMD="threat-radar ai analyze demo-02-results/${SERVICE}_scan.json \
    -o demo-06-results/${SERVICE}_analysis.json \
    --batch-mode auto"

if [ "$DEMO_MODE" = "run" ]; then
    echo "Press Enter to run AI analysis..."
    read
    eval $CMD

    echo ""
    echo "Analysis Summary:"
    jq '{total_vulnerabilities: (.vulnerabilities | length), critical: [.vulnerabilities[] | select(.exploitability=="CRITICAL")] | length, high: [.vulnerabilities[] | select(.exploitability=="HIGH")] | length, medium: [.vulnerabilities[] | select(.exploitability=="MEDIUM")] | length}' \
        demo-06-results/${SERVICE}_analysis.json

    echo ""
    echo "AI Summary:"
    jq -r '.summary' demo-06-results/${SERVICE}_analysis.json | fold -w 80 -s
else
    echo "Command (not executed):"
    echo "  $CMD"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: AI Prioritization"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Creates: Ranked vulnerability list by business risk"
echo ""

CMD="threat-radar ai prioritize demo-02-results/${SERVICE}_scan.json \
    -o demo-06-results/${SERVICE}_priorities.json \
    --top 20"

if [ "$DEMO_MODE" = "run" ]; then
    echo "Press Enter to generate priorities..."
    read
    eval $CMD

    echo ""
    echo "Top 5 Priority Vulnerabilities:"
    jq -r '(.priority_levels.critical + .priority_levels.high)[:5] | to_entries[] | "  \(.key + 1). \(.value.cve_id) (\(.value.package_name)) - Urgency: \(.value.urgency_score)\n     \(.value.reason[:100])..."' \
        demo-06-results/${SERVICE}_priorities.json
else
    echo "Command (not executed):"
    echo "  $CMD"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3: AI Remediation Guidance"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Generates: Actionable fix recommendations with commands"
echo ""

CMD="threat-radar ai remediate demo-02-results/${SERVICE}_scan.json \
    -o demo-06-results/${SERVICE}_remediation.json"

if [ "$DEMO_MODE" = "run" ]; then
    echo "Press Enter to generate remediation plan..."
    read
    eval $CMD

    echo ""
    echo "Sample Remediation Plans:"
    jq -r '.remediations[:3] | .[] | "CVE: \(.cve_id)\nPackage: \(.package_name) (\(.current_version) → \(.fixed_version))\nUpgrade: \(.upgrade_command)\nEffort: \(.estimated_effort)\n"' \
        demo-06-results/${SERVICE}_remediation.json
else
    echo "Command (not executed):"
    echo "  $CMD"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4: Business Context-Aware Analysis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Combines: Vulnerability data + environment business context"
echo ""

# Check if environment config exists
if [ -f "demo-03-results/production-environment.json" ]; then
    CMD="threat-radar ai analyze-with-context \
        demo-02-results/${SERVICE}_scan.json \
        demo-03-results/production-environment.json \
        --provider \${AI_PROVIDER} \
        --model \${AI_MODEL} \
        -o demo-06-results/${SERVICE}_business_analysis.json"

    if [ "$DEMO_MODE" = "run" ]; then
        echo "Press Enter to run business context analysis..."
        read
        eval $CMD

        echo ""
        echo "Business Risk Scores (combines CVSS + asset criticality):"
        jq -r '.business_assessments[:5] | .[] | "  \(.cve_id): CVSS \(.cvss_score) → Business Risk \(.business_risk_score) (\(.business_risk_level))"' \
            demo-06-results/${SERVICE}_business_analysis.json 2>/dev/null || echo "  (Analysis complete - see output file)"
    else
        echo "Command (not executed):"
        echo "  $CMD"
    fi
else
    echo "⚠️  Environment config not found. Run demo 03-environment-context.sh first."
    echo ""
    echo "This feature combines vulnerability scan data with:"
    echo "  • Asset criticality levels (critical/high/medium/low)"
    echo "  • Data classification (PCI, PHI, PII, confidential)"
    echo "  • Network exposure (internet-facing vs internal)"
    echo "  • Compliance requirements (PCI-DSS, HIPAA, GDPR)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 5: AI Threat Modeling"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Generates: Realistic attack scenarios based on vulnerabilities"
echo ""

# Check if infrastructure graph exists first
if [ -f "demo-03-results/infrastructure-graph.graphml" ]; then
    GRAPH_FILE="demo-03-results/infrastructure-graph.graphml"
    echo "Using infrastructure graph with business context: $GRAPH_FILE"
else
    echo "⚠️  No graph file found."
    echo ""
    echo "Threat modeling requires a graph database with:"
    echo "  • Vulnerability relationships"
    echo "  • Asset topology (optional but recommended)"
    echo "  • Business context (optional but recommended)"
    GRAPH_FILE=""
fi

if [ "$DEMO_MODE" = "run" ] && [ -n "$GRAPH_FILE" ]; then
    echo ""
    echo "Press Enter to generate threat model..."
    read

    threat-radar ai threat-model "$GRAPH_FILE" \
        -o demo-06-results/${SERVICE}_threat_model.json

    echo ""
    echo "Sample Attack Scenarios:"
    jq -r '.attack_scenarios[:2] | .[] | "Scenario: \(.title)\nLikelihood: \(.likelihood)\nImpact: \(.impact)\nDescription: \(.description[:150])...\n"' \
        demo-06-results/${SERVICE}_threat_model.json 2>/dev/null || echo "  (Threat model complete - see output file)"
elif [ "$DEMO_MODE" != "run" ]; then
    echo "Command (not executed):"
    echo "  threat-radar ai threat-model demo-03-results/infrastructure-graph.graphml -o demo-06-results/${SERVICE}_threat_model.json"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "AI ANALYSIS FEATURES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Vulnerability Analysis (ai analyze)"
echo "   → Exploitability assessment (HIGH/MEDIUM/LOW)"
echo "   → Attack vector identification"
echo "   → Business impact evaluation"
echo "   → Contextual recommendations"
echo ""
echo "2. Prioritization (ai prioritize)"
echo "   → Risk-based ranking (not just CVSS)"
echo "   → Business criticality scoring"
echo "   → Quick wins identification"
echo "   → Remediation timeline suggestions"
echo ""
echo "3. Remediation Guidance (ai remediate)"
echo "   → Specific version upgrades"
echo "   → Package manager commands"
echo "   → Workarounds when patches unavailable"
echo "   → Testing recommendations"
echo ""
echo "4. Business Context Analysis (ai analyze-with-context)"
echo "   → Combines technical severity + business impact"
echo "   → Asset criticality scoring (critical/high/medium/low)"
echo "   → Data sensitivity awareness (PCI, PHI, PII)"
echo "   → Compliance impact assessment (PCI-DSS, HIPAA, GDPR)"
echo "   → Network exposure consideration"
echo ""
echo "5. Threat Modeling (ai threat-model)"
echo "   → Realistic attack scenario generation"
echo "   → Likelihood and impact assessment"
echo "   → Attack chain analysis"
echo "   → Mitigation strategy recommendations"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ADVANCED OPTIONS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "• Severity Filtering (analyze only critical):"
echo "  threat-radar ai analyze scan.json --severity critical"
echo ""
echo "• Custom Batch Size (for large scans):"
echo "  threat-radar ai analyze scan.json --batch-size 20"
echo ""
echo "• Disable Progress Bar (for CI/CD):"
echo "  threat-radar ai analyze scan.json --no-progress"
echo ""
echo "• Auto-save Results:"
echo "  threat-radar ai analyze scan.json --auto-save"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SUPPORTED AI PROVIDERS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. OpenAI (Cloud)"
echo "   Models: gpt-4o, gpt-4-turbo"
echo "   Best for: High accuracy, structured outputs"
echo ""
echo "2. Anthropic Claude (Cloud)"
echo "   Models: claude-3-5-sonnet, claude-3-opus"
echo "   Best for: Deep reasoning, complex analysis"
echo ""
echo "3. OpenRouter (Cloud - Unified API)"
echo "   Models: 100+ models from multiple providers"
echo "   Best for: Cost optimization, fallbacks"
echo ""
echo "4. Ollama (Local)"
echo "   Models: llama2, mistral, codellama"
echo "   Best for: Privacy, no API costs"
echo ""

echo "Results saved to: demo-06-results/"
echo ""
echo "✓ Demo Complete"
