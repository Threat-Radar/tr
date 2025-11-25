#!/bin/bash
# Demo: Attack Path Discovery
# Shows attack surface analysis and exploitation route discovery

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Demo: Attack Path Discovery                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Demonstrates: threat-radar graph attack-* commands"
echo "Use case: Understanding real-world attack scenarios"
echo ""

mkdir -p demo-05-results

# Check if infrastructure graph exists
if [ ! -f "demo-03-results/infrastructure-graph.graphml" ]; then
    echo "⚠ Infrastructure graph not found."
    echo "Running Demo (Environment Context) first..."
    echo ""
    bash demo-scripts/06-environment-context.sh
fi

GRAPH="demo-03-results/infrastructure-graph.graphml"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Discover Attack Paths"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Finding shortest attack paths from entry points to critical assets..."
echo "Press Enter to continue..."
read

threat-radar graph attack-paths "$GRAPH" \
    --max-paths 20 \
    --max-length 10 \
    -o demo-05-results/attack-paths.json

echo ""
echo "Attack Paths Discovered:"
jq '{total_paths: (.attack_paths | length), critical_paths: [.attack_paths[] | select(.threat_level=="critical")] | length, high_paths: [.attack_paths[] | select(.threat_level=="high")] | length}' \
    demo-05-results/attack-paths.json

echo ""
echo "Sample Attack Path:"
jq -r '.attack_paths[0] | "  Path \(.path_id): \(.threat_level) threat\n  From: \(.entry_point)\n  To: \(.target)\n  Steps: \(.steps | length)\n  CVSS: \(.total_cvss)\n  Exploitability: \((.exploitability * 100) | floor)%"' \
    demo-05-results/attack-paths.json

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Privilege Escalation Analysis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Identifying privilege escalation opportunities..."

threat-radar graph privilege-escalation "$GRAPH" \
    --max-paths 15 \
    -o demo-05-results/privilege-escalation.json

echo ""
echo "Privilege Escalation Opportunities:"
jq '{total_opportunities: .total_escalations, easy_escalations: [.privilege_escalations[] | select(.difficulty=="easy")] | length}' \
    demo-05-results/privilege-escalation.json

if [ "$(jq '.total_escalations' demo-05-results/privilege-escalation.json)" -gt 0 ]; then
    echo ""
    echo "Sample Escalation Path:"
    jq -r '.privilege_escalations[0] | "  From: \(.from_privilege) → To: \(.to_privilege)\n  Difficulty: \(.difficulty)\n  CVEs exploited: \(.vulnerabilities | length)"' \
        demo-05-results/privilege-escalation.json
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3: Lateral Movement Detection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Detecting lateral movement opportunities between assets..."

threat-radar graph lateral-movement "$GRAPH" \
    --max-opportunities 20 \
    -o demo-05-results/lateral-movement.json

if [ -f "demo-05-results/lateral-movement.json" ]; then
    echo ""
    echo "Lateral Movement Opportunities:"
    jq '{total_opportunities: (.lateral_movements | length), hard_to_detect: [.lateral_movements[]? | select(.detection_difficulty=="hard")] | length}' \
        demo-05-results/lateral-movement.json 2>/dev/null || echo "  (No lateral movement data available)"

    if [ "$(jq '.lateral_movements | length' demo-05-results/lateral-movement.json 2>/dev/null || echo 0)" -gt 0 ]; then
        echo ""
        echo "Sample Lateral Movement:"
        jq -r '.lateral_movements[0] | "  From: \(.from_asset) → To: \(.to_asset)\n  Type: \(.movement_type)\n  Detection: \(.detection_difficulty)"' \
            demo-05-results/lateral-movement.json
    fi
else
    echo ""
    echo "Lateral Movement Opportunities: No opportunities found"
    echo "  (This is expected when assets are well-segmented)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4: Comprehensive Attack Surface Analysis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Generating complete attack surface report..."

threat-radar graph attack-surface "$GRAPH" \
    -o demo-05-results/attack-surface.json

echo ""
echo "Attack Surface Summary:"
jq '{total_risk_score: .total_risk_score, entry_points: (.entry_points | length), high_value_targets: (.high_value_targets | length), attack_paths: (.attack_paths | length), privilege_escalations: (.privilege_escalations | length), recommendations: (.recommendations | length)}' \
    demo-05-results/attack-surface.json

echo ""
echo "Entry Points:"
jq -r '.entry_points[] | "  • \(.)"' \
    demo-05-results/attack-surface.json

echo ""
echo "High-Value Targets:"
jq -r '.high_value_targets[] | "  • \(.)"' \
    demo-05-results/attack-surface.json

echo ""
echo "Top Security Recommendations:"
jq -r '.recommendations[:5] | .[] | "  • \(.)"' \
    demo-05-results/attack-surface.json

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ATTACK PATH ANALYSIS INSIGHTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Attack Paths"
echo "   → Shows actual exploitation routes attackers could use"
echo "   → Combines vulnerabilities + network topology + business context"
echo "   → Prioritizes by exploitability and business impact"
echo ""
echo "2. Privilege Escalation"
echo "   → Identifies ways to elevate from low to high privileges"
echo "   → Maps zone-to-zone escalation (DMZ → Internal → Trusted)"
echo "   → Rates difficulty (easy/medium/hard)"
echo ""
echo "3. Lateral Movement"
echo "   → Finds ways to move between assets in same security zone"
echo "   → Considers network access and shared credentials"
echo "   → Assesses detection difficulty"
echo ""
echo "4. Attack Surface"
echo "   → Comprehensive view of all attack vectors"
echo "   → Overall risk score (0-100)"
echo "   → Prioritized remediation recommendations"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ATTACK STEP TYPES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "• ENTRY_POINT - Initial access via exposed service"
echo "• EXPLOIT_VULNERABILITY - CVE exploitation"
echo "• PRIVILEGE_ESCALATION - Elevation to higher privileges"
echo "• LATERAL_MOVEMENT - Movement between assets"
echo "• TARGET_ACCESS - Final access to critical asset"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "USE CASES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Red Team Exercise Planning"
echo "   → Identify realistic attack scenarios"
echo ""
echo "2. Security Architecture Review"
echo "   → Find weaknesses in network segmentation"
echo ""
echo "3. Incident Response Preparation"
echo "   → Understand potential attack vectors in advance"
echo ""
echo "4. Compliance Demonstrations"
echo "   → Show auditors your threat model"
echo ""
echo "5. Defense Prioritization"
echo "   → Focus security controls on critical paths"
echo ""

echo "Results saved to: demo-05-results/"
echo ""
echo "✓ Demo Complete"
