#!/bin/bash
# Demo: Comprehensive Reporting
# Shows report generation in multiple formats and detail levels

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Demo: Comprehensive Reporting                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Demonstrates: threat-radar report generate"
echo "Use case: Creating security reports for different audiences"
echo ""

mkdir -p demo-08-results

SERVICE="paymentservice"
if [ ! -f "demo-02-results/${SERVICE}_scan.json" ]; then
    echo "Running CVE scan first..."
    IMAGE="us-central1-docker.pkg.dev/google-samples/microservices-demo/paymentservice:v0.10.3"
    mkdir -p demo-02-results
    threat-radar cve scan-image "$IMAGE" -o "demo-02-results/${SERVICE}_scan.json"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Detailed HTML Report (for Security Teams)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Press Enter to generate..."
read

threat-radar report generate "demo-02-results/${SERVICE}_scan.json" \
    -o "demo-08-results/${SERVICE}_detailed.html" \
    -f html \
    --level detailed

echo ""
echo "✓ Detailed HTML report generated"
echo "  View: open demo-08-results/${SERVICE}_detailed.html"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Executive Summary Markdown (for Leadership)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar report generate "demo-02-results/${SERVICE}_scan.json" \
    -o "demo-08-results/${SERVICE}_executive.md" \
    -f markdown \
    --level executive

echo ""
echo "Executive Summary:"
cat "demo-08-results/${SERVICE}_executive.md"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3: Summary Report JSON (for Dashboards)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar report generate "demo-02-results/${SERVICE}_scan.json" \
    -o "demo-08-results/${SERVICE}_summary.json" \
    -f json \
    --level summary

echo "Summary (key metrics):"
jq '{total: .summary.total_vulnerabilities, critical: .summary.critical, high: .summary.high, medium: .summary.medium}' \
    demo-08-results/${SERVICE}_summary.json

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4: Critical-Only Report (for Incident Response)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar report generate "demo-02-results/${SERVICE}_scan.json" \
    -o "demo-08-results/${SERVICE}_critical_only.json" \
    -f json \
    --level critical-only

CRITICAL_COUNT=$(jq '.summary.critical' demo-08-results/${SERVICE}_critical_only.json)
echo "Critical vulnerabilities found: $CRITICAL_COUNT"

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo ""
    echo "Critical CVEs:"
    jq -r '.findings[] | "  • \(.cve_id): \(.package_name) - CVSS \(.cvss_score)"' \
        demo-08-results/${SERVICE}_critical_only.json | head -5
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 5: Dashboard Data Export (for Grafana/Splunk)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

threat-radar report dashboard-export "demo-02-results/${SERVICE}_scan.json" \
    -o "demo-08-results/${SERVICE}_dashboard.json"

echo "Dashboard data structure:"
jq 'keys' demo-08-results/${SERVICE}_dashboard.json

echo ""
echo "Summary cards:"
jq '.summary_cards' demo-08-results/${SERVICE}_dashboard.json

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "REPORT FORMATS & USE CASES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "┌─────────────┬──────────────┬─────────────────────────────┐"
echo "│ Format      │ Level        │ Audience                    │"
echo "├─────────────┼──────────────┼─────────────────────────────┤"
echo "│ HTML        │ Detailed     │ Security engineers          │"
echo "│ Markdown    │ Executive    │ CTO, CISO, executives       │"
echo "│ JSON        │ Summary      │ Dashboards, automation      │"
echo "│ JSON        │ Critical     │ Incident response teams     │"
echo "│ PDF         │ Executive    │ Board meetings, auditors    │"
echo "└─────────────┴──────────────┴─────────────────────────────┘"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ADVANCED FEATURES (Not Shown)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "• PDF Export (requires: pip install weasyprint)"
echo "  threat-radar report generate scan.json -o report.pdf -f pdf"
echo ""
echo "• AI Executive Summary (requires: AI provider setup)"
echo "  threat-radar report generate scan.json --ai-provider openai"
echo ""
echo "• Report Comparison (track remediation progress)"
echo "  threat-radar report compare old.json new.json"
echo ""
echo "• Attack Path Integration"
echo "  threat-radar report generate scan.json --attack-paths paths.json"
echo ""

echo "Results saved to: demo-08-results/"
echo ""
echo "✓ Demo Complete"
