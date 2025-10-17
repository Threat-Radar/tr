# Threat Radar Reporting Guide

**Complete guide to vulnerability reporting with Threat Radar**

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Report Types](#report-types)
- [Output Formats](#output-formats)
- [AI-Powered Features](#ai-powered-features)
- [Dashboard Integration](#dashboard-integration)
- [Practical Workflows](#practical-workflows)
- [API Reference](#api-reference)
- [Best Practices](#best-practices)

---

## Overview

Threat Radar's comprehensive reporting system transforms vulnerability scan results into actionable intelligence for different audiences:

- **Executives**: High-level risk assessment and business impact
- **Security Teams**: Detailed vulnerability analysis and remediation plans
- **Developers**: Actionable fix recommendations and upgrade paths
- **Compliance**: Audit-ready documentation and compliance mapping
- **Operations**: Dashboard-ready metrics for monitoring

### Key Features

✅ **AI-Powered Executive Summaries** - Risk ratings, compliance impact, business context
✅ **Multiple Output Formats** - JSON, Markdown, HTML for different use cases
✅ **Report Levels** - Executive, Summary, Detailed, Critical-only
✅ **Dashboard Data** - Visualization-ready structures for Grafana, custom dashboards
✅ **Trend Analysis** - Compare reports over time to track improvements
✅ **Risk Assessment** - Uses existing AI prompt templates for consistency

---

## Quick Start

### 1. Generate Your First Report

```bash
# Scan an image
threat-radar cve scan-image alpine:3.18 -o scan.json

# Generate HTML report
threat-radar report generate scan.json -o report.html -f html

# View it
open report.html
```

### 2. Generate Executive Summary

```bash
# With AI (requires OpenAI API key or Ollama)
threat-radar report generate scan.json -o exec-summary.md -f markdown --level executive

# Without AI (uses fallback summary)
threat-radar report generate scan.json -o summary.md -f markdown --level executive --no-executive
```

### 3. Export Dashboard Data

```bash
# Extract visualization-ready data
threat-radar report dashboard-export scan.json -o dashboard.json
```

---

## Report Types

### Executive Summary (`--level executive`)

**Audience:** C-suite, Board members, Non-technical stakeholders

**Contains:**
- Overall risk rating (CRITICAL, HIGH, MEDIUM, LOW)
- 3-5 key findings in business terms
- Immediate actions required (prioritized)
- Compliance impact (PCI-DSS, HIPAA, SOC 2, etc.)
- Business context and operational impact
- Estimated remediation effort (LOW, MEDIUM, HIGH)
- Timeline (days to patch critical issues)

**Best Format:** Markdown (for email/Slack) or HTML (for presentation)

**Example:**
```bash
threat-radar report generate scan.json \
  -o exec-summary.md \
  -f markdown \
  --level executive \
  --ai-provider openai
```

**Output Includes:**
```
# Vulnerability Scan Report

Overall Risk Rating: HIGH

Key Findings:
1. Critical remote code execution vulnerability (Likelihood: HIGH, Impact: HIGH)
2. Multiple high-severity issues in core infrastructure packages
3. 40% of vulnerabilities have no available patches

Immediate Actions Required:
1. Upgrade OpenSSL to version 1.1.1w within 48 hours
2. Implement network segmentation for affected services
3. Review and update incident response procedures

Compliance Impact:
May impact compliance with: PCI-DSS, SOC 2, ISO 27001
```

---

### Detailed Report (`--level detailed`)

**Audience:** Security engineers, DevOps teams

**Contains:**
- All vulnerabilities with complete details
- Package-level groupings
- CVSS scores and severity ratings
- CVE descriptions and references
- Fix availability and upgrade paths
- Dashboard visualization data
- Remediation recommendations

**Best Format:** HTML (for review) or JSON (for automation)

**Example:**
```bash
threat-radar report generate scan.json \
  -o detailed-report.html \
  -f html \
  --level detailed
```

---

### Summary Report (`--level summary`)

**Audience:** Development teams, Project managers

**Contains:**
- Vulnerability statistics
- Top vulnerable packages
- Critical/High severity findings
- Quick remediation recommendations
- Key metrics and trends

**Best Format:** Markdown or HTML

**Example:**
```bash
threat-radar report generate scan.json \
  -o summary.md \
  -f markdown \
  --level summary
```

---

### Critical-Only Report (`--level critical-only`)

**Audience:** Incident response teams, On-call engineers

**Contains:**
- Only CRITICAL and HIGH severity vulnerabilities
- Immediate action items
- Priority remediation guidance
- Focused, actionable information

**Best Format:** JSON (for automation) or Markdown (for tickets)

**Example:**
```bash
threat-radar report generate scan.json \
  -o critical.json \
  --level critical-only

# Use in CI/CD to fail on critical issues
CRITICAL_COUNT=$(jq '.summary.critical' critical.json)
if [ $CRITICAL_COUNT -gt 0 ]; then
  echo "❌ $CRITICAL_COUNT critical vulnerabilities found!"
  cat critical.json | jq '.findings[] | select(.severity=="critical") | .cve_id'
  exit 1
fi
```

---

## Output Formats

### JSON Format (`-f json`)

**Use Cases:**
- API integrations
- Automated processing
- Data warehousing
- CI/CD pipelines

**Advantages:**
- Complete data structure
- Easy parsing
- Machine-readable
- Programmatic access

**Example:**
```bash
threat-radar report generate scan.json -o report.json -f json

# Parse with jq
jq '.summary.total_vulnerabilities' report.json
jq '.findings[] | select(.severity=="critical")' report.json
```

**Structure:**
```json
{
  "report_id": "vuln-report-abc123",
  "generated_at": "2024-01-15T10:30:00",
  "target": "alpine:3.18",
  "summary": {
    "total_vulnerabilities": 45,
    "critical": 5,
    "high": 12,
    "average_cvss_score": 6.8
  },
  "findings": [...],
  "packages": [...],
  "dashboard_data": {...}
}
```

---

### Markdown Format (`-f markdown`)

**Use Cases:**
- Documentation
- GitHub/GitLab issues
- Slack/Teams messages
- Version control

**Advantages:**
- Human-readable
- Version control friendly
- Platform-agnostic
- Easy to share

**Example:**
```bash
threat-radar report generate scan.json -o report.md -f markdown

# Create GitHub issue
gh issue create \
  --title "Weekly Vulnerability Scan Results" \
  --body-file report.md
```

**Features:**
- Severity icons (🔴 🟠 🟡)
- ASCII charts for distributions
- Formatted tables
- Clickable CVE links

---

### HTML Format (`-f html`)

**Use Cases:**
- Executive presentations
- Team reviews
- Audit reports
- Client deliverables

**Advantages:**
- Beautiful styling
- No external dependencies
- Print-friendly
- Interactive tables

**Example:**
```bash
threat-radar report generate scan.json -o report.html -f html

# Open in browser
open report.html
```

**Features:**
- Modern CSS styling
- Color-coded severity levels
- Collapsible sections
- Responsive design
- Dark/light mode support (via browser)

---

## AI-Powered Features

### Executive Summary with AI

The AI integration uses the existing `RISK_ASSESSMENT_PROMPT` template from `threat_radar/ai/prompt_templates.py` to generate:

1. **Risk Assessment** - Overall risk score (0-100) and level
2. **Key Risks** - Identified risks with likelihood and impact
3. **Compliance Concerns** - Specific frameworks (PCI-DSS, HIPAA, etc.)
4. **Recommended Actions** - Prioritized by CRITICAL/HIGH/MEDIUM/LOW
5. **Risk Summary** - Executive-level description

**Configuration:**

```bash
# OpenAI (Cloud)
export OPENAI_API_KEY=sk-your-key-here
export AI_PROVIDER=openai
export AI_MODEL=gpt-4

# Ollama (Local)
export AI_PROVIDER=ollama
export AI_MODEL=llama2
```

**Example with AI:**
```bash
threat-radar report generate scan.json \
  -o ai-report.html \
  -f html \
  --level executive \
  --ai-provider openai \
  --ai-model gpt-4
```

**Fallback Behavior:**
If AI is unavailable, the system automatically generates a fallback executive summary based on:
- Vulnerability counts and severity distribution
- CVSS scores
- Fix availability
- Package health

---

## Dashboard Integration

### Dashboard Data Structure

The `DashboardData` object provides visualization-ready metrics:

```python
{
  "summary_cards": {
    "total_vulnerabilities": 45,
    "critical_vulnerabilities": 5,
    "average_cvss_score": 6.8,
    "fix_available_percentage": 75.5
  },
  "severity_distribution_chart": [
    {"severity": "Critical", "count": 5, "color": "#dc2626"},
    {"severity": "High", "count": 12, "color": "#ea580c"}
  ],
  "top_vulnerable_packages_chart": [...],
  "cvss_score_histogram": [...],
  "fix_availability_pie": {...},
  "package_type_breakdown": [...],
  "critical_items": [...]
}
```

### Grafana Integration

```bash
# Export dashboard data
threat-radar report dashboard-export scan.json -o dashboard.json

# Transform for Grafana
jq '.summary_cards' dashboard.json > grafana-metrics.json
```

**Grafana Panel Examples:**

1. **Severity Distribution (Pie Chart)**
   ```json
   {
     "type": "piechart",
     "dataFormat": "table",
     "values": [5, 12, 18, 10],
     "labels": ["Critical", "High", "Medium", "Low"]
   }
   ```

2. **CVSS Score Trend (Time Series)**
   - Use historical dashboard exports
   - Plot average_cvss_score over time

3. **Top Vulnerable Packages (Bar Chart)**
   ```json
   {
     "type": "bargauge",
     "data": dashboard.top_vulnerable_packages_chart
   }
   ```

### Custom Dashboards (React/Vue)

```javascript
// Load dashboard data
import dashboardData from './dashboard.json';

// Render summary cards
dashboardData.summary_cards.map(card => (
  <Card title={card.title} value={card.value} />
));

// Severity chart
<PieChart
  data={dashboardData.severity_distribution_chart}
  dataKey="count"
  nameKey="severity"
  colors={data => data.color}
/>
```

---

## Practical Workflows

### Workflow 1: Weekly Security Review

**Goal:** Regular vulnerability assessment for production systems

```bash
#!/bin/bash
# weekly-security-review.sh

WEEK=$(date +%Y-W%U)
IMAGE="prod-app:latest"

echo "Starting weekly security review for $WEEK..."

# 1. Scan production image
threat-radar cve scan-image $IMAGE \
  -o scans/scan-${WEEK}.json \
  --auto-save

# 2. Generate executive summary for leadership
threat-radar report generate scans/scan-${WEEK}.json \
  -o reports/exec-${WEEK}.md \
  -f markdown \
  --level executive

# 3. Generate detailed HTML for security team
threat-radar report generate scans/scan-${WEEK}.json \
  -o reports/detailed-${WEEK}.html \
  -f html \
  --level detailed

# 4. Export dashboard data for monitoring
threat-radar report dashboard-export scans/scan-${WEEK}.json \
  -o dashboards/dashboard-${WEEK}.json

# 5. Compare with last week
if [ -f "scans/scan-${LAST_WEEK}.json" ]; then
  threat-radar report compare \
    scans/scan-${LAST_WEEK}.json \
    scans/scan-${WEEK}.json \
    -o reports/trend-${WEEK}.json
fi

# 6. Send notifications
send_slack_notification reports/exec-${WEEK}.md
send_email_report reports/detailed-${WEEK}.html

echo "✅ Weekly security review complete!"
```

---

### Workflow 2: CI/CD Pipeline Integration

**Goal:** Automated vulnerability checking in deployment pipeline

```yaml
# .github/workflows/security-scan.yml

name: Security Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  vulnerability-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Scan for vulnerabilities
        run: |
          threat-radar cve scan-image myapp:${{ github.sha }} \
            -o scan-results.json \
            --cleanup

      - name: Generate critical-only report
        run: |
          threat-radar report generate scan-results.json \
            -o critical-report.json \
            --level critical-only

      - name: Check for critical vulnerabilities
        run: |
          CRITICAL=$(jq '.summary.critical' critical-report.json)
          if [ $CRITICAL -gt 0 ]; then
            echo "❌ Found $CRITICAL critical vulnerabilities!"
            jq '.findings[]' critical-report.json
            exit 1
          fi

      - name: Upload scan artifacts
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: |
            scan-results.json
            critical-report.json
```

---

### Workflow 3: Compliance Reporting

**Goal:** Generate audit-ready compliance documentation

```bash
#!/bin/bash
# compliance-report.sh

QUARTER=$(date +%Y-Q$(( ($(date +%-m)-1)/3+1 )))

echo "Generating compliance report for $QUARTER..."

# Scan all production images
for IMAGE in $(cat production-images.txt); do
  echo "Scanning $IMAGE..."

  threat-radar cve scan-image $IMAGE \
    -o "compliance/${IMAGE//:/─}-scan.json" \
    --auto-save

  threat-radar report generate "compliance/${IMAGE//:/─}-scan.json" \
    -o "compliance/${IMAGE//:/─}-report.html" \
    -f html \
    --level detailed \
    --ai-provider openai
done

# Generate consolidated compliance report
python3 << EOF
import json
import glob
from pathlib import Path

# Aggregate results
all_scans = []
for scan_file in glob.glob('compliance/*-scan.json'):
    with open(scan_file) as f:
        all_scans.append(json.load(f))

# Calculate compliance metrics
total_vulnerabilities = sum(s['total_vulnerabilities'] for s in all_scans)
critical_vulns = sum(s['severity_counts'].get('critical', 0) for s in all_scans)

# Generate compliance summary
summary = {
    'quarter': '$QUARTER',
    'total_images_scanned': len(all_scans),
    'total_vulnerabilities': total_vulnerabilities,
    'critical_vulnerabilities': critical_vulns,
    'compliance_status': 'PASS' if critical_vulns == 0 else 'FAIL',
    'scan_dates': [s['scan_metadata']['timestamp'] for s in all_scans],
}

Path('compliance/summary-$QUARTER.json').write_text(json.dumps(summary, indent=2))
EOF

echo "✅ Compliance report generated: compliance/summary-$QUARTER.json"
```

---

## API Reference

### Python API

```python
from threat_radar.utils import (
    ComprehensiveReportGenerator,
    ReportLevel,
    get_formatter,
)

# Initialize generator
generator = ComprehensiveReportGenerator(
    ai_provider="openai",  # or "ollama"
    ai_model="gpt-4",      # or "llama2"
)

# Generate report
report = generator.generate_report(
    scan_result=scan_result,
    report_level=ReportLevel.DETAILED,
    include_executive_summary=True,
    include_dashboard_data=True,
)

# Access report data
print(f"Total vulnerabilities: {report.summary.total_vulnerabilities}")
print(f"Critical: {report.summary.critical}")
print(f"Risk rating: {report.executive_summary.overall_risk_rating}")

# Filter critical only
critical_report = report.filter_critical_only()

# Get summary view
summary_view = report.get_summary_view()

# Format output
formatter = get_formatter("html")
html_output = formatter.format(report)

# Save
Path("report.html").write_text(html_output)
```

---

## Best Practices

### For Executives
✅ Use `--level executive` for concise summaries
✅ Enable AI for better business context
✅ Export to Markdown for Slack/Teams sharing
✅ Focus on risk rating and immediate actions
✅ Review compliance impact section

### For Security Teams
✅ Use `--level detailed` for complete analysis
✅ Export dashboard data for monitoring
✅ Compare reports weekly for trend analysis
✅ Automate report generation
✅ Archive reports with `--auto-save`

### For Developers
✅ Use `--level critical-only` in CI/CD
✅ Export to JSON for tool integration
✅ Set up automated Slack notifications
✅ Focus on fixable vulnerabilities
✅ Track remediation progress

### For Compliance
✅ Generate full HTML reports quarterly
✅ Use AI to identify compliance frameworks
✅ Archive all reports for audit trails
✅ Document remediation timelines
✅ Track metrics over time

---

## Troubleshooting

### AI Not Generating Summaries

**Problem:** `--executive` flag doesn't generate AI summary

**Solutions:**
1. Check API key: `echo $OPENAI_API_KEY`
2. Verify provider: `echo $AI_PROVIDER`
3. Test Ollama: `ollama list`
4. Use fallback: Add `--no-executive` flag

### Report is Empty

**Problem:** Generated report has no vulnerabilities

**Solutions:**
1. Check scan results: `jq '.total_vulnerabilities' scan.json`
2. Verify scan completed successfully
3. Check report level (critical-only might filter all)

### Dashboard Data Missing

**Problem:** `dashboard_data` is null in report

**Solutions:**
1. Add `--dashboard` flag
2. Check report generation: `include_dashboard_data=True`
3. Verify scan results have data

---

## Additional Resources

- [Examples](../../examples/05_reporting/) - Working code examples
- [CLAUDE.md](../../CLAUDE.md) - Complete documentation
- [CLI Reference](../../examples/CLI_EXAMPLES.md) - Command-line usage
- [API Documentation](../../docs/API.md) - Python API reference

---

**Last Updated:** 2024-01-15
**Version:** 1.0.0
