# Reporting Examples

This directory contains comprehensive examples demonstrating the Threat Radar reporting capabilities.

## 📁 Examples Overview

### 01_basic_report_generation.py
**Basic report generation in multiple formats**

Demonstrates:
- Generating JSON reports for automation
- Creating Markdown reports for documentation
- Producing HTML reports for sharing
- Filtering critical-only vulnerabilities
- Exporting dashboard data

**Run:**
```bash
python examples/05_reporting/01_basic_report_generation.py
```

**Output:**
- `output/basic_report.json` - Structured JSON report
- `output/vulnerability_report.md` - Markdown documentation
- `output/vulnerability_report.html` - Styled HTML report
- `output/dashboard_data.json` - Visualization data

---

### 02_ai_powered_reports.py
**AI-enhanced reports with executive summaries**

Demonstrates:
- AI-powered executive summaries
- Risk assessment and compliance analysis
- Comparison with/without AI
- Using different AI providers (OpenAI, Ollama)
- Complete automated workflow

**Prerequisites:**
- Set `OPENAI_API_KEY` in `.env` for OpenAI
- OR install Ollama and set `AI_PROVIDER=ollama`

**Run:**
```bash
# With OpenAI
export OPENAI_API_KEY=your_key_here
python examples/05_reporting/02_ai_powered_reports.py

# With Ollama (local)
export AI_PROVIDER=ollama
export AI_MODEL=llama2
python examples/05_reporting/02_ai_powered_reports.py
```

**Output:**
- `output/executive_summary.md` - Executive report with AI insights
- `output/ai_full_report.json` - Complete JSON report
- `output/ai_full_report.md` - Markdown with AI analysis
- `output/ai_full_report.html` - HTML with AI insights
- `output/ai_dashboard_data.json` - Dashboard metrics

---

### 03_dashboard_integration.py
**Dashboard data structures and integrations**

Demonstrates:
- Extracting dashboard-ready data
- Grafana-compatible format
- React/JavaScript dashboard format
- Custom visualization metrics
- Risk score calculations

**Run:**
```bash
python examples/05_reporting/03_dashboard_integration.py
```

**Output:**
- `output/dashboard_structure.json` - Raw dashboard data
- `output/grafana_dashboard.json` - Grafana import format
- `output/react_dashboard_data.json` - React component data
- `output/custom_metrics.json` - Custom calculated metrics

---

## 🎯 Quick Start

### Generate Your First Report

1. **Scan a Docker image:**
   ```bash
   threat-radar cve scan-image alpine:3.18 -o scan-results.json
   ```

2. **Generate a report:**
   ```bash
   threat-radar report generate scan-results.json -o report.html -f html
   ```

3. **View the report:**
   ```bash
   open report.html  # macOS
   # or
   xdg-open report.html  # Linux
   ```

### Use in Python

```python
from threat_radar.utils import ComprehensiveReportGenerator, ReportLevel
from threat_radar.utils.report_formatters import get_formatter

# Load scan results
scan_result = load_scan_results("scan-results.json")

# Generate report
generator = ComprehensiveReportGenerator()
report = generator.generate_report(
    scan_result=scan_result,
    report_level=ReportLevel.DETAILED,
    include_executive_summary=True,
    include_dashboard_data=True,
)

# Format as HTML
formatter = get_formatter("html")
html_output = formatter.format(report)

# Save
Path("report.html").write_text(html_output)
```

---

## 📊 Report Types

### Executive Summary
**For:** C-level executives, board members
**Contains:**
- Overall risk rating (CRITICAL/HIGH/MEDIUM/LOW)
- Key findings (3-5 bullet points)
- Immediate actions required
- Compliance impact analysis
- Business context
- Estimated remediation effort and timeline

**Best Format:** Markdown or HTML

### Detailed Report
**For:** Security teams, developers
**Contains:**
- All vulnerabilities with full details
- Package-level groupings
- CVSS scores and severity ratings
- Fix availability and upgrade paths
- Dashboard visualization data
- Remediation recommendations

**Best Format:** HTML or JSON

### Critical-Only Report
**For:** Urgent response teams
**Contains:**
- Only CRITICAL and HIGH severity findings
- Immediate action items
- Priority remediation guidance

**Best Format:** JSON or Markdown

### Dashboard Data
**For:** Monitoring systems, custom dashboards
**Contains:**
- Summary cards (metrics)
- Chart data (pie, bar, histogram)
- Critical items list
- Package health metrics

**Best Format:** JSON

---

## 🎨 Output Formats

### JSON
```bash
threat-radar report generate scan.json -o report.json -f json
```
- ✅ Machine-readable
- ✅ API integration
- ✅ Complete data
- ✅ Easy parsing

### Markdown
```bash
threat-radar report generate scan.json -o report.md -f markdown
```
- ✅ Human-readable
- ✅ Version control friendly
- ✅ GitHub/GitLab compatible
- ✅ Severity icons and charts

### HTML
```bash
threat-radar report generate scan.json -o report.html -f html
```
- ✅ Beautiful styling
- ✅ No external dependencies
- ✅ Shareable via browser
- ✅ Print-friendly

---

## 🔧 Common Workflows

### Weekly Security Review
```bash
# 1. Scan production image
threat-radar cve scan-image prod-app:latest -o scan.json --auto-save

# 2. Generate executive summary
threat-radar report generate scan.json -o exec-summary.md -f markdown --level executive

# 3. Generate detailed HTML report
threat-radar report generate scan.json -o detailed-report.html -f html

# 4. Export dashboard data for monitoring
threat-radar report dashboard-export scan.json -o dashboard.json
```

### CI/CD Pipeline
```bash
# Scan and generate critical-only report
threat-radar cve scan-image $IMAGE:$TAG -o scan.json --cleanup
threat-radar report generate scan.json -o critical.json --level critical-only

# Fail if critical issues found
CRITICAL_COUNT=$(jq '.summary.critical' critical.json)
if [ $CRITICAL_COUNT -gt 0 ]; then
  echo "CRITICAL vulnerabilities found!"
  exit 1
fi
```

### Trend Monitoring
```bash
# Compare this week vs last week
threat-radar report compare last-week-scan.json this-week-scan.json -o trend.json

# Generate comparison report
threat-radar report generate this-week-scan.json -o progress.html -f html
```

---

## 💡 Tips & Best Practices

### For Executives
- Use `--level executive` for high-level summaries
- Enable AI for better insights: `--ai-provider openai`
- Export to Markdown for easy sharing in Slack/Teams

### For Security Teams
- Use `--level detailed` for complete analysis
- Export dashboard data for continuous monitoring
- Compare reports weekly to track progress

### For Developers
- Use `--level critical-only` to focus on urgent issues
- Export to JSON for integration with tools
- Automate report generation in CI/CD

### For Compliance
- Generate full HTML reports for audit trails
- Use AI to identify compliance frameworks
- Archive reports with `--auto-save`

---

## 🤖 AI Configuration

### OpenAI (Cloud)
```bash
# .env
OPENAI_API_KEY=sk-your-key-here
AI_PROVIDER=openai
AI_MODEL=gpt-4
```

### Ollama (Local)
```bash
# Install Ollama
brew install ollama  # macOS
# or visit https://ollama.ai

# Pull a model
ollama pull llama2

# Configure
export AI_PROVIDER=ollama
export AI_MODEL=llama2
```

---

## 📚 Additional Resources

- [CLAUDE.md](../../CLAUDE.md) - Full documentation
- [CLI Examples](../CLI_EXAMPLES.md) - Command-line usage
- [Troubleshooting](../TROUBLESHOOTING.md) - Common issues

---

## 🆘 Troubleshooting

### "No AI configuration detected"
**Solution:** Set up AI provider in `.env` or use `--no-executive` to skip AI

### "Module not found"
**Solution:** Install package: `pip install -e .`

### "Dashboard data is None"
**Solution:** Use `--dashboard` flag: `threat-radar report generate scan.json --dashboard`

### Report is empty
**Solution:** Check that scan results file contains vulnerabilities

---

**Happy Reporting! 📊🛡️**
