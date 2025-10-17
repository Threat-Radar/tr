# Reporting Examples Summary

## 📚 What's Included

This directory contains comprehensive examples and documentation for Threat Radar's reporting capabilities.

### 📄 Example Scripts

1. **`01_basic_report_generation.py`**
   - Demonstrates report generation in JSON, Markdown, and HTML formats
   - Shows how to create critical-only filtered reports
   - Includes dashboard data export examples
   - **Run:** `python 01_basic_report_generation.py`

2. **`02_ai_powered_reports.py`**
   - AI-enhanced executive summaries using existing prompt templates
   - Comparison of AI vs non-AI reports
   - Multiple AI provider examples (OpenAI, Ollama)
   - Complete end-to-end workflow
   - **Run:** `python 02_ai_powered_reports.py`

3. **`03_dashboard_integration.py`**
   - Dashboard data structure extraction
   - Grafana-compatible format generation
   - React/JavaScript dashboard data
   - Custom metrics calculation
   - **Run:** `python 03_dashboard_integration.py`

### 📖 Documentation

- **`README.md`** - Quick start guide and command reference
- **`../docs/REPORTING_GUIDE.md`** - Complete reporting guide with workflows

### 🎯 Key Features Demonstrated

✅ **Multiple Output Formats**
- JSON for automation and APIs
- Markdown for documentation and GitHub
- HTML for presentations and sharing

✅ **AI Integration**
- Uses existing `RISK_ASSESSMENT_PROMPT` template
- Automatic compliance framework detection
- Business context and risk analysis
- Fallback for when AI is unavailable

✅ **Report Levels**
- Executive (high-level for leadership)
- Summary (overview with key metrics)
- Detailed (complete analysis)
- Critical-only (urgent issues only)

✅ **Dashboard Ready Data**
- Summary cards (metrics)
- Severity distribution charts
- Top vulnerable packages
- CVSS histograms
- Critical items lists

✅ **Practical Workflows**
- Weekly security reviews
- CI/CD pipeline integration
- Compliance reporting
- Trend monitoring
- Custom dashboard updates

## 🚀 Quick Start

### Generate Your First Report

```bash
# 1. Run an example
cd examples/05_reporting
python 01_basic_report_generation.py

# 2. Check the output directory
ls -lh output/

# 3. View the HTML report
open output/vulnerability_report.html
```

### Use with Real Scan Data

```bash
# 1. Scan an image
threat-radar cve scan-image alpine:3.18 -o scan.json

# 2. Generate a report
threat-radar report generate scan.json -o report.html -f html

# 3. View it
open report.html
```

## 📊 Example Outputs

All examples create output in the `output/` directory:

```
output/
├── basic_report.json              # JSON format (automation)
├── vulnerability_report.md        # Markdown (documentation)
├── vulnerability_report.html      # HTML (presentation)
├── dashboard_data.json            # Dashboard metrics
├── executive_summary.md           # AI executive summary
├── ai_full_report.html            # Complete AI report
├── grafana_dashboard.json         # Grafana import
├── react_dashboard_data.json      # React components
└── custom_metrics.json            # Custom calculations
```

## 💡 What to Try

### For Learning
1. Run `01_basic_report_generation.py` to see all formats
2. Compare JSON vs Markdown vs HTML outputs
3. Examine the dashboard data structure

### For AI Features
1. Set up AI (OpenAI or Ollama)
2. Run `02_ai_powered_reports.py`
3. Compare AI vs fallback summaries
4. Try different AI models

### For Integration
1. Run `03_dashboard_integration.py`
2. Examine Grafana-compatible format
3. Try custom metrics calculation
4. Adapt for your monitoring stack

## 🔗 Additional Resources

- **[CLAUDE.md](../../CLAUDE.md)** - Complete system documentation
- **[REPORTING_GUIDE.md](../../docs/REPORTING_GUIDE.md)** - Detailed reporting guide
- **[CLI_EXAMPLES.md](../CLI_EXAMPLES.md)** - Command-line examples

## 🆘 Need Help?

- Check `README.md` in this directory
- Review the troubleshooting section in the reporting guide
- Run examples with `--help` flag
- Review test files in `tests/test_comprehensive_report.py`

---

**Ready to generate reports! 📊🛡️**
