# Vulnerability Command Center Dashboards 🎯

Advanced multi-panel command center visualizations for comprehensive vulnerability analysis, attack path tracking, and remediation planning.

## 🎬 Command Center Showcase

### 1. Critical Vulnerability Command Center 🚨
**File:** `command_center_critical_vulns.html`

**What it does:**
- Tracks all CRITICAL and HIGH severity vulnerabilities
- Maps CVEs to attack paths they enable
- Shows package connections to vulnerabilities
- Analyzes severity distribution across infrastructure

**Layout (2x2 Multi-Panel):**

**Top-Left: Critical CVE Table**
- Lists top 20 critical/high severity CVEs
- Shows CVSS scores
- Package counts affected
- Attack paths each CVE appears in
- Sortable and scannable

**Top-Right: Attack Path Network**
- Interactive network graph
- Critical CVEs as nodes (colored by severity)
- Connections to packages
- Hover for detailed CVE information
- Visual representation of blast radius

**Bottom-Left: Severity Distribution Pie**
- Overall vulnerability breakdown
- Critical, High, Medium, Low counts
- Percentage distribution
- Quick risk overview

**Bottom-Right: Critical CVEs by CVSS**
- Horizontal bar chart
- Top 15 critical vulnerabilities
- Sorted by CVSS score (0-10)
- Color-coded by severity
- Easy identification of highest risks

**Perfect for:**
- Daily security standup meetings
- Vulnerability triage sessions
- Incident response prioritization
- Executive risk briefings
- SOC monitoring displays

**What to Look For:**
- ⚠️ **CVEs in multiple attack paths** = High priority
- 🔴 **CVSS > 9.0** = Critical, immediate action
- 📦 **Multiple packages per CVE** = Widespread impact
- 🎯 **Severity distribution** = Overall posture health

---

### 2. Package Risk Command Center 📦
**File:** `command_center_package_risk.html`

**What it does:**
- Analyzes risk at the package level
- Shows which packages have the most vulnerabilities
- Maps packages to attack paths they enable
- Identifies remediation targets

**Layout (2x2 Multi-Panel):**

**Top-Left: Top Vulnerable Packages Table**
- Top 20 riskiest packages
- Version information
- Critical and High CVE counts
- Total vulnerabilities per package
- Average CVSS score
- Quick remediation targeting

**Top-Right: Package-Vulnerability Network**
- Network graph showing top 15 packages
- Vulnerability connections (edges colored by severity)
- Package nodes in purple
- CVE nodes as diamonds (colored by severity)
- Visual blast radius for each package

**Bottom-Left: Package Ecosystem Distribution**
- Pie chart of package ecosystems
- Alpine (apk), npm, pip, deb, etc.
- Shows attack surface by technology
- Identifies ecosystem concentration

**Bottom-Right: Packages Enabling Attack Paths**
- Bar chart of packages that appear in attack paths
- Shows how many paths each package enables
- Prioritizes packages for remediation
- Color-coded by severity

**Perfect for:**
- Dependency management
- Supply chain risk assessment
- Upgrade planning meetings
- Remediation prioritization
- SBOM analysis

**What to Look For:**
- 📦 **High CVE count packages** = Urgent updates needed
- 🔗 **Packages in many attack paths** = Critical dependencies
- 🎯 **Ecosystem concentrations** = Single points of failure
- ⬆️ **Average CVSS > 7.0** = High-risk packages

---

### 3. Attack Vector Analysis Center ⚔️
**File:** `command_center_attack_vectors.html`

**What it does:**
- Categorizes attacks by type (RCE, privilege escalation, etc.)
- Shows which attack vectors are most prevalent
- Maps vectors to CVEs and packages
- Analyzes attack sequences

**Layout (2x2 Multi-Panel):**

**Top-Left: Attack Vector Breakdown Table**
- Categorizes attacks by type:
  - RCE (Remote Code Execution)
  - Privilege Escalation
  - Lateral Movement
  - Data Exfiltration
  - DoS (Denial of Service)
- Shows occurrences, attack paths, CVEs, packages per vector

**Top-Right: Attack Paths by Vector Type**
- Bar chart showing which vectors are most common
- Color-coded: Red (>2 paths), Yellow (≤2 paths)
- Quick identification of attack trends
- Helps focus defensive efforts

**Bottom-Left: Vector Impact Distribution**
- Pie chart showing occurrence distribution
- Shows which attack types dominate
- Percentage breakdown
- Risk landscape overview

**Bottom-Right: Attack Sequences**
- Visual flow of top 3 attack paths
- Step-by-step progression
- Color-coded by threat level
- Shows attack chains

**Perfect for:**
- Threat modeling sessions
- Red team exercise planning
- Defense strategy development
- Attack surface analysis
- Security architecture reviews

**What to Look For:**
- ⚔️ **RCE prevalence** = Entry point risks
- ⬆️ **Privilege escalation paths** = Lateral movement risk
- 🔁 **Attack sequence complexity** = Defense difficulty
- 🎯 **Dominant vectors** = Focus defensive controls

---

### 4. Remediation Command Center 🔧
**File:** `command_center_remediation.html`

**What it does:**
- Prioritizes fixes based on impact
- Shows which package updates close the most attack paths
- Estimates remediation effort and timeline
- Tracks fix availability

**Layout (2x2 Multi-Panel):**

**Top-Left: Priority Remediation Targets Table**
- Top 20 packages to fix
- Critical CVE count
- Total CVE count
- Number of attack paths closed by fixing
- Effort estimate (LOW/MEDIUM/HIGH)
- Days to remediate
- Impact score-based ranking

**Top-Right: Remediation Impact Bar Chart**
- Shows attack paths closed per package
- Top 10 highest-impact fixes
- Color-coded by effort:
  - Green: LOW effort
  - Yellow: MEDIUM effort
  - Red: HIGH effort
- Helps identify quick wins

**Bottom-Left: Fix Availability Status**
- Pie chart showing:
  - Fixes available
  - No fix available
  - Unknown status
- Helps set realistic expectations
- Identifies workaround needs

**Bottom-Right: Remediation Timeline**
- Gantt-style timeline
- Shows sequential fix schedule
- Top 8 priority packages
- Color-coded by effort
- Cumulative days estimate
- Helps sprint planning

**Perfect for:**
- Sprint planning meetings
- Remediation roadmap creation
- Resource allocation
- SLA compliance tracking
- Risk reduction planning

**What to Look For:**
- 🎯 **High paths closed, low effort** = Quick wins
- ⏱️ **Timeline bottlenecks** = Resource constraints
- ✅ **Fix availability gaps** = Need workarounds
- 📊 **Critical CVE clustering** = Urgent sprints

---

## 🎯 Comparison Matrix

| Command Center | Focus | Best For | Primary Insight | Update Frequency |
|----------------|-------|----------|-----------------|------------------|
| **Critical Vulnerability** | CVE tracking | Daily monitoring | Which CVEs are most dangerous | Daily |
| **Package Risk** | Dependencies | Update planning | Which packages need urgent updates | Weekly |
| **Attack Vector** | Attack types | Defense strategy | Which attack types to defend against | Monthly |
| **Remediation** | Fix planning | Sprint planning | What to fix first for maximum impact | Sprint cycles |

## 🚀 Usage

### Generate All Command Centers

```bash
cd examples/11_graph_visualization
python 05_vulnerability_command_centers.py
```

### Prerequisites

First, run the attack path discovery to generate the graph:

```bash
cd ../10_attack_path_discovery
./run_attack_path_demo.sh

cd ../11_graph_visualization
python 05_vulnerability_command_centers.py
```

## 🎨 Customization

### Adjust Table Row Counts

```python
# In each function, find the table creation:
for vuln in critical_vulns[:20]:  # Change from 20 to 50
    # ...

for pkg in packages[:20]:  # Change from 20 to 30
    # ...
```

### Modify Color Schemes

```python
# Severity colors
severity_colors = {
    'critical': '#your_red',
    'high': '#your_orange',
    # ...
}

# Background colors
paper_bgcolor='#your_background',
plot_bgcolor='#your_panel_color',
```

### Change Dashboard Size

```python
fig.update_layout(
    height=1400,  # Increase from 1200
    width=2400,   # Increase from 2000
)
```

### Adjust Panel Layout

```python
# Change from 2x2 to 3x2 layout
fig = make_subplots(
    rows=3, cols=2,  # More rows
    # Update specs accordingly
)
```

## 💡 Workflow Strategies

### Daily Security Operations

**Morning Standup:**
1. Open **Critical Vulnerability Command Center**
2. Review new critical/high CVEs
3. Check attack path counts
4. Assign triage tasks

**Afternoon Review:**
1. Open **Remediation Command Center**
2. Update fix progress
3. Adjust timeline
4. Report blockers

### Weekly Planning

**Monday Planning:**
1. **Package Risk Command Center** - Identify update targets
2. **Remediation Command Center** - Plan sprint tasks
3. Set weekly goals

**Friday Review:**
1. **Critical Vulnerability Command Center** - Check resolved CVEs
2. **Attack Vector Analysis** - Review trends
3. Document progress

### Monthly Strategy

**Architecture Review:**
1. **Attack Vector Analysis Center** - Identify defense gaps
2. **Package Risk Command Center** - Review ecosystem health
3. Plan architecture improvements

**Executive Briefing:**
1. **Critical Vulnerability Command Center** - Risk overview
2. **Remediation Command Center** - Progress metrics
3. Present ROI and risk reduction

## 🔧 Integration Examples

### Automated Daily Report

```bash
#!/bin/bash
# daily-command-center-update.sh

# Scan latest production images
threat-radar cve scan-image production:latest --auto-save -o scan.json

# Rebuild graph
threat-radar env build-graph production-env.json \
  --merge-scan scan.json --auto-save

# Generate command centers
python 05_vulnerability_command_centers.py

# Send to Slack
curl -X POST $SLACK_WEBHOOK \
  -d "text=Daily Command Center Updated" \
  -d "attachments=[{\"text\":\"View at: http://dashboards/command-centers/\"}]"
```

### CI/CD Integration

```yaml
# .github/workflows/command-center-update.yml
name: Update Command Centers
on:
  schedule:
    - cron: '0 8 * * 1-5'  # Weekdays at 8 AM

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - name: Generate Command Centers
        run: |
          python 05_vulnerability_command_centers.py

      - name: Upload to S3
        run: |
          aws s3 sync output/ s3://command-centers/$(date +%Y-%m-%d)/
```

### Live Dashboard Embedding

```html
<!-- Embed in internal security portal -->
<!DOCTYPE html>
<html>
<head>
  <title>Security Command Center</title>
</head>
<body>
  <h1>Live Security Dashboards</h1>

  <div class="dashboard-grid">
    <iframe src="command_center_critical_vulns.html"
            width="100%" height="800px"></iframe>

    <iframe src="command_center_package_risk.html"
            width="100%" height="800px"></iframe>

    <iframe src="command_center_attack_vectors.html"
            width="100%" height="800px"></iframe>

    <iframe src="command_center_remediation.html"
            width="100%" height="800px"></iframe>
  </div>

  <script>
    // Auto-refresh every 5 minutes
    setInterval(() => location.reload(), 300000);
  </script>
</body>
</html>
```

## 📊 Metrics Tracking

Use command centers to track KPIs:

### Vulnerability Metrics
- **Critical CVE Count** - Track reduction over time
- **Average CVSS Score** - Overall severity trend
- **Fix Availability %** - Patchability metric
- **Mean Time to Remediate** - Response efficiency

### Attack Path Metrics
- **Total Attack Paths** - Attack surface size
- **Critical Path Count** - Highest risk routes
- **Average Path Length** - Attack complexity
- **Paths Closed This Sprint** - Remediation velocity

### Package Metrics
- **Vulnerable Package Count** - Dependency health
- **Average Package Age** - Update cadence
- **Ecosystem Diversity** - Technology spread
- **Packages in Attack Paths** - Critical dependencies

### Remediation Metrics
- **Fixes Completed This Week** - Team velocity
- **Average Days to Fix** - Response time
- **Quick Wins Identified** - Low-hanging fruit
- **Attack Paths Closed** - Risk reduction

## 🆘 Troubleshooting

**Q: Dashboard shows no data**
A: Ensure you've run the attack path discovery first to generate the graph with vulnerability data

**Q: Tables are too crowded**
A: Adjust the row count in each table section (e.g., `[:20]` → `[:10]`)

**Q: Colors are hard to read**
A: Modify the color schemes in the `get_vulnerability_severity_color()` and background colors

**Q: Layout looks cramped**
A: Increase `width` and `height` in `fig.update_layout()`

**Q: Missing attack path connections**
A: Verify attack paths were successfully analyzed (check console output)

**Q: Package risk center empty**
A: Ensure packages have vulnerabilities in the graph data

## 🌟 Advanced Features

### Custom Metrics Panel

Add a custom metrics panel to any dashboard:

```python
# Add summary metrics at the top
metrics_html = f"""
<div style="background: #1e293b; padding: 20px; margin: 20px;">
  <h2>Key Metrics</h2>
  <div style="display: flex; gap: 20px;">
    <div>Total CVEs: {total_cves}</div>
    <div>Critical: {critical_count}</div>
    <div>Attack Paths: {len(attack_paths)}</div>
    <div>Risk Score: {risk_score}/100</div>
  </div>
</div>
"""
```

### Export to PDF

```python
# Install: pip install kaleido
fig.write_image("command_center.pdf", width=2000, height=1200)
```

### Real-Time Updates

```python
# Use Dash for live updates
import dash
from dash import dcc, html
from dash.dependencies import Input, Output

app = dash.Dash(__name__)

app.layout = html.Div([
    dcc.Graph(id='command-center'),
    dcc.Interval(id='interval', interval=60000)  # Update every minute
])

@app.callback(
    Output('command-center', 'figure'),
    Input('interval', 'n_intervals')
)
def update_graph(n):
    # Regenerate command center
    # Return new figure
    pass
```

## 🔗 Integration with Other Tools

### Jira Integration

```python
# Auto-create tickets for critical findings
from jira import JIRA

jira = JIRA(server, basic_auth=(user, token))

for vuln in critical_vulns[:5]:
    issue = jira.create_issue(
        project='SEC',
        summary=f"Fix {vuln['cve_id']}",
        description=f"CVSS: {vuln['cvss_score']}, Packages: {len(vuln['packages'])}",
        issuetype={'name': 'Bug'},
        priority={'name': 'Critical'}
    )
```

### Slack Notifications

```bash
# Send daily summary
CRITICAL=$(jq '.critical_count' metrics.json)

curl -X POST $SLACK_WEBHOOK \
  -H 'Content-Type: application/json' \
  -d "{\"text\":\"🚨 $CRITICAL critical vulnerabilities found\"}"
```

### Grafana Dashboards

Export metrics to Prometheus for Grafana:

```python
from prometheus_client import Gauge, push_to_gateway

critical_gauge = Gauge('vulnerability_critical_count', 'Critical vulnerabilities')
critical_gauge.set(critical_count)

push_to_gateway('pushgateway:9091', job='vulnerability-scan')
```

---

## 📚 Learn More

- **Plotly Subplots**: https://plotly.com/python/subplots/
- **Table Formatting**: https://plotly.com/python/table/
- **Dashboard Design**: https://plotly.com/python/dashboard/
- **Real-Time Dashboards**: https://dash.plotly.com/

---

Created with ❤️ for security operations excellence!
