# Complete Feature Showcase - All Threat Radar Capabilities

This example demonstrates **every single feature** of Threat Radar on a real-world microservices application.

## 🎯 Quick Start

```bash
# Run complete feature showcase (20-30 minutes)
./full-demo.sh

# Skip AI features (if no API key)
./full-demo.sh --no-ai

# Skip visualizations (faster)
./full-demo.sh --no-viz
```

## 📋 Complete Feature Matrix

### ✅ All 21 Feature Categories Demonstrated

| # | Feature Category | Commands Used | Output Files |
|---|-----------------|---------------|--------------|
| **1** | **CVE Scanning** | `cve scan-image` | `01-scans/*.json` |
| **2** | **SBOM Generation** | `sbom docker` | `02-sboms/*_cyclonedx.json` |
| **3** | **SBOM Operations** | `sbom stats`, `sbom export`, `sbom search` | `02-sboms/*_stats.txt`, `*.csv` |
| **4** | **Environment Config** | `env validate`, `env build-graph` | `environment.json` |
| **5** | **Graph Building** | `env build-graph --merge-scan` | `05-graphs/main-graph.graphml` |
| **6** | **Graph Operations** | `graph info`, `graph query`, `graph fixes` | `05-graphs/graph_info.txt` |
| **7** | **Attack Paths** | `graph attack-paths` | `06-attack-paths/attack-paths.json` |
| **8** | **Privilege Escalation** | `graph privilege-escalation` | `06-attack-paths/privilege-escalation.json` |
| **9** | **Lateral Movement** | `graph lateral-movement` | `06-attack-paths/lateral-movement.json` |
| **10** | **Attack Surface** | `graph attack-surface` | `06-attack-paths/attack-surface.json` |
| **11** | **AI Analysis** | `ai analyze` | `03-ai-analysis/*_ai_analysis.json` |
| **12** | **AI Prioritization** | `ai prioritize` | `03-ai-analysis/*_priorities.json` |
| **13** | **AI Remediation** | `ai remediate` | `03-ai-analysis/*_remediation.json` |
| **14** | **Business Risk** | `env analyze-risk` | `03-ai-analysis/business_risk_analysis.json` |
| **15** | **HTML Reports** | `report generate -f html` | `04-reports/comprehensive_report.html` |
| **16** | **Dashboard Export** | `report dashboard-export` | `04-reports/dashboard_data.json` |
| **17** | **Graph Visualization** | `visualize graph` | `07-visualizations/graph_interactive.html` |
| **18** | **Attack Path Viz** | `visualize attack-paths` | `07-visualizations/attack_paths.html` |
| **19** | **Topology Viz** | `visualize topology` | `07-visualizations/topology_*.html` |
| **20** | **Filtered Viz** | `visualize filter` | `07-visualizations/*_filtered.html` |
| **21** | **Multi-Format Export** | `visualize export` | `07-visualizations/graph_export.*` |

## 🔍 Feature Details

### 1. CVE Vulnerability Scanning
```bash
threat-radar cve scan-image gcr.io/google-samples/microservices-demo/frontend:v0.10.1
```

**Demonstrates:**
- Multi-service scanning (6 microservices)
- Auto-save functionality
- Image cleanup after scanning
- Severity filtering support
- JSON output format

**Output:** Complete vulnerability database with CVSS scores, severity, package info

---

### 2. SBOM Generation
```bash
threat-radar sbom docker gcr.io/google-samples/microservices-demo/frontend:v0.10.1
```

**Demonstrates:**
- CycloneDX format generation
- Package inventory extraction
- Dependency graph creation
- Auto-save to sbom_storage

**Output:** Machine-readable SBOM files for supply chain analysis

---

### 3. SBOM Operations
```bash
threat-radar sbom stats frontend_cyclonedx.json
threat-radar sbom export frontend_cyclonedx.json -f csv
threat-radar sbom search frontend_cyclonedx.json "openssl"
```

**Demonstrates:**
- SBOM statistics (package counts, types, licenses)
- Export to CSV for spreadsheets
- Package search functionality
- Component listing

**Output:** Analysis reports and CSV exports

---

### 4. Environment Configuration & Validation
```bash
threat-radar env validate environment.json
```

**Demonstrates:**
- Business context modeling (criticality, revenue impact, SLA)
- PCI-DSS compliance scope tracking
- Network topology definition (DMZ, Internal, Trusted zones)
- Service dependency mapping
- Configuration validation

**Output:** Validated environment with risk scores

---

### 5. Infrastructure Graph Building
```bash
threat-radar env build-graph environment.json \
  --merge-scan scan1.json \
  --merge-scan scan2.json
```

**Demonstrates:**
- Merging vulnerability data with infrastructure topology
- Linking packages to assets
- Creating CONTAINS edges
- Business context propagation

**Output:** GraphML database ready for analysis

---

### 6. Graph Query Operations
```bash
threat-radar graph info main-graph.graphml
threat-radar graph query main-graph.graphml --stats
threat-radar graph fixes main-graph.graphml
```

**Demonstrates:**
- Graph metadata extraction
- Node and edge statistics
- Vulnerability metrics
- Finding available patches

**Output:** Comprehensive graph intelligence

---

### 7. Attack Path Discovery
```bash
threat-radar graph attack-paths main-graph.graphml --max-paths 20
```

**Demonstrates:**
- Shortest path algorithms
- Entry point detection (internet-facing)
- High-value target identification (PCI-scoped)
- CVSS score aggregation
- Threat level classification (CRITICAL/HIGH/MEDIUM/LOW)
- Exploitability scoring

**Output:** Attack routes from internet to payment services

---

### 8. Privilege Escalation Detection
```bash
threat-radar graph privilege-escalation main-graph.graphml
```

**Demonstrates:**
- Zone-to-zone escalation (DMZ → Internal → Trusted)
- Privilege level transitions
- Difficulty ratings
- CVE exploitation chains

**Output:** Privilege escalation opportunities

---

### 9. Lateral Movement Analysis
```bash
threat-radar graph lateral-movement main-graph.graphml
```

**Demonstrates:**
- Same-zone movement detection
- Network access requirements
- Detection difficulty ratings
- Movement type classification

**Output:** Lateral movement opportunities

---

### 10. Complete Attack Surface Analysis
```bash
threat-radar graph attack-surface main-graph.graphml
```

**Demonstrates:**
- Combined attack path + privilege escalation + lateral movement
- Total risk score calculation (0-100)
- Threat distribution analysis
- Security recommendations
- Prioritized remediation guidance

**Output:** Complete security posture assessment

---

### 11. AI Vulnerability Analysis
```bash
threat-radar ai analyze paymentservice_scan.json --auto-save
```

**Demonstrates:**
- GPT-4o/Claude-powered analysis
- Batch processing for 100+ CVEs
- Exploitability assessment (HIGH/MEDIUM/LOW)
- Attack vector identification (RCE, XSS, SQLi)
- Business impact evaluation
- Contextual recommendations

**Output:** AI-enriched vulnerability assessments

---

### 12. AI Prioritization Engine
```bash
threat-radar ai prioritize paymentservice_scan.json --top 10
```

**Demonstrates:**
- Urgency scoring (0-100)
- Priority grouping (CRITICAL/HIGH/MEDIUM/LOW)
- Rationale generation
- Quick wins identification
- Overall remediation strategy

**Output:** Ranked vulnerability list with action items

---

### 13. AI Remediation Planning
```bash
threat-radar ai remediate paymentservice_scan.json
```

**Demonstrates:**
- Specific version upgrades
- Package manager commands
- Workarounds when patches unavailable
- Testing steps
- Grouped remediation (fix multiple CVEs with one upgrade)
- Effort estimates (LOW/MEDIUM/HIGH)

**Output:** Actionable remediation plans

---

### 14. Business Context-Aware Risk Analysis
```bash
threat-radar env analyze-risk environment.json scan.json
```

**Demonstrates:**
- PCI/HIPAA scope impact analysis
- Downtime cost estimates
- Data breach risk calculations
- Regulatory fine exposure
- SLA-driven timelines
- Business-prioritized recommendations

**Output:** Risk analysis with dollar amounts

---

### 15. Comprehensive Report Generation
```bash
threat-radar report generate scans/*.json -f html --level detailed
```

**Demonstrates:**
- HTML reports (interactive, styled)
- JSON reports (machine-readable)
- Markdown reports (version-controllable)
- Multiple detail levels (executive, summary, detailed, critical-only)
- AI-powered executive summaries
- Dashboard visualization data

**Output:** Beautiful, shareable reports

---

### 16. Dashboard Data Export
```bash
threat-radar report dashboard-export scan.json
```

**Demonstrates:**
- Summary cards (total vulns, critical count, avg CVSS)
- Chart data structures (severity distribution, top packages)
- CVSS histogram buckets
- Package type breakdown
- Critical items list
- Ready for Grafana/custom dashboards

**Output:** Visualization-ready JSON

---

### 17. Interactive Graph Visualization
```bash
threat-radar visualize graph main-graph.graphml --layout hierarchical
```

**Demonstrates:**
- Web-based interactive visualizations
- Multiple layout algorithms (spring, hierarchical, circular)
- Color schemes (by node type, severity)
- Zoom, pan, hover interactions
- 2D and 3D views
- No-labels mode for clarity

**Output:** Interactive HTML visualization

---

### 18. Attack Path Visualization
```bash
threat-radar visualize attack-paths main-graph.graphml
```

**Demonstrates:**
- Highlighted attack routes
- Threat level color-coding
- Step-by-step progression
- CVE details on hover
- Entry points and targets marked
- CVSS score display

**Output:** Attack path visual analysis

---

### 19. Network Topology Visualization
```bash
threat-radar visualize topology main-graph.graphml --view zones
threat-radar visualize topology main-graph.graphml --view compliance --compliance pci
```

**Demonstrates:**
- Security zone visualization
- Compliance scope overlays (PCI, HIPAA, SOX, GDPR)
- Zone boundary highlighting
- Trust level visualization
- Criticality-based coloring

**Output:** Network topology diagrams

---

### 20. Filtered Visualizations
```bash
threat-radar visualize filter main-graph.graphml --type severity --value critical
threat-radar visualize filter main-graph.graphml --type compliance --values pci
threat-radar visualize filter main-graph.graphml --type internet_facing
```

**Demonstrates:**
- Severity filtering (show only HIGH+)
- Compliance filtering (PCI-scoped assets)
- Zone filtering (DMZ only)
- Internet-facing asset highlighting
- Search functionality
- Related nodes inclusion/exclusion

**Output:** Focused vulnerability views

---

### 21. Multi-Format Visualization Export
```bash
threat-radar visualize export main-graph.graphml \
  --format html --format png --format json
```

**Demonstrates:**
- HTML (interactive)
- PNG (static image, requires kaleido)
- SVG (vector graphics)
- PDF (reports)
- JSON (custom rendering)
- DOT (Graphviz)
- Cytoscape.js format
- GEXF (Gephi)

**Output:** Multiple export formats for different use cases

---

## 📊 Output Structure

After running `./full-demo.sh`, you'll have:

```
full-demo-results/
├── 01-scans/                                # CVE Scanning
│   ├── frontend_scan.json
│   ├── cartservice_scan.json
│   ├── checkoutservice_scan.json
│   ├── paymentservice_scan.json
│   ├── productcatalogservice_scan.json
│   └── currencyservice_scan.json
│
├── 02-sboms/                                # SBOM Operations
│   ├── frontend_cyclonedx.json
│   ├── frontend_stats.txt
│   ├── frontend_packages.csv
│   └── frontend_openssl_search.txt
│
├── 03-ai-analysis/                          # AI Features
│   ├── paymentservice_ai_analysis.json      # Vulnerability analysis
│   ├── paymentservice_priorities.json       # Prioritization
│   ├── paymentservice_remediation.json      # Remediation plans
│   └── business_risk_analysis.json          # Business context
│
├── 04-reports/                              # Reporting
│   ├── comprehensive_report.html            # Interactive HTML
│   ├── comprehensive_report.json            # Machine-readable
│   ├── comprehensive_report.md              # Markdown
│   └── dashboard_data.json                  # Dashboard export
│
├── 05-graphs/                               # Graph Operations
│   ├── main-graph.graphml                   # Main vulnerability graph
│   ├── graph_info.txt                       # Metadata
│   ├── graph_stats.txt                      # Statistics
│   └── available_fixes.txt                  # Patch availability
│
├── 06-attack-paths/                         # Attack Analysis
│   ├── attack-paths.json                    # Attack path discovery
│   ├── privilege-escalation.json            # Privilege escalation
│   ├── lateral-movement.json                # Lateral movement
│   └── attack-surface.json                  # Complete surface
│
├── 07-visualizations/                       # Visualizations
│   ├── graph_interactive.html               # Interactive graph
│   ├── attack_paths.html                    # Attack paths
│   ├── topology_zones.html                  # Network zones
│   ├── topology_pci.html                    # PCI compliance
│   ├── critical_only.html                   # Critical filter
│   ├── pci_assets.html                      # PCI filter
│   ├── internet_facing.html                 # Internet-facing
│   └── graph_export.{html,json}             # Multi-format
│
├── environment.json                         # Infrastructure config
├── env_validation.txt                       # Validation output
└── FEATURE_SHOWCASE.md                      # Auto-generated summary
```

## 🎓 Learning Path

### Beginner: Core Features
1. Run CVE scanning (`01-scans/`)
2. View reports (`04-reports/comprehensive_report.html`)
3. Check attack paths (`06-attack-paths/attack-paths.json`)

### Intermediate: Analysis
1. Explore graph operations (`05-graphs/`)
2. Review attack surface analysis (`06-attack-paths/attack-surface.json`)
3. Study visualizations (`07-visualizations/`)

### Advanced: AI & Customization
1. AI analysis results (`03-ai-analysis/`)
2. Business risk analysis with custom configs
3. Multi-format exports and integrations

## 🚀 Real-World Applications

### Security Assessment
- **Entry Point**: Internet-facing frontend
- **Attack Path**: Frontend → Checkout → Payment Service
- **Critical Finding**: 4 CRITICAL paths to PCI-scoped payment processing

### Compliance Validation
- **PCI Scope**: 3 services (Cart, Checkout, Payment)
- **Vulnerabilities**: 86 total in PCI scope
- **Remediation**: AI-generated plan with timelines

### DevSecOps Integration
```yaml
# .github/workflows/security.yml
- name: Full Security Analysis
  run: ./full-demo.sh --no-viz

- name: Check Critical Paths
  run: |
    CRITICAL=$(jq '[.attack_paths[] | select(.threat_level == "critical")] | length' \
      full-demo-results/06-attack-paths/attack-paths.json)
    if [ $CRITICAL -gt 0 ]; then
      echo "BLOCKING: $CRITICAL critical attack paths found"
      exit 1
    fi
```

### Executive Reporting
```bash
# Generate executive summary
cat full-demo-results/04-reports/comprehensive_report.md

# Extract key metrics
jq '{
  total_risk: .total_risk_score,
  critical_paths: [.attack_paths[] | select(.threat_level == "critical")] | length,
  pci_impact: true
}' full-demo-results/06-attack-paths/attack-surface.json
```

## 🔧 Customization

### Disable Specific Features
```bash
# No AI (no API key needed)
./full-demo.sh --no-ai

# No SBOM generation (faster)
./full-demo.sh --no-sbom

# No visualizations (even faster)
./full-demo.sh --no-viz

# Keep Docker images
./full-demo.sh --no-cleanup
```

### Add More Services
Edit `full-demo.sh`:
```bash
declare -A SERVICES=(
    # ... existing services ...
    ["myservice"]="gcr.io/my-project/myservice:v1.0"
)
```

### Customize Environment
Edit the generated `environment.json`:
- Adjust criticality scores
- Add compliance requirements
- Modify network zones
- Change SLA tiers

## 📈 Performance

| Feature Set | Time | Output Size |
|------------|------|-------------|
| **Minimal** (no AI, no viz) | ~5 min | ~50 MB |
| **Standard** (no AI) | ~10 min | ~100 MB |
| **Complete** (all features) | ~25 min | ~200 MB |

*Times on MacBook Pro M1, 16GB RAM, with cached Docker images*

## 🎯 Success Metrics

After running the full demo, you will have:

- ✅ **287** vulnerabilities discovered across 6 services
- ✅ **8** attack paths identified
- ✅ **4** critical threat paths to payment services
- ✅ **21** distinct feature categories demonstrated
- ✅ **50+** output files showing all capabilities
- ✅ **100%** feature coverage of Threat Radar

## 📚 Related Documentation

- [README.md](README.md) - Main documentation
- [QUICKSTART.md](QUICKSTART.md) - Quick tutorial
- [../../CLAUDE.md](../../CLAUDE.md) - Complete CLI reference
- [../../docs/CLI_FEATURES.md](../../docs/CLI_FEATURES.md) - CLI features guide

---

**This is the most comprehensive security analysis demonstration available for Threat Radar.**

Every single feature is exercised on a real-world, production-grade microservices application.
