# Threat Radar - Individual Feature Demonstrations

This directory contains individual demonstration scripts for each major Threat Radar feature. Each script is self-contained and can be run independently or as part of a presentation.

## 🔄 Logical Workflow Order

The demos follow a logical security analysis workflow:

1. **Understand** → What's in your software (SBOM)
2. **Discover** → What vulnerabilities exist (CVE Scanning)
3. **Contextualize** → What matters to your business (Environment)
4. **Model** → How things relate (Graph Building)
5. **Analyze** → How attacks happen (Attack Paths)
6. **Prioritize** → What to fix first (AI Analysis)
7. **Visualize** → See the big picture (Visualizations)
8. **Communicate** → Share findings (Reporting)

---

## 📋 Demo Scripts

### 1️⃣ SBOM Generation (`01-sbom-generation.sh`)
**Feature**: `threat-radar sbom` commands
**Duration**: ~4-5 minutes
**What it shows**:
- SBOM generation from Docker images
- Reading and analyzing SBOMs
- Searching for specific packages
- Comparing SBOMs across versions
- Exporting to CSV

**Key Learning**: Software bill of materials for supply chain transparency

**Why first**: You need to understand what's in your containers before you can assess their security

---

### 2️⃣ Vulnerability Scanning (`02-vulnerability-scanning.sh`)
**Feature**: `threat-radar cve scan-image`
**Duration**: ~2-3 minutes
**What it shows**:
- Basic vulnerability scanning with Grype
- Severity filtering and counting
- Auto-save and cleanup options
- Fail-on-severity for CI/CD

**Key Learning**: Finding known vulnerabilities in container images

**Why second**: After knowing what's in your software, find what's broken

---

### 3️⃣ Environment & Business Context (`03-environment-context.sh`)
**Feature**: `threat-radar env` commands
**Duration**: ~5-6 minutes
**What it shows**:
- Environment configuration (JSON)
- Business context metadata
- Infrastructure graph building
- Compliance tracking (PCI, GDPR)
- Business-aware risk assessment

**Key Learning**: Adding business context to technical vulnerabilities

**Why third**: Not all vulnerabilities are equal - business context determines priority

---

### 4️⃣ Graph Building (`04-graph-building.sh`)
**Feature**: `threat-radar graph build` and query commands
**Duration**: ~3-4 minutes
**What it shows**:
- Building vulnerability graphs
- Querying by CVE (blast radius)
- Finding top vulnerable packages
- Discovering available fixes
- Graph statistics

**Key Learning**: Relationship-based vulnerability analysis

**Why fourth**: Model how vulnerabilities, packages, and assets relate

---

### 5️⃣ Attack Path Discovery (`05-attack-paths.sh`)
**Feature**: `threat-radar graph attack-*` commands
**Duration**: ~6-8 minutes
**What it shows**:
- Attack path discovery
- Privilege escalation detection
- Lateral movement opportunities
- Attack surface analysis
- Security recommendations

**Key Learning**: Understanding real-world exploitation routes

**Why fifth**: See how attackers could actually exploit vulnerabilities in your environment

**Prerequisites**: Environment graph from Demo 3

---

### 6️⃣ AI-Powered Analysis (`06-ai-analysis.sh`)
**Feature**: `threat-radar ai` commands
**Duration**: ~5-10 minutes (depends on AI provider)
**What it shows**:
- AI vulnerability analysis
- Intelligent prioritization
- Remediation guidance
- Batch processing for large scans
- Multiple AI provider support

**Key Learning**: LLM-powered security intelligence

**Why sixth**: Use AI to prioritize what to fix based on exploitability and business impact

**Prerequisites**: AI provider configured (OpenAI, Anthropic, OpenRouter, or Ollama)

---

### 7️⃣ Interactive Visualizations (`07-visualizations.sh`)
**Feature**: `threat-radar visualize` commands
**Duration**: ~4-5 minutes
**What it shows**:
- Interactive graph visualizations
- Attack path visualization
- Network topology views
- Filtering and exploration
- Multi-format export (HTML, PNG, SVG, PDF)

**Key Learning**: Visual exploration and stakeholder communication

**Why seventh**: Visualize complex relationships for easier understanding and communication

**Prerequisites**: `pip install plotly kaleido`

---

### 8️⃣ Comprehensive Reporting (`08-comprehensive-reporting.sh`)
**Feature**: `threat-radar report generate`
**Duration**: ~4-5 minutes
**What it shows**:
- HTML reports for security teams
- Markdown executive summaries
- JSON for dashboards
- Critical-only reports
- Dashboard data export

**Key Learning**: Multi-format, multi-audience reporting

**Why last**: After analysis, visualization, and prioritization, communicate findings

---

## 🚀 Quick Start

### Complete Multi-Service Analysis (Recommended)

Run comprehensive security analysis across ALL 12 microservices:

```bash
# Basic analysis (scans, graphs, attack paths)
./00-run-all-services.sh

# Enable all features (AI analysis + visualizations)
RUN_ALL=true ./00-run-all-services.sh

# Enable specific features
RUN_RISK_ASSESSMENT=true \
RUN_REMEDIATION=true \
RUN_PRIORITIES=true \
./00-run-all-services.sh
```

**Available toggles:**
- `RUN_VISUALIZATIONS=true` - Interactive HTML visualizations
- `RUN_RISK_ASSESSMENT=true` - AI risk assessment with business context
- `RUN_REMEDIATION=true` - Detailed remediation plans
- `RUN_PRIORITIES=true` - AI-powered priority rankings
- `RUN_THREAT_MODEL=true` - Threat modeling and attack analysis
- `RUN_ALL=true` - Enable all features at once

See [RUNNING_ALL_SERVICES.md](RUNNING_ALL_SERVICES.md) for detailed documentation.

### Run Individual Demos

```bash
cd /Users/chemch/PycharmProjects/tr-m2/examples/microservices-demo-analysis/demo-scripts

# Make scripts executable (if needed)
chmod +x *.sh

# Run demos in order
./01-sbom-generation.sh
./02-vulnerability-scanning.sh
./03-environment-context.sh
./04-graph-building.sh
./05-attack-paths.sh
./06-ai-analysis.sh
./07-visualizations.sh
./08-comprehensive-reporting.sh
```

### Run All Demos in Sequence

```bash
# Execute all demos automatically
./00-run-all-demos.sh
```

This will run all 8 demos in logical order, pausing between each for explanation.

**✨ Enterprise-Wide Consolidation**: When you run all demos, the master script automatically creates a consolidated enterprise-wide view by merging all individual service graphs into:
- `consolidated-results/enterprise-graph.graphml` - Unified graph of all services with vulnerabilities
- `consolidated-results/enterprise-attack-surface.json` - Complete attack surface analysis
- `consolidated-results/enterprise-topology.html` - Interactive visualization of entire infrastructure

---

## 📊 Demo Workflow Diagram

```
01. SBOM Generation
    ↓ (What's in the software?)
02. Vulnerability Scanning
    ↓ (What's broken?)
03. Environment & Business Context
    ↓ (What matters to business?)
04. Graph Building
    ↓ (How do things relate?)
05. Attack Paths
    ↓ (How can attackers exploit?)
06. AI Analysis
    ↓ (What should we fix first?)
07. Visualizations
    ↓ (How do we see the big picture?)
08. Reporting
    ↓ (How do we communicate findings?)
```

---

## 🎯 Presentation Tips

### For Security Engineers
**Recommended order**: 2 → 4 → 5 → 6
**Focus**: Technical capabilities, graph analysis, attack paths, AI prioritization

### For Executives
**Recommended order**: 2 → 3 → 5 → 8
**Focus**: Vulnerabilities found, business context, attack scenarios, reports

### For DevOps Teams
**Recommended order**: 1 → 2 → 6 → 8
**Focus**: SBOM compliance, CVE scanning, AI remediation, CI/CD integration

### For Compliance Officers
**Recommended order**: 1 → 3 → 8
**Focus**: SBOM requirements, compliance scope, audit reports

---

## 💡 Demo Scenarios

### Scenario 1: Quick Security Overview (10 minutes)
```bash
./02-vulnerability-scanning.sh    # Find vulnerabilities
./03-environment-context.sh       # Add business context
./08-comprehensive-reporting.sh   # Generate report
```

### Scenario 2: Deep Threat Analysis (25 minutes)
```bash
./02-vulnerability-scanning.sh    # Scan
./03-environment-context.sh       # Business context
./04-graph-building.sh            # Build graph
./05-attack-paths.sh              # Find attack routes
./07-visualizations.sh            # Visualize
```

### Scenario 3: AI-Powered Remediation (15 minutes)
```bash
./02-vulnerability-scanning.sh    # Scan
./06-ai-analysis.sh               # AI prioritization + remediation
./08-comprehensive-reporting.sh   # Report
```

### Scenario 4: Supply Chain & Compliance (15 minutes)
```bash
./01-sbom-generation.sh           # SBOM generation
./03-environment-context.sh       # Compliance scope
./08-comprehensive-reporting.sh   # Compliance report
```

---

## 🔧 Prerequisites

### Required for All Demos
- Threat Radar installed (`pip install -e /path/to/threat-radar`)
- Grype installed (`brew install grype`)
- Docker running
- `jq` for JSON parsing (`brew install jq`)

### Optional (Enhanced Features)
- **AI Demos (Demo 6)**: AI provider configured
  ```bash
  export OPENAI_API_KEY=your_key
  export AI_PROVIDER=openai
  ```

- **Visualizations (Demo 7)**: Plotly installed
  ```bash
  pip install plotly kaleido
  ```

---

## 📁 Output Structure

After running demos, you'll have:

```
demo-scripts/
├── demo-01-results/      # SBOMs (JSON, CSV)
├── demo-02-results/      # CVE scans (JSON)
├── demo-03-results/      # Environment config, infrastructure graph
├── demo-04-results/      # Vulnerability graphs (GraphML)
├── demo-05-results/      # Attack paths, escalation data
├── demo-06-results/      # AI analysis, prioritization, remediation
├── demo-07-results/      # Interactive visualizations (HTML, PNG)
├── demo-08-results/      # Reports (HTML, MD, JSON, PDF)
└── consolidated-results/ # Enterprise-wide consolidated view (created by 00-run-all-demos.sh)
    ├── enterprise-graph.graphml           # Merged graph of all services
    ├── enterprise-attack-surface.json     # Complete attack surface
    └── enterprise-topology.html           # Interactive topology visualization
```

### 🌐 Enterprise-Wide Graph Consolidation

**How it works:**
- **Individual Demos**: Each service gets its own graph file (demo-04-results/)
- **Demo 3 (Environment Context)**: Merges ALL vulnerability scans with infrastructure topology
- **Master Runner**: Creates final consolidated view in `consolidated-results/`

**The consolidated graph includes:**
- All 12 microservices (11 app services + Redis)
- Complete vulnerability data from all scans
- Business context (criticality, compliance, SLA)
- Network topology and security zones
- Inter-service dependencies
- Attack paths across the entire infrastructure

**Use cases:**
- Executive presentations showing enterprise-wide security posture
- Compliance audits requiring complete infrastructure view
- Attack surface analysis across all services
- Business impact assessment of vulnerabilities
- Remediation planning considering cross-service dependencies

---

## 🎤 Speaking Points for Each Demo

### Demo 1: SBOM Generation
- "SBOM = Software Bill of Materials - inventory of software components"
- "Required by Executive Order 14028 for federal software"
- "Foundation for vulnerability management and supply chain security"
- "Can track dependency changes across versions"

### Demo 2: Vulnerability Scanning
- "Using Grype to scan for known CVEs"
- "Found 37 vulnerabilities in paymentservice, 2 critical"
- "Auto-save tracks scan history for trending"
- "Can fail CI/CD builds on critical findings"

### Demo 3: Environment & Business Context
- "Not all vulnerabilities are equal - context matters"
- "Paymentservice handles payments (PCI scope) = CRITICAL"
- "Downtime costs $25K/hour for this business"
- "Risk = Technical Severity × Business Impact"

### Demo 4: Graph Building
- "Models relationships between containers, packages, and CVEs"
- "Query blast radius: which assets affected by CVE-X?"
- "Find packages with most vulnerabilities"
- "Discover which CVEs have patches available"

### Demo 5: Attack Paths
- "Shows how attackers could actually exploit your environment"
- "From public frontend → internal payment API = 3 steps"
- "Identifies privilege escalation and lateral movement"
- "Risk score based on exploitability + business impact"

### Demo 6: AI Analysis
- "GPT-4o/Claude analyzes exploitability, not just CVSS"
- "Prioritizes based on business context + threat landscape"
- "Generates specific remediation with upgrade commands"
- "Batch processing handles 100+ CVEs efficiently"

### Demo 7: Visualizations
- "Interactive Plotly graphs for exploration"
- "Color-coded by severity/zone/criticality"
- "Export as PNG for reports, HTML for exploration"
- "Attack path visualization shows exploitation routes"

### Demo 8: Reporting
- "Multiple formats for different audiences"
- "HTML for security teams, PDF for executives"
- "Dashboard export for Grafana/Splunk"
- "Critical-only reports for incident response"

---

## 🐛 Troubleshooting

**Demo fails with "image not found"**:
- Pull the image manually: `docker pull <image>`
- Or let Threat Radar pull it automatically

**AI demos skip execution**:
- Set up AI provider:
  ```bash
  export OPENAI_API_KEY=your_key
  export AI_PROVIDER=openai
  ```

**Visualization demos skip execution**:
- Install plotly: `pip install plotly kaleido`

**Demo 5 can't find infrastructure graph**:
- Run Demo 3 first: `./03-environment-context.sh`

**Demos run out of order produce errors**:
- Some demos depend on earlier demos
- Run in numerical order (1→2→3→4→5→6→7→8) for best results

---

## 📞 Support

For questions or issues:
- Review main documentation: `/Users/chemch/PycharmProjects/tr-m2/CLAUDE.md`
- Check examples README: `../README.md`
- View feature coverage: `../FEATURE_COVERAGE.md`

---

**Last Updated**: 2025-11-22
**Target Application**: Google Cloud microservices-demo
**Total Demo Time**: ~35-45 minutes (all demos)
**Individual Demo Time**: 2-10 minutes each

**Workflow Order**: SBOM → Vulnerabilities → Context → Graph → Attacks → AI → Visualize → Report
