# Graph Visualization Examples

This directory contains comprehensive examples demonstrating Threat Radar's interactive graph visualization capabilities.

## Quick Start

### 1. Setup

First, ensure you have the visualization dependencies installed:

```bash
# Install Threat Radar with visualization dependencies
pip install -e .

# The following packages will be installed:
# - plotly>=5.18.0 (interactive visualizations)
# - kaleido>=0.2.1 (static image export)
```

### 2. Generate Sample Data

Run the setup script to create a sample vulnerability graph:

```bash
python 00_setup.py
```

This creates `sample_graph.graphml` with:
- 5 containers across 3 security zones (DMZ, Internal, Trusted)
- 11 packages from various ecosystems (Alpine, npm, PyPI, Maven)
- 10 vulnerabilities (CRITICAL, HIGH, MEDIUM, LOW severity)
- Security context (zones, criticality, compliance scope)
- Container dependencies for attack path analysis

### 3. Run Examples

Run the examples in order to see different visualization capabilities:

```bash
# Basic graph visualizations with different layouts
python 01_basic_visualization.py

# Attack path discovery and visualization
python 02_attack_path_visualization.py

# Network topology with security overlays
python 03_topology_visualization.py

# Advanced filtering capabilities
python 04_filtered_visualization.py

# Multi-format export (HTML, PNG, SVG, PDF, JSON, etc.)
python 05_export_formats.py

# Complete end-to-end workflow
python 06_complete_workflow.py
```

## Examples Overview

### 00_setup.py
**Purpose**: Generate sample vulnerability graph for examples

**What it creates**:
- Realistic multi-container infrastructure
- Vulnerabilities across severity levels
- Security zones and compliance scope
- Attack path scenarios

**Output**: `sample_graph.graphml`

---

### 01_basic_visualization.py
**Purpose**: Demonstrate basic graph visualization with different layouts

**Features**:
- Spring layout (force-directed)
- Hierarchical layout (layered)
- Circular layout
- Color schemes (node type, severity)
- 3D visualization
- Label options

**Output**: `output/` directory with 6 HTML files

**Key concepts**:
- Layout algorithms affect how nodes are positioned
- Color schemes highlight different aspects (node type vs severity)
- Interactive features: zoom, pan, hover for details

---

### 02_attack_path_visualization.py
**Purpose**: Visualize attack paths from entry points to high-value targets

**Features**:
- Automatic entry point detection (internet-facing assets)
- High-value target identification (critical assets, PCI/HIPAA scope)
- Shortest attack path finding
- Threat level classification (CRITICAL, HIGH, MEDIUM, LOW)
- Multi-path and single-path views
- Attack path data export

**Output**:
- `output/attack_paths_all.html` - All attack paths
- `output/attack_paths_critical.html` - Critical paths only
- `output/attack_path_detail.html` - Single path detailed view
- `output/attack_paths.json` - Attack path data

**Key concepts**:
- Attack paths show how vulnerabilities can be chained
- Threat levels combine CVSS scores and path complexity
- Entry points are potential initial access vectors
- Targets represent high-value assets to protect

---

### 03_topology_visualization.py
**Purpose**: Visualize network topology with security context

**Features**:
- Security zone visualization (DMZ, Internal, Trusted)
- Asset criticality overlay
- Compliance scope highlighting (PCI-DSS, HIPAA, SOX, GDPR)
- Zone-optimized layouts
- Internet-facing asset identification

**Output**: 6 HTML files showing different topology views
- Zone-colored topology
- Criticality-colored topology
- Zone-focused view
- Compliance scope views (All, PCI-DSS, HIPAA)

**Key concepts**:
- Security zones represent network segmentation
- Compliance markers show regulatory scope
- Criticality indicates business importance
- Internet-facing assets are high-risk entry points

---

### 04_filtered_visualization.py
**Purpose**: Demonstrate advanced filtering for large graphs

**Features**:
- Severity filtering (HIGH+, CRITICAL only)
- Node type filtering (vulnerabilities, packages)
- Security zone filtering
- Criticality filtering
- Compliance scope filtering
- Internet-facing asset filtering
- Search filtering (by name/CVE)

**Output**: 8 filtered visualization HTML files

**Key concepts**:
- Filters create focused views of large graphs
- `include_related=True` shows neighboring nodes
- Filters can be combined for targeted analysis
- Filter statistics show available values

---

### 05_export_formats.py
**Purpose**: Export visualizations to multiple formats

**Features**:
- HTML (interactive web visualization)
- PNG (raster image for presentations)
- SVG (vector graphics for scaling)
- PDF (for reports and documentation)
- JSON (with pre-calculated positions for web apps)
- DOT (Graphviz format)
- Cytoscape.js (web visualization framework)
- GEXF (Gephi format for advanced analysis)
- Complete data package (metadata + graph)

**Output**: `output/exports/` directory with 10+ files

**Key concepts**:
- HTML preserves interactivity (best for exploration)
- PNG/SVG/PDF for static reports and presentations
- JSON for custom web applications
- GEXF/DOT for external graph analysis tools

---

### 06_complete_workflow.py
**Purpose**: End-to-end workflow combining all features

**Workflow**:
1. Load graph
2. Create overview visualization
3. Analyze and visualize attack paths
4. Create topology views
5. Apply filters (high severity, critical severity)
6. Export to multiple formats
7. Generate summary report

**Output**: `output/complete_workflow/` directory with:
- Overview visualization
- Attack path visualizations
- Topology views
- Filtered views
- Multi-format exports
- Summary JSON report

**Key concepts**:
- Complete security analysis workflow
- Multiple perspectives on same data
- Export for different audiences (technical, executive, compliance)

---

## Output Structure

After running all examples, your directory structure will look like:

```
11_graph_visualization/
├── 00_setup.py
├── 01_basic_visualization.py
├── 02_attack_path_visualization.py
├── 03_topology_visualization.py
├── 04_filtered_visualization.py
├── 05_export_formats.py
├── 06_complete_workflow.py
├── README.md
├── sample_graph.graphml                    # Sample data
└── output/                                 # Generated visualizations
    ├── basic_spring_layout.html
    ├── basic_hierarchical_layout.html
    ├── basic_circular_layout.html
    ├── basic_severity_colors.html
    ├── basic_clean_view.html
    ├── basic_3d_visualization.html
    ├── attack_paths_all.html
    ├── attack_paths_critical.html
    ├── attack_path_detail.html
    ├── attack_paths.json
    ├── topology_zones.html
    ├── topology_criticality.html
    ├── topology_zones_focused.html
    ├── topology_compliance_all.html
    ├── topology_compliance_pci.html
    ├── topology_compliance_hipaa.html
    ├── filtered_high_severity.html
    ├── filtered_critical_only.html
    ├── filtered_vuln_packages.html
    ├── filtered_zone_*.html
    ├── filtered_critical_assets.html
    ├── filtered_compliance.html
    ├── filtered_internet_facing.html
    ├── filtered_search_openssl.html
    ├── exports/
    │   ├── graph.html
    │   ├── graph.png
    │   ├── graph.svg
    │   ├── graph.pdf
    │   ├── graph.json
    │   ├── graph.dot
    │   ├── graph.cytoscape.json
    │   ├── graph.gexf
    │   ├── visualization_data.json
    │   └── graph_all_formats.*
    └── complete_workflow/
        ├── 01_overview.html
        ├── 02_attack_paths.html
        ├── 03_topology.html
        ├── 04_filtered_high_severity.html
        ├── 05_filtered_critical.html
        ├── attack_paths.json
        ├── summary.json
        └── exports/
            └── overview.*
```

## CLI Usage

All visualization features are also available via CLI:

```bash
# Basic graph visualization
threat-radar visualize graph sample_graph.graphml -o output.html

# Attack path visualization
threat-radar visualize attack-paths sample_graph.graphml -o attack-paths.html

# Topology visualization
threat-radar visualize topology sample_graph.graphml --color-by zone

# Filtered visualization
threat-radar visualize filter sample_graph.graphml --severity high -o filtered.html

# Export to multiple formats
threat-radar visualize export sample_graph.graphml --format png -o graph.png

# Show filter statistics
threat-radar visualize stats sample_graph.graphml
```

See `threat-radar visualize --help` for complete CLI documentation.

## Use Cases

### Security Analysis
- Identify attack paths from internet-facing assets to critical systems
- Assess blast radius of specific CVEs
- Prioritize remediation based on exploitability

### Compliance Reporting
- Visualize PCI-DSS or HIPAA scoped assets
- Show compliance boundaries and dependencies
- Generate audit-ready topology diagrams

### Infrastructure Overview
- Understand network topology and segmentation
- Identify internet-facing attack surface
- Track dependencies between services

### Vulnerability Management
- Filter to critical/high severity issues
- Find packages with most vulnerabilities
- Export vulnerability data for reporting

## Tips

1. **Start with 01_basic_visualization.py** to understand layouts and color schemes
2. **Use filtering** (04) to focus on specific concerns in large graphs
3. **Export to HTML** for interactive exploration, PDF for static reports
4. **Combine with real scans**: Replace `sample_graph.graphml` with your own vulnerability graphs from `threat-radar graph build`

## Troubleshooting

### "Sample graph not found"
Run `python 00_setup.py` first to generate the sample data.

### "Module 'plotly' not found"
Install visualization dependencies: `pip install plotly kaleido`

### "kaleido export failed"
PNG/SVG/PDF export requires kaleido. Install with: `pip install kaleido`

If kaleido installation fails, you can still use HTML/JSON exports.

### Graphs look cluttered
- Try different layout algorithms (hierarchical often works well)
- Use filtering to reduce node count
- Disable labels for overview: `--no-labels`
- Adjust figure size: `--width 1600 --height 1000`

## Next Steps

After exploring these examples:

1. **Use with real data**: Scan your own containers and build graphs
   ```bash
   threat-radar cve scan-image myapp:latest -o scan.json
   threat-radar graph build scan.json -o myapp.graphml
   python 01_basic_visualization.py  # Edit to use myapp.graphml
   ```

2. **Integrate into workflows**: Add visualization to CI/CD pipelines
   ```bash
   threat-radar cve scan-image $IMAGE --auto-save
   threat-radar graph build latest-scan.json --auto-save
   threat-radar visualize attack-paths latest-graph.graphml -o report.html
   ```

3. **Customize**: Modify examples for your specific needs
   - Change color schemes
   - Adjust layouts
   - Add custom filters
   - Create custom export formats

4. **Explore the API**: Use Python API for custom analysis
   ```python
   from threat_radar.graph import NetworkXClient
   from threat_radar.visualization import NetworkGraphVisualizer

   client = NetworkXClient()
   client.load("sample_graph.graphml")

   visualizer = NetworkGraphVisualizer(client)
   fig = visualizer.visualize(layout="spring", color_by="severity")
   visualizer.save_html(fig, "custom.html")
   ```

## Documentation

For complete documentation, see:
- **CLAUDE.md** - Interactive Graph Visualization section
- **docs/API.md** - Python API reference
- **docs/CLI_FEATURES.md** - CLI usage guide

## Feedback

Found a bug or have a feature request? Please open an issue at:
https://github.com/Threat-Radar/threat-radar/issues
