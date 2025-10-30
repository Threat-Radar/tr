# Graph Database Examples

This directory contains comprehensive examples demonstrating Threat Radar's graph database capabilities for vulnerability and infrastructure modeling.

## Overview

The graph database feature models security relationships as a graph structure, enabling powerful queries that are difficult or impossible with flat data structures:

- **Blast Radius Analysis**: Find all assets affected by a CVE
- **Package Risk Assessment**: Identify most vulnerable packages
- **Attack Path Discovery**: Trace potential exploit chains
- **Fix Prioritization**: Intelligently prioritize remediation efforts
- **Trend Analysis**: Track security posture over time

## Files in This Directory

### 01_basic_graph_usage.py
**Beginner-friendly introduction to graph operations**

Demonstrates:
- Building graphs from CVE scan results
- Querying graph metadata
- Finding vulnerable packages
- Calculating vulnerability blast radius
- Discovering available fixes
- Saving and loading graphs
- Getting vulnerability statistics

**Run time**: ~30 seconds
**Prerequisites**: None (uses mock data)

```bash
python 01_basic_graph_usage.py
```

**Key Takeaways:**
- Understand graph structure (nodes and edges)
- Learn basic querying patterns
- See how to persist graphs for later analysis

---

### 02_advanced_graph_analysis.py
**Deep dive into sophisticated graph queries**

Demonstrates:
- Most vulnerable packages analysis
- Package usage pattern detection
- Vulnerability trend analysis with visualizations
- Intelligent fix prioritization algorithms
- Custom NetworkX queries
- Exporting for visualization tools

**Run time**: ~45 seconds
**Prerequisites**: Complete basic examples first

```bash
python 02_advanced_graph_analysis.py
```

**Key Takeaways:**
- Advanced analytical queries
- Priority scoring algorithms
- Direct NetworkX graph manipulation
- Export formats for visualization

---

### 03_graph_workflows.py
**Real-world security operations scenarios**

Demonstrates:
1. **CI/CD Pipeline Integration** - Pass/fail security checks
2. **Multi-Container Stack Analysis** - Microservices security
3. **Vulnerability Trend Tracking** - Weekly progress monitoring
4. **Security Audit Reporting** - Compliance documentation
5. **Remediation Planning** - Step-by-step fix plans

**Run time**: ~60 seconds
**Prerequisites**: Understand basic and advanced concepts

```bash
python 03_graph_workflows.py
```

**Key Takeaways:**
- Production-ready workflows
- Policy enforcement patterns
- Reporting templates
- Actionable remediation plans

## Quick Start

### 1. Run with Mock Data (Fastest)

All examples include mock data and can run immediately:

```bash
# Basic concepts
python 01_basic_graph_usage.py

# Advanced queries
python 02_advanced_graph_analysis.py

# Complete workflows
python 03_graph_workflows.py
```

### 2. Run with Real CVE Scans

For real-world results, scan actual containers first:

```bash
# Step 1: Scan container
threat-radar cve scan-image alpine:3.18 --auto-save -o alpine-scan.json

# Step 2: Build graph
threat-radar graph build alpine-scan.json --auto-save -o alpine-graph.graphml

# Step 3: Query graph
threat-radar graph query alpine-graph.graphml --stats
threat-radar graph query alpine-graph.graphml --top-packages 10
threat-radar graph query alpine-graph.graphml --cve CVE-2023-XXXX
```

## Example Output Highlights

### Vulnerability Blast Radius
```
Impact Analysis for CVE-2023-0001:
  Affected packages: 1
  Affected containers: 3
  Affected services: 2
  Affected hosts: 1

  Vulnerable packages:
    • package:openssl@1.1.1

  Impacted containers:
    • container:frontend-app
    • container:backend-api
    • container:worker-service
```

### Fix Prioritization
```
🎯 Prioritized Fix Plan:
Priority    CVE               Severity     CVSS    Affected
🔴 URGENT   CVE-2023-0001    CRITICAL     9.8     3
🟠 HIGH     CVE-2023-0002    HIGH         7.5     2
🟡 MEDIUM   CVE-2023-0003    MEDIUM       5.3     1
```

### Trend Analysis
```
📈 Trend Analysis:
Date         Total    Critical   High     Avg CVSS   Change
----------------------------------------------------------------
2025-01-01   8        2          3        7.2
2025-01-08   6        1          2        6.5        ↓ 2
2025-01-15   4        1          1        5.8        ↓ 2
2025-01-22   3        0          1        4.9        ↓ 1

📊 Overall Progress:
   ✅ IMPROVING: 5 fewer vulnerabilities (62.5% reduction)
```

## Common Use Cases

### CI/CD Integration

Use graph analysis to enforce security policies in your build pipeline:

```python
# In your CI/CD script
from threat_radar.graph import NetworkXClient, GraphBuilder, GraphAnalyzer

client = NetworkXClient()
builder = GraphBuilder(client)
builder.build_from_scan(scan_result)

analyzer = GraphAnalyzer(client)
stats = analyzer.vulnerability_statistics()

# Enforce policy
if stats['by_severity']['critical'] > 0:
    print("❌ Build failed: Critical vulnerabilities found")
    sys.exit(1)
```

### Security Dashboards

Export graph data for custom dashboards:

```python
# Export for web visualization
graph_dict = client.export_to_dict()

# Save for D3.js, Cytoscape.js, etc.
with open('dashboard-data.json', 'w') as f:
    json.dump(graph_dict, f)
```

### Compliance Reporting

Generate audit reports for stakeholders:

```python
analyzer = GraphAnalyzer(client)
stats = analyzer.vulnerability_statistics()
top_packages = analyzer.most_vulnerable_packages(top_n=10)
fixes = analyzer.find_fix_candidates()

# Generate report sections
# (See 03_graph_workflows.py for complete example)
```

## Graph Structure Reference

### Node Types

| Type | Description | Properties |
|------|-------------|------------|
| `container` | Docker images | image_name, image_id, distro, architecture |
| `package` | Installed packages | name, version, ecosystem |
| `vulnerability` | CVE entries | cve_id, severity, cvss_score, description |
| `service` | Exposed services | name, port, protocol |
| `host` | Infrastructure hosts | hostname, os, ip |
| `scan_result` | Scan metadata | timestamp, total_vulns, severity_counts |

### Edge Types

| Type | Direction | Meaning |
|------|-----------|---------|
| `CONTAINS` | Container → Package | Container includes package |
| `HAS_VULNERABILITY` | Package → Vulnerability | Package has CVE |
| `FIXED_BY` | Vulnerability → Package | CVE fixed in version |
| `DEPENDS_ON` | Container → Container | Dependency relationship |
| `EXPOSES` | Container → Service | Container exposes service |
| `RUNS_ON` | Container → Host | Deployment location |
| `SCANNED_BY` | Container → ScanResult | Scan history |

## Advanced Topics

### Custom Queries with NetworkX

Access the underlying NetworkX graph for custom analysis:

```python
from threat_radar.graph import NetworkXClient
import networkx as nx

client = NetworkXClient()
# ... build graph ...

# Access NetworkX graph
G = client.graph

# Use any NetworkX algorithm
pagerank = nx.pagerank(G)
shortest_paths = nx.shortest_path(G, source, target)
communities = nx.community.louvain_communities(G)
```

### Graph Visualization

Export graphs for visualization tools:

```bash
# GraphML format (Gephi, Cytoscape)
threat-radar graph build scan.json -o graph.graphml

# JSON format (D3.js, custom web apps)
```

**Recommended Tools:**
- **Gephi** (https://gephi.org) - Desktop, powerful
- **Cytoscape** (https://cytoscape.org) - Network analysis
- **Neo4j Browser** - Graph database UI
- **D3.js** - Web-based custom visualizations

### Migration to Neo4j

The architecture supports future Neo4j migration:

```python
# Current: NetworkX
from threat_radar.graph import NetworkXClient
client = NetworkXClient()

# Future: Neo4j (when implemented)
from threat_radar.graph import Neo4jClient
client = Neo4jClient(uri="bolt://localhost:7687")

# Same API, different backend!
```

## Performance Considerations

### Graph Size

- **Small** (< 100 nodes): Instant queries
- **Medium** (100-1000 nodes): Sub-second queries
- **Large** (> 1000 nodes): Consider Neo4j migration

### Storage

GraphML files are compact:
- Typical scan: 50-200 KB
- Large scan: 500 KB - 2 MB
- Historical collection: Manageable with cleanup

```bash
# Clean up old graphs
threat-radar graph cleanup --days 30
```

## Troubleshooting

### Issue: "Graph file not found"
**Solution**: Check file path and ensure graph was saved:
```bash
threat-radar graph build scan.json --auto-save
threat-radar graph list  # Verify saved
```

### Issue: "No vulnerabilities found in graph"
**Solution**: Verify scan results have vulnerabilities:
```bash
# Check scan output
cat scan.json | jq '.matches | length'
```

### Issue: "CVE not found in graph"
**Solution**: Use correct CVE ID format:
```bash
# Correct
threat-radar graph query graph.graphml --cve CVE-2023-0001

# Incorrect (missing CVE- prefix)
threat-radar graph query graph.graphml --cve 2023-0001
```

## Next Steps

1. **Run Examples**: Start with `01_basic_graph_usage.py`
2. **Real Scans**: Try with your actual containers
3. **Customize**: Adapt workflows to your security operations
4. **Automate**: Integrate into CI/CD pipelines
5. **Visualize**: Export graphs to visualization tools

## Resources

- **Main Documentation**: `../../CLAUDE.md` (Graph Commands Reference)
- **CLI Help**: `threat-radar graph --help`
- **Python API**: `../../docs/API.md`
- **NetworkX Docs**: https://networkx.org/documentation/stable/

## Contributing

Found a useful pattern? Submit examples via pull request!

## Support

Questions or issues? Check:
- GitHub Issues: https://github.com/anthropics/threat-radar/issues
- Documentation: `../../docs/`
- Examples Index: `../INDEX.md`

---

**Happy Graph Analysis! 🔷**
