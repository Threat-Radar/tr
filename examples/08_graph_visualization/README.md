# Graph Visualization Examples

This directory contains examples for visualizing Threat Radar graphs using various tools and techniques.

## Overview

Threat Radar graphs can be visualized in multiple ways:
- **Matplotlib** - Python-based static visualizations
- **Interactive HTML** - D3.js-based interactive web visualizations
- **External Tools** - Export to Gephi, yEd, Cytoscape
- **GraphML/JSON** - Standard formats for custom visualizations

## Quick Start

### Install Visualization Dependencies

```bash
# Basic visualization (matplotlib)
pip install matplotlib

# Optional: Advanced layouts (Graphviz)
pip install pygraphviz

# For macOS users:
brew install graphviz
pip install pygraphviz
```

### Run Examples

```bash
# Run all visualization examples
python 01_visualization_examples.py
```

## Visualization Options

### 1. Static PNG Images (matplotlib)

**Best for**: Reports, documentation, presentations

```python
from threat_radar.graph import NetworkXClient
import matplotlib.pyplot as plt
import networkx as nx

# Load or create graph
client = NetworkXClient()
# ... build graph ...

# Simple visualization
plt.figure(figsize=(12, 8))
pos = nx.spring_layout(client.graph)
nx.draw(client.graph, pos, with_labels=True, node_color='lightblue', node_size=3000)
plt.savefig('graph.png', dpi=300)
```

**Advantages:**
- ✅ Easy to generate
- ✅ Good for static documentation
- ✅ High-resolution output
- ✅ No external dependencies

**Disadvantages:**
- ❌ Not interactive
- ❌ Difficult for large graphs

### 2. Interactive HTML (D3.js)

**Best for**: Exploration, presentations, sharing

```bash
# Generate interactive HTML
python 01_visualization_examples.py

# Open in browser
open /tmp/graph_interactive.html
```

**Features:**
- ✅ Drag and drop nodes
- ✅ Click to highlight connections
- ✅ Zoom and pan
- ✅ Colored by asset type
- ✅ Sized by criticality
- ✅ No installation required (works in any browser)

**Advantages:**
- ✅ Interactive exploration
- ✅ Easy to share (single HTML file)
- ✅ Professional appearance
- ✅ Good for medium-sized graphs

**Disadvantages:**
- ❌ Performance degrades with >1000 nodes

### 3. External Tools

#### Gephi (Recommended for Large Graphs)

[Gephi](https://gephi.org) is a powerful open-source graph visualization platform.

```bash
# Export from Threat Radar
threat-radar graph build scan-results.json --auto-save

# Or via Python
client.save("graph.graphml")

# Open in Gephi:
# 1. Download and install Gephi from https://gephi.org
# 2. File → Open → Select graph.graphml
# 3. Choose layout (Force Atlas 2, Fruchterman Reingold)
# 4. Apply styling and filters
# 5. Export as PNG/PDF/SVG
```

**Gephi Features:**
- ✅ Handles large graphs (10,000+ nodes)
- ✅ Advanced layouts and algorithms
- ✅ Community detection
- ✅ Statistical analysis
- ✅ High-quality exports

**Best for:**
- Large-scale vulnerability analysis
- Network topology visualization
- Academic/research presentations

#### yEd

[yEd](https://www.yworks.com/products/yed) is a free desktop application for graph visualization.

```bash
# Export GraphML
client.save("graph.graphml")

# Open in yEd:
# 1. Download yEd from https://www.yworks.com/products/yed
# 2. File → Open → Select graph.graphml
# 3. Layout → Hierarchical or Organic
# 4. Export as PNG/SVG/PDF
```

**yEd Features:**
- ✅ Automatic layout algorithms
- ✅ Hierarchical views
- ✅ Clean, professional output
- ✅ Easy to use

**Best for:**
- Architecture diagrams
- Dependency visualizations
- Clean, publication-ready graphics

#### Cytoscape

[Cytoscape](https://cytoscape.org) is a platform for complex network analysis and visualization.

```bash
# Export GraphML
client.save("graph.graphml")

# Open in Cytoscape:
# 1. Download Cytoscape from https://cytoscape.org
# 2. File → Import → Network from File
# 3. Select graph.graphml
# 4. Apply layouts and styles
```

**Cytoscape Features:**
- ✅ Scientific/biotech focus
- ✅ Advanced network analysis
- ✅ Plugin ecosystem
- ✅ Pathway analysis

**Best for:**
- Scientific research
- Complex network analysis
- Biological pathways

### 4. Web-Based Custom Visualization

Use the JSON export for custom web visualizations:

```python
# Export to JSON
json_data = client.export_to_dict()

# Use with:
# - D3.js force-directed graphs
# - Vis.js network visualization
# - Sigma.js graph drawing
# - Cytoscape.js (JavaScript version)
```

## Example Outputs

### Example 1: Simple Visualization
![Simple Graph](../../docs/images/graph_simple.png)

Basic visualization showing nodes and edges.

### Example 2: Styled by Type
![Styled Graph](../../docs/images/graph_styled.png)

Nodes colored by asset type (container, service, database).

### Example 3: Sized by Criticality
![Criticality Graph](../../docs/images/graph_criticality.png)

Node sizes represent business criticality scores.

### Example 4: Interactive HTML
![Interactive Graph](../../docs/images/graph_interactive.gif)

Interactive D3.js visualization with drag-and-drop.

## Visualization Styles

### By Node Type

Color code nodes based on asset type:

```python
node_colors = {
    'container': '#3498db',  # Blue
    'service': '#2ecc71',    # Green
    'database': '#e74c3c',   # Red
    'vulnerability': '#e67e22',  # Orange
}
```

### By Criticality

Size nodes based on business criticality:

```python
# Size 500-5000 based on criticality score (0-100)
size = 500 + (criticality_score * 45)
```

### By Severity

Color vulnerabilities by severity:

```python
severity_colors = {
    'critical': '#e74c3c',  # Red
    'high': '#f39c12',      # Orange
    'medium': '#f1c40f',    # Yellow
    'low': '#2ecc71',       # Green
}
```

## Command-Line Visualization

Currently, Threat Radar doesn't have a built-in CLI visualization command, but you can:

1. **Export and visualize manually:**
```bash
# Build and save graph
threat-radar graph build scan-results.json -o graph.graphml

# Open in external tool
open graph.graphml  # Opens with default GraphML viewer
```

2. **Use Python script:**
```bash
# Create visualization
python examples/08_graph_visualization/01_visualization_examples.py
```

3. **Future CLI command (planned):**
```bash
# Generate visualization (coming soon)
threat-radar graph visualize scan-results.json -o graph.png --style criticality
threat-radar graph visualize scan-results.json -o graph.html --interactive
```

## Tips for Large Graphs

### Performance Optimization

For graphs with >100 nodes:

1. **Filter before visualizing:**
```python
# Only show critical/high severity
filtered = [n for n in graph.nodes() if node_data['criticality'] in ['critical', 'high']]
```

2. **Use hierarchical layouts:**
```python
# Better for dependency trees
pos = nx.nx_agraph.graphviz_layout(G, prog='dot')
```

3. **Simplify for overview:**
```python
# Show only packages with vulnerabilities
vulnerables_only = [n for n in graph.nodes() if n.startswith('vuln:')]
```

### Layout Algorithms

Choose the right layout for your data:

- **Spring layout** - Good for general graphs, organic look
- **Hierarchical** - Good for dependency trees
- **Circular** - Good for highlighting cycles
- **Kamada-Kawai** - Good for even spacing
- **Spectral** - Fast for large graphs

```python
# Spring layout (organic)
pos = nx.spring_layout(G, k=2, iterations=50)

# Hierarchical (top-down)
pos = nx.nx_agraph.graphviz_layout(G, prog='dot')

# Circular
pos = nx.circular_layout(G)

# Kamada-Kawai
pos = nx.kamada_kawai_layout(G)
```

## Integration with Analysis

### Highlight Critical Paths

```python
from threat_radar.environment import EnvironmentGraphBuilder

# Find critical paths
paths = builder.find_critical_paths(env)

# Highlight in visualization
critical_nodes = set()
for path in paths:
    critical_nodes.update(path)

# Color critical path nodes differently
colors = ['red' if node in critical_nodes else 'lightblue' for node in G.nodes()]
```

### Show Risk Scores

```python
# Calculate risk scores
risk_scores = builder.calculate_risk_scores(env)

# Annotate nodes with scores
labels = {
    node: f"{name}\n(Risk: {risk_scores.get(node, 0):.0f})"
    for node, name in node_names.items()
}
```

## Export Formats

### GraphML (.graphml)

**Standard format for graph visualization tools**

```python
client.save('graph.graphml')
```

**Supported by:**
- Gephi, yEd, Cytoscape
- igraph, NetworkX
- Neo4j Desktop

**Advantages:**
- ✅ Preserves all node/edge properties
- ✅ Widely supported
- ✅ XML-based (human-readable)

### JSON (.json)

**For web visualizations and custom tools**

```python
json_data = client.export_to_dict()
with open('graph.json', 'w') as f:
    json.dump(json_data, f, indent=2)
```

**Format:**
```json
{
  "nodes": [
    {"id": "node1", "name": "Web Server", "criticality": 85},
    {"id": "node2", "name": "Database", "criticality": 95}
  ],
  "links": [
    {"source": "node1", "target": "node2", "type": "depends_on"}
  ]
}
```

**Supported by:**
- D3.js
- Vis.js
- Sigma.js
- Custom tools

### DOT (.dot)

**For Graphviz rendering**

```python
from networkx.drawing.nx_agraph import write_dot
write_dot(client.graph, 'graph.dot')
```

**Render with Graphviz:**
```bash
dot -Tpng graph.dot -o graph.png
dot -Tsvg graph.dot -o graph.svg
dot -Tpdf graph.dot -o graph.pdf
```

## Troubleshooting

### Issue: "matplotlib not found"

```bash
pip install matplotlib
```

### Issue: "pygraphviz not found"

```bash
# macOS
brew install graphviz
pip install pygraphviz

# Ubuntu/Debian
sudo apt-get install graphviz graphviz-dev
pip install pygraphviz

# Fedora/RHEL
sudo dnf install graphviz graphviz-devel
pip install pygraphviz
```

### Issue: "Graph is too small/large"

Adjust figure size and node sizes:

```python
plt.figure(figsize=(20, 16))  # Larger canvas
nx.draw(..., node_size=5000)  # Larger nodes
```

### Issue: "Labels overlap"

Use fewer labels or adjust layout:

```python
# Only label important nodes
labels = {n: n for n in important_nodes}
nx.draw_networkx_labels(G, pos, labels)
```

### Issue: "Graph is too dense"

Filter or simplify:

```python
# Remove low-criticality nodes
G_filtered = G.subgraph([n for n in G.nodes() if criticality[n] >= 70])
```

## Best Practices

1. **Start simple** - Use matplotlib for quick visualizations
2. **Use colors meaningfully** - Map to asset types, criticality, or risk
3. **Size matters** - Size nodes by importance (criticality, connection count)
4. **Label strategically** - Don't label every node in large graphs
5. **Export for sharing** - GraphML for colleagues with tools, HTML for everyone
6. **Filter for clarity** - Focus on critical/high risk items
7. **Use hierarchical layouts** - For dependency chains
8. **Test layouts** - Try different algorithms for best results

## Additional Resources

- [NetworkX Documentation](https://networkx.org/documentation/stable/)
- [Matplotlib Graph Visualization](https://matplotlib.org/)
- [D3.js Force-Directed Graph](https://d3js.org/)
- [Gephi Tutorial](https://gephi.org/users/)
- [yEd Manual](https://yed.yworks.com/support/manual/)
- [Cytoscape Documentation](https://cytoscape.org/documentation.html)

## Coming Soon

Future visualization features planned:
- Built-in CLI visualization command
- Automatic layout selection
- Real-time graph updates
- 3D graph visualization
- VR/AR graph exploration
