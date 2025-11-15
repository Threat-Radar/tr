# Dynamic Attack Path Visualizations

This guide explains the enhanced, interactive visualizations available in `02b_dynamic_attack_path_visualization.py`.

## Overview

The dynamic visualization script creates four types of interactive, animated visualizations for attack path analysis:

1. **Animated Step-by-Step Attack Path** - Watch attacks unfold in real-time
2. **3D Attack Path Visualization** - Explore paths in three dimensions
3. **Side-by-Side Comparison** - Compare different attack strategies
4. **Risk Heatmap** - Identify vulnerability concentration points

## Installation

Ensure you have the required dependencies:

```bash
pip install plotly kaleido
```

## Usage

Run the script from the examples directory:

```bash
python 02b_dynamic_attack_path_visualization.py
```

Or use the existing sample graph:

```bash
# First, generate a sample graph
python 00_setup.py

# Then create dynamic visualizations
python 02b_dynamic_attack_path_visualization.py
```

## Visualization Types

### 1. Animated Attack Path (`attack_path_animated.html`)

**Features:**
- ▶️ **Play/Pause Controls** - Control animation playback
- 📊 **Progress Slider** - Jump to specific attack steps
- 🎯 **Step Highlighting** - Current step pulses in red
- 📈 **Attack Metrics** - Real-time CVSS and exploitability scores

**How to Use:**
- Click "Play" to watch the attack unfold step-by-step
- Use the slider to jump to a specific step
- Hover over nodes to see step details
- Click "Reset" to restart the animation

**Best For:**
- Executive presentations
- Demonstrating attack progression
- Training and education
- Incident response walkthroughs

---

### 2. 3D Visualization (`attack_paths_3d.html`)

**Features:**
- 🌐 **3D Network Layout** - Full spatial representation
- 🎨 **Height-Based Criticality** - Z-axis shows asset importance
- 🔄 **Interactive Rotation** - Click and drag to rotate
- 📊 **Multi-Path Overlay** - See up to 10 paths simultaneously
- 🎯 **Color-Coded Threats** - Different colors for threat levels

**How to Use:**
- Click and drag to rotate the view
- Scroll to zoom in/out
- Double-click to reset view
- Hover over paths to see threat details

**Layer Meanings:**
- **Bottom (Z=0)**: Low criticality assets
- **Middle (Z=1-2)**: Medium/High criticality
- **Top (Z=3)**: Critical infrastructure

**Best For:**
- Complex attack path analysis
- Understanding infrastructure depth
- Identifying layered defenses
- Security architecture review

---

### 3. Comparison View (`attack_paths_comparison.html`)

**Features:**
- 📊 **2×2 Grid Layout** - Four paths side-by-side
- 🎯 **Strategy Comparison** - Different attack approaches
- 📈 **Metric Cards** - Quick stats for each path
- 🔍 **Isolated Views** - Each path shown independently

**Compared Paths:**
1. **Most Critical** - Highest threat level and CVSS score
2. **Shortest Path** - Fewest steps to target
3. **Most Exploitable** - Easiest to execute
4. **Longest Path** - Most complex attack chain

**How to Use:**
- Compare path lengths visually
- Review metrics in the top-right of each panel
- Identify which strategy poses the greatest risk
- Understand different attacker approaches

**Best For:**
- Risk prioritization decisions
- Understanding attacker motivations
- Defense strategy planning
- Vulnerability remediation planning

---

### 4. Risk Heatmap (`attack_surface_heatmap.html`)

**Features:**
- 🌡️ **Heat Coloring** - Red = High risk, White = Low risk
- 📊 **Risk Scores** - 0-100 scale per asset
- 📈 **Size Scaling** - Node size indicates risk level
- 🎯 **Path Density** - Shows attack concentration

**Risk Calculation:**
- **Path Count**: Number of attack paths passing through
- **Threat Weight**: Critical=4, High=3, Medium=2, Low=1
- **Normalized Score**: Scaled 0-100 for easy comparison

**How to Use:**
- Identify red/dark nodes (highest risk)
- Focus remediation on largest, darkest nodes
- Look for clusters of high-risk assets
- Hover for exact risk scores

**Best For:**
- Prioritizing security investments
- Identifying critical chokepoints
- Resource allocation decisions
- Attack surface reduction planning

---

## Common Interactive Features

All visualizations support:

- **Hover Details** - Mouse over nodes/edges for information
- **Zoom** - Scroll wheel to zoom in/out
- **Pan** - Click and drag to move around
- **Reset View** - Double-click to reset to default
- **Legend** - Color-coded threat/risk indicators
- **Responsive Design** - Works on different screen sizes

## Tips & Tricks

### For Presentations

1. **Start with Animated View**
   - Shows attack progression clearly
   - Engages audience with movement
   - Easy to follow step-by-step

2. **Use 3D for "Wow Factor"**
   - Impressive visual impact
   - Shows complexity effectively
   - Great for opening slides

3. **Comparison for Decision Making**
   - Side-by-side is easy to understand
   - Clear metrics for each option
   - Supports data-driven decisions

4. **Heatmap for Priorities**
   - Visual prioritization is clear
   - Easy to identify "hot spots"
   - Supports budget discussions

### For Analysis

1. **Animation for Forensics**
   - Replay actual attack sequences
   - Identify critical steps
   - Find prevention points

2. **3D for Architecture Review**
   - Understand network depth
   - Identify layer breaches
   - Validate segmentation

3. **Comparison for Strategy**
   - Evaluate multiple scenarios
   - Compare remediation impact
   - Test defense effectiveness

4. **Heatmap for Planning**
   - Resource allocation
   - Patching priorities
   - Continuous monitoring focus

## Customization

### Modify Animation Speed

Edit the animation duration in the code:

```python
args=[None, {
    'frame': {'duration': 1500, 'redraw': True},  # Change 1500 to desired milliseconds
    ...
}]
```

### Change Color Schemes

Update the threat colors dictionary:

```python
threat_colors = {
    'critical': '#8b0000',  # Dark red
    'high': '#dc143c',      # Crimson
    'medium': '#ffa500',    # Orange
    'low': '#4682b4',       # Steel blue
}
```

### Adjust 3D Height

Modify the criticality Z-values:

```python
criticality_z = {
    'critical': 3.0,  # Increase for more height
    'high': 2.0,
    'medium': 1.0,
    'low': 0.0,
}
```

### Limit Displayed Paths

Change the path count in 3D visualization:

```python
for path in attack_paths[:10]:  # Change 10 to desired count
```

## Performance Considerations

- **Large Graphs**: Limit to <100 nodes for smooth animations
- **Many Paths**: Use filtering to show top 10-20 paths
- **Browser**: Chrome/Firefox recommended for best performance
- **Export**: Use PNG export for static sharing

## Exporting Visualizations

### To PNG/PDF (Static)

Use the `visualize export` command:

```bash
threat-radar visualize export graph.graphml \
  -o attack_paths \
  --format png --format pdf
```

### To Video (Animated)

Use browser screen recording or tools like:
- OBS Studio (free)
- QuickTime (macOS)
- PowerPoint screen recording

### For Reports

1. Open HTML in browser
2. Use browser's "Print to PDF"
3. Or screenshot specific frames

## Troubleshooting

### Animation Not Working

- **Issue**: Play button doesn't work
- **Fix**: Ensure using modern browser (Chrome 90+, Firefox 88+)
- **Alternative**: Use slider to manually step through

### 3D View Performance

- **Issue**: Slow rotation/laggy
- **Fix**: Reduce number of paths displayed (line 279)
- **Fix**: Close other browser tabs
- **Fix**: Use smaller graph (<50 nodes)

### Colors Not Showing

- **Issue**: All nodes same color
- **Fix**: Ensure graph has `criticality` or `zone` attributes
- **Fix**: Check `node_data.get('criticality', 'low')` returns valid values

### Heatmap All White

- **Issue**: No risk scores calculated
- **Fix**: Ensure attack paths were found
- **Fix**: Check that nodes have path intersections

## Integration with CI/CD

### Automated Generation

```bash
#!/bin/bash
# generate-dynamic-viz.sh

# Scan and build graph
threat-radar cve scan-image myapp:latest --auto-save
threat-radar graph build scan.json --auto-save

# Find attack paths
threat-radar graph attack-paths graph.graphml --auto-save

# Generate dynamic visualizations
python 02b_dynamic_attack_path_visualization.py

# Upload to S3/artifact storage
aws s3 cp output/ s3://security-reports/ --recursive
```

### Scheduled Reports

Add to cron:

```bash
# Daily dynamic security visualization
0 2 * * * cd /path/to/examples && ./generate-dynamic-viz.sh
```

## Further Enhancements

Want even more dynamic features? Consider:

1. **Real-time Updates** - Use Dash or Streamlit for live data
2. **Custom Filters** - Add dropdown menus to filter paths
3. **Time Series** - Show attack path changes over time
4. **Network Flow** - Animate data flow along paths
5. **VR/AR Support** - Use WebXR for immersive viewing

---

## Support

For issues or questions:
- Check examples in `examples/11_graph_visualization/`
- Review main docs at `docs/`
- Open issues at https://github.com/Threat-Radar/threat-radar/issues
