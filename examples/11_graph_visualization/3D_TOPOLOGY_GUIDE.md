# 3D Network Topology Visualizations 🌐

Advanced 3D visualizations for network architecture, security zones, and attack path analysis.

## 🎬 Visualization Showcase

### 1. Layered 3D Network Architecture 🏗️
**File:** `topology_3d_layered.html`

**What it does:**
- Shows your **network as actual 3D layers**
- Each security zone is a different height
- Cross-zone connections highlighted in RED
- Perfect for understanding network segmentation

**Layer Heights:**
```
9.0 ┃ DATABASE      🔒 Most secure - data storage
6.0 ┃ TRUSTED       🛡️ Secure zone - critical apps
3.0 ┃ INTERNAL      🏢 Internal - applications
0.0 ┃ DMZ/PUBLIC    🌐 Exposed - internet-facing
```

**Visual Features:**
- **Z-Axis = Security Level**: Higher = More secure
- **Zone Colors**: Each zone has distinct color
- **Cross-Zone Links**: Red lines = potential attack vectors
- **Dotted Planes**: Show layer boundaries
- **Interactive Rotation**: Click & drag to explore

**Perfect for:**
- Architecture review presentations
- Understanding defense-in-depth
- Identifying segmentation gaps
- Compliance reviews (showing isolation)

**Controls:**
- 🖱️ Click & drag to rotate
- 🔍 Scroll to zoom
- 🎯 Hover for node details

**What to Look For:**
- ⚠️ **Red lines crossing layers** = Attack path risk
- 🔴 **Nodes at wrong layer** = Misplaced assets
- 📊 **Layer density** = Resource distribution
- 🎨 **Color clusters** = Zone grouping

---

### 2. Rotating Zone Boundaries 🔄
**File:** `topology_3d_rotating_zones.html`

**What it does:**
- **Auto-rotating 360° view** of network
- **Cylinder boundaries** around each security zone
- Nodes grouped within their zone boundaries
- Dark background for dramatic effect

**Zone Boundaries:**
- **Dashed cylinders** = Security perimeter
- **Cylinder radius** = Zone size/scope
- **Cylinder height** = Vertical separation
- **Color matched** to zone identity

**Animation:**
- Camera orbits around infrastructure
- Complete 360° rotation
- Constant viewing angle
- Smooth, continuous motion

**Perfect for:**
- Security operations center (SOC) displays
- Continuous monitoring screens
- Trade show/conference displays
- Executive office displays

**Controls:**
- ▶️ Auto-Rotate - Start rotation
- ⏸ Stop - Freeze view
- 🖱️ Manual - Click & drag when stopped

**Pro Tips:**
- Let it rotate during meetings for visual interest
- Stop to examine specific areas
- Works great on ultra-wide monitors
- Use dark mode for better contrast

---

### 3. Attack Layer Transition ⚡
**File:** `topology_3d_attack_transition.html`

**What it does:**
- **Watch attacks move through network layers**
- Red diamond shows active attack position
- Compromised nodes turn RED
- Attack path builds up step-by-step

**Animation Features:**
- **Moving Particle**: Red diamond = attacker position
- **Progressive Path**: Path appears as attack advances
- **Node States**:
  - ⚪ Gray = Safe (not yet compromised)
  - 🔴 Red = Compromised (attack passed through)
  - 💎 Diamond = Current attack position
- **Zone Transitions**: Watch attack cross layers

**Timeline:**
- 10 frames per attack step
- Smooth interpolation between nodes
- Slider to jump to specific moments
- Progress indicator shows current step

**Perfect for:**
- Incident response training
- Explaining breach progression
- Red team exercise reviews
- Security awareness training

**Controls:**
- ▶️ Play - Watch attack unfold
- ⏸ Pause - Freeze at current moment
- 📊 Slider - Jump to specific step

**Educational Value:**
- Shows **lateral movement** between layers
- Visualizes **privilege escalation** (moving up layers)
- Demonstrates **zone crossing** attacks
- Illustrates **attack progression** over time

---

### 4. Camera Flythrough Tour 🎥
**File:** `topology_3d_flythrough.html`

**What it does:**
- **Automated camera tour** of entire infrastructure
- Camera orbits while rising from bottom to top
- Shows network from all angles
- Cinematic presentation effect

**Camera Path:**
- **Start**: Low orbit around DMZ layer
- **Middle**: Rising through internal zones
- **End**: High view of database layer
- **Total**: 2 full rotations while ascending

**Tour Progression:**
```
Progress  | View
----------|----------------------------------
0-25%     | DMZ/Public layer (ground level)
25-50%    | Internal applications layer
50-75%    | Trusted secure zone
75-100%   | Database layer (top view)
```

**Perfect for:**
- Opening slide in presentations
- Executive briefings (impressive visuals)
- Architecture overview tours
- Marketing/demo videos

**Controls:**
- ▶️ Start Tour - Begin flythrough
- ⏸ Pause - Stop at current position
- ⏮ Restart - Back to beginning

**Recording Tips:**
- Screen record the tour for videos
- Perfect length for ~6 second loop
- Dark background looks professional
- Add narration for guided tours

---

## 🎯 Comparison Matrix

| Visualization | Best For | Animation | Interactivity | Wow Factor |
|---------------|----------|-----------|---------------|------------|
| **Layered 3D** | Architecture review | ❌ Static | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Rotating Zones** | SOC displays | ✅ Auto-rotate | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Layer Transition** | Training | ✅ Attack progression | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Flythrough** | Presentations | ✅ Camera tour | ⭐⭐ | ⭐⭐⭐⭐⭐ |

## 🚀 Usage

### Generate All Visualizations

```bash
cd examples/11_graph_visualization
python 03_dynamic_3d_topology.py
```

### With Attack Paths

For the attack transition visualization, first generate attack paths:

```bash
cd ../10_attack_path_discovery
./run_attack_path_demo.sh

cd ../11_graph_visualization
python 03_dynamic_3d_topology.py
```

## 🎨 Customization

### Adjust Layer Heights

```python
zone_levels = {
    'dmz': 0.0,
    'internal': 5.0,     # Change from 3.0 to 5.0 for more separation
    'database': 15.0,    # Even higher for more dramatic effect
}
```

### Change Rotation Speed

```python
# Rotating zones
'frame': {'duration': 25}  # Lower = faster rotation

# Flythrough
num_frames = 180  # More frames = slower tour
```

### Modify Camera Path

```python
# Flythrough camera customization
angle = progress * 6 * math.pi  # Change from 4 to 6 for 3 rotations
height = 2 + progress * 20      # Rise higher (was 10)
radius = 20                      # Orbit further out (was 15)
```

### Zone Boundary Size

```python
# Rotating zones - cylinder size
cylinder_radius = 3.5  # Larger boundaries (was 2.5)
cylinder_height = 2.5  # Taller cylinders (was 1.5)
```

## 💡 Presentation Strategies

### For Executives

**Opening:**
1. Start with **Flythrough** - Big visual impact
2. Show **Layered 3D** - Explain architecture
3. If breach occurred, show **Layer Transition**

**Closing:**
- Leave **Rotating Zones** running in background

### For Security Teams

**Analysis:**
1. **Layered 3D** - Identify segmentation gaps
2. **Layer Transition** - Understand attack progression
3. Rotate layers manually to examine cross-zone connections

### For Compliance Auditors

**Demonstration:**
1. **Layered 3D** - Show network segmentation
2. Point out layer separation
3. Highlight cross-zone controls (red lines)
4. Export PNG for compliance documentation

### For SOC/NOC

**Monitoring:**
1. **Rotating Zones** - Continuous display on wall monitor
2. Full screen, dark background
3. Auto-rotate enabled
4. Update graph periodically with new scans

## 🔧 Technical Details

### Layer Assignment Logic

Zones are mapped to Z-coordinates:

```python
# Zone → Height mapping
DMZ/Public     → Z = 0.0   (Bottom - most exposed)
Internal/App   → Z = 3.0   (Middle - protected)
Trusted/Secure → Z = 6.0   (High - restricted)
Database       → Z = 9.0   (Top - most secure)
```

### Camera Mathematics

**Rotating Zones:**
```python
# Circular orbit
camera_x = distance * cos(angle)
camera_y = distance * sin(angle)
camera_z = constant

# Normalized for Plotly
eye = (camera_x/distance, camera_y/distance, camera_z/distance)
```

**Flythrough:**
```python
# Ascending spiral
angle = progress * 4π        # 2 full rotations
height = 2 + progress * 10   # Rise from 2 to 12
```

### Performance Optimization

For large graphs (>100 nodes):

```python
# Reduce frame count
num_frames = 30  # Instead of 60

# Simplify geometry
num_points = 10  # For cylinder boundaries (was 20)

# Limit attack paths
attack_paths = attack_paths[:1]  # Only show first path
```

## 🎬 Recording Videos

### High-Quality Recording

**Settings:**
- Resolution: 1920x1080 (1080p) or 3840x2160 (4K)
- FPS: 30 or 60
- Format: MP4 (H.264)

**Steps:**
1. Open visualization in Chrome (full screen)
2. Set visualization to desired size
3. Start screen recording
4. Click play button
5. Let animation complete
6. Stop recording

### Tools

**macOS:**
```bash
# QuickTime Player (built-in)
# File → New Screen Recording
```

**Windows:**
```bash
# Xbox Game Bar (built-in)
# Windows + G → Record
```

**Linux:**
```bash
# SimpleScreenRecorder (install)
sudo apt install simplescreenrecorder
```

**Cross-platform:**
- OBS Studio (free, professional)
- Camtasia (paid, easy editing)

## 📊 Export Options

### Static Images

**Method 1: Browser Screenshot**
1. Open visualization
2. Rotate to desired angle
3. Right-click → Save Image As

**Method 2: Plotly Export**
```python
fig.write_image("topology.png", width=1920, height=1080)
```

**Method 3: Print to PDF**
1. Open visualization
2. Browser → Print
3. Save as PDF

### For Reports

**PowerPoint:**
1. Export as PNG (high resolution)
2. Insert into slide
3. Or: Embed HTML (Insert → Web Page)

**Word/PDF:**
1. Export as PNG
2. Insert as image
3. Add caption

## 🌟 Advanced Techniques

### Multiple Simultaneous Views

Create split-screen with different angles:

```python
from plotly.subplots import make_subplots

fig = make_subplots(
    rows=1, cols=2,
    specs=[[{'type': 'scatter3d'}, {'type': 'scatter3d'}]]
)

# Add layered view to left
# Add rotating view to right
```

### Custom Zone Definitions

Define your own zones:

```python
custom_zone_levels = {
    'edge': 0.0,           # Edge computing
    'cloud-public': 2.0,   # Public cloud
    'cloud-private': 5.0,  # Private cloud
    'on-prem': 8.0,        # On-premises
}
```

### Compliance Highlighting

Color code by compliance scope:

```python
# In node coloring logic
if node_data.get('pci_scope'):
    node_color = '#ff0000'  # PCI = Red
elif node_data.get('hipaa_scope'):
    node_color = '#4682b4'  # HIPAA = Blue
```

## 🆘 Troubleshooting

**Q: Layers are too close together**
A: Increase z-spacing in `zone_levels` dictionary

**Q: Rotation is choppy**
A: Reduce frame count or increase frame duration

**Q: Can't see all layers**
A: Adjust camera position - move further back or higher up

**Q: Cross-zone edges not visible**
A: Make sure edges exist in graph, check zone assignments

**Q: Flythrough too fast/slow**
A: Adjust `num_frames` and `frame duration` values

**Q: Dark background makes it hard to see**
A: Change `bgcolor` to '#f8f9fa' for light background

## 🔗 Integration

### Dash Real-Time

```python
import dash
from dash import dcc, html
from dash.dependencies import Input, Output

app = dash.Dash(__name__)

app.layout = html.Div([
    dcc.Graph(id='3d-topology', figure=fig),
    dcc.Interval(id='interval', interval=60000)  # Update every minute
])

@app.callback(
    Output('3d-topology', 'figure'),
    Input('interval', 'n_intervals')
)
def update_graph(n):
    # Reload graph data
    # Regenerate visualization
    return new_fig
```

### Web API

```python
from flask import Flask, send_file

app = Flask(__name__)

@app.route('/topology/3d')
def get_3d_topology():
    # Generate visualization
    create_layered_3d_topology(visualizer, 'temp.html')
    return send_file('temp.html')
```

---

## 📚 Learn More

- **3D Plotting**: https://plotly.com/python/3d-charts/
- **Camera Controls**: https://plotly.com/python/3d-camera-controls/
- **Animations**: https://plotly.com/python/animations/
- **Network Viz**: https://networkx.org/documentation/stable/

---

Created with ❤️ for network topology visualization!
