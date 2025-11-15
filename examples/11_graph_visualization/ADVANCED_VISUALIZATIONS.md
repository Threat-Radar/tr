# Advanced Dynamic Attack Path Visualizations 🚀

These are cutting-edge, highly interactive visualizations that take attack path analysis to the next level!

## 🎬 Visualization Showcase

### 1. Network Flow with Moving Particles 🌊
**File:** `attack_flow_particles.html`

**What it does:**
- Shows attacks as **colored particles flowing through the network**
- Multiple attack streams move simultaneously
- Dark background with glowing particle effects
- Continuous loop animation

**Visual Features:**
- 🔴 Red particles = Critical attacks
- 🟠 Orange particles = High severity
- 🟡 Yellow particles = Medium severity
- 🔵 Blue particles = Low severity
- Each path has 5 particles flowing along it
- Particles loop continuously for mesmerizing effect

**Perfect for:**
- Live security operations center (SOC) displays
- Demonstrating active attack detection
- Real-time threat monitoring dashboards
- Security awareness training

**Controls:**
- ▶️ Play - Start particle flow
- ⏸ Pause - Freeze animation

**Pro Tips:**
- Full-screen this on a large monitor for maximum impact
- Works great on dark backgrounds in presentations
- Particles show the "flow" of attack traffic

---

### 2. Multi-Attack Timeline Simulation ⏱️
**File:** `multi_attack_timeline.html`

**What it does:**
- Simulates **6 different attacks happening over time**
- Each attack starts at a different time (staggered)
- Watch as paths progress and overlap
- Nodes turn RED when under active attack

**Timeline Features:**
- Time range: 0-100 time units
- Each attack has different start time
- Attacks can overlap and compound
- Visual progression shows attack advancement
- Attack paths drawn step-by-step

**Attack Lifecycle:**
- Start time: Staggered (0, 15, 30, 45, 60, 75 time units)
- Duration: Based on path length × 8 time units
- Active indication: Red nodes = under attack
- Path colors: Match threat level

**Perfect for:**
- Understanding attack timing
- Incident response planning
- Capacity planning for defenders
- Coordinated attack scenarios

**Controls:**
- ▶️ Play - Run simulation
- ⏸ Pause - Stop at current time
- ⏮ Reset - Back to time 0
- 📊 Slider - Jump to specific time

**What to Look For:**
- Peaks: When multiple attacks overlap (worst case)
- Valleys: Quiet periods between attacks
- Targets: Which nodes get hit most
- Patterns: Coordinated vs. random timing

---

### 3. Rotating 3D Sphere 🌐
**File:** `attack_sphere_3d.html`

**What it does:**
- Maps your entire network onto a **3D sphere**
- Auto-rotates for full 360° viewing
- Attack paths arc across the sphere surface
- Fibonacci spiral algorithm for perfect node distribution

**3D Features:**
- **Perfect Distribution**: Nodes evenly spread using golden ratio
- **Auto-Rotation**: Continuous 360° spin
- **Arc Paths**: Attack paths curve across sphere
- **Depth Perception**: 3D gives instant network overview
- **Interactive**: Click & drag to manually rotate

**Mathematics:**
- Uses Fibonacci sphere algorithm
- Golden ratio (φ) for optimal spacing
- Spherical coordinates (θ, φ, r)
- Radius: 5.0 units

**Perfect for:**
- "Wow factor" in presentations
- Global infrastructure visualization
- Network architecture overview
- Artistic/futuristic displays

**Controls:**
- ▶️ Auto-Rotate - Continuous spin
- ⏸ Stop - Freeze rotation
- 🖱️ Manual: Click + drag to rotate manually
- 🔍 Scroll to zoom

**Pro Tips:**
- Let it auto-rotate during intro slides
- Zoom in to see specific attack paths
- Stop rotation to examine details
- Works great on 4K displays

---

### 4. Force-Directed Attack Pressure 💥
**File:** `attack_pressure_force.html`

**What it does:**
- Nodes **pulse and move** based on attack intensity
- High-pressure nodes "vibrate" under stress
- Edge colors show network tension
- Real-time stress visualization

**Pressure Calculation:**
- **Critical attacks** = 4.0 pressure units
- **High attacks** = 3.0 pressure units
- **Medium attacks** = 2.0 pressure units
- **Low attacks** = 1.0 pressure unit
- Total pressure = Sum of all attacks on that node

**Visual Indicators:**
- 🔴 **Dark Red (8+ pressure)**: EXTREME - Node about to fail
- 🟠 **Red (5-8 pressure)**: HIGH - Critical stress level
- 🟡 **Orange (2-5 pressure)**: MEDIUM - Elevated threat
- ⚪ **Gray (0-2 pressure)**: NORMAL - No significant threat

**Physics Simulation:**
- Nodes displace from original position
- Displacement = f(pressure, time)
- Oscillation creates "pulse" effect
- Gradual return to normal after attack

**Perfect for:**
- Live attack monitoring
- Stress testing visualization
- Capacity planning
- Infrastructure resilience analysis

**Controls:**
- ▶️ Play - Start pressure simulation
- ⏸ Pause - Freeze current state

**What to Watch:**
- **Pulsing nodes**: Currently under attack
- **Color intensity**: Attack severity
- **Movement amount**: Stress level
- **Edge colors**: Network strain

---

### 5. Exploding Path Detail View 💣
**File:** `attack_path_exploding.html`

**What it does:**
- Attack path nodes **explode outward** to reveal details
- Satellite nodes appear showing CVE/vulnerability info
- Smooth explosion and collapse animation
- Focus on the most critical attack path

**Explosion Animation:**
- **Phase 1 (0-50%)**: Nodes expand outward
- **Phase 2 (50-100%)**: Nodes collapse back
- **Detail visibility**: Only shown when explosion > 50%
- **Sine wave**: Smooth, natural motion

**Detail Nodes:**
- 💎 **Diamond shapes**: Detail/CVE information
- 🔶 **Orange color**: Secondary information
- ⭕ **Orbit**: Circle around parent node
- 📏 **Distance**: Scales with explosion factor

**Perfect for:**
- Deep-dive analysis presentations
- Explaining specific vulnerabilities
- Educational demonstrations
- Technical deep dives

**Controls:**
- ▶️ Explode - Start explosion animation
- ⏸ Pause - Freeze at current explosion level

**Interpretation:**
- Red nodes: Part of attack path
- Gray nodes: Not in attack path
- Diamond satellites: Vulnerability details
- Distance from center: Detail relevance

---

## 🎯 Quick Comparison

| Visualization | Best For | Wow Factor | Technical Depth | Interactivity |
|---------------|----------|------------|-----------------|---------------|
| **Particle Flow** | SOC displays | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Timeline Simulation** | Planning | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **3D Sphere** | Presentations | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Force Pressure** | Live monitoring | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Exploding Detail** | Deep analysis | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |

## 🚀 Usage

### Generate All Visualizations

```bash
cd examples/11_graph_visualization
python 02c_advanced_dynamic_visualizations.py
```

### Individual Generation

Modify the script to run only specific visualizations:

```python
# Comment out visualizations you don't need
# create_network_flow_animation(...)
# create_multi_attack_simulation(...)
create_rotating_3d_sphere(...)  # Only this one
# create_force_directed_attack(...)
# create_exploding_path_view(...)
```

## 🎨 Customization Ideas

### Particle Flow
```python
# Change particle count
num_particles = 10  # More particles = denser flow

# Change flow speed
'frame': {'duration': 25}  # Lower = faster

# Change colors
threat_colors = {
    'critical': '#your_color',
}
```

### Timeline
```python
# Adjust timeline length
time_steps = 200  # Longer simulation

# Change attack stagger
start_time = idx * 20  # More spacing between attacks

# Adjust step duration
duration = len(path.steps) * 10  # Slower attack progression
```

### 3D Sphere
```python
# Change sphere size
radius = 10.0  # Bigger sphere

# Rotation speed
'frame': {'duration': 30}  # Faster rotation

# Camera angle
camera=dict(eye=dict(x=2, y=2, z=2))  # Different viewing angle
```

### Force Pressure
```python
# Pressure weights
threat_weights = {
    'critical': 10.0,  # More dramatic effect
}

# Displacement amount
displacement = 0.5 * pressure  # Larger movement

# Pulse frequency
math.sin(progress * 8 * math.pi)  # Faster pulsing
```

### Exploding View
```python
# Explosion size
explosion = math.sin(progress * math.pi) * 5.0  # Bigger explosion

# Detail count
num_details = 8  # More satellite nodes

# Explosion distance
detail_distance = 0.5 * explosion  # Further spread
```

## 💡 Presentation Tips

### For Executives
1. **Start with 3D Sphere**: Big visual impact
2. **Show Particle Flow**: Easy to understand
3. **Use Timeline**: Explain attack scenarios

### For Technical Teams
1. **Timeline Simulation**: Detailed analysis
2. **Force Pressure**: Infrastructure stress
3. **Exploding View**: Deep dive into specifics

### For SOC/NOC
1. **Particle Flow**: Live monitoring feel
2. **Force Pressure**: Real-time status
3. **Timeline**: Incident replay

## 🔧 Performance Tips

- **Large graphs (>100 nodes)**: Reduce particle count or path count
- **Slow animation**: Increase frame duration
- **Memory issues**: Reduce number of frames
- **Smooth playback**: Use Chrome browser, close other tabs

## 🎬 Video Recording

To create videos from these animations:

### macOS (QuickTime)
1. Open visualization in Chrome (full screen)
2. Open QuickTime Player
3. File → New Screen Recording
4. Click play on visualization
5. Stop recording after desired length

### Windows (Game Bar)
1. Press Windows + G
2. Click record button
3. Play visualization
4. Stop with Windows + Alt + R

### Linux (OBS Studio)
1. Install OBS Studio
2. Add Browser Source
3. Point to HTML file
4. Record scene

## 🌟 Advanced Techniques

### Combine Visualizations
Generate multiple views and create side-by-side comparison:

```python
from plotly.subplots import make_subplots

# Create 2x2 grid with different visualizations
fig = make_subplots(rows=2, cols=2)
# Add particle flow to (1,1)
# Add sphere to (1,2)
# Add pressure to (2,1)
# Add timeline to (2,2)
```

### Export to PowerPoint
1. Generate HTML visualizations
2. Open in Chrome
3. Use "Print to PDF"
4. Insert PDF into PowerPoint
5. Or: Screen capture key frames

### Real-time Data Integration
Modify scripts to accept live data:

```python
def update_from_api():
    data = requests.get('http://api/attacks').json()
    attack_paths = parse_attack_data(data)
    create_network_flow_animation(visualizer, attack_paths, output)
```

## 🔗 Integration Examples

### Dash App (Live Dashboard)
```python
import dash
from dash import dcc, html

app = dash.Dash(__name__)
app.layout = html.Div([
    dcc.Graph(figure=fig),
    dcc.Interval(id='interval', interval=5000)  # Update every 5s
])
```

### Streamlit (Quick Prototype)
```python
import streamlit as st

st.title("Live Attack Visualization")
st.plotly_chart(fig, use_container_width=True)
```

### Web Socket (Real-time)
```python
@socketio.on('new_attack')
def handle_attack(data):
    update_visualization(data)
    emit('refresh_viz', {'fig': fig.to_json()})
```

---

## 🆘 Troubleshooting

**Q: Animations are choppy**
A: Reduce number of frames or increase frame duration

**Q: Particles not moving**
A: Check that attack paths were found, ensure plotly is updated

**Q: 3D sphere looks flat**
A: Enable camera controls, adjust viewing angle

**Q: Force pressure too subtle**
A: Increase pressure weights and displacement factors

**Q: Explosion doesn't show details**
A: Ensure explosion factor > 0.5, check detail node creation

---

## 🎓 Learn More

- **Plotly Animation**: https://plotly.com/python/animations/
- **NetworkX Layouts**: https://networkx.org/documentation/stable/reference/drawing.html
- **3D Visualizations**: https://plotly.com/python/3d-charts/
- **Force-Directed Graphs**: https://en.wikipedia.org/wiki/Force-directed_graph_drawing

---

Created with ❤️ for security visualization enthusiasts!
