#!/usr/bin/env bash
#
# Minimal Plotly 3D test - uses hardcoded coordinates
# If this works, the issue is with the graph data
#

echo "🧪 Testing basic Plotly 3D rendering..."
echo ""

OUTPUT_DIR="./plotly-test-output"
mkdir -p "$OUTPUT_DIR"

cat > /tmp/test_plotly_basic.py << 'EOFPYTHON'
import plotly.graph_objects as go

print("Creating minimal 3D scatter plot with hardcoded data...")

# Simple test data - a cube
x = [0, 1, 0, 1, 0, 1, 0, 1]
y = [0, 0, 1, 1, 0, 0, 1, 1]
z = [0, 0, 0, 0, 1, 1, 1, 1]

fig = go.Figure(data=[
    go.Scatter3d(
        x=x, y=y, z=z,
        mode='markers+text',
        marker=dict(
            size=20,
            color=['red', 'green', 'blue', 'yellow', 'cyan', 'magenta', 'orange', 'purple'],
            line=dict(color='white', width=2)
        ),
        text=['Point ' + str(i) for i in range(8)],
        textposition='top center',
        textfont=dict(size=14, color='white')
    )
])

fig.update_layout(
    title='🧪 Basic Plotly 3D Test - You Should See 8 Colored Points',
    width=1000,
    height=800,
    scene=dict(
        camera=dict(
            eye=dict(x=2, y=2, z=2)
        ),
        xaxis=dict(
            title='X Axis',
            showgrid=True,
            gridcolor='white',
            showbackground=True,
            backgroundcolor='rgb(50,50,50)'
        ),
        yaxis=dict(
            title='Y Axis',
            showgrid=True,
            gridcolor='white',
            showbackground=True,
            backgroundcolor='rgb(50,50,50)'
        ),
        zaxis=dict(
            title='Z Axis',
            showgrid=True,
            gridcolor='white',
            showbackground=True,
            backgroundcolor='rgb(50,50,50)'
        ),
        bgcolor='rgb(100,100,100)'
    ),
    paper_bgcolor='white'
)

output = "${OUTPUT_DIR}/plotly_basic_test.html"
fig.write_html(output)

print(f"\n✅ Test file created: {output}")
print("\nWhat you should see:")
print("  - 8 colored points forming a cube")
print("  - White grid lines")
print("  - Axis labels (X, Y, Z)")
print("  - Gray background")
print("\nIf this is ALSO black:")
print("  1. Check browser WebGL support: https://get.webgl.org/")
print("  2. Try a different browser")
print("  3. Check if hardware acceleration is enabled")
print("  4. Update your graphics drivers")

EOFPYTHON

python3 /tmp/test_plotly_basic.py

if [ $? -eq 0 ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ Basic test file created!"
    echo ""
    echo "Open: $OUTPUT_DIR/plotly_basic_test.html"
    echo ""
    echo "This is the SIMPLEST possible 3D visualization."
    echo "If this is also black, the issue is:"
    echo "  • WebGL not available in your browser"
    echo "  • Hardware acceleration disabled"
    echo "  • Graphics driver issue"
    echo ""
    echo "To check WebGL: https://get.webgl.org/"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Try to open it automatically
    if command -v open &> /dev/null; then
        echo ""
        echo "Opening in browser..."
        open "$OUTPUT_DIR/plotly_basic_test.html"
    fi
fi

rm -f /tmp/test_plotly_basic.py
