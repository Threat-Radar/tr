# Command Center Visualization Fix Summary

## Problem
The command center visualizations were empty (showing all zeros for vulnerability counts) despite having valid vulnerability data in the graph.

## Root Causes

### 1. Incorrect Node Attribute Name
**Issue:** The visualization code was checking for `node_data.get('type')` when the GraphML format uses `'node_type'` as the attribute name.

**Files Affected:**
- `examples/13_microservices_demo_analysis/full-demo.sh` (lines 1662, 1733, 1736, 1792, 1816, 1819)

**Fix:** Changed all occurrences of `.get('type')` to `.get('node_type')`

### 2. Incorrect Statistics Dictionary Structure
**Issue:** The code was accessing severity counts as `stats.get('critical', 0)` when the actual structure is nested: `stats['by_severity']['critical']`

**Files Affected:**
- `examples/13_microservices_demo_analysis/full-demo.sh` (lines 1717-1720)

**Fix:** Changed to use correct nested dictionary structure:
```python
# Before
counts = [
    stats.get('critical', 0),
    stats.get('high', 0),
    ...
]

# After
counts = [
    stats['by_severity']['critical'],
    stats['by_severity']['high'],
    ...
]
```

## Verification

After fixes, the command centers now correctly show:

### Critical Vulnerability Command Center
- ✅ Panel 1: Critical CVEs table (5 entries)
- ✅ Panel 2: High CVEs table (10 entries)  
- ✅ Panel 3: Severity pie chart (63 total: Critical=5, High=16, Medium=28, Low=14)
- ✅ Panel 4: Top packages bar chart (10 packages, top: stdlib@go1.22.5 with 22 CVEs)

### Package Risk Command Center
- ✅ Panel 1: Most vulnerable packages (10 packages)
- ✅ Panel 2: Package ecosystem distribution
- ✅ Panel 3: Vulnerability count distribution
- ✅ Panel 4: Packages with critical CVEs

## Testing
```bash
# Rebuild graph with proper vulnerability merging
threat-radar env build-graph full-demo-results/environment.json \
  --merge-scan full-demo-results/01-scans/*.json \
  -o full-demo-results/05-graphs/main-graph.graphml

# Regenerate command centers (automatically done by full-demo.sh)
# Or run the vulnerability_command_centers function manually
```

## Files Modified
1. `examples/13_microservices_demo_analysis/full-demo.sh`
   - Fixed 6 instances of incorrect attribute name
   - Fixed 4 instances of incorrect stats dictionary access

## Date
November 15, 2025
