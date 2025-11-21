# Attack Path Vulnerability Data Fix Summary

## Problem
Attack paths in `attack-paths.json` had **empty vulnerability arrays** and zero CVSS scores, making them ineffective for security analysis.

## Root Cause
**Missing CONTAINS edges** - Assets were not linked to their packages/vulnerabilities in the graph.

### Why CONTAINS edges were missing:
The environment configuration specified fictional image names that didn't match the actual scanned images:

**Environment Config:**
- asset-dmz-web: `nginx:1.21-alpine`
- asset-payment-processor: `payment-processor:1.0`

**Actual Scans:**
- `gcr.io/google-samples/microservices-demo/frontend:v0.10.1`
- `gcr.io/google-samples/microservices-demo/paymentservice:v0.10.1`

When `env build-graph --merge-scan` tried to match scans to assets by image name, **no matches were found**, so assets remained disconnected from vulnerability data.

## The Fix

### Step 1: Update Environment Config
Modified `environment.json` to use actual scanned image names:
```bash
jq '
  .assets[0].software.image = "gcr.io/google-samples/microservices-demo/frontend:v0.10.1" |
  .assets[1].software.image = "gcr.io/google-samples/microservices-demo/checkoutservice:v0.10.1" |
  # ... etc
' environment.json > environment-updated.json
```

### Step 2: Rebuild Graph with Correct Mappings
```bash
threat-radar env build-graph environment-updated.json \
  --merge-scan frontend_scan.json \
  --merge-scan paymentservice_scan.json \
  # ... etc \
  -o main-graph-with-contains.graphml
```

**Result:** ✓ **36 CONTAINS edges created!**

### Step 3: Regenerate Attack Paths
```bash
threat-radar graph attack-paths main-graph-with-contains.graphml \
  --max-paths 20 \
  -o attack-paths-fixed.json
```

## Results

### Before Fix:
```json
{
  "vulnerabilities": [],
  "cvss_score": null,
  "total_cvss": 0.0,
  "threat_level": "low"
}
```

### After Fix:
```json
{
  "vulnerabilities": [
    "GHSA-v778-237x-gjrc",
    "CVE-2024-34156",
    "CVE-2024-6119",
    "... 24 more CVEs ..."
  ],
  "cvss_score": 9.1,
  "total_cvss": 508.80,
  "threat_level": "CRITICAL"
}
```

### Attack Path Summary:
- **6 attack paths discovered**
- **All rated CRITICAL threat level**
- **Total CVSS scores: 257.80 - 508.80**
- **Exploitability: 70-80%**
- **27 CVEs in entry point alone**

## Graph Statistics

### Before:
- CONTAINS edges: **0**
- Assets could reach vulnerabilities: **NO**

### After:
- CONTAINS edges: **36**
- Assets can reach vulnerabilities: **YES** (63 vulnerabilities reachable)

## Files Created
1. `environment-updated.json` - Corrected environment config
2. `main-graph-with-contains.graphml` - Graph with CONTAINS edges
3. `attack-paths-fixed.json` - Attack paths with full vulnerability data

## Testing
```bash
# Verify CONTAINS edges
python3 -c "
import networkx as nx
G = nx.read_graphml('main-graph-with-contains.graphml')
contains = sum(1 for u,v in G.edges() if G.get_edge_data(u,v).get('edge_type')=='CONTAINS')
print(f'CONTAINS edges: {contains}')
"

# Verify attack paths have vulnerabilities
jq '.attack_paths[0].steps[0].vulnerabilities | length' attack-paths-fixed.json
```

## Lesson Learned
**Always ensure environment asset image names exactly match the scan targets** for proper vulnerability attribution in attack path analysis.

---

Date: November 15, 2025
