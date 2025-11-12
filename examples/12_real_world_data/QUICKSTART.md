# Real-World Data Quick Start Guide

## ✅ What Just Worked

You now have a complete test dataset with:
- ✅ **Environment config** (ecommerce-production with 5 assets)
- ✅ **Real CVE scan** (nginx:latest with 56 vulnerabilities)
- ✅ **Complete graph** (infrastructure + vulnerabilities merged)

## 📍 Important: Working Directory

**All commands below assume you're in `examples/12_real_world_data/`:**

```bash
# Navigate to the example directory
cd examples/12_real_world_data

# Check you're in the right place
pwd  # Should show: .../tr-m2/examples/12_real_world_data
```

## 🚀 Quick Commands

### 1. Validate Environment Config
```bash
threat-radar env validate \
  real-world-data/configs/ecommerce-production-environment.json
```

**Output:** Risk score, asset count, compliance scope

### 2. Build Infrastructure Graph
```bash
threat-radar env build-graph \
  real-world-data/configs/ecommerce-production-environment.json \
  --auto-save
```

**Output:** Graph with 5 nodes (assets) and 4 edges (dependencies)

### 3. Build Complete Graph (Infrastructure + Vulnerabilities)
```bash
threat-radar env build-graph \
  real-world-data/configs/ecommerce-production-environment.json \
  --merge-scan real-world-data/scans/nginx_latest_sbom.json \
  -o complete-graph.graphml
```

**Output:** Full graph with 56+ vulnerabilities merged

### 4. Query Graph Statistics
```bash
threat-radar graph query complete-graph.graphml --stats
```

### 5. Visualize the Graph
```bash
threat-radar visualize graph complete-graph.graphml \
  -o ecommerce-viz.html \
  --layout hierarchical \
  --open
```

### 6. Find Attack Paths
```bash
threat-radar graph attack-paths complete-graph.graphml \
  -o attack-paths.json \
  --max-paths 20

threat-radar visualize attack-paths complete-graph.graphml \
  -o attack-viz.html \
  --paths attack-paths.json \
  --open
```

### 7. Generate Compliance Report
```bash
# Reports require CVE scan JSON file (not graph file)
threat-radar report generate \
  real-world-data/scans/nginx_latest_sbom.json \
  -o compliance-report.html \
  -f html \
  --level detailed
```

**Note:** Reports are generated from CVE scan JSON files, not graph files.

## 📊 What's in Your Dataset

### Environment Config
- **5 Assets:**
  - `asset-web-frontend` (nginx:alpine) - DMZ zone, High criticality
  - `asset-app-server` (node:18-alpine) - Internal zone, Critical
  - `asset-payment-api` (python:3.11-alpine) - Internal zone, Critical, PCI-scoped
  - `asset-database` (postgres:15-alpine) - Data zone, Critical, PCI-scoped
  - `asset-cache` (redis:7-alpine) - Internal zone, Medium

- **4 Dependencies:**
  - web-frontend → app-server (communicates_with)
  - app-server → database (reads_from)
  - app-server → cache (reads_from)
  - payment-api → database (writes_to)

- **3 Network Zones:**
  - DMZ (medium trust, internet-accessible)
  - Internal (high trust)
  - Data (high trust)

### Vulnerability Scan
- **Image:** nginx:latest
- **Vulnerabilities:** 56 total
  - High: 4
  - Medium: 6
  - Low: 4
- **Average CVSS:** 6.06

## 🎯 Next Steps

### Generate More Data

```bash
# Full dataset (3 industries, multiple images)
python generate_real_world_data.py

# Custom dataset
python generate_real_world_data.py \
  --industries ecommerce saas fintech \
  --image-categories web_servers app_runtimes databases \
  --limit-images 3 \
  --output ./my-test-data
```

### Test Complete Workflow

```bash
#!/bin/bash
# complete-workflow.sh

# 1. Generate data
python generate_real_world_data.py --quick

# 2. Build graph with vulnerabilities
threat-radar env build-graph \
  real-world-data/configs/ecommerce-production-environment.json \
  --merge-scan real-world-data/scans/*.json \
  -o complete-graph.graphml

# 3. Analyze attack paths
threat-radar graph attack-paths complete-graph.graphml \
  -o attack-paths.json

# 4. Visualize
threat-radar visualize attack-paths complete-graph.graphml \
  -o attack-paths.html --paths attack-paths.json --open

# 5. Generate report (use scan JSON, not graph file)
threat-radar report generate \
  real-world-data/scans/nginx_latest_sbom.json \
  -o security-report.html -f html
```

### Test AI Analysis

```bash
# Analyze vulnerabilities with business context
threat-radar env analyze-risk \
  real-world-data/configs/ecommerce-production-environment.json \
  real-world-data/scans/nginx_latest_sbom.json \
  --auto-save

# Generate prioritized remediation
threat-radar ai prioritize \
  real-world-data/scans/nginx_latest_sbom.json \
  --auto-save
```

## 🐛 Troubleshooting

### Schema Validation Errors

**Fixed!** The generator now produces configs that match the schema:
- ✅ Dependencies use `source`/`target` (not `from`/`to`)
- ✅ Dependency types from enum: `communicates_with`, `reads_from`, `writes_to`
- ✅ Network zones have `id` field
- ✅ Criticality values are valid enums

### Docker Not Running

```bash
# Start Docker
# macOS: Open Docker Desktop
# Linux: sudo systemctl start docker
```

### No Vulnerabilities Found

This is normal for some images! Try scanning:
```bash
python generate_real_world_data.py \
  --image-categories app_runtimes databases \
  --limit-images 2
```

## 📚 Learn More

- **Full Documentation:** `README.md` (in this directory)
- **CLAUDE.md:** Complete feature reference (project root)
- **Examples:** `examples/` directory (project root)
