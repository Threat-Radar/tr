# Quick Start - Online Boutique Security Analysis

Get started analyzing the Google Cloud microservices-demo in 5 minutes.

## 🚀 Want the Full Experience?

For a **complete showcase of ALL 21 Threat Radar features**, run:
```bash
./full-demo.sh
```

See **[FEATURES.md](FEATURES.md)** for full documentation.

This quickstart shows manual commands for learning. For automation, use the scripts above.

---

## Prerequisites Check

```bash
# 1. Verify threat-radar is installed
threat-radar --help

# 2. Verify grype is installed
grype version

# 3. Verify Docker is running
docker info
```

If any are missing, see [installation instructions](README.md#prerequisites).

## Run Complete Analysis

### Option 1: Full Analysis (Recommended First Time)

```bash
cd examples/microservices-demo-analysis

# Run everything (scans + analysis)
./analyze-microservices-demo.sh
```

**Time**: ~10-15 minutes
**Output**: `./microservices-demo-data/`

### Option 2: Quick Test (Single Service)

Test with just the frontend service:

```bash
# Scan frontend only
threat-radar cve scan-image \
  gcr.io/google-samples/microservices-demo/frontend:v0.10.1 \
  -o frontend-scan.json

# View results
jq '.severity_counts' frontend-scan.json
```

## View Results

### 1. Read Summary Report

```bash
cat microservices-demo-data/SUMMARY.md
```

### 2. Check Attack Paths

```bash
# Show all attack paths
jq '.attack_paths[] | {
  threat_level,
  total_cvss,
  path_length,
  from: .entry_point,
  to: .target
}' microservices-demo-data/attack-paths.json

# Filter critical paths only
jq '.attack_paths[] | select(.threat_level == "critical")' \
  microservices-demo-data/attack-paths.json
```

### 3. Interactive Visualization

```bash
threat-radar visualize attack-paths \
  microservices-demo-data/online-boutique-graph.graphml \
  -o visualization.html --open
```

This opens an interactive graph in your browser showing:
- Attack paths highlighted in red
- CVEs at each step
- CVSS scores
- Entry points and targets

## Analyze Specific Areas

### Focus on Payment Services (PCI Scope)

```bash
# View PCI-scoped vulnerabilities
jq '.attack_paths[] | select(.target | contains("payment"))' \
  microservices-demo-data/attack-paths.json

# Visualize PCI compliance scope
threat-radar visualize topology \
  microservices-demo-data/online-boutique-graph.graphml \
  -o pci-scope.html --view compliance --compliance pci --open
```

### Service-Specific Analysis

```bash
# Payment Service (highest risk)
cat microservices-demo-data/scans/paymentservice_scan.json | jq '{
  total: .total_vulnerabilities,
  critical: .severity_counts.critical,
  high: .severity_counts.high
}'

# Frontend (internet-facing)
cat microservices-demo-data/scans/frontend_scan.json | jq '{
  total: .total_vulnerabilities,
  critical: .severity_counts.critical,
  high: .severity_counts.high
}'
```

## AI-Powered Analysis

### Generate Comprehensive Report

```bash
threat-radar report generate \
  microservices-demo-data/scans/*.json \
  -o online-boutique-report.html \
  -f html \
  --level detailed
```

Open `online-boutique-report.html` in your browser.

### Get Prioritized Recommendations

```bash
# Prioritize all vulnerabilities
threat-radar ai prioritize \
  microservices-demo-data/scans/paymentservice_scan.json \
  --top 10 \
  --auto-save

# Generate remediation plan
threat-radar ai remediate \
  microservices-demo-data/scans/paymentservice_scan.json \
  --auto-save
```

**Note**: Requires `OPENAI_API_KEY` in `.env` file.

## Common Commands Reference

```bash
# Re-analyze without re-scanning
./analyze-microservices-demo.sh --skip-scans

# View graph statistics
threat-radar graph info \
  microservices-demo-data/online-boutique-graph.graphml

# Find privilege escalation opportunities
threat-radar graph privilege-escalation \
  microservices-demo-data/online-boutique-graph.graphml \
  -o privesc.json

# Check lateral movement risks
threat-radar graph lateral-movement \
  microservices-demo-data/online-boutique-graph.graphml \
  -o lateral.json

# Complete attack surface analysis
threat-radar graph attack-surface \
  microservices-demo-data/online-boutique-graph.graphml \
  -o attack-surface.json
```

## Expected Output Examples

### Attack Path Example

```json
{
  "path_id": "path_0",
  "entry_point": "asset-frontend",
  "target": "asset-paymentservice",
  "threat_level": "critical",
  "total_cvss": 156.3,
  "path_length": 3,
  "exploitability": 0.75,
  "steps": [
    {
      "node_id": "asset-frontend",
      "step_type": "entry_point",
      "description": "Gain initial access via Frontend Web Application",
      "vulnerabilities": ["CVE-2024-1234", "CVE-2024-5678"],
      "cvss_score": 7.5
    },
    {
      "node_id": "asset-checkoutservice",
      "step_type": "privilege_escalation",
      "description": "Escalate privileges through Checkout Service",
      "vulnerabilities": ["CVE-2024-9012"],
      "cvss_score": 8.1
    },
    {
      "node_id": "asset-paymentservice",
      "step_type": "target_access",
      "description": "Gain access to target: Payment Service",
      "vulnerabilities": ["CVE-2024-3456"],
      "cvss_score": 9.8
    }
  ]
}
```

### Summary Statistics

```
Services Analyzed: 10/10
Total Vulnerabilities: 287
Critical: 6
High: 45

Attack Paths Found: 8
Critical Paths: 4 (to payment services)

PCI-Scoped Services:
- Cart Service: 23 vulnerabilities
- Checkout Service: 18 vulnerabilities
- Payment Service: 45 vulnerabilities
```

## Next Steps

Once you've run the analysis:

1. **Review Critical Paths** - Focus on paths to PCI-scoped services
2. **Prioritize Fixes** - Start with critical vulnerabilities in payment flow
3. **Set up Monitoring** - Add to CI/CD pipeline
4. **Generate Reports** - Share with security team

For more details, see [README.md](README.md).

## Troubleshooting

### "Image not found"

The script uses version `v0.10.1`. Check available versions:

```bash
# List available tags
curl -s https://gcr.io/v2/google-samples/microservices-demo/frontend/tags/list | jq
```

Update the `SERVICES` array in the script with your desired version.

### "Out of disk space"

The script uses `--cleanup` to remove images after scanning. If you still have issues:

```bash
# Clean up Docker
docker image prune -a
docker system prune -a --volumes
```

### "Scan failed"

Test Grype directly:

```bash
grype gcr.io/google-samples/microservices-demo/frontend:v0.10.1
```

If this works but the script fails, check Threat Radar:

```bash
threat-radar cve scan-image \
  gcr.io/google-samples/microservices-demo/frontend:v0.10.1 \
  -vv  # Verbose output
```

## Getting Help

- **Documentation**: [README.md](README.md)
- **Threat Radar Docs**: [CLAUDE.md](../../CLAUDE.md)
- **GitHub Issues**: [Report a bug](https://github.com/Threat-Radar/threat-radar/issues)
