# Threat Radar Analysis for Google Cloud Microservices Demo

Complete security analysis workflow for the [Google Cloud Platform microservices-demo](https://github.com/GoogleCloudPlatform/microservices-demo) (Online Boutique).

## 🎯 Choose Your Experience

| Script | Features | Time | Best For |
|--------|----------|------|----------|
| **[full-demo.sh](full-demo.sh)** | **ALL 21 features** | ~25 min | **Complete showcase** |
| [analyze-microservices-demo.sh](analyze-microservices-demo.sh) | Core features | ~15 min | Quick analysis |
| [QUICKSTART.md](QUICKSTART.md) | Manual commands | ~5 min | Learning |

**🌟 RECOMMENDED**: Run `./full-demo.sh` to see **EVERY** Threat Radar capability demonstrated on a real application.

See **[FEATURES.md](FEATURES.md)** for complete feature documentation (21 categories, 100% coverage).

---

## Overview

This example demonstrates how to use Threat Radar to perform comprehensive vulnerability and attack path analysis on a realistic microservices application.

**What is Online Boutique?**
- 10-service microservices e-commerce application
- Multiple languages: Go, Python, Node.js, Java, C#
- gRPC-based inter-service communication
- Real-world architecture patterns
- PCI-DSS compliance requirements (payment processing)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   Frontend  │ (Go - DMZ)
                    │   :8080     │
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐     ┌─────▼─────┐    ┌─────▼─────┐
    │  Cart   │     │  Checkout │    │  Product  │
    │ Service │     │  Service  │    │  Catalog  │
    │  (C#)   │     │   (Go)    │    │   (Go)    │
    └─────────┘     └─────┬─────┘    └───────────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
         ┌────▼────┐ ┌───▼────┐ ┌───▼─────┐
         │ Payment │ │Shipping│ │  Email  │
         │ Service │ │Service │ │ Service │
         │(Node.js)│ │  (Go)  │ │(Python) │
         └─────────┘ └────────┘ └─────────┘
         [PCI Scope]
```

## Quick Start

### Prerequisites

1. **Install Threat Radar**
   ```bash
   pip install threat-radar
   ```

2. **Install Grype** (vulnerability scanner)
   ```bash
   # macOS
   brew install grype

   # Linux
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
   ```

3. **Docker** (running)
   ```bash
   docker info  # Verify Docker is running
   ```

### Run Analysis

```bash
# Make script executable
chmod +x analyze-microservices-demo.sh

# Run complete analysis (scans all 10 services)
./analyze-microservices-demo.sh
```

**Expected duration**: 10-15 minutes (includes pulling images and scanning)

### Skip Scanning (Use Existing Scans)

If you've already run scans and want to regenerate the graph/analysis:

```bash
./analyze-microservices-demo.sh --skip-scans
```

## What It Does

The script performs a complete security analysis workflow:

### 1. Vulnerability Scanning
Scans all 10 microservices for CVEs:
- Frontend (Go)
- Cart Service (C#)
- Checkout Service (Go)
- Payment Service (Node.js) - **PCI Scope**
- Product Catalog Service (Go)
- Currency Service (Node.js)
- Shipping Service (Go)
- Email Service (Python)
- Recommendation Service (Python)
- Ad Service (Java)

### 2. Environment Modeling
Creates infrastructure configuration with:
- **Network topology** (DMZ, Internal, Trusted zones)
- **Business context** (criticality, revenue impact, SLA tiers)
- **Compliance scope** (PCI-DSS for payment services)
- **Service dependencies** (gRPC call chains)

### 3. Graph Building
Merges vulnerability data with infrastructure topology:
- Assets (services) linked to packages
- Packages linked to vulnerabilities
- Services linked by dependencies
- Business context attached to all assets

### 4. Attack Path Discovery
Identifies attack routes from entry points to high-value targets:
- **Entry point**: Frontend (internet-facing)
- **Targets**: Payment Service, Cart Service, Checkout Service (PCI-scoped)
- Calculates CVSS scores and threat levels
- Maps exploitation chains

### 5. Reporting
Generates comprehensive summary with:
- Vulnerability counts per service
- Attack path statistics
- PCI-scoped service analysis
- Remediation recommendations

## Output Files

After running, you'll find in `./microservices-demo-data/`:

```
microservices-demo-data/
├── scans/                              # CVE scan results
│   ├── frontend_scan.json
│   ├── cartservice_scan.json
│   ├── paymentservice_scan.json
│   └── ... (all 10 services)
├── online-boutique-environment.json    # Infrastructure config
├── online-boutique-graph.graphml       # Vulnerability graph
├── attack-paths.json                   # Attack path analysis
└── SUMMARY.md                          # Summary report
```

## Example Workflows

### 1. View Attack Paths to Payment Service

```bash
cd microservices-demo-data

# Filter critical paths
jq '.attack_paths[] | select(.threat_level == "critical")' attack-paths.json

# Find paths to payment service
jq '.attack_paths[] | select(.target | contains("payment"))' attack-paths.json
```

### 2. Visualize Attack Paths

```bash
# Interactive visualization
threat-radar visualize attack-paths online-boutique-graph.graphml \
  -o visualization.html --open

# Filter to PCI-scoped assets
threat-radar visualize filter online-boutique-graph.graphml \
  -o pci-assets.html --type compliance --values pci --open
```

### 3. AI-Powered Analysis

```bash
# Analyze all vulnerabilities with business context
threat-radar env analyze-risk \
  online-boutique-environment.json \
  scans/paymentservice_scan.json \
  --auto-save

# Generate prioritized remediation plan
threat-radar ai prioritize scans/*.json --top 20 --auto-save

# Create comprehensive HTML report
threat-radar report generate scans/*.json \
  -o online-boutique-report.html -f html --level detailed
```

### 4. Focus on PCI-DSS Compliance

```bash
# Scan only PCI-scoped services
threat-radar cve scan-image \
  gcr.io/google-samples/microservices-demo/paymentservice:v0.10.1 \
  --auto-save

# Analyze PCI scope risk
threat-radar visualize topology online-boutique-graph.graphml \
  -o pci-topology.html --view compliance --compliance pci

# Generate compliance report
jq '{
  pci_scoped_services: [
    .assets[] | select(.business_context.pci_scope == true) | .name
  ],
  total_vulns_in_scope: [
    .attack_paths[] |
    select(.target | contains("payment") or contains("cart") or contains("checkout"))
  ] | length
}' online-boutique-environment.json
```

### 5. Compare Different Versions

```bash
# Scan v0.10.0
threat-radar cve scan-image \
  gcr.io/google-samples/microservices-demo/frontend:v0.10.0 \
  -o frontend-v0.10.0.json

# Scan v0.10.1
threat-radar cve scan-image \
  gcr.io/google-samples/microservices-demo/frontend:v0.10.1 \
  -o frontend-v0.10.1.json

# Compare
threat-radar report compare frontend-v0.10.0.json frontend-v0.10.1.json
```

## Real-World Use Cases

### Security Assessment
- Identify attack paths from internet to payment processing
- Calculate blast radius of critical vulnerabilities
- Prioritize remediation based on business impact

### Compliance Validation
- Verify PCI-DSS scope isolation
- Track vulnerabilities in payment services
- Generate audit reports for compliance teams

### DevSecOps Integration
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan microservices
        run: |
          for service in frontend cartservice paymentservice; do
            threat-radar cve scan-image \
              gcr.io/google-samples/microservices-demo/${service}:latest \
              --auto-save --cleanup
          done

      - name: Check critical paths
        run: |
          threat-radar env build-graph config.json --merge-scan *.json -o graph.graphml
          threat-radar graph attack-paths graph.graphml -o paths.json

          CRITICAL=$(jq '[.attack_paths[] | select(.threat_level == "critical")] | length' paths.json)
          if [ $CRITICAL -gt 0 ]; then
            echo "CRITICAL: Found $CRITICAL critical attack paths!"
            exit 1
          fi
```

### Continuous Monitoring
```bash
#!/bin/bash
# weekly-security-scan.sh

# Scan all production images
./analyze-microservices-demo.sh

# Compare with baseline
threat-radar report compare \
  baseline-attack-paths.json \
  microservices-demo-data/attack-paths.json

# Send alerts if situation worsened
TREND=$(jq -r '.trend' comparison.json)
if [ "$TREND" = "worsening" ]; then
  send_alert "Security posture degraded - review attack paths"
fi
```

## Customization

### Add Your Own Services

Edit the script to add additional services:

```bash
declare -A SERVICES=(
    # ... existing services ...
    ["myservice"]="gcr.io/my-project/myservice:v1.0.0"
)

declare -A LANGUAGES=(
    # ... existing languages ...
    ["myservice"]="Rust"
)
```

### Modify Environment Configuration

Edit `online-boutique-environment.json` to:
- Add more network zones
- Adjust criticality scores
- Change compliance requirements
- Add custom business context

### Change Analysis Parameters

```bash
# Find more attack paths
threat-radar graph attack-paths graph.graphml --max-paths 50

# Adjust privilege escalation difficulty
threat-radar graph privilege-escalation graph.graphml --max-paths 30

# Focus on specific zones
threat-radar visualize filter graph.graphml \
  -o dmz-only.html --type zone --values dmz
```

## Troubleshooting

### Docker Image Pull Fails

```bash
# Authenticate with Google Container Registry
gcloud auth configure-docker

# Or use public mirror (if available)
docker pull gcr.io/google-samples/microservices-demo/frontend:v0.10.1
```

### Scan Failures

```bash
# Check Grype database
grype db status
grype db update

# Test with single service first
threat-radar cve scan-image \
  gcr.io/google-samples/microservices-demo/frontend:v0.10.1
```

### Memory Issues (Large Scans)

```bash
# Scan services individually
for service in "${!SERVICES[@]}"; do
  threat-radar cve scan-image "${SERVICES[$service]}" \
    -o "scans/${service}_scan.json" --cleanup

  # Sleep between scans to reduce memory pressure
  sleep 5
done
```

## Example Results

Based on a recent scan:

| Service | Language | Vulns | Critical | High |
|---------|----------|-------|----------|------|
| Frontend | Go | 12 | 0 | 3 |
| Payment Service | Node.js | 45 | 2 | 12 |
| Cart Service | C# | 23 | 1 | 6 |
| Ad Service | Java | 67 | 3 | 18 |

**Attack Paths Found**: 8 paths to payment services (4 critical)

**Key Finding**: Direct path from internet-facing frontend to PCI-scoped payment service through checkout service, with 15 exploitable CVEs.

## Related Resources

- [Online Boutique Repository](https://github.com/GoogleCloudPlatform/microservices-demo)
- [Threat Radar Documentation](../../README.md)
- [Attack Path Discovery Guide](../../docs/ATTACK_PATH_DISCOVERY.md)
- [Environment Configuration Guide](../../CLAUDE.md#environment-configuration-commands)

## Contributing

Have improvements for this example? Submit a PR!

Ideas for enhancements:
- Add Redis/database scanning
- Include Kubernetes manifest analysis
- Add performance benchmarks
- Create comparison dashboards
