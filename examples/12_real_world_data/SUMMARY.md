# Example 12: Real-World Test Data Generator

## Overview

This example provides a complete test data generator that creates realistic environment configurations and vulnerability scans from publicly available Docker images.

## What's Included

- **`generate_real_world_data.py`** - Python script to generate test datasets
- **`README.md`** - Complete documentation on using the generator
- **`QUICKSTART.md`** - Quick reference guide for common tasks
- **`.gitignore`** - Ignores generated data files

## Quick Start

```bash
# Navigate to this directory
cd examples/12_real_world_data

# Generate minimal test dataset (1 industry, 1 image)
python generate_real_world_data.py --quick

# This creates:
# - Environment config in real-world-data/configs/
# - CVE scan in real-world-data/scans/
# - Summary in real-world-data/dataset_summary.json
```

## What It Generates

### 1. Environment Configurations (Industry-Specific)

**Available Industries:**
- **E-commerce** - PCI-DSS compliant online store (web, app server, payment API, database, cache)
- **SaaS** - SOC2 compliant application platform (API gateway, backend, workers, database, message queue)
- **Fintech** - PCI-DSS/SOX compliant financial services (transaction processor, fraud detection, audit logs)

Each config includes:
- 5 realistic assets with business context
- Network topology (DMZ, internal, data zones)
- Dependencies between services
- Compliance scope (PCI, HIPAA, SOX, GDPR)
- Criticality levels and SLA tiers

### 2. Vulnerability Scans (Real CVEs)

**Available Image Categories:**
- Web servers (nginx, httpd, caddy)
- App runtimes (node, python, ruby, java)
- Databases (postgres, mysql, redis, mongo)
- Message queues (rabbitmq, kafka)
- Monitoring (grafana, prometheus)
- CI/CD (jenkins, gitlab)

Each scan includes:
- Real vulnerabilities from Docker Hub images
- CVE IDs, CVSS scores, severity levels
- Package information
- Fix availability

## Usage Examples

### Example 1: Generate E-commerce Test Data

```bash
cd examples/12_real_world_data
python generate_real_world_data.py --quick

# Validate the config
threat-radar env validate real-world-data/configs/ecommerce-production-environment.json

# Build graph with vulnerabilities
threat-radar env build-graph \
  real-world-data/configs/ecommerce-production-environment.json \
  --merge-scan real-world-data/scans/nginx_latest_sbom.json \
  -o graph.graphml

# Find attack paths
threat-radar graph attack-paths graph.graphml -o attack-paths.json
```

### Example 2: Generate Multi-Industry Dataset

```bash
# Generate all 3 industries with multiple image types
python generate_real_world_data.py \
  --industries ecommerce saas fintech \
  --image-categories web_servers databases \
  --limit-images 2

# Outputs:
# - 3 environment configs (one per industry)
# - 4 vulnerability scans (2 categories × 2 images)
```

### Example 3: Test Compliance Analysis

```bash
# Generate fintech data (has PCI-DSS scope)
python generate_real_world_data.py --industries fintech --quick

# Build graph
threat-radar env build-graph \
  real-world-data/configs/fintech-production-environment.json \
  --merge-scan real-world-data/scans/*.json \
  -o fintech.graphml

# Visualize PCI-scoped assets
threat-radar visualize filter fintech.graphml \
  -o pci-assets.html --type compliance --values pci --open
```

## Why This Is Useful

### For Development
- Test new features against realistic data
- Validate detection accuracy
- Benchmark performance
- Continuous integration testing

### For Demos
- Generate screenshots for documentation
- Create example outputs for users
- Produce demo videos
- Showcase real-world scenarios

### For Testing
- Compliance scenario testing (PCI, GDPR, HIPAA)
- Attack path discovery validation
- Business context prioritization
- Multi-industry comparisons

### For Benchmarking
- Compare AI analysis quality
- Test multiple models
- Performance profiling
- Scalability testing

## Output Directory Structure

```
real-world-data/              # Git-ignored generated data
├── dataset_summary.json      # Overview of what was generated
├── configs/                  # Environment configurations
│   ├── ecommerce-production-environment.json
│   ├── saas-production-environment.json
│   └── fintech-production-environment.json
└── scans/                    # CVE vulnerability scans
    ├── nginx_latest_sbom.json
    ├── postgres_15-alpine_sbom.json
    └── ...
```

## Documentation

- **`README.md`** - Complete generator documentation
- **`QUICKSTART.md`** - Quick reference for all commands
- **`../../CLAUDE.md`** - Full Threat Radar feature reference

## Integration with Other Examples

This generator creates inputs for:
- **Example 10** - Environment configuration
- **Example 11** - Graph visualization
- All AI analysis commands
- All reporting commands
- All attack path discovery commands

## Requirements

- Docker (for scanning images)
- Grype (for CVE scanning)
- Internet connection (to pull images)
- ~1-5 MB disk space per scan

## Tips

1. **Start with `--quick`** for initial testing
2. **Use `--limit-images 1`** to reduce scan time
3. **Choose specific `--image-categories`** for focused testing
4. **Generated data is git-ignored** - safe to regenerate anytime
5. **Combine with CI/CD** for continuous testing

## Next Steps

1. Read `QUICKSTART.md` for command examples
2. Generate your first dataset with `--quick`
3. Try the complete workflow in QUICKSTART.md
4. Customize industries/images for your needs
5. Integrate into your test suite

## Support

See troubleshooting section in `README.md` for common issues.
