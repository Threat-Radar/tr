# Real-World Test Data Generator

This script generates realistic test datasets from publicly available Docker images to test Threat Radar against real-world scenarios.

## What It Does

The script creates:

1. **Environment Configurations** - Realistic infrastructure configs for different industries:
   - E-commerce (web store with payment processing)
   - SaaS (API-driven application platform)
   - Fintech (transaction processing with compliance requirements)

2. **Vulnerability Scans** - CVE scans of popular public Docker images:
   - Web servers (nginx, httpd, caddy)
   - App runtimes (node, python, ruby, java)
   - Databases (postgres, mysql, redis, mongo)
   - Message queues (rabbitmq, kafka)
   - Monitoring tools (grafana, prometheus)
   - CI/CD tools (jenkins, gitlab)

## Usage

### Quick Start (Minimal Dataset)

```bash
# From the examples/12_real_world_data directory
cd examples/12_real_world_data

# Generate a minimal dataset for quick testing
python generate_real_world_data.py --quick

# This creates:
# - 1 industry config (ecommerce)
# - 1 web server scan (nginx)
# - Output in ./real-world-data/
```

### Full Dataset

```bash
# Generate complete dataset (default: 3 industries, 3 categories, 2 images each)
python generate_real_world_data.py

# Custom dataset
python generate_real_world_data.py \
  --industries ecommerce saas fintech \
  --image-categories web_servers databases \
  --limit-images 3 \
  --output ./my-test-data
```

### Available Options

```
-o, --output PATH           Output directory (default: ./real-world-data)
--industries [...]          Industries to generate (default: ecommerce saas fintech)
--image-categories [...]    Image categories to scan (default: web_servers app_runtimes databases)
--limit-images N           Images per category (default: 2)
--quick                    Quick mode: minimal dataset
```

### Available Industries

- `ecommerce` - E-commerce platform with PCI-DSS compliance
- `saas` - SaaS application with SOC2 compliance
- `fintech` - Financial technology with PCI-DSS/SOX compliance

### Available Image Categories

- `web_servers` - nginx, httpd, caddy
- `app_runtimes` - node, python, ruby, java
- `databases` - postgres, mysql, redis, mongo, mariadb
- `message_queues` - rabbitmq, kafka
- `monitoring` - grafana, prometheus, jaeger
- `ci_cd` - jenkins, gitlab, drone

## Output Structure

```
real-world-data/                   # Generated data (git-ignored)
├── dataset_summary.json           # Overview of generated data
├── configs/                       # Environment configurations
│   ├── ecommerce-production-environment.json
│   ├── saas-production-environment.json
│   └── fintech-production-environment.json
└── scans/                        # CVE scan results
    ├── nginx_alpine_sbom.json
    ├── postgres_15-alpine_sbom.json
    └── ...
```

## Example Workflows

### 1. Generate and Analyze E-commerce Dataset

```bash
# From examples/12_real_world_data
cd examples/12_real_world_data

# Generate data
python generate_real_world_data.py --quick

# Build infrastructure graph with vulnerabilities
threat-radar env build-graph \
  real-world-data/configs/ecommerce-production-environment.json \
  --merge-scan real-world-data/scans/*.json \
  --auto-save

# Analyze attack paths
threat-radar graph attack-paths graph.graphml -o attack-paths.json

# Visualize
threat-radar visualize attack-paths graph.graphml -o viz.html --open
```

### 2. Compare Vulnerability Profiles Across Industries

```bash
# Generate all industries
python generate_real_world_data.py

# Scan each industry's primary images
for industry in ecommerce saas fintech; do
  config="real-world-data/configs/${industry}-production-environment.json"

  # Build graph
  threat-radar env build-graph $config \
    --merge-scan real-world-data/scans/*.json \
    -o ${industry}-graph.graphml

  # Generate reports
  threat-radar report generate real-world-data/scans/*.json \
    -o ${industry}-report.html -f html
done
```

### 3. Test Compliance Scope Analysis

```bash
# Generate fintech (has PCI-DSS scope)
python generate_real_world_data.py --industries fintech --quick

# Build graph
threat-radar env build-graph \
  real-world-data/configs/fintech-production-environment.json \
  --merge-scan real-world-data/scans/*.json \
  -o fintech-graph.graphml

# Filter PCI-scoped assets
threat-radar visualize filter fintech-graph.graphml \
  -o pci-assets.html --type compliance --values pci
```

### 4. Benchmark AI Analysis Quality

```bash
# Generate diverse dataset
python generate_real_world_data.py --limit-images 5

# Run AI analysis on all scans
for scan in real-world-data/scans/*.json; do
  echo "Analyzing $scan..."
  threat-radar ai analyze $scan --auto-save
done

# Compare prioritization across models
threat-radar ai prioritize real-world-data/scans/*.json \
  --provider openai --model gpt-4o -o gpt4-priorities.json

threat-radar ai prioritize real-world-data/scans/*.json \
  --provider anthropic --model claude-3-5-sonnet-20241022 -o claude-priorities.json
```

## Why This Is Useful

### Real-World Testing
- Test against actual vulnerabilities in popular images
- Validate detection accuracy
- Benchmark performance with realistic data volumes

### Compliance Scenarios
- PCI-DSS scope identification
- GDPR data classification
- SOX control mapping
- Multi-compliance environments

### Attack Path Discovery
- Real CVE exploitation chains
- Realistic network topologies
- Business context prioritization

### Documentation & Demos
- Generate screenshots for docs
- Create demo videos
- Provide sample outputs for users

### Continuous Testing
- Integrate into CI/CD
- Track vulnerability trends
- Validate new features against real data

## Notes

- **Docker Required**: Must have Docker running to scan images
- **Network Access**: Pulls images from Docker Hub (internet required)
- **Disk Space**: Each scan ~1-5MB, plan accordingly for large datasets
- **Time**: Expect 1-3 minutes per image scan
- **Rate Limits**: Docker Hub has rate limits for anonymous pulls (consider login)

## Extending

You can easily add more:

1. **Industries** - Add to `INDUSTRY_TEMPLATES` in the script
2. **Images** - Add to `POPULAR_IMAGES` categories
3. **Custom Configs** - Modify templates for specific scenarios

Example: Add healthcare industry:

```python
"healthcare": {
    "assets": [
        {
            "id": "patient-portal",
            "image": "nginx:alpine",
            "zone": "dmz",
            "criticality": "critical",
            "function": "patient-portal",
            "hipaa_scope": True,
            "customer_facing": True,
        },
        # ... more assets
    ],
    "compliance": ["hipaa", "soc2", "gdpr"],
}
```

## Troubleshooting

### Docker Rate Limits

```bash
# Login to Docker Hub for higher limits
docker login

# Or use authenticated pulls in script (future enhancement)
```

### Scan Failures

```bash
# Check Docker is running
docker ps

# Verify threat-radar is installed
threat-radar --help

# Check Grype is available
grype version
```

### Large Datasets

```bash
# Use --limit-images to reduce dataset size
python generate_real_world_data.py --limit-images 1

# Or scan specific categories only
python generate_real_world_data.py \
  --image-categories web_servers --limit-images 2
```
