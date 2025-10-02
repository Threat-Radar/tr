# Syft SBOM Integration

Complete SBOM (Software Bill of Materials) generation and analysis using [Syft](https://github.com/anchore/syft).

## Features

✅ **Multi-language support** - Python, Node.js, Go, Rust, Java, Ruby, PHP, and more
✅ **Multiple SBOM formats** - CycloneDX (JSON/XML), SPDX (JSON/Tag-Value), Syft JSON
✅ **Docker image scanning** - Analyze container images for all packages
✅ **Local project scanning** - Scan directories and files
✅ **SBOM comparison** - Compare two SBOMs to track changes
✅ **License analysis** - Extract and analyze package licenses
✅ **Package search** - Find specific packages in SBOMs
✅ **Format conversion** - Convert between SBOM formats
✅ **Component inventory** - Display all components (libraries, files, OS packages) with filtering and grouping

## Installation

### Prerequisites

1. **Install Syft CLI** (required):
   ```bash
   # macOS
   brew install syft

   # Linux/macOS
   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin

   # Add to PATH
   export PATH="$HOME/.local/bin:$PATH"
   ```

2. **Install threat-radar**:
   ```bash
   uv pip install -e .
   ```

## Usage

### Generate SBOM from Local Project

```bash
# Generate SBOM for current directory
threat-radar sbom generate . -o sbom.json

# Specify format
threat-radar sbom generate . -o sbom.xml -f cyclonedx-xml

# Generate SPDX format
threat-radar sbom generate . -o sbom.spdx.json -f spdx-json
```

### Scan Docker Images

```bash
# Scan Docker image
threat-radar sbom docker alpine:3.18 -o alpine_sbom.json

# Scan with specific scope
threat-radar sbom docker ubuntu:22.04 -o ubuntu.json --scope all-layers
```

### Read and Display SBOMs

```bash
# Display summary
threat-radar sbom read sbom.json -f summary

# Display as table
threat-radar sbom read sbom.json -f table

# Display raw JSON
threat-radar sbom read sbom.json -f json
```

### Compare SBOMs

```bash
# Compare two SBOMs
threat-radar sbom compare old_sbom.json new_sbom.json

# Show version changes
threat-radar sbom compare v1_sbom.json v2_sbom.json --versions
```

### Package Search

```bash
# Search for packages
threat-radar sbom search sbom.json requests

# Search for packages containing 'ssl'
threat-radar sbom search sbom.json ssl
```

### Component Inventory

Display all components (libraries, files, OS packages) from SBOM with filtering and grouping:

```bash
# Show all components
threat-radar sbom components sbom.json

# Filter by type
threat-radar sbom components sbom.json --type library
threat-radar sbom components sbom.json --type file

# Filter by language
threat-radar sbom components sbom.json --language python

# Combine filters
threat-radar sbom components sbom.json --type library --language python

# Show detailed information
threat-radar sbom components sbom.json --details

# Group by type
threat-radar sbom components sbom.json --group-by type

# Group by language
threat-radar sbom components sbom.json --group-by language

# Limit output
threat-radar sbom components sbom.json --limit 20
```

### Statistics and Analysis

```bash
# Show package statistics
threat-radar sbom stats sbom.json

# Export to CSV
threat-radar sbom export sbom.json -o packages.csv -f csv

# Export to requirements.txt (Python only)
threat-radar sbom export sbom.json -o requirements.txt -f requirements
```

## Supported Package Ecosystems

Syft automatically detects and extracts packages from:

- **Python**: pip, poetry, pipenv, conda
- **JavaScript/Node.js**: npm, yarn, pnpm
- **Java**: Maven, Gradle
- **Go**: go.mod
- **Rust**: Cargo.toml
- **Ruby**: Gemfile
- **PHP**: Composer
- **.NET**: NuGet
- **C/C++**: Conan
- **Swift**: Swift Package Manager
- **Dart**: pub
- **Elixir**: Mix

## SBOM Formats

### CycloneDX
Industry-standard SBOM format widely used in security tools.

```bash
threat-radar sbom generate . -f cyclonedx-json -o sbom.cdx.json
```

### SPDX
Linux Foundation standard for software supply chain.

```bash
threat-radar sbom generate . -f spdx-json -o sbom.spdx.json
```

### Syft JSON
Syft's native format with rich metadata.

```bash
threat-radar sbom generate . -f syft-json -o sbom.syft.json
```

## Examples

### Example 1: Scan Current Project

```bash
threat-radar sbom generate . -o project_sbom.json
```

Output:
```
SBOM Summary

 Source          .
 Total Packages  167
 Package Types   2

Packages by Type:
┏━━━━━━━━━┳━━━━━━━┓
┃ Type    ┃ Count ┃
┡━━━━━━━━━╇━━━━━━━┩
│ library │ 95    │
│ file    │ 72    │
└─────────┴───────┘

SBOM saved to project_sbom.json
```

### Example 2: Compare Versions

```bash
# Scan two versions
threat-radar sbom docker alpine:3.17 -o alpine_3.17.json
threat-radar sbom docker alpine:3.18 -o alpine_3.18.json

# Compare
threat-radar sbom compare alpine_3.17.json alpine_3.18.json --versions
```

Output:
```
SBOM Comparison

SBOM 1: alpine_3.17.json
SBOM 2: alpine_3.18.json

Summary
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Category         ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Common packages  │ 12    │
│ Added packages   │ 2     │
│ Removed packages │ 1     │
└──────────────────┴───────┘
```

### Example 3: Component Inventory

```bash
threat-radar sbom components project_sbom.json --group-by type
```

Output:
```
Components Grouped by Type

LIBRARY (95 items)
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┓
┃ Name               ┃ Version  ┃ Language ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━┩
│ black              │ 25.9.0   │ python   │
│ requests           │ 2.31.0   │ python   │
│ typer              │ 0.19.1   │ python   │
└────────────────────┴──────────┴──────────┘
... and 92 more library components

FILE (72 items)
  Metadata: 26 files
  Record: 26 files
  Documentation: 17 files
  Config: 1 files
  Other: 2 files
```

### Example 4: License Analysis

```bash
threat-radar sbom stats project_sbom.json
```

Output:
```
SBOM Statistics: project_sbom.json

 Packages by Type
┏━━━━━━━━━┳━━━━━━━┓
┃ Type    ┃ Count ┃
┡━━━━━━━━━╇━━━━━━━┩
│ library │ 95    │
└─────────┴───────┘

License Summary:
Total unique licenses: 11

                Top Licenses
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ License         ┃ Package Count ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ MIT             │ 10            │
│ BSD-3-Clause    │ 4             │
│ Apache-2.0      │ 3             │
└─────────────────┴───────────────┘
```

## Python API

You can also use the Syft integration programmatically:

```python
from threat_radar.core.syft_integration import SyftClient, SBOMFormat
from threat_radar.utils.sbom_utils import save_sbom

# Initialize client
client = SyftClient()

# Scan directory
sbom = client.scan_directory(".", output_format=SBOMFormat.CYCLONEDX_JSON)

# Save SBOM
save_sbom(sbom, Path("sbom.json"))

# Scan Docker image
docker_sbom = client.scan_docker_image("alpine:3.18")

# Parse packages
packages = client.parse_syft_json(docker_sbom)
for pkg in packages[:10]:
    print(f"{pkg.name} {pkg.version} ({pkg.type})")
```

## Troubleshooting

### Syft not found

```bash
# Check if Syft is installed
syft version

# Add to PATH
export PATH="$HOME/.local/bin:$PATH"

# Or specify custom path
export SYFT_PATH="/path/to/syft"
```

### Docker images require Docker running

```bash
# Check Docker status
docker ps

# Start Docker if needed
```

### Permission errors

```bash
# Ensure Syft binary is executable
chmod +x ~/.local/bin/syft
```

## Advanced Usage

### Custom Syft Arguments

```python
from threat_radar.core.syft_integration import SyftClient

client = SyftClient()
sbom = client.scan(
    ".",
    additional_args=["--exclude", "*/test/*", "--exclude", "*/node_modules/*"]
)
```

### Batch Processing

```python
from pathlib import Path

projects = ["project1", "project2", "project3"]

for project in projects:
    sbom = client.scan_directory(project)
    save_sbom(sbom, Path(f"{project}_sbom.json"))
```

## Integration with Other Tools

### Vulnerability Scanning

Combine SBOM generation with CVE scanning:

```bash
# Generate SBOM
threat-radar sbom generate . -o sbom.json

# Use with vulnerability scanners
grype sbom:sbom.json
trivy sbom sbom.json
```

## References

- [Syft Documentation](https://github.com/anchore/syft)
- [CycloneDX Specification](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.dev/)
