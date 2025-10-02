# SBOM Storage Directory

This directory stores all generated Software Bill of Materials (SBOMs) organized by type.

## Directory Structure

```
sbom_storage/
├── docker/         # SBOMs from Docker container scans
├── local/          # SBOMs from local project scans
├── comparisons/    # SBOM comparison results
└── archives/       # Archived/historical SBOMs
```

## Naming Convention

### Docker Container SBOMs
Format: `docker_<image-name>_<tag>_<timestamp>.json`

Examples:
- `docker_alpine_3.18_20251002_143022.json`
- `docker_ubuntu_22.04_20251002_143530.json`
- `docker_jupyter_datascience-notebook_latest_20251002_144015.json`

### Local Project SBOMs
Format: `local_<project-name>_<timestamp>.json`

Examples:
- `local_threat-radar_20251002_143022.json`
- `local_myproject_20251002_150000.json`

### Comparison Results
Format: `compare_<name1>_vs_<name2>_<timestamp>.json`

Examples:
- `compare_alpine-3.17_vs_alpine-3.18_20251002_143022.json`
- `compare_v1.0_vs_v2.0_20251002_150000.json`

### Archive Naming
Format: `archive_<original-filename>_<archive-date>.json`

Examples:
- `archive_docker_alpine_3.18_20251001.json`

## Usage

SBOMs are automatically saved to the appropriate directory when using the `--auto-save` flag:

```bash
# Automatically save to sbom_storage/docker/
threat-radar sbom docker alpine:3.18 --auto-save

# Automatically save to sbom_storage/local/
threat-radar sbom generate . --auto-save

# Or specify custom output path
threat-radar sbom docker alpine:3.18 -o custom/path/sbom.json
```

## Retention Policy

- **Current SBOMs**: Kept in main directories (docker/, local/)
- **Historical SBOMs**: Older than 30 days automatically moved to archives/
- **Comparisons**: Kept for 90 days, then deleted

## File Formats

- `.json` - Default CycloneDX JSON format
- `.xml` - CycloneDX XML format
- `.spdx.json` - SPDX JSON format
- `.syft.json` - Syft native format
