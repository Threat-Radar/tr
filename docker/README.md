# Docker Setup

Docker configuration files for Threat Radar.

## Quick Start

```bash
# Build the image
make docker-build

# Run interactive shell
make docker-shell

# Run with local project mounted
make docker-shell-project PROJECT=/path/to/your/project
```

## Files

- **Dockerfile** - Multi-stage Docker build configuration
- **docker-compose.yml** - Docker Compose orchestration
- **docker-entrypoint.sh** - Container startup script
- **.dockerignore** - Files to exclude from Docker build
- **requirements-docker.txt** - Docker-specific Python dependencies
- **requirements-ai-docker.txt** - AI dependencies for Docker

## Documentation

See [docs/docker/](../docs/docker/) for detailed guides:
- **DOCKER_INTERACTIVE.md** - Interactive mode usage
- **DOCKER_LOCAL_SCANNING.md** - Scanning local projects

## Environment Setup

1. Create `.env` file in project root:
```bash
cp .env.example .env
```

2. Edit `.env` with your API keys:
```bash
OPENAI_API_KEY=sk-your-key-here
AI_PROVIDER=openai
AI_MODEL=gpt-4o
```

3. The Makefile commands automatically load the `.env` file.

## Build

```bash
make docker-build
```

This builds a production-ready image (~500MB) with:
- Python 3.11
- Grype CLI (vulnerability scanner)
- Syft CLI (SBOM generator)
- All Python dependencies
- Non-root user execution

## Usage

### Interactive Shell
```bash
make docker-shell
```

### Scan Local Project
```bash
make docker-shell-project PROJECT=/path/to/project

# Inside container:
$ tradar sbom generate /workspace -o /app/sbom_storage/my-project.json
$ tradar cve scan-sbom /app/sbom_storage/my-project.json --auto-save
```

## Storage

The container uses these volume mounts:
- `/app/storage` - Scan results and analysis
- `/app/sbom_storage` - SBOM files
- `/app/cache` - Grype database cache
- `/workspace` - Your mounted project (with `docker-shell-project`)
