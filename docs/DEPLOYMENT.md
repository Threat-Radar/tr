# Threat Radar - Production Deployment Guide

Complete guide for deploying Threat Radar in production using Docker.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Storage & Volumes](#storage--volumes)
- [Running Scans](#running-scans)
- [Health Checks](#health-checks)
- [Logging](#logging)
- [Security Best Practices](#security-best-practices)
- [Scaling](#scaling)
- [Troubleshooting](#troubleshooting)
- [CI/CD Integration](#cicd-integration)

---

## 🎯 Overview

Threat Radar is containerized using Docker for easy deployment in production environments. The Docker image includes:

- ✅ Alpine Linux base (lightweight, ~300MB final size)
- ✅ Python 3.11 runtime
- ✅ Grype vulnerability scanner
- ✅ Syft SBOM generator
- ✅ Docker CLI for container scanning
- ✅ Production logging and health checks

---

## 📦 Prerequisites

**Required:**
- Docker 20.10+ or Docker Desktop
- Docker Compose 2.0+ (optional, for orchestration)
- 2 GB RAM minimum (4 GB recommended)
- 10 GB disk space minimum

**Optional:**
- OpenAI API key (for AI features)
- Anthropic API key (for Claude AI)
- GitHub access token (for GitHub integration)

---

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/Threat-Radar/tr.git
cd tr
```

### 2. Create Environment File

```bash
cp .env.example .env

# Edit .env and add your API keys:
# - OPENAI_API_KEY=sk-your-key-here (optional, for AI features)
# - GITHUB_ACCESS_TOKEN=your-token (optional, for GitHub integration)
```

### 3. Build Docker Image

```bash
# Build the image
docker build -t threat-radar:latest .

# Or use docker-compose
docker-compose build
```

### 4. Run Container

```bash
# Quick test - show help
docker run --rm threat-radar:latest threat-radar --help

# Run a scan
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/storage:/app/storage \
  threat-radar:latest \
  threat-radar cve scan-image alpine:3.18

# Or use docker-compose
docker-compose run --rm threat-radar threat-radar cve scan-image alpine:3.18
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# ============================================================================
# AI Provider Configuration
# ============================================================================
AI_PROVIDER=openai                    # Options: openai, anthropic, ollama
OPENAI_API_KEY=sk-your-key-here      # Required for OpenAI
ANTHROPIC_API_KEY=sk-ant-your-key    # Required for Anthropic
AI_MODEL=gpt-4o                       # Model name (gpt-4o, claude-3-5-sonnet-20241022, llama2)
LOCAL_MODEL_ENDPOINT=http://localhost:11434  # Ollama endpoint

# ============================================================================
# Grype Configuration
# ============================================================================
GRYPE_DB_AUTO_UPDATE=true             # Auto-update vulnerability database
GRYPE_DB_CACHE_DIR=/app/cache/grype   # Cache directory for Grype DB

# ============================================================================
# Logging Configuration
# ============================================================================
LOG_LEVEL=INFO                        # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT=json                       # Options: json, text
LOG_FILE=/app/logs/app.log           # Log file path

# ============================================================================
# Storage Configuration
# ============================================================================
STORAGE_PATH=/app/storage             # Base storage path
CACHE_PATH=/app/cache                 # Cache directory

# ============================================================================
# GitHub Integration (Optional)
# ============================================================================
GITHUB_ACCESS_TOKEN=your-token-here   # Optional, for GitHub features
```

### Using docker-compose.yml

The provided `docker-compose.yml` includes:

- ✅ Persistent volumes for storage, cache, and logs
- ✅ Environment variable configuration
- ✅ Docker socket mounting for container scanning
- ✅ Resource limits (2 CPU, 2GB RAM)
- ✅ Automatic restarts
- ✅ Health checks

**Start service:**

```bash
docker-compose up -d
```

**Run commands:**

```bash
# One-off scan
docker-compose run --rm threat-radar threat-radar cve scan-image alpine:3.18

# With auto-save
docker-compose run --rm threat-radar threat-radar cve scan-image python:3.11 --auto-save

# AI analysis
docker-compose run --rm threat-radar threat-radar ai analyze /app/storage/cve_storage/scan-results.json
```

---

## 💾 Storage & Volumes

### Volume Mappings

The container uses the following persistent volumes:

| Volume | Host Path | Container Path | Purpose |
|--------|-----------|----------------|---------|
| `storage` | `./storage` | `/app/storage` | Scan results, AI analysis, graphs |
| `cache` | `./cache` | `/app/cache` | Grype database cache |
| `logs` | `./logs` | `/app/logs` | Application logs |
| `sbom_storage` | `./sbom_storage` | `/app/sbom_storage` | SBOM files |

### Creating Volumes

```bash
# Create local directories for volumes
mkdir -p storage/cve_storage
mkdir -p storage/ai_analysis
mkdir -p storage/graph_storage
mkdir -p cache/grype
mkdir -p logs
mkdir -p sbom_storage
```

### Backup Strategy

**Backup scan results:**

```bash
# Tar all storage
tar -czf threat-radar-backup-$(date +%Y%m%d).tar.gz storage/ cache/ logs/ sbom_storage/

# Upload to S3 (example)
aws s3 cp threat-radar-backup-*.tar.gz s3://your-backup-bucket/
```

**Restore from backup:**

```bash
tar -xzf threat-radar-backup-20250119.tar.gz
```

---

## 🔍 Running Scans

### CVE Scanning

```bash
# Scan Docker image
docker-compose run --rm threat-radar \
  threat-radar cve scan-image alpine:3.18 --auto-save

# Scan with severity filter
docker-compose run --rm threat-radar \
  threat-radar cve scan-image python:3.11 --severity HIGH --auto-save

# Scan SBOM
docker-compose run --rm threat-radar \
  threat-radar cve scan-sbom /app/storage/my-sbom.json --auto-save
```

### SBOM Generation

```bash
# Generate SBOM from Docker image
docker-compose run --rm threat-radar \
  threat-radar sbom docker alpine:3.18 -o /app/sbom_storage/alpine.json

# Generate from local directory
docker-compose run --rm threat-radar \
  threat-radar sbom generate /app/project -o /app/sbom_storage/project.json
```

### AI Analysis

```bash
# Analyze vulnerabilities
docker-compose run --rm threat-radar \
  threat-radar ai analyze /app/storage/cve_storage/scan-results.json --auto-save

# Prioritize remediation
docker-compose run --rm threat-radar \
  threat-radar ai prioritize /app/storage/cve_storage/scan-results.json --auto-save

# Generate remediation plan
docker-compose run --rm threat-radar \
  threat-radar ai remediate /app/storage/cve_storage/scan-results.json --auto-save
```

### Graph Analysis

```bash
# Build vulnerability graph
docker-compose run --rm threat-radar \
  threat-radar graph build /app/storage/cve_storage/scan.json --auto-save

# Query graph
docker-compose run --rm threat-radar \
  threat-radar graph query /app/storage/graph_storage/graph.graphml --stats

# Find attack paths
docker-compose run --rm threat-radar \
  threat-radar graph attack-paths /app/storage/graph_storage/graph.graphml -o /app/storage/paths.json
```

---

## 🏥 Health Checks

### Health Check Commands

```bash
# Quick ping
docker-compose run --rm threat-radar threat-radar health ping

# Full health check
docker-compose run --rm threat-radar threat-radar health check

# Verbose health check
docker-compose run --rm threat-radar threat-radar health check --verbose

# JSON output
docker-compose run --rm threat-radar threat-radar health check --json
```

### Docker Health Check

The Dockerfile includes a built-in `HEALTHCHECK` that runs every 30 seconds:

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD threat-radar --help || exit 1
```

**Check container health:**

```bash
docker ps
# Look for "(healthy)" status

docker inspect threat-radar --format='{{.State.Health.Status}}'
# Output: healthy, unhealthy, or starting
```

---

## 📝 Logging

### Log Files

The container creates the following log files:

| Log File | Purpose | Format | Rotation |
|----------|---------|--------|----------|
| `/app/logs/app.log` | Main application logs | JSON | 100MB, 10 backups |
| `/app/logs/error.log` | Error-only logs | JSON | 100MB, 10 backups |
| `/app/logs/scan.log` | Scan operation logs | JSON | 100MB, 10 backups |

### Viewing Logs

```bash
# Docker logs (STDOUT)
docker-compose logs -f threat-radar

# Application logs
docker-compose exec threat-radar tail -f /app/logs/app.log

# Error logs
docker-compose exec threat-radar tail -f /app/logs/error.log

# Scan logs
docker-compose exec threat-radar tail -f /app/logs/scan.log
```

### Log Configuration

Configure logging via environment variables:

```bash
# Text format for local development
LOG_LEVEL=DEBUG
LOG_FORMAT=text

# JSON format for production (log aggregation)
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=/app/logs/app.log
```

### Log Aggregation

**Example with Fluentd:**

```yaml
# docker-compose.yml
services:
  threat-radar:
    logging:
      driver: fluentd
      options:
        fluentd-address: localhost:24224
        tag: threat-radar
```

**Example with ELK Stack:**

```bash
# Forward logs to Logstash
docker-compose logs -f threat-radar | nc logstash-host 5000
```

---

## 🔒 Security Best Practices

### 1. Run as Non-Root User

The container runs as user `threatradar` (UID 1000) by default:

```dockerfile
USER threatradar
```

### 2. Read-Only Docker Socket

Mount Docker socket as read-only:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

### 3. Resource Limits

Set CPU and memory limits:

```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
```

### 4. Secrets Management

**Option 1: Docker Secrets**

```bash
echo "sk-your-key-here" | docker secret create openai_api_key -

docker service create \
  --name threat-radar \
  --secret openai_api_key \
  threat-radar:latest
```

**Option 2: Environment Files**

```bash
# Store secrets in separate file
echo "OPENAI_API_KEY=sk-your-key" > .env.secrets

# Load in docker-compose
docker-compose --env-file .env.secrets up
```

### 5. Network Isolation

Use custom bridge networks:

```yaml
networks:
  threat-radar-net:
    driver: bridge
    internal: true
```

### 6. Regular Updates

```bash
# Update Grype database
docker-compose run --rm threat-radar grype db update

# Rebuild image with latest base image
docker-compose build --pull --no-cache
```

---

## 📈 Scaling

### Horizontal Scaling

Run multiple containers for high-volume scanning:

```yaml
# docker-compose.yml
services:
  threat-radar:
    deploy:
      replicas: 3
```

### Job Queue Integration

Use a job queue for distributed scanning:

```python
# Example with Celery
from celery import Celery
import subprocess

app = Celery('threat_radar', broker='redis://localhost:6379/0')

@app.task
def scan_image(image_name):
    result = subprocess.run(
        ["docker", "run", "--rm", "threat-radar:latest",
         "threat-radar", "cve", "scan-image", image_name, "--auto-save"],
        capture_output=True
    )
    return result.stdout.decode()
```

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threat-radar
spec:
  replicas: 3
  selector:
    matchLabels:
      app: threat-radar
  template:
    metadata:
      labels:
        app: threat-radar
    spec:
      containers:
      - name: threat-radar
        image: threat-radar:latest
        resources:
          limits:
            cpu: "2"
            memory: "2Gi"
          requests:
            cpu: "1"
            memory: "512Mi"
        volumeMounts:
        - name: storage
          mountPath: /app/storage
        - name: cache
          mountPath: /app/cache
        envFrom:
        - secretRef:
            name: threat-radar-secrets
      volumes:
      - name: storage
        persistentVolumeClaim:
          claimName: threat-radar-storage
      - name: cache
        persistentVolumeClaim:
          claimName: threat-radar-cache
```

---

## 🐛 Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs threat-radar

# Check health
docker-compose ps

# Inspect container
docker inspect threat-radar
```

**Common issues:**

1. **Missing .env file**
   ```bash
   cp .env.example .env
   ```

2. **Permission issues**
   ```bash
   chmod -R u+w storage/ cache/ logs/
   ```

3. **Docker socket not accessible**
   ```bash
   # Check Docker is running
   docker ps

   # Fix permissions (Linux)
   sudo chmod 666 /var/run/docker.sock
   ```

### Grype Database Issues

```bash
# Update Grype database manually
docker-compose run --rm threat-radar grype db update

# Check database status
docker-compose run --rm threat-radar grype db status
```

### Slow Performance

1. **Allocate more resources:**
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '4'
         memory: 4G
   ```

2. **Enable caching:**
   ```bash
   # Mount cache volume
   -v threat-radar-cache:/app/cache
   ```

3. **Disable auto-update:**
   ```bash
   GRYPE_DB_AUTO_UPDATE=false
   ```

### Out of Disk Space

```bash
# Clean up old scan results
docker-compose run --rm threat-radar \
  find /app/storage -name "*.json" -mtime +30 -delete

# Clean up Docker images
docker image prune -a -f

# Clean up volumes
docker volume prune -f
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Pull Threat Radar
        run: docker pull threat-radar:latest

      - name: Scan image
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock:ro \
            -v $(pwd)/results:/app/storage \
            threat-radar:latest \
            threat-radar cve scan-image myapp:${{ github.sha }} \
            --auto-save --fail-on CRITICAL

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: results/
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security-scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t myapp:$CI_COMMIT_SHA .
    - docker run --rm
        -v /var/run/docker.sock:/var/run/docker.sock:ro
        threat-radar:latest
        threat-radar cve scan-image myapp:$CI_COMMIT_SHA
        --auto-save --fail-on HIGH
  artifacts:
    paths:
      - storage/
  only:
    - main
  schedule:
    - cron: '0 2 * * *'
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock:ro \
                      -v ${WORKSPACE}/results:/app/storage \
                      threat-radar:latest \
                      threat-radar cve scan-image myapp:${BUILD_NUMBER} \
                      --auto-save --fail-on CRITICAL
                '''
            }
        }

        stage('Archive Results') {
            steps {
                archiveArtifacts artifacts: 'results/**/*.json'
            }
        }
    }
}
```

---

## 📚 Additional Resources

- [Main Documentation](../README.md)
- [CLI Features Guide](CLI_FEATURES.md)
- [API Documentation](API.md)
- [Troubleshooting Guide](../examples/TROUBLESHOOTING.md)
- [GitHub Repository](https://github.com/Threat-Radar/tr)

---

## 💡 Best Practices Summary

✅ **Use docker-compose for local development**
✅ **Mount volumes for persistent storage**
✅ **Set resource limits in production**
✅ **Enable JSON logging for log aggregation**
✅ **Run as non-root user**
✅ **Keep Grype database updated**
✅ **Use health checks in orchestration**
✅ **Backup scan results regularly**
✅ **Use secrets management for API keys**
✅ **Monitor container health and logs**

---

## 🆘 Support

For issues and questions:

- **GitHub Issues**: https://github.com/Threat-Radar/tr/issues
- **Documentation**: https://github.com/Threat-Radar/tr/blob/main/README.md
- **Email**: contact@threat-radar.dev

---

**Happy Scanning! 🚀**
