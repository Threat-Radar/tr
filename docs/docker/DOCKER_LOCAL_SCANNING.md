# 🔍 Scanning Local Directories with Docker

Guide for scanning local projects and directories using Threat Radar Docker container.

---

## 🚀 Quick Start

### Method 1: Using Makefile (Easiest!)

```bash
# Mount your project and open interactive shell
make docker-shell-project PROJECT=/path/to/your/project

# Inside container:
$ tradar sbom generate /workspace -o /app/sbom_storage/my-project.json
$ tradar cve scan-sbom /app/sbom_storage/my-project.json --auto-save
$ exit
```

### Method 2: Manual Docker Run

```bash
docker run --rm -it \
  -v $(pwd)/storage:/app/storage \
  -v $(pwd)/sbom_storage:/app/sbom_storage \
  -v /path/to/your/project:/workspace:ro \
  --entrypoint /bin/bash \
  threat-radar:latest

# Inside container:
$ tradar sbom generate /workspace -o /app/sbom_storage/project-sbom.json
```

---

## 📖 Complete Examples

### Example 1: Scan a Node.js Project

```bash
# 1. Start container with your Node.js project mounted
make docker-shell-project PROJECT=~/my-nodejs-app

# Inside container:
# 2. Generate SBOM
$ tradar sbom generate /workspace -o /app/sbom_storage/nodejs-app.json

# 3. View the SBOM
$ tradar sbom read /app/sbom_storage/nodejs-app.json

# 4. Get package statistics
$ tradar sbom stats /app/sbom_storage/nodejs-app.json

# 5. Scan for vulnerabilities
$ tradar cve scan-sbom /app/sbom_storage/nodejs-app.json --auto-save

# 6. View results
$ ls -lh /app/storage/cve_storage/

# 7. Exit
$ exit

# Back on host - check the results
cat sbom_storage/nodejs-app.json | jq '.components | length'
cat storage/cve_storage/nodejs-app_sbom_*.json | jq '.matches | length'
```

### Example 2: Scan a Python Project

```bash
# Start container
make docker-shell-project PROJECT=~/my-python-app

# Inside container:
$ tradar sbom generate /workspace -o /app/sbom_storage/python-app.json
$ tradar sbom search /app/sbom_storage/python-app.json django
$ tradar cve scan-sbom /app/sbom_storage/python-app.json --severity HIGH --auto-save
$ exit
```

### Example 3: Scan a Go Project

```bash
# Start container
make docker-shell-project PROJECT=~/my-go-app

# Inside container:
$ tradar sbom generate /workspace -o /app/sbom_storage/go-app.json
$ tradar sbom components /app/sbom_storage/go-app.json --language go
$ tradar cve scan-sbom /app/sbom_storage/go-app.json --auto-save
$ exit
```

---

## 🔄 Scanning Multiple Projects

### Batch Scan Script

```bash
#!/bin/bash
# batch-scan-projects.sh

PROJECTS=(
  "$HOME/projects/frontend"
  "$HOME/projects/backend"
  "$HOME/projects/api"
  "$HOME/projects/worker"
)

for project in "${PROJECTS[@]}"; do
  name=$(basename "$project")
  echo "Scanning: $name"

  docker run --rm \
    -v $(pwd)/storage:/app/storage \
    -v $(pwd)/sbom_storage:/app/sbom_storage \
    -v "$project:/workspace:ro" \
    threat-radar:latest \
    sh -c "
      tradar sbom generate /workspace -o /app/sbom_storage/${name}.json && \
      tradar cve scan-sbom /app/sbom_storage/${name}.json --auto-save
    "
done

echo "✅ All projects scanned!"
echo "SBOMs: ./sbom_storage/"
echo "CVE Results: ./storage/cve_storage/"
```

### Interactive Multi-Project Session

```bash
# Mount multiple projects at once
docker run --rm -it \
  -v $(pwd)/storage:/app/storage \
  -v $(pwd)/sbom_storage:/app/sbom_storage \
  -v ~/projects/frontend:/projects/frontend:ro \
  -v ~/projects/backend:/projects/backend:ro \
  -v ~/projects/api:/projects/api:ro \
  --entrypoint /bin/bash \
  threat-radar:latest

# Inside container - scan all projects
$ for project in /projects/*; do
    name=$(basename "$project")
    echo "Processing: $name"
    tradar sbom generate "$project" -o "/app/sbom_storage/${name}.json"
    tradar cve scan-sbom "/app/sbom_storage/${name}.json" --auto-save
  done

# Compare SBOMs
$ tradar sbom compare \
    /app/sbom_storage/frontend.json \
    /app/sbom_storage/backend.json

$ exit
```

---

## 🎯 Specific Directory Scanning

### Scan Only Source Directory

```bash
make docker-shell-project PROJECT=~/my-app

# Inside container - scan only src/
$ tradar sbom generate /workspace/src -o /app/sbom_storage/src-only.json
```

### Scan Multiple Subdirectories

```bash
make docker-shell-project PROJECT=~/my-monorepo

# Inside container:
$ tradar sbom generate /workspace/packages/frontend -o /app/sbom_storage/frontend.json
$ tradar sbom generate /workspace/packages/backend -o /app/sbom_storage/backend.json
$ tradar sbom generate /workspace/packages/shared -o /app/sbom_storage/shared.json
```

---

## 📊 Complete Analysis Workflow

### Full Security Assessment

```bash
#!/bin/bash
# full-analysis.sh

PROJECT_PATH="$1"
PROJECT_NAME=$(basename "$PROJECT_PATH")

echo "🔍 Full Security Analysis: $PROJECT_NAME"

docker run --rm -it \
  -v $(pwd)/storage:/app/storage \
  -v $(pwd)/sbom_storage:/app/sbom_storage \
  -v $(pwd)/cache:/app/cache \
  -v "$PROJECT_PATH:/workspace:ro" \
  --env-file .env \
  --entrypoint /bin/bash \
  threat-radar:latest << COMMANDS

echo "Step 1: Generating SBOM..."
tradar sbom generate /workspace -o /app/sbom_storage/${PROJECT_NAME}.json

echo "Step 2: SBOM Statistics..."
tradar sbom stats /app/sbom_storage/${PROJECT_NAME}.json

echo "Step 3: Scanning for vulnerabilities..."
tradar cve scan-sbom /app/sbom_storage/${PROJECT_NAME}.json --auto-save

echo "Step 4: Building vulnerability graph..."
SCAN_FILE=\$(ls -t /app/storage/cve_storage/${PROJECT_NAME}*.json | head -1)
tradar graph build "\$SCAN_FILE" --auto-save

echo "Step 5: Querying graph..."
GRAPH_FILE=\$(ls -t /app/storage/graph_storage/*.graphml | head -1)
tradar graph query "\$GRAPH_FILE" --stats

echo "Step 6: Finding attack paths..."
tradar graph attack-paths "\$GRAPH_FILE" -o /app/storage/attack-paths.json

# If AI is configured
if [ -n "\$OPENAI_API_KEY" ]; then
  echo "Step 7: AI Analysis..."
  tradar ai analyze "\$SCAN_FILE" --auto-save
  tradar ai prioritize "\$SCAN_FILE" --auto-save
fi

echo ""
echo "✅ Analysis complete!"
echo "Results:"
echo "  - SBOM: /app/sbom_storage/${PROJECT_NAME}.json"
echo "  - CVE Scan: \$SCAN_FILE"
echo "  - Graph: \$GRAPH_FILE"
echo "  - Attack Paths: /app/storage/attack-paths.json"

COMMANDS

echo ""
echo "📊 Results available in:"
echo "   - sbom_storage/"
echo "   - storage/cve_storage/"
echo "   - storage/graph_storage/"
```

Usage:
```bash
chmod +x full-analysis.sh
./full-analysis.sh ~/my-project
```

---

## 💡 Pro Tips

### 1. Mount as Read-Only

Always mount your project as read-only (`:ro`) for safety:
```bash
-v /path/to/project:/workspace:ro
```

### 2. Scan Current Directory

```bash
# Mount current working directory
docker run --rm -it \
  -v $(pwd):/workspace:ro \
  -v $(pwd)/storage:/app/storage \
  -v $(pwd)/sbom_storage:/app/sbom_storage \
  --entrypoint /bin/bash \
  threat-radar:latest

# Inside:
$ tradar sbom generate /workspace -o /app/sbom_storage/current-dir.json
```

### 3. Use Absolute Paths

```bash
# ✅ Good - absolute path
make docker-shell-project PROJECT=/home/user/my-app

# ✅ Good - home directory
make docker-shell-project PROJECT=~/my-app

# ✅ Good - current directory
make docker-shell-project PROJECT=$(pwd)

# ❌ Bad - relative path (may not work)
make docker-shell-project PROJECT=../my-app
```

### 4. Check Mount Points

Inside the container, verify your project is mounted:
```bash
$ ls -la /workspace
$ tree /workspace -L 2
```

### 5. Cache for Speed

Mount cache directory to speed up repeated scans:
```bash
-v $(pwd)/cache:/app/cache
```

---

## 🐛 Troubleshooting

### Issue: Directory Not Found

**Problem:**
```bash
$ tradar sbom generate /workspace
Error: directory not found
```

**Solution:**
Check if directory is mounted:
```bash
$ ls -la /workspace
# If empty or doesn't exist, exit and remount:
$ exit

# Remount with correct path:
make docker-shell-project PROJECT=/correct/path/to/project
```

### Issue: Permission Denied

**Problem:**
```bash
$ tradar sbom generate /workspace -o /workspace/sbom.json
Error: Permission denied
```

**Solution:**
Output to the container's storage (not the read-only mounted directory):
```bash
# ✅ Correct - output to /app/sbom_storage
$ tradar sbom generate /workspace -o /app/sbom_storage/project.json

# ❌ Wrong - trying to write to read-only mount
$ tradar sbom generate /workspace -o /workspace/sbom.json
```

### Issue: No Packages Found

**Problem:**
```bash
$ tradar sbom generate /workspace
Warning: No packages found
```

**Solution:**
Make sure you're scanning the right directory:
```bash
# Check directory contents
$ ls -la /workspace

# Try scanning subdirectories
$ tradar sbom generate /workspace/src
$ tradar sbom generate /workspace/packages/myapp
```

---

## 📝 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan Local Code

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Threat Radar Image
        run: docker build -t threat-radar:latest .

      - name: Generate SBOM
        run: |
          docker run --rm \
            -v $(pwd):/workspace:ro \
            -v $(pwd)/results:/app/sbom_storage \
            threat-radar:latest \
            tradar sbom generate /workspace -o /app/sbom_storage/sbom.json

      - name: Scan SBOM
        run: |
          docker run --rm \
            -v $(pwd)/results:/app/sbom_storage \
            -v $(pwd)/results:/app/storage \
            threat-radar:latest \
            tradar cve scan-sbom /app/sbom_storage/sbom.json \
              --fail-on HIGH --auto-save

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: results/
```

### GitLab CI

```yaml
security-scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t threat-radar:latest .
    - |
      docker run --rm \
        -v $(pwd):/workspace:ro \
        -v $(pwd)/results:/app/sbom_storage \
        threat-radar:latest \
        tradar sbom generate /workspace -o /app/sbom_storage/sbom.json
    - |
      docker run --rm \
        -v $(pwd)/results:/app/sbom_storage \
        -v $(pwd)/results:/app/storage \
        threat-radar:latest \
        tradar cve scan-sbom /app/sbom_storage/sbom.json --auto-save
  artifacts:
    paths:
      - results/
```

---

## 📚 Additional Resources

- **[Interactive Mode Guide](DOCKER_INTERACTIVE.md)** - Interactive shell usage
- **[Complete Usage Guide](DOCKER_USAGE.md)** - All commands and workflows
- **[Quick Reference](DOCKER_QUICK_REFERENCE.md)** - One-page command reference
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment

---

## 🎓 Summary

**Key Points:**
1. ✅ Mount your project directory with `-v /path/to/project:/workspace:ro`
2. ✅ Always use `:ro` (read-only) for safety
3. ✅ Output results to `/app/sbom_storage` or `/app/storage`
4. ✅ Use `make docker-shell-project PROJECT=/path` for convenience
5. ✅ Scan the mounted directory with `tradar sbom generate /workspace`

---

**Happy Scanning! 🚀**
