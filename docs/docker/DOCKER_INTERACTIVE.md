# 🖥️ Interactive Mode - Threat Radar Docker Container

Complete guide for using Threat Radar in interactive mode.

---

## 🚀 Quick Start - Interactive Shell

### Method 1: Using Makefile (Easiest!)

```bash
make docker-shell
```

This opens an interactive bash shell with all volumes mounted.

### Method 2: Docker Run

```bash
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/storage:/app/storage \
  -v $(pwd)/cache:/app/cache \
  --entrypoint /bin/bash \
  threat-radar:latest
```

### Method 3: Docker Compose

```bash
docker-compose run --rm --entrypoint /bin/bash threat-radar
```

---

## 📖 Inside the Interactive Shell

Once inside the container, you have full access to all threat-radar commands:

```bash
# You'll see the startup banner:
==========================================
  Threat Radar - Starting Container
==========================================
Threat Radar Version: 0.3.0
Python Version: Python 3.11.14
Grype Version: Application:         grype
Syft Version: Application:   syft
...

# Now you can run any command:
threatradar@container:/app$ threat-radar --help
threatradar@container:/app$ threat-radar cve scan-image alpine:3.18 --auto-save
threatradar@container:/app$ threat-radar health check
```

---

## 🎯 Common Interactive Workflows

### Workflow 1: Explore and Scan Multiple Images

```bash
# Start interactive session
make docker-shell

# Inside container:
$ threat-radar cve scan-image alpine:3.18 --auto-save
$ threat-radar cve scan-image python:3.11 --auto-save
$ threat-radar cve scan-image nginx:alpine --auto-save

# Check results
$ ls -lh storage/cve_storage/

# View a scan result
$ cat storage/cve_storage/alpine_3_18_image_*.json | jq '.matches | length'

# Exit when done
$ exit
```

### Workflow 2: Complete Security Analysis

```bash
# Start with AI credentials
docker run --rm -it \
  --env-file .env \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/storage:/app/storage \
  -v $(pwd)/cache:/app/cache \
  --entrypoint /bin/bash \
  threat-radar:latest

# Inside container - full workflow:
$ # Step 1: Scan
$ threat-radar cve scan-image myapp:latest --auto-save

$ # Step 2: Find the scan file
$ SCAN_FILE=$(ls -t storage/cve_storage/myapp*.json | head -1)
$ echo "Analyzing: $SCAN_FILE"

$ # Step 3: AI analysis
$ threat-radar ai analyze $SCAN_FILE --auto-save

$ # Step 4: Build graph
$ threat-radar graph build $SCAN_FILE --auto-save

$ # Step 5: Query graph
$ GRAPH_FILE=$(ls -t storage/graph_storage/*.graphml | head -1)
$ threat-radar graph query $GRAPH_FILE --stats

$ # Step 6: Find attack paths
$ threat-radar graph attack-paths $GRAPH_FILE -o storage/attack-paths.json

$ # View results
$ ls -lh storage/
$ exit
```

### Workflow 3: Development and Testing

```bash
# Start shell with all volumes
make docker-shell

# Test different severity filters
$ threat-radar cve scan-image alpine:3.18 --severity CRITICAL -o /tmp/critical.json
$ threat-radar cve scan-image alpine:3.18 --severity HIGH -o /tmp/high.json
$ threat-radar cve scan-image alpine:3.18 --severity MEDIUM -o /tmp/medium.json

# Compare results
$ jq '.matches | length' /tmp/critical.json
$ jq '.matches | length' /tmp/high.json
$ jq '.matches | length' /tmp/medium.json

# Test SBOM generation
$ threat-radar sbom docker python:3.11 -o /tmp/python-sbom.json
$ threat-radar sbom read /tmp/python-sbom.json

# Test health checks
$ threat-radar health check --verbose
$ threat-radar health version

$ exit
```

### Workflow 4: Batch Processing

```bash
make docker-shell

# Create a list of images to scan
$ cat > /tmp/images.txt << EOF
alpine:3.18
python:3.11
nginx:alpine
redis:alpine
postgres:15-alpine
EOF

# Scan all images
$ while read image; do
    echo "Scanning $image..."
    threat-radar cve scan-image $image --auto-save --cleanup
  done < /tmp/images.txt

# View all results
$ ls -lh storage/cve_storage/

# Generate summary report
$ for file in storage/cve_storage/*.json; do
    echo "=== $file ==="
    jq -r '.matches | length' $file
  done

$ exit
```

---

## 🛠️ Advanced Interactive Features

### 1. Real-time Log Monitoring

```bash
# Terminal 1: Start container in background
docker-compose up -d

# Terminal 2: Interactive shell
docker-compose exec threat-radar /bin/bash

# Terminal 3: Watch logs
docker-compose logs -f threat-radar

# In Terminal 2, run commands and watch logs in Terminal 3
$ threat-radar cve scan-image alpine:3.18 --auto-save
```

### 2. Python REPL Access

```bash
# Start Python interactive shell
docker run --rm -it \
  -v $(pwd)/storage:/app/storage \
  --entrypoint python \
  threat-radar:latest
```

Inside Python:
```python
>>> from threat_radar.core.grype_integration import GrypeClient
>>> from threat_radar.utils.version import __version__
>>> from pathlib import Path
>>> import json

>>> print(f"Threat Radar v{__version__}")
Threat Radar v0.3.0

>>> # List scan results
>>> scans = list(Path('/app/storage/cve_storage').glob('*.json'))
>>> print(f"Found {len(scans)} scan results")

>>> # Load and analyze a scan
>>> if scans:
...     with open(scans[0]) as f:
...         data = json.load(f)
...     print(f"Vulnerabilities: {len(data.get('matches', []))}")
...     print(f"Target: {data.get('source', {}).get('target', 'unknown')}")

>>> exit()
```

### 3. File System Exploration

```bash
make docker-shell

# Explore the container filesystem
$ ls -la /app/
$ ls -la /app/storage/
$ ls -la /opt/venv/lib/python3.11/site-packages/

# Check installed packages
$ pip list | grep threat

# View Grype database
$ ls -lh /app/cache/grype/

# Check logs
$ ls -lh /app/logs/
$ tail -20 /app/logs/app.log

$ exit
```

### 4. Multi-session Development

```bash
# Create a persistent development container
docker run -d -it \
  --name tr-dev \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/storage:/app/storage \
  -v $(pwd)/cache:/app/cache \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd):/workspace:ro \
  --entrypoint /bin/bash \
  threat-radar:latest

# Session 1: Connect and run scans
docker exec -it tr-dev /bin/bash
$ threat-radar cve scan-image alpine:3.18 --auto-save

# Session 2 (different terminal): Monitor
docker exec -it tr-dev tail -f /app/logs/app.log

# Session 3 (different terminal): Check results
docker exec -it tr-dev ls -lh /app/storage/cve_storage/

# When completely done:
docker stop tr-dev
docker rm tr-dev
```

---

## 🔧 Debugging and Troubleshooting

### Interactive Debugging Session

```bash
make docker-shell

# Check system status
$ threat-radar health check --verbose

# Test Docker connection
$ docker ps

# Test Grype
$ grype version
$ grype db status

# Test Syft
$ syft version

# Check environment variables
$ env | grep -E "(AI_|GRYPE_|LOG_)"

# Verify volumes are mounted
$ ls -la /app/storage/
$ ls -la /app/cache/
$ touch /app/storage/test.txt && rm /app/storage/test.txt && echo "Storage writable"

# Run a test scan with verbose output
$ threat-radar -vv cve scan-image alpine:3.18 -o /tmp/test-scan.json

# Check the output
$ cat /tmp/test-scan.json | jq '.matches | length'

$ exit
```

### Error Investigation

```bash
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/storage:/app/storage \
  --entrypoint /bin/bash \
  threat-radar:latest

# Inside container:

# Enable debug logging
$ export LOG_LEVEL=DEBUG

# Run problematic command
$ threat-radar cve scan-image problematic-image:tag 2>&1 | tee /tmp/debug.log

# Analyze the error
$ cat /tmp/debug.log | grep -i error
$ cat /tmp/debug.log | grep -i "traceback" -A 20

# Check Grype directly
$ grype problematic-image:tag 2>&1 | tee /tmp/grype-direct.log

$ exit
```

---

## 📊 Interactive Data Analysis

### Analyze Scan Results Interactively

```bash
make docker-shell

# Find all scans
$ SCANS=($(ls storage/cve_storage/*.json))
$ echo "Found ${#SCANS[@]} scans"

# Show summary of each
$ for scan in "${SCANS[@]}"; do
    echo "=== $scan ==="
    jq -r '"\(.source.target.userInput): \(.matches | length) vulnerabilities"' "$scan"
  done

# Find scans with critical vulnerabilities
$ for scan in "${SCANS[@]}"; do
    CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "$scan")
    if [ "$CRITICAL" -gt 0 ]; then
      echo "$scan: $CRITICAL critical vulnerabilities"
    fi
  done

# Extract all unique CVE IDs
$ jq -r '.matches[].vulnerability.id' storage/cve_storage/*.json | sort -u > /tmp/all-cves.txt
$ wc -l /tmp/all-cves.txt

$ exit
```

### Generate Custom Reports

```bash
docker run --rm -it \
  --env-file .env \
  -v $(pwd)/storage:/app/storage \
  --entrypoint /bin/bash \
  threat-radar:latest

# Create a custom summary
$ cat > /tmp/summary.sh << 'EOF'
#!/bin/bash
echo "Security Scan Summary"
echo "===================="
echo ""

for file in storage/cve_storage/*.json; do
  TARGET=$(jq -r '.source.target.userInput' "$file")
  TOTAL=$(jq '.matches | length' "$file")
  CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "$file")
  HIGH=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' "$file")

  echo "Image: $TARGET"
  echo "  Total: $TOTAL | Critical: $CRITICAL | High: $HIGH"
  echo ""
done
EOF

$ chmod +x /tmp/summary.sh
$ /tmp/summary.sh

$ exit
```

---

## �� Pro Tips for Interactive Mode

1. **Use tab completion:**
   ```bash
   $ threat-radar c<TAB>
   $ threat-radar cve s<TAB>
   ```

2. **History navigation:**
   ```bash
   $ # Use arrow keys to navigate command history
   $ # Ctrl+R to search history
   ```

3. **Background jobs:**
   ```bash
   $ threat-radar cve scan-image large-image:tag --auto-save &
   $ jobs
   $ fg  # Bring back to foreground
   ```

4. **Multiple terminals:**
   ```bash
   # Terminal 1: Run commands
   docker exec -it container-name /bin/bash

   # Terminal 2: Monitor logs
   docker exec -it container-name tail -f /app/logs/app.log

   # Terminal 3: Watch storage
   watch -n 1 'docker exec container-name ls -lh /app/storage/cve_storage/'
   ```

5. **Persist work:**
   ```bash
   # Save your shell history before exit
   $ history > /app/storage/shell-history.txt
   $ exit

   # Later, reload history
   $ cat /app/storage/shell-history.txt
   ```

---

## 🎓 Learning and Experimentation

### Safe Experimentation

```bash
make docker-shell

# Experiment safely - container is ephemeral
$ threat-radar --help | less
$ threat-radar cve --help
$ threat-radar ai --help

# Try different options
$ threat-radar cve scan-image alpine:3.18 --help
$ threat-radar cve scan-image alpine:3.18 --severity HIGH -o /tmp/test.json
$ cat /tmp/test.json | jq '.matches | length'

# Everything is cleaned up on exit
$ exit
```

### Training and Demos

```bash
# Perfect for live demos or training sessions
make docker-shell

# Show capabilities step by step
$ echo "Step 1: Health Check"
$ threat-radar health check --verbose

$ echo -e "\nStep 2: Scan an image"
$ threat-radar cve scan-image alpine:3.18 --auto-save

$ echo -e "\nStep 3: View results"
$ ls -lh storage/cve_storage/

$ echo -e "\nStep 4: Generate SBOM"
$ threat-radar sbom docker python:3.11 -o /tmp/python-sbom.json

$ echo -e "\nStep 5: Analyze SBOM"
$ threat-radar sbom stats /tmp/python-sbom.json

$ exit
```

---

## 📚 Additional Resources

- **[Complete Usage Guide](DOCKER_USAGE.md)** - All commands and workflows
- **[Quick Reference](DOCKER_QUICK_REFERENCE.md)** - One-page command reference
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment
- **[Makefile](Makefile)** - All available shortcuts

---

## 🆘 Getting Help in Interactive Mode

```bash
# Inside the container:
$ threat-radar --help                    # Main help
$ threat-radar <command> --help          # Command-specific help
$ threat-radar health check --verbose    # System status
$ grype --help                           # Grype help
$ syft --help                            # Syft help
```

---

**Enjoy interactive exploration of Threat Radar! 🚀**
