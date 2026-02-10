# Threat Radar Installation Guide

Complete installation instructions for all platforms and use cases.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Methods](#installation-methods)
3. [Platform-Specific Instructions](#platform-specific-instructions)
4. [Post-Installation Configuration](#post-installation-configuration)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)
7. [Upgrading](#upgrading)
8. [Uninstallation](#uninstallation)

---

## Prerequisites

### Required Software

#### 1. Python 3.8 or Higher

**Check if Python is installed:**
```bash
python3 --version  # Should show 3.8 or higher
```

**Install Python:**

<details>
<summary><b>macOS</b></summary>

```bash
# Using Homebrew (recommended)
brew install python@3.11

# Or download from python.org
# Visit: https://www.python.org/downloads/macos/
```
</details>

<details>
<summary><b>Ubuntu/Debian</b></summary>

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```
</details>

<details>
<summary><b>RHEL/CentOS/Fedora</b></summary>

```bash
sudo dnf install python3 python3-pip
# or for older systems
sudo yum install python3 python3-pip
```
</details>

<details>
<summary><b>Windows</b></summary>

1. Download from https://www.python.org/downloads/windows/
2. Run installer and check "Add Python to PATH"
3. Verify: `python --version`
</details>

#### 2. Docker (Required for container analysis)

**Check if Docker is installed:**
```bash
docker --version
docker ps  # Should not error
```

**Install Docker:**

<details>
<summary><b>macOS</b></summary>

```bash
# Download Docker Desktop from:
# https://www.docker.com/products/docker-desktop

# Or use Homebrew
brew install --cask docker
```
</details>

<details>
<summary><b>Ubuntu/Debian</b></summary>

```bash
# Add Docker's official GPG key
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add user to docker group (to run without sudo)
sudo usermod -aG docker $USER
newgrp docker
```
</details>

<details>
<summary><b>RHEL/CentOS/Fedora</b></summary>

```bash
sudo dnf install docker
# or
sudo yum install docker

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```
</details>

<details>
<summary><b>Windows</b></summary>

1. Download Docker Desktop from: https://www.docker.com/products/docker-desktop
2. Install and start Docker Desktop
3. Verify: `docker --version`
</details>

#### 3. Grype (Required for CVE scanning)

**Install Grype:**

<details>
<summary><b>macOS</b></summary>

```bash
brew install grype

# Verify installation
grype version
```
</details>

<details>
<summary><b>Linux</b></summary>

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
grype version
```
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Using scoop
scoop install grype

# Or download from GitHub releases
# Visit: https://github.com/anchore/grype/releases
```
</details>

#### 4. Syft (Required for SBOM generation)

**Install Syft:**

<details>
<summary><b>macOS</b></summary>

```bash
brew install syft

# Verify installation
syft version
```
</details>

<details>
<summary><b>Linux</b></summary>

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
syft version
```
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Using scoop
scoop install syft

# Or download from GitHub releases
# Visit: https://github.com/anchore/syft/releases
```
</details>

---

## Installation Methods

### Method 1: Install from PyPI (Recommended for end users)

```bash
# Install latest stable version
pip install threat-radar

# Or with optional AI features
pip install threat-radar[ai]

# Or with development tools
pip install threat-radar[dev]
```

### Method 2: Install from Source (Recommended for developers)

```bash
# Clone the repository
git clone https://github.com/Threat-Radar/tr.git
cd threat-radar

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e .

# Or with all optional dependencies
pip install -e ".[dev,ai]"
```

### Method 3: Install from GitHub (Latest development version)

```bash
# Install directly from GitHub main branch
pip install git+https://github.com/Threat-Radar/tr.git

# Or specific branch/tag
pip install git+https://github.com/Threat-Radar/tr.git@v0.1.0
```

### Method 4: Using requirements.txt

```bash
# For minimal installation
pip install -r requirements.txt

# For development
pip install -r requirements-dev.txt

# For AI features
pip install -r requirements-ai.txt
```

---

## Platform-Specific Instructions

### Complete Setup on macOS

```bash
# 1. Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install all prerequisites
brew install python@3.11 docker grype syft

# 3. Start Docker Desktop
open -a Docker

# 4. Install Threat Radar
pip3 install threat-radar

# 5. Verify installation
threat-radar --version
threat-radar --help
```

### Complete Setup on Ubuntu 22.04

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install Python and pip
sudo apt install -y python3 python3-pip python3-venv

# 3. Install Docker (see Docker section above for full commands)
# ... Docker installation commands ...

# 4. Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# 5. Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# 6. Install Threat Radar
pip3 install threat-radar

# 7. Verify installation
threat-radar --version
threat-radar --help
```

### Complete Setup on Windows 10/11

```powershell
# 1. Install Python from python.org (check "Add to PATH")
# Download: https://www.python.org/downloads/windows/

# 2. Install Docker Desktop
# Download: https://www.docker.com/products/docker-desktop

# 3. Install Scoop (package manager)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

# 4. Install Grype and Syft
scoop install grype syft

# 5. Install Threat Radar
pip install threat-radar

# 6. Verify installation
threat-radar --version
threat-radar --help
```

---

## Post-Installation Configuration

### 1. Environment Variables

Create a `.env` file for configuration:

```bash
# Copy example configuration
cp .env.example .env

# Edit with your preferred editor
nano .env  # or vim, code, etc.
```

**Required for AI features:**
```bash
# OpenAI (Cloud)
OPENAI_API_KEY=sk-your-key-here
AI_PROVIDER=openai
AI_MODEL=gpt-4o

# OR Anthropic Claude (Cloud)
ANTHROPIC_API_KEY=sk-ant-your-key-here
AI_PROVIDER=anthropic
AI_MODEL=claude-3-5-sonnet-20241022

# OR Ollama (Local)
AI_PROVIDER=ollama
AI_MODEL=llama2
LOCAL_MODEL_ENDPOINT=http://localhost:11434
```

### 2. Grype Database Update

Update Grype's vulnerability database:

```bash
threat-radar cve db-update
threat-radar cve db-status
```

### 3. Ollama Setup (for local AI)

If using local AI with Ollama:

```bash
# Install Ollama
brew install ollama  # macOS
# Visit https://ollama.ai for other platforms

# Start Ollama service
ollama serve &

# Pull a model
ollama pull llama2
ollama pull mistral  # Alternative

# Verify
ollama list
```

---

## Verification

### Basic Verification

```bash
# Check CLI is accessible
threat-radar --version
tradar --version  # Shortened alias

# View help
threat-radar --help
threat-radar cve --help
threat-radar ai --help
```

### Test Basic Functionality

```bash
# Test CVE scanning
threat-radar cve scan-image alpine:3.18

# Test SBOM generation
threat-radar sbom docker alpine:3.18 -o test-sbom.json

# Test Docker integration
threat-radar docker list-images
```

### Test AI Features (if configured)

```bash
# Scan and analyze
threat-radar cve scan-image alpine:3.18 -o scan.json
threat-radar ai analyze scan.json
```

### Run Test Suite (for development installations)

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/test_grype_integration.py
pytest tests/test_ai_integration.py -v
```

---

## Troubleshooting

### Common Issues

#### Issue: "threat-radar: command not found"

**Solution:**
```bash
# Ensure pip installation directory is in PATH
python3 -m pip show threat-radar  # Check install location

# Add to PATH (Linux/macOS)
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Or reinstall with --user flag
pip3 install --user threat-radar
```

#### Issue: "grype: command not found"

**Solution:**
```bash
# Verify Grype installation
which grype

# Reinstall Grype
# macOS:
brew install grype

# Linux:
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
```

#### Issue: "Cannot connect to the Docker daemon"

**Solution:**
```bash
# Start Docker service
# macOS: Open Docker Desktop application
# Linux:
sudo systemctl start docker

# Verify Docker is running
docker ps
```

#### Issue: "ModuleNotFoundError: No module named 'threat_radar'"

**Solution:**
```bash
# Reinstall package
pip3 uninstall threat-radar
pip3 install threat-radar

# For development installation
cd /path/to/threat-radar
pip3 install -e .
```

#### Issue: AI features not working

**Solution:**
```bash
# Verify .env configuration
cat .env | grep API_KEY

# Test API key
export OPENAI_API_KEY=your-key
python3 -c "import openai; print('OpenAI configured')"

# For Ollama, verify service is running
ollama list
```

### Getting More Help

- **Documentation:** See `README.md` and `CLAUDE.md`
- **Examples:** Check `examples/` directory
- **Troubleshooting:** See `examples/TROUBLESHOOTING.md`
- **Issues:** https://github.com/Threat-Radar/tr/issues

---

## Upgrading

### Upgrade from PyPI

```bash
# Upgrade to latest version
pip install --upgrade threat-radar
```

### Upgrade from Source

```bash
cd /path/to/threat-radar
git pull origin main
pip install -e . --upgrade
```

### Update External Tools

```bash
# Update Grype
brew upgrade grype  # macOS
# Or reinstall: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Update Syft
brew upgrade syft  # macOS
# Or reinstall: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Update vulnerability database
threat-radar cve db-update
```

---

## Uninstallation

### Remove Threat Radar

```bash
# Uninstall Python package
pip uninstall threat-radar

# Remove configuration (optional)
rm ~/.env
rm -rf storage/ sbom_storage/
```

### Remove External Tools (Optional)

```bash
# Remove Grype
brew uninstall grype  # macOS
# Linux: rm /usr/local/bin/grype

# Remove Syft
brew uninstall syft  # macOS
# Linux: rm /usr/local/bin/syft
```

### Clean Up Docker

```bash
# Remove Threat Radar-related Docker images (optional)
docker image prune -a
```

---

## Additional Resources

- **Quick Start:** See `README.md`
- **API Documentation:** See `docs/API.md`
- **Examples:** See `examples/START_HERE.md`
- **Development:** See `CLAUDE.md`
- **Contributing:** See `CONTRIBUTING.md` (if exists)

---

**Installation complete!** 🎉

Next steps:
1. Configure your API keys in `.env` (if using AI features)
2. Update Grype database: `threat-radar cve db-update`
3. Run your first scan: `threat-radar cve scan-image alpine:3.18`
4. Explore examples: `cd examples && ls`
