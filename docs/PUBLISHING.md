# Publishing to PyPI Guide

This guide walks through the process of building and publishing Threat Radar to PyPI.

---

## Prerequisites

### 1. Install Build Tools

```bash
pip install build twine
```

### 2. Create PyPI Account

1. Register at https://pypi.org/account/register/
2. Verify your email
3. Enable 2FA (required for publishing)
4. Generate API token at https://pypi.org/manage/account/token/

### 3. Configure API Token

Create `~/.pypirc`:

```ini
[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcC...  # Your API token here
```

Set permissions:
```bash
chmod 600 ~/.pypirc
```

---

## Pre-Publication Checklist

### 1. Update Version

Update version in `pyproject.toml`:

```toml
[project]
name = "threat-radar"
version = "0.1.0"  # Update this
```

Also update in `threat_radar/__init__.py`:

```python
__version__ = "0.1.0"  # Update this
```

### 2. Update CHANGELOG.md

Document changes in `CHANGELOG.md`:

```markdown
## [0.1.0] - 2025-01-23

### Added
- Feature 1
- Feature 2

### Changed
- Change 1

### Fixed
- Bug fix 1
```

### 3. Run Tests

```bash
# Run full test suite
pytest

# Run with coverage
pytest --cov=threat_radar --cov-report=html

# Ensure all tests pass
pytest -v
```

### 4. Check Code Quality

```bash
# Format code
black threat_radar/ tests/

# Type checking
mypy threat_radar/

# Linting
flake8 threat_radar/
```

### 5. Verify Package Metadata

Check `pyproject.toml` has correct:
- Name
- Version
- Description
- Author/email
- URLs (homepage, repository, issues)
- Classifiers
- Keywords
- Dependencies

### 6. Test Installation Locally

```bash
# Build distribution
python -m build

# Install locally
pip install dist/threat_radar-0.1.0-py3-none-any.whl

# Test CLI
threat-radar --version
threat-radar --help

# Test imports
python -c "from threat_radar import GrypeClient; print('Import successful')"
```

---

## Building the Package

### 1. Clean Previous Builds

```bash
rm -rf build/ dist/ *.egg-info/
```

### 2. Build Distribution

```bash
python -m build
```

This creates:
- `dist/threat_radar-0.1.0-py3-none-any.whl` (wheel)
- `dist/threat_radar-0.1.0.tar.gz` (source distribution)

### 3. Verify Build

```bash
# Check distribution
twine check dist/*

# List contents
tar -tzf dist/threat_radar-0.1.0.tar.gz | head -20
unzip -l dist/threat_radar-0.1.0-py3-none-any.whl | head -20
```

---

## Publishing to TestPyPI (Recommended First)

### 1. Register on TestPyPI

Register at https://test.pypi.org/account/register/

### 2. Create TestPyPI Token

Generate token at https://test.pypi.org/manage/account/token/

### 3. Upload to TestPyPI

```bash
twine upload --repository testpypi dist/*
```

Or specify token directly:
```bash
twine upload --repository testpypi dist/* -u __token__ -p pypi-AgEI...
```

### 4. Test Installation from TestPyPI

```bash
# Create clean environment
python -m venv test_env
source test_env/bin/activate

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --no-deps threat-radar

# Install dependencies from regular PyPI
pip install PyGithub python-dotenv typer docker openai tenacity

# Test
threat-radar --version
threat-radar --help
```

---

## Publishing to PyPI (Production)

### 1. Final Checks

- [ ] All tests passing
- [ ] Documentation complete
- [ ] CHANGELOG.md updated
- [ ] Version bumped
- [ ] Git tagged
- [ ] TestPyPI installation successful

### 2. Create Git Tag

```bash
# Tag the release
git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin v0.1.0

# Or tag and push main
git tag v0.1.0
git push origin main --tags
```

### 3. Upload to PyPI

```bash
twine upload dist/*
```

### 4. Verify Upload

Visit: https://pypi.org/project/threat-radar/

Check:
- Version number correct
- Description renders properly
- Links work
- Classifiers correct

### 5. Test Installation

```bash
# Clean environment
python -m venv verify_env
source verify_env/bin/activate

# Install from PyPI
pip install threat-radar

# Verify
threat-radar --version
python -c "from threat_radar import GrypeClient; print('Success!')"
```

---

## Post-Publication

### 1. Create GitHub Release

1. Go to https://github.com/yourusername/threat-radar/releases
2. Click "Create a new release"
3. Select tag `v0.1.0`
4. Title: "Threat Radar v0.1.0"
5. Copy CHANGELOG.md content
6. Attach distribution files
7. Publish release

### 2. Update Documentation

Update README.md badges (if any):
```markdown
[![PyPI version](https://badge.fury.io/py/threat-radar.svg)](https://badge.fury.io/py/threat-radar)
[![Downloads](https://pepy.tech/badge/threat-radar)](https://pepy.tech/project/threat-radar)
```

### 3. Announce Release

Consider announcing on:
- GitHub Discussions
- Project blog
- Social media
- Security communities
- Relevant forums

---

## Automated Publishing with GitHub Actions

Create `.github/workflows/publish.yml`:

```yaml
name: Publish to PyPI

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install build twine

      - name: Build package
        run: python -m build

      - name: Publish to PyPI
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: twine upload dist/*
```

Add `PYPI_API_TOKEN` to GitHub repository secrets.

---

## Version Numbering

Follow Semantic Versioning (SemVer): `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

Examples:
- `0.1.0` - Initial beta release
- `0.1.1` - Bug fix
- `0.3.0` - New features
- `1.0.0` - Stable release

Pre-release versions:
- `0.1.0a1` - Alpha
- `0.1.0b1` - Beta
- `0.1.0rc1` - Release candidate

---

## Troubleshooting

### Issue: "File already exists"

**Solution:**
You cannot re-upload the same version. Bump version number and rebuild.

```bash
# Update version in pyproject.toml
# Update version in __init__.py
python -m build
twine upload dist/*
```

### Issue: "Invalid distribution"

**Solution:**
Run checks before upload:

```bash
twine check dist/*
```

Fix any reported issues in `pyproject.toml` or `README.md`.

### Issue: "README doesn't render"

**Solution:**
- Ensure README.md uses standard Markdown
- Test rendering locally
- Check for unsupported features

### Issue: "Dependencies not installing"

**Solution:**
- Verify dependency specifications in `pyproject.toml`
- Test in clean environment
- Check dependency availability on PyPI

---

## Quick Reference

```bash
# Complete publishing workflow
rm -rf build/ dist/ *.egg-info/
python -m build
twine check dist/*
twine upload --repository testpypi dist/*  # Test first
# Verify on TestPyPI
twine upload dist/*  # Production
```

---

## Resources

- **PyPI:** https://pypi.org/
- **TestPyPI:** https://test.pypi.org/
- **Packaging Guide:** https://packaging.python.org/
- **twine docs:** https://twine.readthedocs.io/
- **build docs:** https://build.pypa.io/

---

**Ready to publish?** Follow the checklist carefully and test on TestPyPI first!
