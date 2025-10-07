# SBOM Storage Organization

**Location:** `/sbom_storage/` (Project root)
**Purpose:** Centralized storage for all generated Software Bill of Materials
**Status:** ✅ Auto-organized, Git-managed structure

---

## 📂 Directory Structure

```
sbom_storage/
├── .gitignore              # Ignores generated files, keeps structure
├── README.md               # Usage documentation
├── ORGANIZATION.md         # This file - organization rationale
├── docker/                 # Docker container SBOMs
│   └── .gitkeep           # Preserves directory in git
├── local/                  # Local project SBOMs
│   └── .gitkeep
├── comparisons/            # SBOM comparison results
│   └── .gitkeep
└── archives/               # Historical/archived SBOMs
    └── .gitkeep
```

---

## 🎯 Design Rationale

### Why Root Level?

**Decision:** Keep `sbom_storage/` at project root (not moved to `data/` or `outputs/`)

**Reasons:**
1. ✅ **Standard Pattern** - Similar to `build/`, `dist/`, `node_modules/`
2. ✅ **User Expectations** - Easy to discover and understand
3. ✅ **No Breaking Changes** - 15 examples already use this path
4. ✅ **Well-Named** - Clear purpose from directory name
5. ✅ **Already Organized** - Good internal structure

### Why Git-Ignore Generated Files?

**Problem:** Generated SBOMs can be large (1.8 MB+ currently)

**Solution:** Git-ignore all generated files but preserve directory structure

**Implementation:**
- `.gitignore` in `sbom_storage/` - Ignores *.json, *.xml, etc.
- `.gitkeep` in subdirectories - Preserves empty directories in git
- Root `.gitignore` - Comprehensive ignore patterns

**Result:**
- Git tracks structure and documentation
- Git ignores user-generated content
- New users get proper directory structure
- No 1.8 MB of SBOMs in repository

---

## 📝 Naming Conventions

### Docker Container SBOMs
**Format:** `docker_<image-name>_<tag>_<timestamp>.json`

**Examples:**
```
docker_alpine_3.18_20251006_180000.json
docker_ubuntu_22.04_20251006_181500.json
docker_python_3.11-slim_20251006_182000.json
```

### Local Project SBOMs
**Format:** `local_<project-name>_<timestamp>.json`

**Examples:**
```
local_threat-radar_20251006_180000.json
local_myproject_20251006_190000.json
```

### Comparison Results
**Format:** `compare_<name1>_vs_<name2>_<timestamp>.json`

**Examples:**
```
compare_alpine-3.17_vs_alpine-3.18_20251006_180000.json
compare_v1.0_vs_v2.0_20251006_190000.json
```

### Archives
**Format:** `archive_<original-filename>_<archive-date>.json`

**Examples:**
```
archive_docker_alpine_3.18_20251005.json
```

---

## 🔧 Git Configuration

### sbom_storage/.gitignore
```gitignore
# Ignore all generated SBOM files
*.json
*.xml
*.spdx.json
*.syft.json

# Keep structure and documentation
!README.md
!.gitignore
```

### Root .gitignore
```gitignore
# SBOM generated outputs - ignore all generated files but keep structure
sbom_storage/**/*.json
sbom_storage/**/*.xml
sbom_storage/**/*.spdx.json
sbom_storage/**/*.syft.json
!sbom_storage/**/.gitkeep
!sbom_storage/README.md
!sbom_storage/.gitignore

# Example outputs - keep these for demonstration
!examples/output/*.json
```

---

## 📊 Storage Strategy

### What Gets Committed to Git?

✅ **Committed:**
- Directory structure (via .gitkeep)
- Documentation (README.md, ORGANIZATION.md)
- Configuration (.gitignore)

❌ **Not Committed (Ignored):**
- All generated SBOM files (*.json, *.xml, etc.)
- User-specific outputs
- Large binary files

### Why This Approach?

**Benefits:**
- ✅ New users get proper directory structure
- ✅ Repository stays lightweight (<100 MB)
- ✅ Examples work out of the box
- ✅ Clear organization from day one
- ✅ No merge conflicts on generated files

**Trade-offs:**
- ⚠️ Users must generate their own SBOMs (expected behavior)
- ⚠️ Demo outputs in `examples/output/` kept for reference (small, ~50 KB)

---

## 📈 Growth Management

### Current State (2025-10-06)
- **Files:** 13 SBOMs
- **Size:** 1.8 MB
- **Categories:** 4 (docker, local, comparisons, archives)

### Retention Policy

**Active SBOMs** (docker/, local/, comparisons/)
- Keep most recent version
- Auto-archive older than 30 days

**Archives** (archives/)
- Keep for 90 days
- Compress if > 1 MB
- Manual deletion after 90 days

**Implementation Status:** 📋 Planned (not yet automated)

---

## 🔄 Automatic Organization

### Via sbom_storage.py Utility

The `threat_radar/utils/sbom_storage.py` module provides:

```python
from threat_radar.utils.sbom_storage import (
    get_docker_sbom_path,      # Returns: sbom_storage/docker/...
    get_local_sbom_path,       # Returns: sbom_storage/local/...
    get_comparison_path,       # Returns: sbom_storage/comparisons/...
    ensure_storage_directories # Creates structure if needed
)
```

**Usage in Examples:**
```python
# Examples automatically use organized storage
from threat_radar.utils.sbom_storage import get_docker_sbom_path

sbom_path = get_docker_sbom_path("alpine", "3.18")
# Returns: sbom_storage/docker/docker_alpine_3.18_<timestamp>.json
```

---

## 🎓 User Workflow

### First Time Setup
1. Clone repository
2. Run `pip install -e .`
3. Directory structure already exists (via .gitkeep)
4. Generate first SBOM → Automatically saved to correct location

### Normal Usage
```bash
# Generate Docker SBOM - auto-saved to sbom_storage/docker/
python examples/02_advanced/syft_sbom_example.py

# Output automatically organized:
# sbom_storage/docker/docker_alpine_3.18_20251006_180000.json
```

### Manual Cleanup
```bash
# Remove old SBOMs (keep structure)
rm sbom_storage/docker/*.json

# Directory structure preserved (via .gitkeep)
```

---

## 🔍 Comparison to Alternatives

| Approach | Pros | Cons | Chosen? |
|----------|------|------|---------|
| **Current: Root `sbom_storage/`** | Standard pattern, no breaking changes | Root clutter | ✅ **YES** |
| Move to `data/sbom/` | Cleaner root | Breaking change, update 9+ examples | ❌ No |
| Move to `outputs/sbom/` | Clear purpose | Breaking change, update utilities | ❌ No |
| Keep in examples/ | Co-located | Examples are demos, not outputs | ❌ No |
| User home directory | Persistent | Hard to find, not project-specific | ❌ No |

**Winner:** Keep at root with git-ignore strategy

---

## 📚 Related Documentation

- **[SBOM Storage README](README.md)** - User-facing usage guide
- **[SBOM Syft Guide](../docs/SBOM_SYFT.md)** - SBOM generation capabilities
- **[Project README](../README.md)** - Main project documentation

---

## ✅ Implementation Checklist

- [x] Created `.gitignore` in `sbom_storage/`
- [x] Created `.gitkeep` in all subdirectories
- [x] Updated root `.gitignore` with comprehensive rules
- [x] Updated `README.md` to document structure
- [x] Created `ORGANIZATION.md` (this file)
- [x] Verified examples still work (15/15 passing)
- [ ] Future: Implement automated archival policy
- [ ] Future: Add compression for large SBOMs

---

**Organized:** 2025-10-06
**Status:** ✅ Complete
**Maintainer:** Threat Radar Team
