# Threat Radar Tech Stack

## Overview

Threat Radar is a Python-based security vulnerability analysis platform with a modern, modular architecture.

## Core Technologies

### Language & Runtime
- **Python 3.8+** - Primary language
  - Type hints throughout (`mypy` for static type checking)
  - Dataclasses for data models
  - Async support where beneficial

### CLI Framework
- **Typer 0.9+** - Modern CLI framework
  - Built on Click
  - Automatic help generation
  - Type-safe argument parsing
  - Sub-command architecture
  - Rich terminal output

## External Tools Integration

### Vulnerability Scanning
- **Grype** (Anchore) - CVE vulnerability scanner
  - CLI tool (installed separately)
  - No API limits
  - Local vulnerability database
  - Supports multiple SBOM formats

### SBOM Generation
- **Syft** (Anchore) - SBOM generator
  - CLI tool + Python bindings (`anchore-syft>=1.18.0`)
  - CycloneDX and SPDX formats
  - Comprehensive package detection
  - Container and filesystem scanning

## Python Dependencies

### Core Libraries

#### Container & Infrastructure
```python
docker>=7.0.0              # Docker SDK for Python
```
- Container operations
- Image inspection
- Container execution
- Network management

#### API Integrations
```python
python-dotenv==1.0.0      # Environment variable management
```

#### Graph Database & Analytics
```python
networkx>=3.0             # Graph data structures and algorithms
numpy                     # Numerical operations for graph analytics
```
- Vulnerability relationship modeling
- Attack path discovery (Dijkstra, BFS)
- Graph analysis and queries
- Network topology analysis

#### AI & LLM Integration
```python
openai>=1.0.0            # OpenAI GPT API
tenacity>=8.2.0          # Retry logic for API calls
```

**Optional AI providers**:
```python
anthropic>=0.7.0         # Anthropic Claude API
ollama>=0.1.0            # Local Ollama models
```

Features:
- Vulnerability analysis and risk assessment
- Batch processing for large scans (25+ CVEs)
- Remediation plan generation
- Prioritization with business context
- Structured output with JSON mode

#### Visualization & Reporting
```python
plotly>=5.18.0           # Interactive visualizations
kaleido>=0.2.1           # Static image export (PNG, SVG, PDF)
```

Capabilities:
- Interactive HTML graphs
- Attack path visualization
- Network topology views
- Force-directed layouts
- Export to multiple formats

### Development Tools

```python
pytest>=7.0.0            # Testing framework
pytest-cov>=4.0.0        # Coverage reporting
black>=22.0.0            # Code formatting (88 char line length)
flake8>=4.0.0            # Linting
mypy>=0.950              # Static type checking
```

## Architecture Components

### Module Structure

```
threat_radar/
├── cli/                 # CLI interface (Typer)
│   ├── app.py          # Main CLI app with global options
│   ├── cve.py          # CVE scanning commands
│   ├── docker.py       # Docker operations
│   ├── sbom.py         # SBOM generation
│   ├── ai.py           # AI-powered analysis
│   ├── graph.py        # Graph database
│   ├── report.py       # Reporting
│   ├── env.py          # Environment configuration
│   └── config.py       # Configuration management
├── core/                # Core business logic
│   ├── docker_integration.py      # Docker SDK wrapper
│   ├── grype_integration.py       # Grype CLI wrapper
│   ├── syft_integration.py        # Syft integration
│   ├── container_analyzer.py      # Container analysis
│   ├── package_extractors.py      # Package manager parsers
│   ├── sbom_operations.py         # SBOM utilities
│   └── cve_storage_manager.py     # Storage management
├── ai/                  # AI integration
│   ├── llm_client.py              # LLM client abstraction
│   ├── vulnerability_analyzer.py  # Vulnerability analysis
│   ├── prioritization.py          # Risk prioritization
│   ├── remediation_generator.py   # Fix recommendations
│   └── prompt_templates.py        # Prompt engineering
├── graph/               # Graph database
│   ├── graph_client.py            # NetworkX client
│   ├── builders.py                # Graph construction
│   ├── queries.py                 # Graph analysis
│   ├── models.py                  # Data models
│   └── analytics_models.py        # Attack path models
├── environment/         # Business context
│   ├── models.py                  # Environment data models
│   ├── parser.py                  # Config file parser
│   └── graph_builder.py           # Infrastructure graphs
├── visualization/       # Interactive visualizations
│   ├── graph_visualizer.py        # Base graph viz
│   ├── attack_path_visualizer.py  # Attack path viz
│   ├── topology_visualizer.py     # Network topology
│   ├── filters.py                 # Graph filtering
│   └── exporters.py               # Multi-format export
├── utils/               # Utilities
│   ├── config_manager.py          # Configuration system
│   ├── cli_context.py             # Global CLI state
│   ├── comprehensive_report.py    # Report generator
│   ├── report_formatters.py       # Output formatters
│   ├── report_templates.py        # Report data models
│   └── graph_storage.py           # Graph persistence
└── __init__.py
```

### Data Flow Architecture

```
┌─────────────────────────────────────────────────┐
│              CLI Layer (Typer)                  │
│  User Commands → Argument Parsing → Validation  │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│           Core Business Logic                   │
│                                                 │
│  Docker SDK ──→ Container Analysis              │
│  Grype CLI ──→ CVE Scanning                     │
│  Syft ──────→ SBOM Generation                   │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│          Graph Database (NetworkX)              │
│                                                 │
│  Nodes: Containers, Packages, CVEs, Assets      │
│  Edges: Dependencies, Vulnerabilities           │
│  Analytics: Attack Paths, Risk Scoring          │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│          Analysis & Intelligence                │
│                                                 │
│  AI Analysis (OpenAI/Anthropic/Ollama)          │
│  Risk Prioritization                            │
│  Remediation Planning                           │
│  Business Context Integration                   │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│      Visualization & Reporting                  │
│                                                 │
│  Plotly ────→ Interactive Graphs                │
│  Templates ─→ HTML/Markdown/JSON Reports        │
│  Export ────→ PNG/SVG/PDF/GraphML               │
└─────────────────────────────────────────────────┘
```

## Design Patterns

### CLI Architecture
- **Command Pattern** - Each command is a separate function
- **Dependency Injection** - Services passed via context
- **Factory Pattern** - LLM client creation based on provider

### Data Models
- **Dataclasses** - Immutable data structures
- **Type Hints** - Full type coverage for safety
- **Pydantic** (future) - Schema validation for configs

### Error Handling
- **Tenacity** - Retry logic for API calls
- **Graceful Degradation** - Continue on non-critical errors
- **Rich Error Messages** - User-friendly CLI output

## External Services & APIs

### Required External Tools
- **Docker Engine** - Container operations
- **Grype** - Vulnerability scanning
- **Syft** - SBOM generation

### Optional External Services
- **OpenAI API** - GPT models for analysis
- **Anthropic API** - Claude models
- **Ollama** - Local LLM server

## Data Storage

### File Formats
- **JSON** - Primary format for results, configs, reports
- **GraphML** - Graph database export
- **CycloneDX** - SBOM standard format
- **SPDX** - Alternative SBOM format
- **Markdown** - Human-readable reports
- **HTML** - Interactive reports and visualizations

### Storage Locations
```
./storage/
├── cve_storage/        # CVE scan results (JSON)
├── ai_analysis/        # AI analysis outputs (JSON)
└── graph_storage/      # Graph databases (GraphML + JSON metadata)

./sbom_storage/
├── docker/             # Docker image SBOMs
├── local/              # Local directory SBOMs
└── comparisons/        # SBOM comparison results
```

## Performance Considerations

### Optimization Techniques
- **Batch Processing** - AI analysis batches 25 CVEs at a time
- **Lazy Loading** - Load graphs only when needed
- **Caching** - Vulnerability database local cache (Grype)
- **Parallel Operations** - Multiple scans in parallel
- **Graph Algorithms** - Efficient NetworkX algorithms

### Scalability
- **Local Database** - Grype DB (no API limits)
- **Incremental Scans** - Only scan changed images
- **Modular Architecture** - Easy to parallelize

## Security

### Secrets Management
- **Environment Variables** - `.env` files for API keys
- **Git Ignore** - `.env` excluded from version control
- **No Hardcoded Secrets** - All sensitive data via env vars

### Input Validation
- **Typer** - Built-in type checking
- **Path Validation** - Secure file path handling
- **Container Isolation** - Docker SDK with proper permissions

## Platform Support

### Operating Systems
- ✅ **macOS** - Primary development platform
- ✅ **Linux** - Production deployment
- ⚠️  **Windows** - Limited support (WSL recommended)

### Python Versions
- ✅ Python 3.8, 3.9, 3.10, 3.11, 3.12
- Type hints compatible with 3.8+
- Tested on Python 3.11

## Development Stack

### Code Quality Tools
```bash
black threat_radar/           # Format code (88 char)
mypy threat_radar/            # Type checking
flake8 threat_radar/          # Linting
pytest --cov=threat_radar     # Tests + coverage
```

### Testing Framework
- **pytest** - Test runner
- **pytest-cov** - Coverage reporting
- **Fixtures** - Reusable test data
- **Mocking** - Docker SDK mocking for tests

### CI/CD (Future)
- Automated releases to PyPI
- Docker image builds
- Documentation generation

## Unique Capabilities

### What Makes Threat Radar Different

1. **Graph-Based Analysis**
   - NetworkX for relationship modeling
   - Attack path discovery algorithms
   - Visual topology mapping

2. **AI Integration**
   - Multi-provider support (OpenAI, Anthropic, Ollama)
   - Batch processing for scale
   - Business context-aware analysis

3. **Offline-First**
   - Grype local database (no API limits)
   - Works without internet (except AI)
   - No SaaS dependencies

4. **Interactive Visualizations**
   - Plotly for web-based graphs
   - Attack path highlighting
   - Network topology views

5. **Business Context**
   - Environment configuration
   - Asset criticality scoring
   - Compliance mapping (PCI, HIPAA, SOX)

## Future Tech Additions

### Planned Integrations
- **Neo4j** - Production graph database (alternative to NetworkX)
- **PostgreSQL** - Structured data storage
- **Redis** - Caching layer
- **FastAPI** - REST API server
- **React/Vue** - Web dashboard UI
- **MITRE ATT&CK** - Threat intelligence integration
- **Prometheus** - Metrics export
- **OpenTelemetry** - Observability

### Potential Features
- **Machine Learning** - CVE risk scoring with ML
- **Kubernetes Integration** - K8s cluster scanning
- **Cloud Provider APIs** - AWS, GCP, Azure scanning
- **SIEM Integration** - Splunk, ELK export

## Tech Stack Summary

| Category | Technology | Purpose |
|----------|-----------|---------|
| **Language** | Python 3.8+ | Core development |
| **CLI** | Typer | Command-line interface |
| **Container** | Docker SDK | Container operations |
| **Scanning** | Grype (CLI) | Vulnerability detection |
| **SBOM** | Syft (CLI + bindings) | Software bill of materials |
| **Graph** | NetworkX | Relationship modeling |
| **AI** | OpenAI/Anthropic/Ollama | Intelligent analysis |
| **Visualization** | Plotly | Interactive graphs |
| **Export** | Kaleido | Static image generation |
| **Testing** | pytest | Test framework |
| **Formatting** | Black | Code formatting |
| **Type Checking** | mypy | Static type analysis |
| **Config** | python-dotenv | Environment variables |

## Installation Footprint

```bash
# Core package
pip install threat-radar          # ~50MB

# With AI features
pip install threat-radar[ai]      # ~200MB (includes model libs)

# External tools (separate installation)
brew install grype syft           # ~100MB total
# or
curl -sSfL <install-scripts>
```

## Conclusion

Threat Radar combines:
- ✅ **Modern Python** - Type-safe, clean architecture
- ✅ **Industry-Standard Tools** - Grype, Syft, Docker
- ✅ **Cutting-Edge AI** - LLM integration for analysis
- ✅ **Advanced Analytics** - Graph algorithms for attack paths
- ✅ **Rich Visualizations** - Interactive, exportable graphs
- ✅ **Developer-Friendly** - CLI-first, modular design

Built for security professionals who need deep analysis without vendor lock-in.
