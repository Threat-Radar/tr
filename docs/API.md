# Threat Radar API Reference

Complete API documentation for programmatic use of Threat Radar.

---

## Table of Contents

1. [Overview](#overview)
2. [Core Scanning APIs](#core-scanning-apis)
3. [AI Analysis APIs](#ai-analysis-apis)
4. [Reporting APIs](#reporting-apis)
5. [Utility APIs](#utility-apis)
6. [Data Models](#data-models)
7. [Examples](#examples)

---

## Overview

Threat Radar provides a comprehensive Python API for vulnerability scanning, SBOM generation, AI-powered analysis, and reporting.

### Quick Start

```python
from threat_radar import GrypeClient, VulnerabilityAnalyzer, ComprehensiveReportGenerator

# Scan for vulnerabilities
grype = GrypeClient()
scan_result = grype.scan_image("alpine:3.18")

# Analyze with AI
analyzer = VulnerabilityAnalyzer()
analysis = analyzer.analyze_scan_result(scan_result)

# Generate report
generator = ComprehensiveReportGenerator()
report = generator.generate_report(scan_result)
```

---

## Core Scanning APIs

### GrypeClient

Client for Grype vulnerability scanner.

#### Constructor

```python
from threat_radar.core import GrypeClient

client = GrypeClient(grype_path=None)
```

**Parameters:**
- `grype_path` (Optional[str]): Custom path to grype binary. If None, uses PATH.

**Raises:**
- `RuntimeError`: If Grype is not installed or not accessible.

#### Methods

##### scan_image()

Scan a Docker image for vulnerabilities.

```python
result = client.scan_image(
    image_name="alpine:3.18",
    severity=None,
    only_fixed=False,
    scope="squashed"
)
```

**Parameters:**
- `image_name` (str): Docker image name and tag (e.g., "alpine:3.18")
- `severity` (Optional[GrypeSeverity]): Minimum severity level to report
- `only_fixed` (bool): Only report vulnerabilities with fixes available
- `scope` (str): Scan scope - "squashed" (default) or "all-layers"

**Returns:**
- `GrypeScanResult`: Scan results with vulnerabilities

**Example:**
```python
from threat_radar.core import GrypeClient, GrypeSeverity

client = GrypeClient()
result = client.scan_image(
    "python:3.11-slim",
    severity=GrypeSeverity.HIGH,
    only_fixed=True
)

print(f"Found {result.total_count} vulnerabilities")
for vuln in result.vulnerabilities:
    print(f"  - {vuln.id}: {vuln.package_name} ({vuln.severity})")
```

##### scan_sbom()

Scan an SBOM file for vulnerabilities.

```python
result = client.scan_sbom(
    sbom_path="path/to/sbom.json",
    severity=None,
    only_fixed=False
)
```

**Parameters:**
- `sbom_path` (str): Path to SBOM file (CycloneDX, SPDX, or Syft JSON)
- `severity` (Optional[GrypeSeverity]): Minimum severity level
- `only_fixed` (bool): Only show vulnerabilities with fixes

**Returns:**
- `GrypeScanResult`: Scan results

**Example:**
```python
result = client.scan_sbom("my-app-sbom.json", only_fixed=True)
```

##### scan_directory()

Scan a local directory for vulnerabilities.

```python
result = client.scan_directory(
    directory_path="./my-project",
    severity=None
)
```

**Parameters:**
- `directory_path` (str): Path to directory to scan
- `severity` (Optional[GrypeSeverity]): Minimum severity level

**Returns:**
- `GrypeScanResult`: Scan results

##### update_database()

Update Grype's vulnerability database.

```python
success = client.update_database()
```

**Returns:**
- `bool`: True if update successful

---

### SyftClient

Client for Syft SBOM generator.

#### Constructor

```python
from threat_radar.core import SyftClient

client = SyftClient(syft_path=None)
```

**Parameters:**
- `syft_path` (Optional[str]): Custom path to syft binary

#### Methods

##### generate_sbom()

Generate SBOM from a source.

```python
sbom = client.generate_sbom(
    source="docker:alpine:3.18",
    output_format=SBOMFormat.CYCLONEDX_JSON
)
```

**Parameters:**
- `source` (str): Source to scan (docker:image, dir:path, file:path)
- `output_format` (SBOMFormat): Output format (CYCLONEDX_JSON, SPDX_JSON, SYFT_JSON)

**Returns:**
- `Dict[str, Any]`: Parsed SBOM as dictionary

**Example:**
```python
from threat_radar.core import SyftClient, SBOMFormat

client = SyftClient()

# Generate SBOM from Docker image
sbom = client.generate_sbom(
    "docker:python:3.11",
    output_format=SBOMFormat.CYCLONEDX_JSON
)

# Save to file
import json
with open("sbom.json", "w") as f:
    json.dump(sbom, f, indent=2)
```

---

### ContainerAnalyzer

Analyzes Docker containers and extracts package information.

#### Constructor

```python
from threat_radar.core import ContainerAnalyzer

analyzer = ContainerAnalyzer(syft_client=None)
```

**Parameters:**
- `syft_client` (Optional[SyftClient]): SyftClient instance for SBOM-based analysis

#### Methods

##### import_container()

Import and analyze a container image from registry.

```python
analysis = analyzer.import_container(
    image_name="ubuntu",
    tag="22.04"
)
```

**Parameters:**
- `image_name` (str): Name of the image
- `tag` (str): Image tag (default: "latest")

**Returns:**
- `ContainerAnalysis`: Analysis results

##### analyze_container()

Analyze an existing local container image.

```python
analysis = analyzer.analyze_container(image_name="alpine:3.18")
```

**Parameters:**
- `image_name` (str): Name or ID of local image

**Returns:**
- `ContainerAnalysis`: Analysis results with packages, distro info, etc.

**Example:**
```python
from threat_radar.core import ContainerAnalyzer

analyzer = ContainerAnalyzer()
analysis = analyzer.analyze_container("python:3.11-slim")

print(f"Distribution: {analysis.distro} {analysis.distro_version}")
print(f"Packages: {len(analysis.packages)}")
for pkg in analysis.packages[:5]:
    print(f"  - {pkg.name} {pkg.version}")
```

---

## AI Analysis APIs

### VulnerabilityAnalyzer

AI-powered vulnerability analysis engine.

#### Constructor

```python
from threat_radar.ai import VulnerabilityAnalyzer

analyzer = VulnerabilityAnalyzer(
    llm_client=None,
    provider="openai",
    model="gpt-4o",
    batch_size=25,
    auto_batch_threshold=30
)
```

**Parameters:**
- `llm_client` (Optional[LLMClient]): Pre-configured LLM client
- `provider` (Optional[str]): AI provider ("openai", "anthropic", "ollama")
- `model` (Optional[str]): Model name (e.g., "gpt-4o", "claude-3-5-sonnet-20241022")
- `batch_size` (int): Vulnerabilities per batch (default: 25)
- `auto_batch_threshold` (int): Auto-batch when count exceeds this (default: 30)

#### Methods

##### analyze_scan_result()

Analyze Grype scan results with AI.

```python
analysis = analyzer.analyze_scan_result(
    scan_result,
    temperature=0.3,
    batch_mode="auto",
    progress_callback=None
)
```

**Parameters:**
- `scan_result` (GrypeScanResult): Scan results from Grype
- `temperature` (float): LLM temperature (0.0-1.0, lower = more consistent)
- `batch_mode` (str): "auto", "enabled", or "disabled"
- `progress_callback` (Optional[Callable]): Progress callback function

**Returns:**
- `VulnerabilityAnalysis`: AI analysis with insights

**Example:**
```python
from threat_radar import GrypeClient, VulnerabilityAnalyzer

# Scan image
grype = GrypeClient()
scan_result = grype.scan_image("alpine:3.18")

# Analyze with AI
analyzer = VulnerabilityAnalyzer(provider="openai", model="gpt-4o")
analysis = analyzer.analyze_scan_result(scan_result)

# Print insights
print(f"Summary: {analysis.summary}")
for insight in analysis.vulnerabilities[:5]:
    print(f"\nCVE: {insight.cve_id}")
    print(f"Exploitability: {insight.exploitability}")
    print(f"Impact: {insight.business_impact}")
    print(f"Recommendations: {', '.join(insight.recommendations)}")
```

---

### PrioritizationEngine

Generate prioritized vulnerability lists.

#### Constructor

```python
from threat_radar.ai import PrioritizationEngine

engine = PrioritizationEngine(
    llm_client=None,
    provider="openai",
    model="gpt-4o"
)
```

#### Methods

##### prioritize_vulnerabilities()

Generate prioritized vulnerability list.

```python
prioritized = engine.prioritize_vulnerabilities(
    scan_result,
    top_n=None,
    temperature=0.3
)
```

**Parameters:**
- `scan_result` (GrypeScanResult): Scan results
- `top_n` (Optional[int]): Limit to top N vulnerabilities
- `temperature` (float): LLM temperature

**Returns:**
- `PrioritizedVulnerabilityList`: Prioritized list with urgency scores

**Example:**
```python
from threat_radar.ai import PrioritizationEngine

engine = PrioritizationEngine()
prioritized = engine.prioritize_vulnerabilities(scan_result, top_n=10)

for vuln in prioritized.vulnerabilities[:10]:
    print(f"{vuln.cve_id}: Urgency {vuln.urgency_score}/100 - {vuln.rationale}")
```

---

### RemediationGenerator

Generate remediation plans.

#### Constructor

```python
from threat_radar.ai import RemediationGenerator

generator = RemediationGenerator(
    llm_client=None,
    provider="openai",
    model="gpt-4o"
)
```

#### Methods

##### generate_remediation_plan()

Create actionable remediation plan.

```python
plan = generator.generate_remediation_plan(
    scan_result,
    include_commands=True,
    temperature=0.3
)
```

**Parameters:**
- `scan_result` (GrypeScanResult): Scan results
- `include_commands` (bool): Include upgrade commands
- `temperature` (float): LLM temperature

**Returns:**
- `RemediationReport`: Remediation plan with actions

**Example:**
```python
from threat_radar.ai import RemediationGenerator

generator = RemediationGenerator()
plan = generator.generate_remediation_plan(scan_result)

print(f"Immediate Actions: {len(plan.immediate_actions)}")
for action in plan.immediate_actions[:3]:
    print(f"  - {action}")

for group in plan.package_groups[:5]:
    print(f"\nPackage: {group.package_name}")
    print(f"Upgrade: {group.current_version} -> {group.target_version}")
    print(f"Command: {group.upgrade_command}")
```

---

## Reporting APIs

### ComprehensiveReportGenerator

Generate comprehensive vulnerability reports.

#### Constructor

```python
from threat_radar.utils import ComprehensiveReportGenerator

generator = ComprehensiveReportGenerator(
    llm_client=None,
    ai_provider="openai",
    ai_model="gpt-4o"
)
```

#### Methods

##### generate_report()

Generate comprehensive report from scan results.

```python
report = generator.generate_report(
    scan_result,
    report_level="detailed",
    include_executive_summary=True,
    include_dashboard_data=True
)
```

**Parameters:**
- `scan_result` (GrypeScanResult): Scan results
- `report_level` (str): "executive", "summary", "detailed", "critical-only"
- `include_executive_summary` (bool): Include AI executive summary
- `include_dashboard_data` (bool): Include dashboard visualization data

**Returns:**
- `ComprehensiveReport`: Complete report object

**Example:**
```python
from threat_radar.utils import ComprehensiveReportGenerator
from threat_radar.utils.report_formatters import HTMLFormatter

# Generate report
generator = ComprehensiveReportGenerator()
report = generator.generate_report(scan_result, report_level="detailed")

# Export to HTML
formatter = HTMLFormatter()
html = formatter.format(report)

with open("report.html", "w") as f:
    f.write(html)
```

---

## Data Models

### GrypeScanResult

Results of a vulnerability scan.

```python
@dataclass
class GrypeScanResult:
    target: str                              # Scan target
    vulnerabilities: List[GrypeVulnerability]  # Found vulnerabilities
    total_count: int                         # Total vulnerability count
    severity_counts: Dict[str, int]          # Count by severity
    scan_metadata: Optional[Dict]            # Scan metadata
```

**Methods:**
- `filter_by_severity(min_severity: GrypeSeverity) -> GrypeScanResult`
- `to_dict() -> Dict[str, Any]`

---

### GrypeVulnerability

Individual vulnerability details.

```python
@dataclass
class GrypeVulnerability:
    id: str                          # CVE ID
    severity: str                    # Severity level
    package_name: str                # Affected package
    package_version: str             # Package version
    package_type: str                # Package ecosystem
    fixed_in_version: Optional[str]  # Fix version if available
    description: Optional[str]       # Vulnerability description
    cvss_score: Optional[float]      # CVSS score
    urls: List[str]                  # Reference URLs
```

---

### VulnerabilityAnalysis

AI analysis results.

```python
@dataclass
class VulnerabilityAnalysis:
    vulnerabilities: List[VulnerabilityInsight]  # Per-CVE insights
    summary: str                                 # Overall summary
    metadata: Dict[str, Any]                     # Analysis metadata
```

**Methods:**
- `to_dict() -> Dict[str, Any]`

---

### VulnerabilityInsight

AI insight for a single vulnerability.

```python
@dataclass
class VulnerabilityInsight:
    cve_id: str                          # CVE identifier
    package_name: str                    # Affected package
    exploitability: str                  # HIGH, MEDIUM, LOW
    exploitability_details: str          # Detailed assessment
    attack_vectors: List[str]            # Possible attack vectors
    business_impact: str                 # HIGH, MEDIUM, LOW
    business_impact_details: str         # Impact explanation
    recommendations: List[str]           # Remediation recommendations
```

---

## Examples

### Complete Analysis Workflow

```python
from threat_radar import (
    GrypeClient,
    VulnerabilityAnalyzer,
    PrioritizationEngine,
    RemediationGenerator,
    ComprehensiveReportGenerator
)
import json

# 1. Scan for vulnerabilities
print("Scanning image...")
grype = GrypeClient()
scan_result = grype.scan_image("python:3.11-slim")
print(f"Found {scan_result.total_count} vulnerabilities")

# 2. Analyze with AI
print("\nAnalyzing with AI...")
analyzer = VulnerabilityAnalyzer()
analysis = analyzer.analyze_scan_result(scan_result)
print(f"Summary: {analysis.summary}")

# 3. Prioritize vulnerabilities
print("\nPrioritizing...")
priority_engine = PrioritizationEngine()
prioritized = priority_engine.prioritize_vulnerabilities(scan_result, top_n=10)

print("\nTop 10 priorities:")
for i, vuln in enumerate(prioritized.vulnerabilities[:10], 1):
    print(f"{i}. {vuln.cve_id} (Urgency: {vuln.urgency_score}/100)")

# 4. Generate remediation plan
print("\nGenerating remediation plan...")
remediation_gen = RemediationGenerator()
remediation = remediation_gen.generate_remediation_plan(scan_result)

print(f"\nImmediate actions: {len(remediation.immediate_actions)}")
for action in remediation.immediate_actions[:3]:
    print(f"  - {action}")

# 5. Create comprehensive report
print("\nGenerating report...")
report_gen = ComprehensiveReportGenerator()
report = report_gen.generate_report(
    scan_result,
    report_level="detailed",
    include_executive_summary=True
)

# 6. Save results
with open("analysis_results.json", "w") as f:
    json.dump({
        "scan": scan_result.to_dict(),
        "analysis": analysis.to_dict(),
        "prioritization": prioritized.to_dict(),
        "remediation": remediation.to_dict(),
        "report": report.to_dict()
    }, f, indent=2)

print("\nAnalysis complete! Results saved to analysis_results.json")
```

### Batch Scanning Multiple Images

```python
from threat_radar import GrypeClient
import concurrent.futures

images = [
    "alpine:3.18",
    "python:3.11-slim",
    "node:18-alpine",
    "nginx:alpine",
]

def scan_image(image_name):
    client = GrypeClient()
    result = client.scan_image(image_name)
    return {
        "image": image_name,
        "total": result.total_count,
        "critical": result.severity_counts.get("critical", 0),
        "high": result.severity_counts.get("high", 0),
    }

# Scan in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(scan_image, images))

# Print summary
for result in results:
    print(f"{result['image']}: {result['total']} total "
          f"({result['critical']} critical, {result['high']} high)")
```

### Custom Progress Tracking

```python
from threat_radar import VulnerabilityAnalyzer, GrypeClient

def progress_callback(batch_num, total_batches, analyzed_count):
    print(f"Processing batch {batch_num}/{total_batches} "
          f"({analyzed_count} vulnerabilities analyzed)")

# Scan and analyze with progress tracking
grype = GrypeClient()
scan_result = grype.scan_image("ubuntu:22.04")

analyzer = VulnerabilityAnalyzer()
analysis = analyzer.analyze_scan_result(
    scan_result,
    batch_mode="enabled",
    progress_callback=progress_callback
)

print(f"\nAnalysis complete: {len(analysis.vulnerabilities)} insights generated")
```

---

## Error Handling

### Common Exceptions

```python
from threat_radar import GrypeClient
from threat_radar.core.grype_integration import GrypeError

try:
    client = GrypeClient()
    result = client.scan_image("nonexistent:image")
except RuntimeError as e:
    print(f"Grype error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Retry Logic

```python
from tenacity import retry, stop_after_attempt, wait_exponential
from threat_radar import VulnerabilityAnalyzer

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
def analyze_with_retry(scan_result):
    analyzer = VulnerabilityAnalyzer()
    return analyzer.analyze_scan_result(scan_result)

# Use with automatic retry on failures
try:
    analysis = analyze_with_retry(scan_result)
except Exception as e:
    print(f"Analysis failed after retries: {e}")
```

---

## Additional Resources

- **CLI Reference:** See `CLAUDE.md`
- **Installation Guide:** See `INSTALLATION.md`
- **Examples:** See `examples/` directory
- **Source Code:** https://github.com/yourusername/threat-radar

---

**Need help?** Open an issue: https://github.com/yourusername/threat-radar/issues
