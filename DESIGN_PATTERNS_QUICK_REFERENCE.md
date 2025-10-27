# Threat Radar Design Patterns - Quick Reference
## For Midterm Presentation

### Design Patterns Used

| Pattern | Location | Purpose | Example |
|---------|----------|---------|---------|
| **Factory** | `core/package_extractors.py` | Create appropriate package extractor for each distro (APT, APK, YUM) | `PackageExtractorFactory.get_extractor('ubuntu')` |
| **Factory** | `ai/llm_client.py` | Create LLM clients (OpenAI, Anthropic, Ollama) based on config | `get_llm_client(provider='openai')` |
| **Strategy** | `utils/report_formatters.py` | Select report format at runtime (JSON, Markdown, HTML) | `JSONFormatter().format(report)` |
| **Strategy** | `core/package_extractors.py` | Different parsing strategy for each Linux distro | `APKExtractor` vs `APTExtractor` |
| **Adapter** | `core/docker_integration.py` | Wrap Docker SDK with error handling | `DockerClient.pull_image()` |
| **Adapter** | `core/grype_integration.py` | Wrap Grype CLI with Python API | `GrypeClient.scan_docker_image()` |
| **Adapter** | `core/syft_integration.py` | Wrap Syft CLI with Python API | `SyftClient.scan()` |
| **Singleton** | `utils/config_manager.py` | Single global config instance | `get_config_manager()` |
| **Singleton** | `utils/cli_context.py` | Single global CLI context | `get_cli_context()` |
| **Builder** | `utils/comprehensive_report.py` | Build complex report through steps | `ComprehensiveReportGenerator.generate_report()` |
| **Bridge** | `ai/vulnerability_analyzer.py` | Separate abstraction from LLM implementations | `VulnerabilityAnalyzer(llm_client)` |
| **Data Class** | `core/grype_integration.py` | Type-safe domain models | `@dataclass GrypeScanResult` |

---

### Architecture Overview

```
CLI Commands (Typer)
    ↓
CLIContext (Global State)
    ↓
Core Logic & Integration Layer
    ├── Docker (DockerClient wrapper)
    ├── Grype (GrypeClient wrapper)
    ├── Syft (SyftClient wrapper)
    ├── AI (LLMClient abstraction)
    ├── Reporting (Builder pattern)
    └── Storage (Persistence)
    ↓
External Systems (Docker, Grype, Syft, LLMs, GitHub)
```

---

### Key Files to Examine

#### Essential Pattern Examples:

1. **Factory Pattern (2 examples)**
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/package_extractors.py` (lines 147-196)
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/ai/llm_client.py` (lines 453-491)

2. **Strategy Pattern (2 examples)**
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/utils/report_formatters.py` (lines 9-30)
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/package_extractors.py` (lines 35-145)

3. **Adapter Pattern (3 examples)**
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/docker_integration.py` (entire file)
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/grype_integration.py` (lines 106-180)
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/syft_integration.py` (lines 47-140)

4. **Singleton Pattern (2 examples)**
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/utils/config_manager.py` (lines 240-260)
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/utils/cli_context.py` (lines 109-128)

5. **Builder Pattern**
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/utils/comprehensive_report.py` (lines 39-106)

6. **Domain Models (Dataclasses)**
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/package_extractors.py` (lines 10-17)
   - `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/grype_integration.py` (lines 31-71)

---

### Core Architectural Principles

1. **Layered Architecture**
   - Clear separation: CLI → Context → Business Logic → External Systems
   - Dependencies flow inward only

2. **Dependency Injection**
   - Constructor injection (e.g., `VulnerabilityAnalyzer(llm_client)`)
   - Factory functions for complex creation (e.g., `get_llm_client()`)

3. **Abstraction Over Implementation**
   - LLMClient ABC with 3 implementations
   - PackageExtractor ABC with 3 implementations
   - ReportFormatter ABC with 3 implementations

4. **Configuration Management**
   - Hierarchical: Defaults → Files → Environment → CLI
   - Dot-notation access (e.g., `config.get('scan.severity')`)
   - Single global instance via singleton

5. **Error Handling**
   - Exception translation in adapters
   - Retry logic with exponential backoff
   - Context managers for resource cleanup

6. **Domain-Driven Design**
   - Rich domain models with behavior
   - Type-safe dataclasses
   - Value objects for immutability

---

### CLI Command Structure (Typer Framework)

```python
# App setup with global options callback
app = typer.Typer()

@app.callback()  # Global options parsed here
def main_callback(
    config_file: Optional[Path],
    verbosity: int,
    quiet: bool,
    output_format: str,
    no_color: bool,
    no_progress: bool,
):
    context = CLIContext.create(...)
    set_cli_context(context)

# Sub-commands
@cve_app.command("scan-image")
def scan_docker_image(
    image: str,
    severity: Optional[str],
):
    ctx = get_cli_context()
    # Command logic...
```

**Key Pattern:** Typer callback creates and stores global context, commands access it via singleton getter.

---

### Configuration Precedence

```
┌─ Defaults (hardcoded in dataclasses)
├─ Configuration file (.threat-radar.json, ~/.threat-radar/config.json)
├─ Environment variables (THREAT_RADAR_SEVERITY, AI_PROVIDER)
└─ Command-line arguments (highest priority)
```

---

### Testing Approach

1. **Dependency Injection for Testability**
   ```python
   # Production
   analyzer = VulnerabilityAnalyzer()  # Creates real LLM client
   
   # Testing
   mock_client = MockLLMClient()
   analyzer = VulnerabilityAnalyzer(llm_client=mock_client)
   ```

2. **Reset Singletons**
   ```python
   reset_config_manager()
   reset_cli_context()
   ```

3. **Fixtures**
   - Tests use fixtures directory: `tests/fixtures/`
   - Grype outputs, SBOM samples, config files

---

### Data Flow Example: CVE Scanning

```
1. CLI Command (scan-image)
   ├─ Get global CLIContext
   ├─ Initialize GrypeClient (adapter)
   └─ Scan Docker image

2. GrypeClient (adapter wrapper)
   ├─ Build CLI command
   ├─ Execute subprocess
   ├─ Parse JSON output
   └─ Convert to GrypeScanResult (dataclass)

3. Result Processing
   ├─ Filter by severity (strategy on dataclass)
   ├─ Save to storage
   └─ Format output (strategy)

4. Output
   ├─ Table format (CLI)
   ├─ JSON format (machine-readable)
   ├─ Markdown format (documentation)
   └─ HTML format (reports)
```

---

### Key Takeaways for Presentation

1. **Design patterns enable flexibility**
   - Add new AI providers → Just add new LLMClient
   - Add new distros → Just add new Extractor
   - Add new formats → Just add new Formatter

2. **Abstraction creates resilience**
   - Tool versions change → Adapter hides changes
   - APIs change → Abstract interface adapts

3. **Separation of concerns enables testing**
   - Mock external dependencies
   - Test business logic independently
   - Integration tests separate from unit tests

4. **Configuration-driven design**
   - Users control behavior via config files
   - No code changes needed for different configurations
   - Environment variables override config files

5. **Rich domain models encode business logic**
   - Not just data containers
   - Contain behavior (filter_by_severity)
   - Encapsulate validation

---

### Recommended Presentation Order

1. **Start:** Architecture overview diagram
2. **Pattern 1:** Factory (package extractors)
   - Show distro-specific parsing challenges
   - How factory creates appropriate extractor
   
3. **Pattern 2:** Strategy (report formatters)
   - Show format selection at runtime
   - How strategies eliminate if/else chains
   
4. **Pattern 3:** Adapter (Docker/Grype/Syft wrappers)
   - Why wrap external tools
   - Error handling and translation
   - Simplifying client code
   
5. **Pattern 4:** Singleton (configuration)
   - Global state management
   - Lazy initialization
   - Testing implications
   
6. **Pattern 5:** Builder (report generation)
   - Complex object construction
   - Step-by-step assembly
   
7. **Integration:** Show how patterns work together
   - CLI command → Context → Core logic → Adapters → External systems
   
8. **Principles:** SOLID, DRY, YAGNI adherence

