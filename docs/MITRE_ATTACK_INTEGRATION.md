# MITRE ATT&CK Framework Integration

## Overview

Integrating MITRE ATT&CK provides context about how vulnerabilities can be exploited using real-world adversary tactics, techniques, and procedures (TTPs).

## Integration Points

### 1. CVE to ATT&CK Mapping

Map CVEs to MITRE ATT&CK techniques based on vulnerability characteristics.

**Example Mappings**:

| CVE Type | ATT&CK Technique | Tactic |
|----------|------------------|--------|
| RCE (Remote Code Execution) | T1059 - Command and Scripting Interpreter | Execution |
| SQL Injection | T1190 - Exploit Public-Facing Application | Initial Access |
| Privilege Escalation | T1068 - Exploitation for Privilege Escalation | Privilege Escalation |
| Path Traversal | T1083 - File and Directory Discovery | Discovery |
| XSS | T1189 - Drive-by Compromise | Initial Access |
| Authentication Bypass | T1078 - Valid Accounts | Persistence |

### 2. Attack Path Analysis Enhancement

Enhance attack paths with MITRE ATT&CK tactics for each step:

**Current Attack Path**:
```json
{
  "path_id": "path_001",
  "steps": [
    {
      "type": "ENTRY_POINT",
      "asset": "asset-frontend",
      "vulnerabilities": ["CVE-2023-1234"]
    }
  ]
}
```

**Enhanced with ATT&CK**:
```json
{
  "path_id": "path_001",
  "steps": [
    {
      "type": "ENTRY_POINT",
      "asset": "asset-frontend",
      "vulnerabilities": ["CVE-2023-1234"],
      "mitre_attack": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploiting weakness in internet-facing application",
        "sub_techniques": ["T1190.001"]
      }
    },
    {
      "type": "EXPLOIT_VULNERABILITY",
      "asset": "asset-api",
      "vulnerabilities": ["CVE-2023-5678"],
      "mitre_attack": {
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "description": "Executing commands via shell injection vulnerability"
      }
    },
    {
      "type": "PRIVILEGE_ESCALATION",
      "asset": "asset-database",
      "vulnerabilities": ["CVE-2023-9999"],
      "mitre_attack": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Escalating privileges via kernel vulnerability"
      }
    }
  ],
  "attack_chain": {
    "tactics_used": ["Initial Access", "Execution", "Privilege Escalation"],
    "techniques_count": 3,
    "kill_chain_phase": "Exploitation"
  }
}
```

### 3. Vulnerability Categorization

Automatically categorize vulnerabilities by ATT&CK technique:

```python
# threat_radar/mitre/classifier.py

CVE_TO_ATTACK_PATTERNS = {
    # Execution techniques
    "command_injection": "T1059",
    "code_injection": "T1055",

    # Initial Access
    "exploit_public_facing": "T1190",
    "phishing": "T1566",

    # Privilege Escalation
    "privilege_escalation": "T1068",
    "sudo_vulnerability": "T1548.003",

    # Defense Evasion
    "obfuscation": "T1027",
    "rootkit": "T1014",

    # Credential Access
    "credential_dumping": "T1003",
    "brute_force": "T1110",

    # Discovery
    "network_discovery": "T1046",
    "file_discovery": "T1083",

    # Lateral Movement
    "remote_services": "T1021",
    "ssh_hijacking": "T1563.001",

    # Collection
    "data_staged": "T1074",

    # Exfiltration
    "data_transfer": "T1041",
}
```

## Implementation Architecture

### Data Models

```python
# threat_radar/mitre/models.py
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class MitreAttackTechnique:
    """MITRE ATT&CK technique information."""
    technique_id: str  # e.g., "T1190"
    technique_name: str
    tactic: str  # e.g., "Initial Access"
    description: str
    sub_techniques: List[str] = None
    mitigation_id: Optional[str] = None
    detection_id: Optional[str] = None

@dataclass
class AttackChain:
    """Complete attack chain with MITRE mapping."""
    tactics_used: List[str]
    techniques: List[MitreAttackTechnique]
    kill_chain_phase: str
    complexity: str  # "Low", "Medium", "High"

@dataclass
class EnrichedVulnerability:
    """Vulnerability with MITRE ATT&CK context."""
    cve_id: str
    severity: str
    cvss_score: float
    mitre_techniques: List[MitreAttackTechnique]
    attack_potential: str  # "High", "Medium", "Low"
    real_world_usage: bool  # Is this technique seen in the wild?
```

### CVE to ATT&CK Mapper

```python
# threat_radar/mitre/mapper.py
from typing import List, Dict
import json
from pathlib import Path

class MitreAttackMapper:
    """Maps CVEs to MITRE ATT&CK techniques."""

    def __init__(self, attack_data_path: Optional[str] = None):
        """
        Initialize with MITRE ATT&CK data.

        Args:
            attack_data_path: Path to MITRE ATT&CK STIX data
                             Download from: https://github.com/mitre/cti
        """
        self.attack_data = self._load_attack_data(attack_data_path)
        self.cve_patterns = self._load_cve_patterns()

    def map_cve_to_techniques(
        self,
        cve_id: str,
        description: str,
        cwe_ids: List[str] = None
    ) -> List[MitreAttackTechnique]:
        """
        Map a CVE to relevant ATT&CK techniques.

        Args:
            cve_id: CVE identifier
            description: CVE description
            cwe_ids: Common Weakness Enumeration IDs

        Returns:
            List of applicable MITRE ATT&CK techniques
        """
        techniques = []

        # 1. Check CVE database for known mappings
        if cve_id in self.known_mappings:
            techniques.extend(self.known_mappings[cve_id])

        # 2. Use CWE to ATT&CK mappings
        if cwe_ids:
            for cwe in cwe_ids:
                techniques.extend(self._map_cwe_to_attack(cwe))

        # 3. Pattern matching on description
        techniques.extend(self._pattern_match(description))

        # 4. ML-based classification (future enhancement)
        # techniques.extend(self._ml_classify(description))

        return list(set(techniques))  # Remove duplicates

    def _pattern_match(self, description: str) -> List[MitreAttackTechnique]:
        """Match vulnerability description to ATT&CK techniques."""
        techniques = []
        desc_lower = description.lower()

        # Remote Code Execution
        if any(term in desc_lower for term in ['remote code execution', 'rce', 'command injection']):
            techniques.append(MitreAttackTechnique(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactic="Execution",
                description="Adversaries may abuse command interpreters to execute commands"
            ))

        # SQL Injection
        if 'sql injection' in desc_lower:
            techniques.append(MitreAttackTechnique(
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic="Initial Access",
                description="SQL injection in public-facing application"
            ))

        # Privilege Escalation
        if any(term in desc_lower for term in ['privilege escalation', 'privilege elevation']):
            techniques.append(MitreAttackTechnique(
                technique_id="T1068",
                technique_name="Exploitation for Privilege Escalation",
                tactic="Privilege Escalation",
                description="Exploitation of software vulnerability to gain elevated access"
            ))

        # Path Traversal
        if any(term in desc_lower for term in ['path traversal', 'directory traversal']):
            techniques.append(MitreAttackTechnique(
                technique_id="T1083",
                technique_name="File and Directory Discovery",
                tactic="Discovery",
                description="Adversaries may enumerate files and directories"
            ))

        # Authentication Bypass
        if any(term in desc_lower for term in ['authentication bypass', 'auth bypass']):
            techniques.append(MitreAttackTechnique(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Persistence",
                description="Adversaries may obtain credentials to maintain access"
            ))

        return techniques

    def _map_cwe_to_attack(self, cwe_id: str) -> List[MitreAttackTechnique]:
        """Map CWE to MITRE ATT&CK techniques."""
        cwe_mapping = {
            "CWE-78": ["T1059"],  # OS Command Injection
            "CWE-89": ["T1190"],  # SQL Injection
            "CWE-79": ["T1189"],  # XSS
            "CWE-287": ["T1078"], # Authentication
            "CWE-264": ["T1068"], # Privilege Escalation
            "CWE-22": ["T1083"],  # Path Traversal
            "CWE-352": ["T1189"], # CSRF
            "CWE-94": ["T1059"],  # Code Injection
        }

        technique_ids = cwe_mapping.get(cwe_id, [])
        return [self._get_technique_details(tid) for tid in technique_ids]

    def enrich_attack_paths(
        self,
        attack_paths: List[Dict]
    ) -> List[Dict]:
        """
        Enrich attack paths with MITRE ATT&CK techniques.

        Args:
            attack_paths: List of attack path dictionaries

        Returns:
            Attack paths with MITRE ATT&CK mappings
        """
        enriched_paths = []

        for path in attack_paths:
            enriched_path = path.copy()
            enriched_steps = []

            for step in path.get('steps', []):
                enriched_step = step.copy()

                # Map vulnerabilities to techniques
                if 'vulnerabilities' in step:
                    techniques = []
                    for cve in step['vulnerabilities']:
                        # Get CVE details (from scan results)
                        cve_info = self._get_cve_info(cve)
                        techniques.extend(
                            self.map_cve_to_techniques(
                                cve,
                                cve_info.get('description', ''),
                                cve_info.get('cwe_ids', [])
                            )
                        )

                    # Add primary technique for this step
                    if techniques:
                        enriched_step['mitre_attack'] = {
                            'technique_id': techniques[0].technique_id,
                            'technique_name': techniques[0].technique_name,
                            'tactic': techniques[0].tactic,
                            'description': techniques[0].description,
                            'all_techniques': [t.technique_id for t in techniques]
                        }

                enriched_steps.append(enriched_step)

            enriched_path['steps'] = enriched_steps

            # Add attack chain summary
            all_tactics = [
                step['mitre_attack']['tactic']
                for step in enriched_steps
                if 'mitre_attack' in step
            ]

            enriched_path['attack_chain'] = {
                'tactics_used': list(set(all_tactics)),
                'techniques_count': len(enriched_steps),
                'kill_chain_phase': self._determine_kill_chain_phase(all_tactics)
            }

            enriched_paths.append(enriched_path)

        return enriched_paths
```

### CLI Integration

```python
# threat_radar/cli/mitre.py
import typer
from typing import Optional
from pathlib import Path

app = typer.Typer(help="MITRE ATT&CK framework integration")

@app.command("map-cves")
def map_cves(
    scan_file: Path = typer.Argument(..., help="CVE scan results file"),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file"),
    format: str = typer.Option("json", "-f", "--format", help="Output format (json, markdown)"),
):
    """Map CVEs to MITRE ATT&CK techniques."""
    from threat_radar.mitre import MitreAttackMapper
    from threat_radar.core.grype_integration import GrypeScanResult

    # Load scan results
    scan_result = GrypeScanResult.from_file(scan_file)

    # Map to ATT&CK
    mapper = MitreAttackMapper()
    enriched_vulns = []

    for vuln in scan_result.vulnerabilities:
        techniques = mapper.map_cve_to_techniques(
            vuln.cve_id,
            vuln.description,
            vuln.cwe_ids
        )

        enriched_vulns.append({
            'cve_id': vuln.cve_id,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'package': vuln.package_name,
            'mitre_techniques': [
                {
                    'id': t.technique_id,
                    'name': t.technique_name,
                    'tactic': t.tactic
                }
                for t in techniques
            ]
        })

    # Output results
    if format == "markdown":
        output_markdown(enriched_vulns, output)
    else:
        output_json(enriched_vulns, output)

@app.command("enrich-attack-paths")
def enrich_attack_paths(
    attack_paths_file: Path = typer.Argument(..., help="Attack paths JSON file"),
    scan_file: Path = typer.Argument(..., help="CVE scan results file"),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file"),
):
    """Enrich attack paths with MITRE ATT&CK techniques."""
    import json
    from threat_radar.mitre import MitreAttackMapper

    # Load attack paths and scan results
    with open(attack_paths_file) as f:
        attack_paths = json.load(f)

    # Enrich with MITRE
    mapper = MitreAttackMapper()
    enriched_paths = mapper.enrich_attack_paths(
        attack_paths.get('attack_paths', [])
    )

    # Save results
    result = {
        'attack_paths': enriched_paths,
        'mitre_summary': {
            'total_techniques': len(set(
                step['mitre_attack']['technique_id']
                for path in enriched_paths
                for step in path['steps']
                if 'mitre_attack' in step
            )),
            'tactics_coverage': list(set(
                step['mitre_attack']['tactic']
                for path in enriched_paths
                for step in path['steps']
                if 'mitre_attack' in step
            ))
        }
    }

    if output:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2)
    else:
        print(json.dumps(result, indent=2))

@app.command("attack-matrix")
def attack_matrix(
    scan_file: Path = typer.Argument(..., help="CVE scan results file"),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output HTML file"),
):
    """Generate MITRE ATT&CK matrix visualization."""
    from threat_radar.mitre import MitreAttackMapper, AttackMatrixGenerator
    from threat_radar.core.grype_integration import GrypeScanResult

    # Load and map
    scan_result = GrypeScanResult.from_file(scan_file)
    mapper = MitreAttackMapper()

    # Generate matrix
    generator = AttackMatrixGenerator()
    html = generator.generate_matrix_html(scan_result, mapper)

    if output:
        with open(output, 'w') as f:
            f.write(html)
        typer.echo(f"Matrix saved to: {output}")
    else:
        print(html)
```

## Usage Examples

### 1. Map CVEs to ATT&CK Techniques

```bash
# Map vulnerabilities to MITRE techniques
threat-radar mitre map-cves scan-results.json -o mitre-mapping.json

# Generate markdown report
threat-radar mitre map-cves scan-results.json -f markdown -o mitre-report.md
```

**Output** (mitre-mapping.json):
```json
[
  {
    "cve_id": "CVE-2023-1234",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "package": "openssl@1.1.1",
    "mitre_techniques": [
      {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution"
      },
      {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access"
      }
    ]
  }
]
```

### 2. Enrich Attack Paths

```bash
# Add MITRE context to attack paths
threat-radar mitre enrich-attack-paths \
  attack-paths.json \
  scan-results.json \
  -o attack-paths-mitre.json
```

**Output** (attack-paths-mitre.json):
```json
{
  "attack_paths": [
    {
      "path_id": "path_001",
      "threat_level": "critical",
      "steps": [
        {
          "step_number": 1,
          "type": "ENTRY_POINT",
          "asset": "asset-frontend",
          "vulnerabilities": ["CVE-2023-1234"],
          "mitre_attack": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "Exploiting weakness in internet-facing web application",
            "all_techniques": ["T1190", "T1059"]
          }
        }
      ],
      "attack_chain": {
        "tactics_used": ["Initial Access", "Execution", "Privilege Escalation"],
        "techniques_count": 5,
        "kill_chain_phase": "Exploitation"
      }
    }
  ],
  "mitre_summary": {
    "total_techniques": 12,
    "tactics_coverage": [
      "Initial Access",
      "Execution",
      "Privilege Escalation",
      "Discovery"
    ]
  }
}
```

### 3. Generate ATT&CK Matrix Visualization

```bash
# Create visual matrix showing which techniques apply
threat-radar mitre attack-matrix scan-results.json -o attack-matrix.html
```

Opens an HTML visualization showing:
- Which ATT&CK tactics are relevant
- Technique coverage
- Heat map of vulnerability concentration

### 4. Complete Workflow with MITRE

```bash
#!/bin/bash
# Complete security analysis with MITRE ATT&CK

IMAGE="myapp:production"

# 1. Scan for vulnerabilities
threat-radar cve scan-image $IMAGE -o scan.json

# 2. Map to MITRE ATT&CK
threat-radar mitre map-cves scan.json -o mitre-mapping.json

# 3. Build graph
threat-radar graph build scan.json -o graph.graphml

# 4. Find attack paths
threat-radar graph attack-paths graph.graphml -o attack-paths.json

# 5. Enrich attack paths with MITRE
threat-radar mitre enrich-attack-paths \
  attack-paths.json \
  scan.json \
  -o attack-paths-mitre.json

# 6. Generate ATT&CK matrix
threat-radar mitre attack-matrix scan.json -o attack-matrix.html

# 7. Generate report with MITRE context
threat-radar report generate scan.json \
  --attack-paths attack-paths-mitre.json \
  -o comprehensive-report.html

echo "✅ Complete MITRE ATT&CK analysis ready!"
echo "   - MITRE Mapping: mitre-mapping.json"
echo "   - Attack Paths: attack-paths-mitre.json"
echo "   - ATT&CK Matrix: attack-matrix.html"
echo "   - Full Report: comprehensive-report.html"
```

## Integration with Existing Features

### Enhanced Reports

Update comprehensive reports to include MITRE context:

```python
# In threat_radar/utils/comprehensive_report.py

def _generate_executive_summary_with_mitre(
    self,
    report: ComprehensiveReport,
    mitre_techniques: List[MitreAttackTechnique]
) -> ExecutiveSummary:
    """Generate executive summary with MITRE ATT&CK context."""

    # Group techniques by tactic
    tactics = {}
    for technique in mitre_techniques:
        if technique.tactic not in tactics:
            tactics[technique.tactic] = []
        tactics[technique.tactic].append(technique)

    # Add to key findings
    mitre_findings = [
        f"Vulnerabilities map to {len(mitre_techniques)} MITRE ATT&CK techniques",
        f"Attack surface covers {len(tactics)} tactics: {', '.join(tactics.keys())}",
        f"Highest risk tactics: {self._get_highest_risk_tactics(tactics)}"
    ]

    # ... rest of summary generation
```

### AI Analysis Integration

Enhance AI analysis with MITRE context:

```python
# In threat_radar/ai/vulnerability_analyzer.py

def analyze_with_mitre(
    self,
    vulnerabilities: List[Vulnerability],
    mitre_techniques: List[MitreAttackTechnique]
) -> VulnerabilityAnalysis:
    """Analyze vulnerabilities with MITRE ATT&CK context."""

    prompt = f"""
    Analyze these vulnerabilities in the context of MITRE ATT&CK framework:

    Vulnerabilities: {json.dumps(vulnerabilities, indent=2)}

    MITRE ATT&CK Techniques identified:
    {json.dumps([
        {'id': t.technique_id, 'name': t.technique_name, 'tactic': t.tactic}
        for t in mitre_techniques
    ], indent=2)}

    Provide:
    1. Real-world attack scenarios using these techniques
    2. Defense recommendations aligned with MITRE D3FEND
    3. Detection strategies (MITRE CAR analytics)
    4. Prioritization based on active threat campaigns
    """

    # ... rest of AI analysis
```

## Data Sources

### MITRE ATT&CK Data

Download official MITRE ATT&CK data:

```bash
# Clone MITRE CTI repository
git clone https://github.com/mitre/cti.git

# Or download specific files
wget https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

### CWE to ATT&CK Mappings

Use community-maintained mappings:
- https://github.com/center-for-threat-informed-defense/attack_to_cwe
- https://capec.mitre.org/ (Common Attack Pattern Enumeration)

### CVE to ATT&CK

Leverage existing databases:
- MITRE CVE database
- NVD (National Vulnerability Database)
- CISA KEV (Known Exploited Vulnerabilities)

## Benefits

✅ **Real-World Context**: Map vulnerabilities to actual attack techniques
✅ **Better Prioritization**: Focus on techniques used by active threat actors
✅ **Defense Planning**: Align mitigations with ATT&CK framework
✅ **Threat Intelligence**: Connect to threat campaign data
✅ **Communication**: Use standardized terminology (MITRE ATT&CK IDs)
✅ **Compliance**: Many frameworks reference MITRE ATT&CK

## Next Steps

1. Implement `MitreAttackMapper` class
2. Add CVE pattern matching rules
3. Create MITRE CLI commands
4. Integrate with attack path analysis
5. Enhance reports with MITRE context
6. Build ATT&CK matrix visualization
7. Add MITRE D3FEND defensive techniques
8. Integrate threat intelligence feeds

## Future Enhancements

- **ML-based mapping**: Use NLP to map CVE descriptions to techniques
- **MITRE D3FEND integration**: Map defensive techniques to vulnerabilities
- **MITRE CAR integration**: Add detection analytics
- **Threat intelligence**: Connect to APT group TTPs
- **Navigator integration**: Export to ATT&CK Navigator
- **STIX/TAXII support**: Threat intelligence sharing
