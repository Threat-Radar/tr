# Attack Path Discovery Examples

This directory contains examples demonstrating Threat Radar's attack path discovery capabilities.

## Overview

Attack path discovery identifies potential security attack vectors through your infrastructure by analyzing:
- **Entry points**: Internet-facing assets, DMZ zones, public services
- **High-value targets**: Critical assets, PCI/HIPAA scope, confidential data
- **Attack paths**: Shortest paths from entry points to targets
- **Privilege escalation**: Opportunities to escalate from low to high privileges
- **Lateral movement**: Movement between assets in the same security zone

## Prerequisites

```bash
# Ensure Threat Radar is installed
pip install -e .

# Verify installation
threat-radar --version

# Install external tools
brew install grype syft  # macOS
```

## Quick Start

```bash
# 1. Run the complete demo
./run_attack_path_demo.sh

# 2. Run individual examples
python 01_basic_attack_path.py
python 02_privilege_escalation.py
python 03_lateral_movement.py
python 04_complete_assessment.py
```

## Example Files

### 1. Sample Data
- `sample-environment.json` - Multi-tier web application environment
- Contains: DMZ web servers, internal application servers, database

### 2. Python Examples
- `01_basic_attack_path.py` - Basic attack path discovery
- `02_privilege_escalation.py` - Privilege escalation detection
- `03_lateral_movement.py` - Lateral movement identification
- `04_complete_assessment.py` - Comprehensive attack surface analysis
- `05_red_team_simulation.py` - Simulate red team attack scenarios

### 3. Shell Scripts
- `run_attack_path_demo.sh` - Complete demonstration workflow
- `continuous_monitoring.sh` - Continuous attack surface monitoring
- `compliance_risk_check.sh` - Check compliance-related attack paths

## Workflows

### Basic Attack Path Discovery

```bash
# Build environment with vulnerability data
threat-radar env build-graph sample-environment.json \
  --merge-scan ../03_vulnerability_scanning/alpine-scan.json \
  -o environment-graph.graphml

# Find attack paths
threat-radar graph attack-paths environment-graph.graphml \
  --max-paths 20 \
  -o attack-paths.json

# View results
cat attack-paths.json | jq '.attack_paths[] | {
  threat: .threat_level,
  from: .entry_point,
  to: .target,
  cvss: .total_cvss
}'
```

### Privilege Escalation Analysis

```bash
# Detect privilege escalation opportunities
threat-radar graph privilege-escalation environment-graph.graphml \
  --max-paths 10 \
  -o privilege-escalation.json

# Show escalations
cat privilege-escalation.json | jq '.privilege_escalations[] | {
  from: .from_privilege,
  to: .to_privilege,
  difficulty: .difficulty,
  cves: .vulnerabilities[:3]
}'
```

### Complete Security Assessment

```bash
# Full attack surface analysis
threat-radar graph attack-surface environment-graph.graphml \
  --max-paths 50 \
  -o attack-surface.json

# Show risk summary
cat attack-surface.json | jq '{
  risk_score: .total_risk_score,
  entry_points: (.entry_points | length),
  targets: (.high_value_targets | length),
  attack_paths: (.attack_paths | length),
  privilege_escalations: (.privilege_escalations | length),
  lateral_movements: (.lateral_movements | length),
  top_recommendations: .recommendations[:5]
}'
```

## Integration Examples

### CI/CD Pipeline

```bash
# Check for critical attack paths in CI/CD
threat-radar graph attack-paths production-graph.graphml -o paths.json

CRITICAL=$(cat paths.json | jq '[.attack_paths[] | select(.threat_level=="critical")] | length')

if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ Found $CRITICAL critical attack paths!"
  cat paths.json | jq -r '.attack_paths[] | select(.threat_level=="critical") |
    "Path: \(.entry_point) → \(.target) (CVSS: \(.total_cvss))"'
  exit 1
fi
```

### Compliance Monitoring

```bash
# Check PCI-scoped attack paths
threat-radar graph attack-paths graph.graphml -o paths.json

# Filter paths to PCI assets
cat paths.json | jq '[.attack_paths[] |
  select(.target | contains("payment") or contains("database"))]' \
  > pci-attack-paths.json

echo "PCI-Scoped Attack Paths: $(cat pci-attack-paths.json | jq '. | length')"
```

## Expected Output

### Attack Path Discovery

```
Found 8 Attack Paths:

Path 1:
  Threat Level: CRITICAL
  Total CVSS: 17.3
  Length: 3 steps
  Exploitability: 70%

  Steps:
    • Gain initial access via DMZ Web Server (container)
      CVEs: CVE-2023-0001, CVE-2023-0002
    • Exploit vulnerabilities in Internal Application Server
      CVEs: CVE-2023-0003
    • Gain access to target: Database Server
```

### Privilege Escalation

```
Found 3 Privilege Escalation Paths:

Escalation 1:
  From: dmz
  To: internal
  Difficulty: MEDIUM
  Path Length: 2 steps
  CVEs: CVE-2023-0001, CVE-2023-0003

  Mitigation:
    • Patch 2 vulnerabilities: CVE-2023-0001, CVE-2023-0003
    • Implement network segmentation to prevent lateral movement
    • Deploy monitoring and detection for this attack pattern
```

### Attack Surface Analysis

```
Attack Surface Analysis Results:
  Total Risk Score: 68.5/100

  Entry Points: 3
  High-Value Targets: 4
  Attack Paths: 12
  Privilege Escalations: 3
  Lateral Movements: 8

Threat Distribution:
  CRITICAL: 2 paths
  HIGH: 5 paths
  MEDIUM: 4 paths
  LOW: 1 paths

Security Recommendations:
  1. URGENT: Address 2 critical attack paths immediately
  2. Prioritize patching 8 unique vulnerabilities across attack paths
  3. Review and restrict 3 privilege escalation opportunities
  4. Implement network segmentation to mitigate 8 lateral movement opportunities
  5. Harden 3 entry points with additional security controls
```

## Advanced Use Cases

### Red Team Exercise

See `05_red_team_simulation.py` for a complete red team attack simulation that:
1. Identifies attack paths
2. Simulates attack progression
3. Generates detailed exploitation reports
4. Provides defender recommendations

### Continuous Monitoring

See `continuous_monitoring.sh` for automated monitoring that:
1. Runs daily attack surface scans
2. Compares with baseline
3. Alerts on risk score changes
4. Tracks attack surface trends over time

## Troubleshooting

### No Attack Paths Found

If no attack paths are found:
1. Verify environment has entry points (internet_facing, zone: dmz)
2. Verify high-value targets exist (criticality: critical/high, pci_scope: true)
3. Check graph has relationships between assets
4. Increase `--max-length` parameter

### Missing Privilege Escalations

If no privilege escalations detected:
1. Verify assets have zone attributes (dmz, internal, trusted)
2. Check for assets in different privilege levels
3. Ensure graph has connections between zones

### Low Risk Score

If risk score is unexpectedly low:
1. Check vulnerability data is merged into graph
2. Verify CVSS scores are present
3. Ensure critical assets are marked with high criticality

## Resources

- [Main Documentation](../../CLAUDE.md#attack-path-discovery-commands)
- [Graph Database Guide](../06_graph_database/README.md)
- [Environment Configuration](../07_environment_configuration/README.md)
- [API Documentation](../../docs/API.md)
