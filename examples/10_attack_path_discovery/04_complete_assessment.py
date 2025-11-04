#!/usr/bin/env python3
"""
Complete Attack Surface Assessment Example

Demonstrates comprehensive security analysis combining:
1. Attack path discovery
2. Privilege escalation detection
3. Lateral movement identification
4. Risk scoring
5. Security recommendations
"""

import json
from pathlib import Path

from threat_radar.graph import NetworkXClient, GraphAnalyzer


def main():
    """Run complete attack surface assessment."""
    print("=" * 70)
    print("COMPLETE ATTACK SURFACE ASSESSMENT")
    print("=" * 70)

    # Load graph
    graph_file = Path("environment-graph.graphml")
    if not graph_file.exists():
        print("\n❌ Graph file not found!")
        print("Run: threat-radar env build-graph sample-environment.json -o environment-graph.graphml")
        return 1

    print(f"\n📊 Loading graph: {graph_file}")
    client = NetworkXClient()
    client.load(str(graph_file))

    metadata = client.get_metadata()
    print(f"   • Nodes: {metadata.node_count}")
    print(f"   • Edges: {metadata.edge_count}")

    analyzer = GraphAnalyzer(client)

    # Run comprehensive analysis
    print("\n🔍 Running Comprehensive Attack Surface Analysis...")
    print("   This combines all attack path analysis methods...")

    attack_surface = analyzer.analyze_attack_surface(max_paths=50)

    # Display results
    print("\n" + "=" * 70)
    print("ATTACK SURFACE ANALYSIS RESULTS")
    print("=" * 70)

    # Overall risk score
    risk_color = "🔴" if attack_surface.total_risk_score >= 70 else "🟡" if attack_surface.total_risk_score >= 40 else "🟢"
    print(f"\n{risk_color} Overall Risk Score: {attack_surface.total_risk_score:.1f}/100")

    # Summary statistics
    print(f"\n📊 Summary:")
    print(f"   • Entry Points: {len(attack_surface.entry_points)}")
    print(f"   • High-Value Targets: {len(attack_surface.high_value_targets)}")
    print(f"   • Attack Paths: {len(attack_surface.attack_paths)}")
    print(f"   • Privilege Escalations: {len(attack_surface.privilege_escalations)}")
    print(f"   • Lateral Movements: {len(attack_surface.lateral_movements)}")

    # Entry points detail
    print(f"\n🔓 Entry Points:")
    for entry in attack_surface.entry_points:
        node_data = client.graph.nodes[entry]
        name = node_data.get('name', entry)
        print(f"   • {name}")

    # High-value targets detail
    print(f"\n🎯 High-Value Targets:")
    for target in attack_surface.high_value_targets:
        node_data = client.graph.nodes[target]
        name = node_data.get('name', target)
        criticality = node_data.get('criticality', 'unknown')
        pci = " [PCI]" if node_data.get('pci_scope') else ""
        print(f"   • {name} ({criticality}){pci}")

    # Threat distribution
    if attack_surface.attack_paths:
        print(f"\n🚨 Threat Distribution:")
        threat_counts = {}
        for path in attack_surface.attack_paths:
            level = path.threat_level.value
            threat_counts[level] = threat_counts.get(level, 0) + 1

        for level in ['critical', 'high', 'medium', 'low']:
            count = threat_counts.get(level, 0)
            if count > 0:
                symbol = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(level)
                print(f"   {symbol} {level.upper()}: {count} paths")

    # Critical paths
    critical_paths = [p for p in attack_surface.attack_paths if p.threat_level.value == 'critical']
    if critical_paths:
        print(f"\n" + "=" * 70)
        print(f"⚠️  CRITICAL ATTACK PATHS ({len(critical_paths)})")
        print("=" * 70)

        for i, path in enumerate(critical_paths[:3], 1):  # Show top 3
            print(f"\n   Path {i}:")
            print(f"      Entry: {path.entry_point}")
            print(f"      Target: {path.target}")
            print(f"      CVSS: {path.total_cvss:.1f}")
            print(f"      Steps: {path.path_length}")

            print(f"      Attack Sequence:")
            for j, step in enumerate(path.steps, 1):
                print(f"         {j}. {step.description}")
                if step.vulnerabilities:
                    print(f"            CVEs: {', '.join(step.vulnerabilities[:2])}")

    # Top privilege escalations
    easy_escalations = []
    if attack_surface.privilege_escalations:
        easy_escalations = [e for e in attack_surface.privilege_escalations if e.difficulty == "easy"]
        if easy_escalations:
            print(f"\n" + "=" * 70)
            print(f"⚠️  EASY PRIVILEGE ESCALATIONS ({len(easy_escalations)})")
            print("=" * 70)

            for i, esc in enumerate(easy_escalations[:3], 1):
                print(f"\n   Escalation {i}:")
                print(f"      {esc.from_privilege} → {esc.to_privilege}")
                print(f"      Path Length: {esc.path.path_length}")
                print(f"      CVEs: {', '.join(esc.vulnerabilities[:3])}")

    # Security recommendations
    print(f"\n" + "=" * 70)
    print("🛡️  SECURITY RECOMMENDATIONS")
    print("=" * 70)

    for i, rec in enumerate(attack_surface.recommendations, 1):
        # Highlight urgent recommendations
        if "URGENT" in rec or "critical" in rec.lower():
            print(f"\n   🔴 {i}. {rec}")
        else:
            print(f"\n   {i}. {rec}")

    # Save comprehensive report
    output_file = Path("attack-surface.json")
    print(f"\n💾 Saving complete assessment to: {output_file}")

    results = {
        "total_risk_score": attack_surface.total_risk_score,
        "summary": {
            "entry_points": len(attack_surface.entry_points),
            "high_value_targets": len(attack_surface.high_value_targets),
            "attack_paths": len(attack_surface.attack_paths),
            "privilege_escalations": len(attack_surface.privilege_escalations),
            "lateral_movements": len(attack_surface.lateral_movements),
        },
        "threat_distribution": {
            "critical": len([p for p in attack_surface.attack_paths if p.threat_level.value == 'critical']),
            "high": len([p for p in attack_surface.attack_paths if p.threat_level.value == 'high']),
            "medium": len([p for p in attack_surface.attack_paths if p.threat_level.value == 'medium']),
            "low": len([p for p in attack_surface.attack_paths if p.threat_level.value == 'low']),
        },
        "entry_points": attack_surface.entry_points,
        "high_value_targets": attack_surface.high_value_targets,
        "attack_paths": [
            {
                "path_id": p.path_id,
                "threat_level": p.threat_level.value,
                "entry_point": p.entry_point,
                "target": p.target,
                "total_cvss": p.total_cvss,
                "path_length": p.path_length,
                "exploitability": p.exploitability,
            }
            for p in attack_surface.attack_paths
        ],
        "privilege_escalations": [
            {
                "from_privilege": e.from_privilege,
                "to_privilege": e.to_privilege,
                "difficulty": e.difficulty,
                "vulnerabilities": e.vulnerabilities,
            }
            for e in attack_surface.privilege_escalations
        ],
        "lateral_movements": [
            {
                "from_asset": m.from_asset,
                "to_asset": m.to_asset,
                "movement_type": m.movement_type,
                "detection_difficulty": m.detection_difficulty,
            }
            for m in attack_surface.lateral_movements
        ],
        "recommendations": attack_surface.recommendations,
    }

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Final summary
    print(f"\n" + "=" * 70)
    print("ASSESSMENT COMPLETE")
    print("=" * 70)

    print(f"\n📊 Results saved:")
    print(f"   • attack-surface.json - Complete assessment")
    print(f"   • attack-paths.json - Attack paths only")
    print(f"   • privilege-escalation.json - Privilege escalations")
    print(f"   • lateral-movement.json - Lateral movements")

    print(f"\n🎯 Priority Actions:")
    if critical_paths:
        print(f"   🔴 CRITICAL: Address {len(critical_paths)} critical attack paths")
    if easy_escalations:
        print(f"   🟠 HIGH: Fix {len(easy_escalations)} easy privilege escalations")
    if attack_surface.total_risk_score >= 70:
        print(f"   ⚠️  Overall risk is HIGH - implement recommendations urgently")

    print("\n✅ Complete attack surface assessment finished!")

    return 0


if __name__ == "__main__":
    exit(main())
