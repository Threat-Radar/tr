#!/usr/bin/env python3
"""
Basic Attack Path Discovery Example

Demonstrates how to:
1. Load a graph with environment and vulnerability data
2. Identify entry points and high-value targets
3. Find shortest attack paths
4. Display results
"""

import json
from pathlib import Path

from threat_radar.graph import NetworkXClient, GraphAnalyzer


def main():
    """Run basic attack path discovery example."""
    print("=" * 70)
    print("BASIC ATTACK PATH DISCOVERY EXAMPLE")
    print("=" * 70)

    # Check if graph exists
    graph_file = Path("environment-graph.graphml")
    if not graph_file.exists():
        print("\n❌ Graph file not found!")
        print("Run this first:")
        print("  threat-radar env build-graph sample-environment.json -o environment-graph.graphml")
        return 1

    # Load graph
    print(f"\n📊 Loading graph: {graph_file}")
    client = NetworkXClient()
    client.load(str(graph_file))

    metadata = client.get_metadata()
    print(f"   • Nodes: {metadata.node_count}")
    print(f"   • Edges: {metadata.edge_count}")

    # Create analyzer
    analyzer = GraphAnalyzer(client)

    # Step 1: Identify entry points
    print("\n🔓 Step 1: Identifying Entry Points...")
    entry_points = analyzer.identify_entry_points()

    print(f"   Found {len(entry_points)} entry points:")
    for entry in entry_points:
        node_data = client.graph.nodes[entry]
        name = node_data.get('name', entry)
        zone = node_data.get('zone', 'unknown')
        print(f"   • {name} (zone: {zone})")

    # Step 2: Identify high-value targets
    print("\n🎯 Step 2: Identifying High-Value Targets...")
    targets = analyzer.identify_high_value_targets()

    print(f"   Found {len(targets)} high-value targets:")
    for target in targets:
        node_data = client.graph.nodes[target]
        name = node_data.get('name', target)
        criticality = node_data.get('criticality', 'unknown')
        pci_scope = node_data.get('pci_scope', False)
        print(f"   • {name} (criticality: {criticality}, PCI: {pci_scope})")

    if not entry_points or not targets:
        print("\n⚠️  No entry points or targets found. Cannot discover attack paths.")
        return 0

    # Step 3: Find attack paths
    print("\n🔍 Step 3: Finding Attack Paths...")
    attack_paths = analyzer.find_shortest_attack_paths(
        entry_points=entry_points,
        targets=targets,
        max_length=10
    )

    print(f"   Found {len(attack_paths)} attack paths")

    # Display results
    print("\n" + "=" * 70)
    print("ATTACK PATHS DISCOVERED")
    print("=" * 70)

    if not attack_paths:
        print("No attack paths found.")
        return 0

    # Show top 5 paths
    for i, path in enumerate(attack_paths[:5], 1):
        print(f"\n🚨 Path {i}: {path.threat_level.value.upper()}")
        print(f"   Entry Point: {path.entry_point}")
        print(f"   Target: {path.target}")
        print(f"   Length: {path.path_length} steps")
        print(f"   Total CVSS: {path.total_cvss:.2f}")
        print(f"   Exploitability: {path.exploitability:.0%}")

        if path.requires_privileges:
            print(f"   ⚠️  Requires privilege escalation")

        print(f"\n   Attack Steps:")
        for j, step in enumerate(path.steps, 1):
            print(f"      {j}. {step.description}")
            if step.vulnerabilities:
                print(f"         CVEs: {', '.join(step.vulnerabilities[:3])}")
                if step.cvss_score:
                    print(f"         CVSS: {step.cvss_score:.1f}")

    # Save results
    output_file = Path("attack-paths.json")
    print(f"\n💾 Saving results to: {output_file}")

    results = {
        "total_paths": len(attack_paths),
        "entry_points": entry_points,
        "high_value_targets": targets,
        "attack_paths": [
            {
                "path_id": p.path_id,
                "threat_level": p.threat_level.value,
                "entry_point": p.entry_point,
                "target": p.target,
                "path_length": p.path_length,
                "total_cvss": p.total_cvss,
                "exploitability": p.exploitability,
                "requires_privileges": p.requires_privileges,
                "description": p.description,
                "steps": [
                    {
                        "node_id": s.node_id,
                        "type": s.step_type.value,
                        "description": s.description,
                        "vulnerabilities": s.vulnerabilities,
                        "cvss_score": s.cvss_score,
                    }
                    for s in p.steps
                ],
            }
            for p in attack_paths
        ],
    }

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print("\n✅ Attack path discovery complete!")
    print(f"\nNext steps:")
    print(f"  1. Review attack-paths.json for detailed results")
    print(f"  2. Run privilege escalation analysis: python 02_privilege_escalation.py")
    print(f"  3. Check lateral movement: python 03_lateral_movement.py")

    return 0


if __name__ == "__main__":
    exit(main())
