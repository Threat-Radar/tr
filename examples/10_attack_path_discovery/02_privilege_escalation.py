#!/usr/bin/env python3
"""
Privilege Escalation Detection Example

Demonstrates how to:
1. Detect privilege escalation paths
2. Analyze escalation difficulty
3. Review mitigation recommendations
"""

import json
from pathlib import Path

from threat_radar.graph import NetworkXClient, GraphAnalyzer


def main():
    """Run privilege escalation detection example."""
    print("=" * 70)
    print("PRIVILEGE ESCALATION DETECTION EXAMPLE")
    print("=" * 70)

    # Load graph
    graph_file = Path("environment-graph.graphml")
    if not graph_file.exists():
        print("\n❌ Graph file not found!")
        print("Run 01_basic_attack_path.py first to generate the graph.")
        return 1

    print(f"\n📊 Loading graph: {graph_file}")
    client = NetworkXClient()
    client.load(str(graph_file))

    analyzer = GraphAnalyzer(client)

    # Detect privilege escalations
    print("\n🔐 Detecting Privilege Escalation Paths...")
    escalations = analyzer.detect_privilege_escalation_paths(max_paths=20)

    print(f"   Found {len(escalations)} privilege escalation opportunities")

    if not escalations:
        print("\n✅ No privilege escalation paths detected.")
        print("   Your infrastructure has good privilege separation!")
        return 0

    # Display results
    print("\n" + "=" * 70)
    print("PRIVILEGE ESCALATION OPPORTUNITIES")
    print("=" * 70)

    # Group by difficulty
    by_difficulty = {"easy": [], "medium": [], "hard": []}
    for esc in escalations:
        by_difficulty[esc.difficulty].append(esc)

    for difficulty in ["easy", "medium", "hard"]:
        group = by_difficulty[difficulty]
        if not group:
            continue

        print(f"\n🚨 {difficulty.upper()} Escalations ({len(group)})")
        print("-" * 70)

        for i, esc in enumerate(group[:5], 1):  # Show top 5 per difficulty
            print(f"\n   Escalation {i}:")
            print(f"      From: {esc.from_privilege}")
            print(f"      To: {esc.to_privilege}")
            print(f"      Path Length: {esc.path.path_length} steps")
            print(f"      Total CVSS: {esc.path.total_cvss:.2f}")

            if esc.vulnerabilities:
                print(f"      Exploitable CVEs: {', '.join(esc.vulnerabilities[:5])}")

            if esc.mitigation:
                print(f"\n      💡 Mitigation Steps:")
                for j, mit in enumerate(esc.mitigation[:3], 1):
                    print(f"         {j}. {mit}")

    # Detailed analysis of easiest escalation
    if by_difficulty["easy"]:
        print("\n" + "=" * 70)
        print("⚠️  CRITICAL: EASIEST PRIVILEGE ESCALATION")
        print("=" * 70)

        easiest = by_difficulty["easy"][0]
        print(f"\nThis is the easiest way for an attacker to escalate privileges:")
        print(f"   • From: {easiest.from_privilege} → To: {easiest.to_privilege}")
        print(f"   • Only {easiest.path.path_length} steps required")
        print(f"   • Uses CVEs: {', '.join(easiest.vulnerabilities[:3])}")

        print(f"\n   Attack Path Details:")
        for i, step in enumerate(easiest.path.steps, 1):
            print(f"      Step {i}: {step.description}")
            if step.vulnerabilities:
                print(f"              Exploits: {', '.join(step.vulnerabilities)}")

        print(f"\n   🛡️  Recommended Actions:")
        for i, mit in enumerate(easiest.mitigation, 1):
            print(f"      {i}. {mit}")

    # Save results
    output_file = Path("privilege-escalation.json")
    print(f"\n💾 Saving results to: {output_file}")

    results = {
        "total_escalations": len(escalations),
        "by_difficulty": {
            "easy": len(by_difficulty["easy"]),
            "medium": len(by_difficulty["medium"]),
            "hard": len(by_difficulty["hard"]),
        },
        "escalations": [
            {
                "from_privilege": e.from_privilege,
                "to_privilege": e.to_privilege,
                "difficulty": e.difficulty,
                "vulnerabilities": e.vulnerabilities,
                "mitigation": e.mitigation,
                "path": {
                    "entry_point": e.path.entry_point,
                    "target": e.path.target,
                    "length": e.path.path_length,
                    "total_cvss": e.path.total_cvss,
                    "threat_level": e.path.threat_level.value,
                    "steps": [
                        {
                            "node_id": s.node_id,
                            "type": s.step_type.value,
                            "description": s.description,
                            "vulnerabilities": s.vulnerabilities,
                        }
                        for s in e.path.steps
                    ],
                },
            }
            for e in escalations
        ],
    }

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"   Total Escalations: {len(escalations)}")
    print(f"   • Easy: {len(by_difficulty['easy'])} (Immediate risk!)")
    print(f"   • Medium: {len(by_difficulty['medium'])}")
    print(f"   • Hard: {len(by_difficulty['hard'])}")

    if by_difficulty["easy"]:
        print(f"\n   ⚠️  URGENT: Address {len(by_difficulty['easy'])} easy escalations immediately!")

    print("\n✅ Privilege escalation analysis complete!")
    print(f"\nNext: python 03_lateral_movement.py")

    return 0


if __name__ == "__main__":
    exit(main())
