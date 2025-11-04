#!/usr/bin/env python3
"""
Lateral Movement Identification Example

Demonstrates how to:
1. Identify lateral movement opportunities
2. Analyze detection difficulty
3. Understand network requirements
"""

import json
from pathlib import Path

from threat_radar.graph import NetworkXClient, GraphAnalyzer


def main():
    """Run lateral movement identification example."""
    print("=" * 70)
    print("LATERAL MOVEMENT IDENTIFICATION EXAMPLE")
    print("=" * 70)

    # Load graph
    graph_file = Path("environment-graph.graphml")
    if not graph_file.exists():
        print("\n❌ Graph file not found!")
        print("Run 01_basic_attack_path.py first.")
        return 1

    print(f"\n📊 Loading graph: {graph_file}")
    client = NetworkXClient()
    client.load(str(graph_file))

    analyzer = GraphAnalyzer(client)

    # Identify lateral movements
    print("\n↔️  Identifying Lateral Movement Opportunities...")
    movements = analyzer.identify_lateral_movement_opportunities(
        max_opportunities=30
    )

    print(f"   Found {len(movements)} lateral movement opportunities")

    if not movements:
        print("\n✅ No lateral movement opportunities detected.")
        print("   Your network segmentation is effective!")
        return 0

    # Display results
    print("\n" + "=" * 70)
    print("LATERAL MOVEMENT OPPORTUNITIES")
    print("=" * 70)

    # Group by zone
    by_zone = {}
    for mov in movements:
        # Extract zone from asset name
        from_asset_data = client.graph.nodes.get(mov.from_asset, {})
        zone = from_asset_data.get('zone', 'unknown')

        if zone not in by_zone:
            by_zone[zone] = []
        by_zone[zone].append(mov)

    for zone, zone_movements in by_zone.items():
        print(f"\n🔄 {zone.upper()} Zone Movements ({len(zone_movements)})")
        print("-" * 70)

        for i, mov in enumerate(zone_movements[:5], 1):  # Show top 5 per zone
            from_data = client.graph.nodes.get(mov.from_asset, {})
            to_data = client.graph.nodes.get(mov.to_asset, {})

            print(f"\n   Movement {i}:")
            print(f"      From: {from_data.get('name', mov.from_asset)}")
            print(f"      To: {to_data.get('name', mov.to_asset)}")
            print(f"      Type: {mov.movement_type}")
            print(f"      Path Length: {mov.path.path_length} steps")

            # Detection difficulty
            difficulty_symbol = {
                "easy": "🟢",
                "medium": "🟡",
                "hard": "🔴"
            }.get(mov.detection_difficulty, "⚪")
            print(f"      Detection: {difficulty_symbol} {mov.detection_difficulty.upper()}")

            if mov.vulnerabilities:
                print(f"      CVEs: {', '.join(mov.vulnerabilities[:3])}")

            if mov.network_requirements:
                print(f"      Network Reqs: {', '.join(mov.network_requirements)}")

    # Analyze hard-to-detect movements
    hard_to_detect = [m for m in movements if m.detection_difficulty == "hard"]
    if hard_to_detect:
        print("\n" + "=" * 70)
        print("⚠️  HARD TO DETECT MOVEMENTS")
        print("=" * 70)

        print(f"\n{len(hard_to_detect)} movements are hard to detect:")
        for i, mov in enumerate(hard_to_detect[:3], 1):
            from_data = client.graph.nodes.get(mov.from_asset, {})
            to_data = client.graph.nodes.get(mov.to_asset, {})

            print(f"\n   {i}. {from_data.get('name')} → {to_data.get('name')}")
            print(f"      • Requires: {', '.join(mov.prerequisites)}")
            print(f"      • Network: {', '.join(mov.network_requirements)}")

            if mov.vulnerabilities:
                print(f"      • Exploits: {', '.join(mov.vulnerabilities[:3])}")

            print(f"      💡 Recommendation: Deploy enhanced monitoring for this path")

    # Save results
    output_file = Path("lateral-movement.json")
    print(f"\n💾 Saving results to: {output_file}")

    results = {
        "total_movements": len(movements),
        "by_zone": {zone: len(movs) for zone, movs in by_zone.items()},
        "by_difficulty": {
            "easy": len([m for m in movements if m.detection_difficulty == "easy"]),
            "medium": len([m for m in movements if m.detection_difficulty == "medium"]),
            "hard": len([m for m in movements if m.detection_difficulty == "hard"]),
        },
        "movements": [
            {
                "from_asset": m.from_asset,
                "to_asset": m.to_asset,
                "movement_type": m.movement_type,
                "detection_difficulty": m.detection_difficulty,
                "vulnerabilities": m.vulnerabilities,
                "network_requirements": m.network_requirements,
                "prerequisites": m.prerequisites,
                "path": {
                    "entry_point": m.path.entry_point,
                    "target": m.path.target,
                    "length": m.path.path_length,
                    "total_cvss": m.path.total_cvss,
                },
            }
            for m in movements
        ],
    }

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"   Total Movements: {len(movements)}")
    print(f"   • Easy to detect: {results['by_difficulty']['easy']} 🟢")
    print(f"   • Medium difficulty: {results['by_difficulty']['medium']} 🟡")
    print(f"   • Hard to detect: {results['by_difficulty']['hard']} 🔴")

    if hard_to_detect:
        print(f"\n   ⚠️  Deploy monitoring for {len(hard_to_detect)} hard-to-detect movements")

    print("\n✅ Lateral movement analysis complete!")
    print(f"\nNext: python 04_complete_assessment.py")

    return 0


if __name__ == "__main__":
    exit(main())
