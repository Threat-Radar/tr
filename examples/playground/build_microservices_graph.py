#!/usr/bin/env python3
"""Build combined graph from all microservices scan files."""

import sys
import json
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from threat_radar.graph import NetworkXClient, GraphBuilder
from threat_radar.core.grype_integration import GrypeScanResult, GrypeVulnerability

def load_scan_result(scan_file):
    """Load scan result from JSON file and convert to GrypeScanResult."""
    with open(scan_file) as f:
        scan_data = json.load(f)

    # Parse Threat Radar format (our scans are in this format)
    vulnerabilities = []
    for vuln_data in scan_data.get("vulnerabilities", []):
        vuln = GrypeVulnerability(
            id=vuln_data.get("id"),
            severity=vuln_data.get("severity", "unknown"),
            package_name=vuln_data.get("package", "").split("@")[0],
            package_version=vuln_data.get("package", "").split("@")[1] if "@" in vuln_data.get("package", "") else "unknown",
            package_type=vuln_data.get("type", "unknown"),
            fixed_in_version=vuln_data.get("fixed_in", None),
            description=vuln_data.get("description"),
            cvss_score=vuln_data.get("cvss_score"),
            urls=vuln_data.get("urls", []),
            data_source=vuln_data.get("data_source"),
            namespace=vuln_data.get("namespace"),
        )
        vulnerabilities.append(vuln)

    # Create GrypeScanResult
    scan_result = GrypeScanResult(
        target=scan_data.get("target", "unknown"),
        vulnerabilities=vulnerabilities,
        total_count=scan_data.get("total_vulnerabilities", len(vulnerabilities)),
        severity_counts=scan_data.get("severity_counts", {}),
        scan_metadata=scan_data.get("scan_metadata"),
    )

    return scan_result

def build_combined_graph(scan_files, output_file):
    """Build combined graph from multiple scan files."""

    print(f"Building combined graph from {len(scan_files)} microservices...")

    # Create graph client
    client = NetworkXClient()
    builder = GraphBuilder(client)

    # Process each scan file
    for scan_file in scan_files:
        print(f"  Processing: {Path(scan_file).stem}...")
        scan_result = load_scan_result(scan_file)

        # Build from scan (merges into existing graph)
        builder.build_from_scan(scan_result)

    # Get graph statistics
    graph = client.graph
    node_types = {}
    for node in graph.nodes():
        node_type = graph.nodes[node].get('node_type', 'unknown')
        node_types[node_type] = node_types.get(node_type, 0) + 1

    print(f"\n✓ Combined graph built successfully!")
    print(f"  • Total nodes: {graph.number_of_nodes()}")
    print(f"  • Total edges: {graph.number_of_edges()}")
    print(f"  • Node types:")
    for node_type, count in sorted(node_types.items()):
        print(f"    - {node_type}: {count}")

    # Save graph
    print(f"\nSaving to: {output_file}")
    client.save(output_file)
    print("✓ Graph saved successfully!")

if __name__ == "__main__":
    # Define scan files
    scan_dir = Path("full-demo-results/01-scans")
    scan_files = [
        scan_dir / "frontend_scan.json",
        scan_dir / "paymentservice_scan.json",
        scan_dir / "cartservice_scan.json",
        scan_dir / "checkoutservice_scan.json",
        scan_dir / "currencyservice_scan.json",
        scan_dir / "productcatalogservice_scan.json",
    ]

    output_file = "full-demo-results/05-graphs/microservices-combined-graph.graphml"

    build_combined_graph(scan_files, output_file)
