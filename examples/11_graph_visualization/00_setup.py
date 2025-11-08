#!/usr/bin/env python3
"""
Example 0: Setup Script for Visualization Examples

This script generates a sample vulnerability graph with realistic data
for use in the visualization examples.

Run this script first before running any other visualization examples:
    python 00_setup.py
"""

from pathlib import Path
from threat_radar.graph import NetworkXClient, GraphBuilder
from threat_radar.graph.models import (
    NodeType,
    EdgeType,
    GraphNode,
    GraphEdge,
)


def create_sample_graph():
    """Create a sample vulnerability graph with realistic security context."""

    print("🔨 Creating sample vulnerability graph...")
    print("=" * 60)

    # Initialize client
    client = NetworkXClient()

    # Create containers with security context
    print("\n📦 Creating containers...")
    containers = [
        {
            "id": "container-web-frontend",
            "name": "Web Frontend",
            "image": "nginx:1.21.6-alpine",
            "zone": "dmz",
            "internet_facing": True,
            "criticality": "high",
            "pci_scope": False,
            "hipaa_scope": False,
        },
        {
            "id": "container-api-gateway",
            "name": "API Gateway",
            "image": "api-gateway:v2.1.0",
            "zone": "dmz",
            "internet_facing": True,
            "criticality": "critical",
            "pci_scope": True,
            "hipaa_scope": False,
        },
        {
            "id": "container-payment-service",
            "name": "Payment Service",
            "image": "payment-svc:v1.5.2",
            "zone": "internal",
            "internet_facing": False,
            "criticality": "critical",
            "pci_scope": True,
            "hipaa_scope": False,
        },
        {
            "id": "container-user-service",
            "name": "User Service",
            "image": "user-svc:v3.2.1",
            "zone": "internal",
            "internet_facing": False,
            "criticality": "high",
            "pci_scope": False,
            "hipaa_scope": True,
        },
        {
            "id": "container-analytics",
            "name": "Analytics Service",
            "image": "analytics:v1.0.3",
            "zone": "trusted",
            "internet_facing": False,
            "criticality": "medium",
            "pci_scope": False,
            "hipaa_scope": False,
        },
    ]

    for container in containers:
        node = GraphNode(
            node_id=container["id"],
            node_type=NodeType.CONTAINER,
            properties={
                "name": container["name"],
                "image": container["image"],
                "zone": container["zone"],
                "internet_facing": container["internet_facing"],
                "criticality": container["criticality"],
                "pci_scope": container["pci_scope"],
                "hipaa_scope": container["hipaa_scope"],
            },
        )
        client.add_node(node)

    print(f"   ✓ Created {len(containers)} containers")

    # Create packages
    print("\n📚 Creating packages...")
    packages = [
        # Web Frontend packages
        {
            "id": "pkg-nginx",
            "name": "nginx",
            "version": "1.21.6",
            "ecosystem": "alpine",
            "container": "container-web-frontend",
        },
        {
            "id": "pkg-openssl-web",
            "name": "openssl",
            "version": "1.1.1n",
            "ecosystem": "alpine",
            "container": "container-web-frontend",
        },
        # API Gateway packages
        {
            "id": "pkg-express",
            "name": "express",
            "version": "4.17.1",
            "ecosystem": "npm",
            "container": "container-api-gateway",
        },
        {
            "id": "pkg-jsonwebtoken",
            "name": "jsonwebtoken",
            "version": "8.5.1",
            "ecosystem": "npm",
            "container": "container-api-gateway",
        },
        {
            "id": "pkg-node",
            "name": "node",
            "version": "16.14.0",
            "ecosystem": "alpine",
            "container": "container-api-gateway",
        },
        # Payment Service packages
        {
            "id": "pkg-django",
            "name": "django",
            "version": "3.2.12",
            "ecosystem": "pypi",
            "container": "container-payment-service",
        },
        {
            "id": "pkg-requests",
            "name": "requests",
            "version": "2.27.1",
            "ecosystem": "pypi",
            "container": "container-payment-service",
        },
        {
            "id": "pkg-stripe",
            "name": "stripe",
            "version": "2.74.0",
            "ecosystem": "pypi",
            "container": "container-payment-service",
        },
        # User Service packages
        {
            "id": "pkg-spring-boot",
            "name": "spring-boot",
            "version": "2.6.3",
            "ecosystem": "maven",
            "container": "container-user-service",
        },
        {
            "id": "pkg-log4j",
            "name": "log4j-core",
            "version": "2.17.0",
            "ecosystem": "maven",
            "container": "container-user-service",
        },
        # Analytics packages
        {
            "id": "pkg-pandas",
            "name": "pandas",
            "version": "1.4.1",
            "ecosystem": "pypi",
            "container": "container-analytics",
        },
    ]

    for package in packages:
        node = GraphNode(
            node_id=package["id"],
            node_type=NodeType.PACKAGE,
            properties={
                "name": package["name"],
                "version": package["version"],
                "ecosystem": package["ecosystem"],
            },
        )
        client.add_node(node)

        # Link package to container
        edge = GraphEdge(
            source_id=package["container"],
            target_id=package["id"],
            edge_type=EdgeType.CONTAINS,
            properties={"relationship": "contains_package"},
        )
        client.add_edge(edge)

    print(f"   ✓ Created {len(packages)} packages")

    # Create vulnerabilities
    print("\n🔒 Creating vulnerabilities...")
    vulnerabilities = [
        # CRITICAL vulnerabilities
        {
            "id": "vuln-cve-2021-44228",
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
            "cvss_score": 10.0,
            "description": "Log4Shell - Remote Code Execution in Log4j",
            "packages": ["pkg-log4j"],
        },
        {
            "id": "vuln-cve-2022-0543",
            "cve_id": "CVE-2022-0543",
            "severity": "critical",
            "cvss_score": 10.0,
            "description": "Redis Lua Sandbox Escape",
            "packages": ["pkg-node"],
        },
        # HIGH vulnerabilities
        {
            "id": "vuln-cve-2022-0778",
            "cve_id": "CVE-2022-0778",
            "severity": "high",
            "cvss_score": 7.5,
            "description": "OpenSSL Infinite Loop in BN_mod_sqrt()",
            "packages": ["pkg-openssl-web"],
        },
        {
            "id": "vuln-cve-2022-22965",
            "cve_id": "CVE-2022-22965",
            "severity": "high",
            "cvss_score": 9.8,
            "description": "Spring4Shell - RCE in Spring Framework",
            "packages": ["pkg-spring-boot"],
        },
        {
            "id": "vuln-cve-2021-3449",
            "cve_id": "CVE-2021-3449",
            "severity": "high",
            "cvss_score": 7.4,
            "description": "Django SQL Injection",
            "packages": ["pkg-django"],
        },
        # MEDIUM vulnerabilities
        {
            "id": "vuln-cve-2021-32640",
            "cve_id": "CVE-2021-32640",
            "severity": "medium",
            "cvss_score": 6.5,
            "description": "Express.js Path Traversal",
            "packages": ["pkg-express"],
        },
        {
            "id": "vuln-cve-2022-23540",
            "cve_id": "CVE-2022-23540",
            "severity": "medium",
            "cvss_score": 5.9,
            "description": "jsonwebtoken Algorithm Confusion",
            "packages": ["pkg-jsonwebtoken"],
        },
        {
            "id": "vuln-cve-2021-43797",
            "cve_id": "CVE-2021-43797",
            "severity": "medium",
            "cvss_score": 6.1,
            "description": "Nginx Off-by-One Buffer Overflow",
            "packages": ["pkg-nginx"],
        },
        # LOW vulnerabilities
        {
            "id": "vuln-cve-2022-24065",
            "cve_id": "CVE-2022-24065",
            "severity": "low",
            "cvss_score": 3.7,
            "description": "Requests Cookie Jar Information Disclosure",
            "packages": ["pkg-requests"],
        },
        {
            "id": "vuln-cve-2021-29510",
            "cve_id": "CVE-2021-29510",
            "severity": "low",
            "cvss_score": 4.2,
            "description": "Pandas CSV Injection",
            "packages": ["pkg-pandas"],
        },
    ]

    for vuln in vulnerabilities:
        node = GraphNode(
            node_id=vuln["id"],
            node_type=NodeType.VULNERABILITY,
            properties={
                "cve_id": vuln["cve_id"],
                "severity": vuln["severity"],
                "cvss_score": vuln["cvss_score"],
                "description": vuln["description"],
            },
        )
        client.add_node(node)

        # Link vulnerability to packages
        for pkg_id in vuln["packages"]:
            edge = GraphEdge(
                source_id=pkg_id,
                target_id=vuln["id"],
                edge_type=EdgeType.HAS_VULNERABILITY,
                properties={"severity": vuln["severity"]},
            )
            client.add_edge(edge)

    print(f"   ✓ Created {len(vulnerabilities)} vulnerabilities")

    # Create container dependencies for attack paths
    print("\n🔗 Creating container dependencies...")
    dependencies = [
        ("container-web-frontend", "container-api-gateway"),
        ("container-api-gateway", "container-payment-service"),
        ("container-api-gateway", "container-user-service"),
        ("container-user-service", "container-analytics"),
    ]

    for source, target in dependencies:
        edge = GraphEdge(
            source_id=source,
            target_id=target,
            edge_type=EdgeType.DEPENDS_ON,
            properties={"relationship": "service_dependency"},
        )
        client.add_edge(edge)

    print(f"   ✓ Created {len(dependencies)} dependencies")

    # Save graph
    output_path = Path(__file__).parent / "sample_graph.graphml"
    client.save(str(output_path))

    # Get metadata
    metadata = client.get_metadata()

    print("\n✅ Sample graph created successfully!")
    print(f"\n📊 Graph Statistics:")
    print(f"   • Nodes: {metadata.node_count}")
    print(f"   • Edges: {metadata.edge_count}")
    print(f"\n   Node Types:")
    for node_type, count in metadata.node_type_counts.items():
        print(f"      • {node_type}: {count}")

    print(f"\n   Vulnerabilities by Severity:")
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vulnerabilities:
        severity_counts[vuln["severity"]] += 1
    for severity, count in severity_counts.items():
        print(f"      • {severity.upper()}: {count}")

    print(f"\n   Security Context:")
    print(f"      • Internet-facing assets: 2")
    print(f"      • PCI-scoped assets: 2")
    print(f"      • HIPAA-scoped assets: 1")
    print(f"      • Security zones: DMZ (2), Internal (2), Trusted (1)")

    print(f"\n📁 Saved to: {output_path}")
    print("\n💡 You can now run the visualization examples:")
    print(f"   python {Path(__file__).parent / '01_basic_visualization.py'}")
    print(f"   python {Path(__file__).parent / '02_attack_path_visualization.py'}")
    print(f"   python {Path(__file__).parent / '03_topology_visualization.py'}")
    print(f"   python {Path(__file__).parent / '04_filtered_visualization.py'}")
    print(f"   python {Path(__file__).parent / '05_export_formats.py'}")
    print(f"   python {Path(__file__).parent / '06_complete_workflow.py'}")


if __name__ == "__main__":
    create_sample_graph()
