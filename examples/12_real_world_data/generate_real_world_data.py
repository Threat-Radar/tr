#!/usr/bin/env python3
"""
Generate real-world test data from publicly available sources.

This script helps create realistic SBOMs and environment configurations
by analyzing:
1. Popular public Docker images
2. Public GitHub repositories
3. Known technology stacks from various industries
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional
import argparse
from datetime import datetime


class PublicImageScanner:
    """Scan popular public Docker images to generate realistic SBOMs."""

    # Curated list of popular images by category
    POPULAR_IMAGES = {
        "web_servers": [
            "nginx:latest",
            "nginx:alpine",
            "httpd:latest",
            "httpd:alpine",
            "caddy:latest",
        ],
        "app_runtimes": [
            "node:18-alpine",
            "node:20-alpine",
            "python:3.11-alpine",
            "python:3.11-slim",
            "ruby:3.2-alpine",
            "openjdk:17-alpine",
            "openjdk:21-jdk",
        ],
        "databases": [
            "postgres:15-alpine",
            "postgres:16-alpine",
            "mysql:8-debian",
            "redis:7-alpine",
            "mongo:7",
            "mariadb:11",
        ],
        "message_queues": [
            "rabbitmq:3-alpine",
            "redis:7-alpine",
            "kafka:latest",
        ],
        "monitoring": [
            "grafana/grafana:latest",
            "prom/prometheus:latest",
            "jaegertracing/all-in-one:latest",
        ],
        "ci_cd": [
            "jenkins/jenkins:lts",
            "gitlab/gitlab-ce:latest",
            "drone/drone:latest",
        ],
    }

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def scan_image(self, image: str) -> Optional[Path]:
        """Scan a single image and generate SBOM."""
        print(f"  Scanning {image}...")

        safe_name = image.replace(":", "_").replace("/", "_")
        output_file = self.output_dir / f"{safe_name}_sbom.json"

        try:
            # Use threat-radar to scan
            result = subprocess.run(
                [
                    "threat-radar",
                    "cve",
                    "scan-image",
                    image,
                    "-o",
                    str(output_file),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                print(f"    ✓ Saved to {output_file}")
                return output_file
            else:
                print(f"    ✗ Failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            print(f"    ✗ Timeout scanning {image}")
            return None
        except Exception as e:
            print(f"    ✗ Error: {e}")
            return None

    def scan_category(self, category: str, limit: Optional[int] = None) -> List[Path]:
        """Scan all images in a category."""
        if category not in self.POPULAR_IMAGES:
            print(f"Unknown category: {category}")
            print(f"Available: {', '.join(self.POPULAR_IMAGES.keys())}")
            return []

        images = self.POPULAR_IMAGES[category]
        if limit:
            images = images[:limit]

        print(f"\nScanning {category} images ({len(images)} total)...")

        results = []
        for image in images:
            output = self.scan_image(image)
            if output:
                results.append(output)

        print(f"\n✓ Scanned {len(results)}/{len(images)} images successfully")
        return results

    def scan_all(self, limit_per_category: Optional[int] = None) -> Dict[str, List[Path]]:
        """Scan all categories."""
        results = {}

        for category in self.POPULAR_IMAGES.keys():
            results[category] = self.scan_category(category, limit_per_category)

        return results


class EnvironmentConfigGenerator:
    """Generate realistic environment configurations based on industry patterns."""

    INDUSTRY_TEMPLATES = {
        "ecommerce": {
            "assets": [
                {
                    "id": "web-frontend",
                    "type": "container",
                    "image": "nginx:alpine",
                    "zone": "dmz",
                    "criticality": "high",
                    "function": "web-frontend",
                    "customer_facing": True,
                },
                {
                    "id": "app-server",
                    "type": "container",
                    "image": "node:18-alpine",
                    "zone": "internal",
                    "criticality": "critical",
                    "function": "application-server",
                    "customer_facing": False,
                },
                {
                    "id": "payment-api",
                    "type": "container",
                    "image": "python:3.11-alpine",
                    "zone": "internal",
                    "criticality": "critical",
                    "function": "payment-processing",
                    "pci_scope": True,
                    "customer_facing": False,
                },
                {
                    "id": "database",
                    "type": "container",
                    "image": "postgres:15-alpine",
                    "zone": "data",
                    "criticality": "critical",
                    "function": "database",
                    "pci_scope": True,
                    "customer_facing": False,
                },
                {
                    "id": "cache",
                    "type": "container",
                    "image": "redis:7-alpine",
                    "zone": "internal",
                    "criticality": "medium",
                    "function": "caching",
                    "customer_facing": False,
                },
            ],
            "compliance": ["pci-dss", "gdpr"],
        },
        "saas": {
            "assets": [
                {
                    "id": "api-gateway",
                    "type": "container",
                    "image": "nginx:alpine",
                    "zone": "dmz",
                    "criticality": "high",
                    "function": "api-gateway",
                    "customer_facing": True,
                },
                {
                    "id": "app-backend",
                    "type": "container",
                    "image": "python:3.11-slim",
                    "zone": "internal",
                    "criticality": "critical",
                    "function": "application-backend",
                    "customer_facing": False,
                },
                {
                    "id": "worker",
                    "type": "container",
                    "image": "python:3.11-slim",
                    "zone": "internal",
                    "criticality": "medium",
                    "function": "background-worker",
                    "customer_facing": False,
                },
                {
                    "id": "database",
                    "type": "container",
                    "image": "postgres:16-alpine",
                    "zone": "data",
                    "criticality": "critical",
                    "function": "database",
                    "customer_facing": False,
                },
                {
                    "id": "message-queue",
                    "type": "container",
                    "image": "rabbitmq:3-alpine",
                    "zone": "internal",
                    "criticality": "high",
                    "function": "message-queue",
                    "customer_facing": False,
                },
            ],
            "compliance": ["soc2", "gdpr"],
        },
        "fintech": {
            "assets": [
                {
                    "id": "api-gateway",
                    "type": "container",
                    "image": "nginx:alpine",
                    "zone": "dmz",
                    "criticality": "critical",
                    "function": "api-gateway",
                    "customer_facing": True,
                },
                {
                    "id": "transaction-processor",
                    "type": "container",
                    "image": "openjdk:17-alpine",
                    "zone": "internal",
                    "criticality": "critical",
                    "function": "transaction-processing",
                    "pci_scope": True,
                    "customer_facing": False,
                },
                {
                    "id": "fraud-detection",
                    "type": "container",
                    "image": "python:3.11-slim",
                    "zone": "internal",
                    "criticality": "high",
                    "function": "fraud-detection",
                    "customer_facing": False,
                },
                {
                    "id": "database-primary",
                    "type": "container",
                    "image": "postgres:15-alpine",
                    "zone": "data",
                    "criticality": "critical",
                    "function": "database-primary",
                    "pci_scope": True,
                    "customer_facing": False,
                },
                {
                    "id": "audit-log",
                    "type": "container",
                    "image": "mongo:7",
                    "zone": "data",
                    "criticality": "high",
                    "function": "audit-logging",
                    "customer_facing": False,
                },
            ],
            "compliance": ["pci-dss", "sox", "gdpr"],
        },
    }

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_config(
        self,
        industry: str,
        environment_name: str,
        environment_type: str = "production",
    ) -> Optional[Path]:
        """Generate environment configuration for an industry."""
        if industry not in self.INDUSTRY_TEMPLATES:
            print(f"Unknown industry: {industry}")
            print(f"Available: {', '.join(self.INDUSTRY_TEMPLATES.keys())}")
            return None

        template = self.INDUSTRY_TEMPLATES[industry]

        config = {
            "environment": {
                "name": environment_name,
                "type": environment_type,
                "cloud_provider": "aws",
                "region": "us-east-1",
                "compliance_requirements": template["compliance"],
                "owner": f"{industry}-team@example.com",
            },
            "global_business_context": {
                "organization": f"{industry.capitalize()} Corp",
                "business_unit": "engineering",
                "regulatory_requirements": template["compliance"],
                "risk_tolerance": "low",
                "incident_cost_estimates": {
                    "data_breach_per_record": 150.0,
                    "downtime_per_hour": 50000.0,
                    "reputation_damage": 1000000.0,
                },
            },
            "assets": [],
            "dependencies": [],
            "network_topology": {
                "zones": [
                    {
                        "id": "zone-dmz",
                        "name": "dmz",
                        "trust_level": "medium",
                        "internet_accessible": True,
                        "assets": [],
                    },
                    {
                        "id": "zone-internal",
                        "name": "internal",
                        "trust_level": "high",
                        "internet_accessible": False,
                        "assets": [],
                    },
                    {
                        "id": "zone-data",
                        "name": "data",
                        "trust_level": "high",
                        "internet_accessible": False,
                        "assets": [],
                    },
                ],
                "segmentation_rules": [
                    {
                        "from_zone": "zone-dmz",
                        "to_zone": "zone-internal",
                        "allowed": True,
                        "policy": "Allow HTTPS traffic from DMZ to internal zone",
                    },
                    {
                        "from_zone": "zone-internal",
                        "to_zone": "zone-data",
                        "allowed": True,
                        "policy": "Allow database connections from internal to data zone",
                    },
                ],
            },
        }

        # Build assets with full details
        for idx, asset_template in enumerate(template["assets"], start=1):
            asset = {
                "id": f"asset-{asset_template['id']}",
                "name": asset_template["id"].replace("-", " ").title(),
                "type": asset_template["type"],
                "host": f"10.0.{idx}.100",
                "software": {
                    "image": asset_template["image"],
                    "os": "Alpine Linux 3.18" if "alpine" in asset_template["image"] else "Debian 12",
                    "packages": [],
                },
                "network": {
                    "internal_ip": f"10.0.{idx}.100",
                    "zone": asset_template["zone"],
                    "exposed_ports": self._generate_ports(asset_template),
                },
                "business_context": {
                    "criticality": asset_template["criticality"],
                    "criticality_score": self._criticality_to_score(asset_template["criticality"]),
                    "function": asset_template["function"],
                    "data_classification": "pci" if asset_template.get("pci_scope") else "internal",
                    "revenue_impact": "critical" if asset_template["criticality"] == "critical" else "medium",
                    "customer_facing": asset_template["customer_facing"],
                    "pci_scope": asset_template.get("pci_scope", False),
                    "sla_tier": "tier-1" if asset_template["criticality"] == "critical" else "tier-2",
                    "mttr_target": 1 if asset_template["criticality"] == "critical" else 4,
                    "owner_team": f"{asset_template['function']}-team",
                },
            }
            config["assets"].append(asset)

        # Generate dependencies
        config["dependencies"] = self._generate_dependencies(config["assets"])

        # Save to file
        output_file = self.output_dir / f"{environment_name}-environment.json"
        with open(output_file, "w") as f:
            json.dump(config, f, indent=2)

        print(f"✓ Generated {industry} environment config: {output_file}")
        return output_file

    def _generate_ports(self, asset_template: Dict) -> List[Dict]:
        """Generate exposed ports based on asset function."""
        function = asset_template["function"]
        ports_map = {
            "web-frontend": [{"port": 443, "protocol": "https", "public": True}],
            "api-gateway": [{"port": 443, "protocol": "https", "public": True}],
            "application-server": [{"port": 8080, "protocol": "http", "public": False}],
            "application-backend": [{"port": 8000, "protocol": "http", "public": False}],
            "payment-processing": [{"port": 8443, "protocol": "https", "public": False}],
            "transaction-processing": [{"port": 8443, "protocol": "https", "public": False}],
            "database": [{"port": 5432, "protocol": "postgresql", "public": False}],
            "database-primary": [{"port": 5432, "protocol": "postgresql", "public": False}],
            "caching": [{"port": 6379, "protocol": "redis", "public": False}],
            "message-queue": [{"port": 5672, "protocol": "amqp", "public": False}],
        }
        return ports_map.get(function, [{"port": 8080, "protocol": "http", "public": False}])

    def _criticality_to_score(self, criticality: str) -> int:
        """Convert criticality level to score."""
        scores = {"critical": 95, "high": 75, "medium": 50, "low": 25}
        return scores.get(criticality, 50)

    def _generate_dependencies(self, assets: List[Dict]) -> List[Dict]:
        """Generate realistic dependencies between assets."""
        dependencies = []

        # Find assets by function
        assets_by_function = {}
        for asset in assets:
            func = asset["business_context"]["function"]
            assets_by_function[func] = asset["id"]

        # Common dependency patterns
        # Format: (from_function, to_function, dependency_type, protocol, port)
        patterns = [
            ("web-frontend", "application-server", "communicates_with", "https", 8080),
            ("web-frontend", "api-gateway", "communicates_with", "https", 443),
            ("api-gateway", "application-backend", "communicates_with", "https", 8000),
            ("application-server", "database", "reads_from", "postgresql", 5432),
            ("application-server", "caching", "reads_from", "redis", 6379),
            ("application-backend", "database", "reads_from", "postgresql", 5432),
            ("application-backend", "database-primary", "reads_from", "postgresql", 5432),
            ("application-backend", "message-queue", "writes_to", "amqp", 5672),
            ("payment-processing", "database", "writes_to", "postgresql", 5432),
            ("transaction-processing", "database-primary", "writes_to", "postgresql", 5432),
            ("transaction-processing", "fraud-detection", "communicates_with", "https", 8443),
            ("background-worker", "message-queue", "reads_from", "amqp", 5672),
        ]

        for from_func, to_func, dep_type, protocol, port in patterns:
            if from_func in assets_by_function and to_func in assets_by_function:
                dependencies.append(
                    {
                        "source": assets_by_function[from_func],
                        "target": assets_by_function[to_func],
                        "type": dep_type,
                        "protocol": protocol,
                        "port": port,
                        "criticality": "high",
                    }
                )

        return dependencies

    def generate_all_industries(self, environment_type: str = "production") -> List[Path]:
        """Generate configs for all industry templates."""
        results = []

        for industry in self.INDUSTRY_TEMPLATES.keys():
            env_name = f"{industry}-{environment_type}"
            output = self.generate_config(industry, env_name, environment_type)
            if output:
                results.append(output)

        return results


class TestDatasetBuilder:
    """Build complete test datasets with SBOMs and environment configs."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.sbom_dir = base_dir / "sboms"
        self.config_dir = base_dir / "configs"
        self.scans_dir = base_dir / "scans"

        for d in [self.sbom_dir, self.config_dir, self.scans_dir]:
            d.mkdir(exist_ok=True)

    def build_complete_dataset(
        self,
        industries: List[str],
        image_categories: List[str],
        limit_images_per_category: int = 2,
    ) -> Dict:
        """Build a complete test dataset."""
        print("\n" + "=" * 80)
        print("BUILDING REAL-WORLD TEST DATASET")
        print("=" * 80)

        results = {
            "timestamp": datetime.now().isoformat(),
            "industries": [],
            "image_scans": {},
            "configs": [],
        }

        # Generate environment configs
        print("\n1. Generating environment configurations...")
        config_gen = EnvironmentConfigGenerator(self.config_dir)

        for industry in industries:
            config_file = config_gen.generate_config(
                industry=industry,
                environment_name=f"{industry}-production",
                environment_type="production",
            )
            if config_file:
                results["configs"].append(str(config_file))
                results["industries"].append(industry)

        # Scan public images
        print("\n2. Scanning public Docker images...")
        image_scanner = PublicImageScanner(self.scans_dir)

        for category in image_categories:
            scan_results = image_scanner.scan_category(category, limit_images_per_category)
            results["image_scans"][category] = [str(f) for f in scan_results]

        # Generate summary
        self._generate_summary(results)

        return results

    def _generate_summary(self, results: Dict):
        """Generate summary report."""
        summary_file = self.base_dir / "dataset_summary.json"

        summary = {
            "generated_at": results["timestamp"],
            "dataset_location": str(self.base_dir),
            "statistics": {
                "total_industries": len(results["industries"]),
                "total_configs": len(results["configs"]),
                "total_image_categories": len(results["image_scans"]),
                "total_scans": sum(len(scans) for scans in results["image_scans"].values()),
            },
            "industries": results["industries"],
            "image_categories": list(results["image_scans"].keys()),
            "files": {
                "configs": results["configs"],
                "scans": results["image_scans"],
            },
        }

        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        print("\n" + "=" * 80)
        print("DATASET GENERATION COMPLETE")
        print("=" * 80)
        print(f"\nDataset location: {self.base_dir}")
        print(f"Summary file: {summary_file}")
        print(f"\nStatistics:")
        print(f"  Industries: {summary['statistics']['total_industries']}")
        print(f"  Environment configs: {summary['statistics']['total_configs']}")
        print(f"  Image scans: {summary['statistics']['total_scans']}")
        print(f"\nNext steps:")
        print(f"  1. Review configs: ls {self.config_dir}")
        print(f"  2. Review scans: ls {self.scans_dir}")
        print(f"  3. Build graphs:")
        for config in results["configs"][:3]:
            print(f"     threat-radar env build-graph {config} --auto-save")
        print(f"  4. Run analysis:")
        print(f"     threat-radar env analyze-risk <config> <scan> --auto-save")


def main():
    parser = argparse.ArgumentParser(
        description="Generate real-world test data from public sources"
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("./real-world-data"),
        help="Output directory for generated data",
    )

    parser.add_argument(
        "--industries",
        nargs="+",
        default=["ecommerce", "saas", "fintech"],
        help="Industries to generate configs for",
    )

    parser.add_argument(
        "--image-categories",
        nargs="+",
        default=["web_servers", "app_runtimes", "databases"],
        help="Image categories to scan",
    )

    parser.add_argument(
        "--limit-images",
        type=int,
        default=2,
        help="Limit number of images per category",
    )

    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick mode: minimal dataset for testing",
    )

    args = parser.parse_args()

    # Adjust for quick mode
    if args.quick:
        args.industries = ["ecommerce"]
        args.image_categories = ["web_servers"]
        args.limit_images = 1

    # Build dataset
    builder = TestDatasetBuilder(args.output)
    results = builder.build_complete_dataset(
        industries=args.industries,
        image_categories=args.image_categories,
        limit_images_per_category=args.limit_images,
    )


if __name__ == "__main__":
    main()
