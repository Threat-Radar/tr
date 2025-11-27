#!/usr/bin/env python3
"""
Simple JSON API server for Grafana JSON datasource plugin.
Serves Threat Radar dashboard data in the format Grafana expects.
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import json
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Path to dashboard data
DATA_FILE = Path("/data/dashboard-data.json")

def load_dashboard_data():
    """Load dashboard data from JSON file."""
    if DATA_FILE.exists():
        with open(DATA_FILE) as f:
            return json.load(f)
    return {}

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "ok", "message": "Threat Radar JSON API Server"})

@app.route('/search', methods=['POST'])
def search():
    """Return available metrics/targets."""
    return jsonify([
        {"text": "summary_cards", "value": "summary_cards"},
        {"text": "severity_distribution", "value": "severity_distribution"},
        {"text": "top_vulnerable_packages", "value": "top_vulnerable_packages"},
        {"text": "cvss_histogram", "value": "cvss_histogram"},
        {"text": "package_types", "value": "package_types"},
        {"text": "critical_items", "value": "critical_items"}
    ])

@app.route('/metrics', methods=['POST', 'GET'])
def metrics():
    """Return available metrics - alternative endpoint."""
    return search()

@app.route('/query', methods=['POST'])
def query():
    """Handle query requests from Grafana."""
    req = request.get_json()

    data = load_dashboard_data()
    results = []
    timestamp = int(datetime.now().timestamp() * 1000)

    for target in req.get('targets', []):
        target_name = target.get('target', '')

        if target_name == 'summary_cards':
            # Return summary cards as time series
            summary = data.get('summary_cards', {})
            for key, value in summary.items():
                results.append({
                    "target": key,
                    "datapoints": [[value, timestamp]]
                })

        elif target_name == 'severity_distribution':
            # Return severity distribution
            for item in data.get('severity_distribution_chart', []):
                results.append({
                    "target": item['severity'],
                    "datapoints": [[item['count'], timestamp]]
                })

        elif target_name == 'top_vulnerable_packages':
            # Return top packages
            for item in data.get('top_vulnerable_packages_chart', []):
                results.append({
                    "target": item['package'],
                    "datapoints": [[item['vulnerability_count'], timestamp]]
                })

        elif target_name == 'cvss_histogram':
            # Return CVSS histogram
            for item in data.get('cvss_score_histogram', []):
                results.append({
                    "target": item['score_range'],
                    "datapoints": [[item['count'], timestamp]]
                })

        elif target_name == 'package_types':
            # Return package type breakdown
            for item in data.get('package_type_breakdown', []):
                results.append({
                    "target": item['package_type'],
                    "datapoints": [[item['vulnerability_count'], timestamp]]
                })

        elif target_name == 'critical_items':
            # Return critical items as table
            critical = data.get('critical_items', [])[:20]
            results.append({
                "target": "critical_items",
                "type": "table",
                "columns": [
                    {"text": "CVE ID", "type": "string"},
                    {"text": "Severity", "type": "string"},
                    {"text": "CVSS", "type": "number"},
                    {"text": "Package", "type": "string"},
                    {"text": "Fix Available", "type": "string"}
                ],
                "rows": [
                    [
                        item['cve_id'],
                        item['severity'],
                        item.get('cvss_score', 0),
                        item['package'],
                        "Yes" if item['has_fix'] else "No"
                    ]
                    for item in critical
                ]
            })

    return jsonify(results)

@app.route('/annotations', methods=['POST'])
def annotations():
    """Handle annotations requests."""
    return jsonify([])

@app.route('/tag-keys', methods=['POST'])
def tag_keys():
    """Return available tag keys."""
    return jsonify([])

@app.route('/tag-values', methods=['POST'])
def tag_values():
    """Return tag values for a given key."""
    return jsonify([])

if __name__ == '__main__':
    print("Starting Threat Radar JSON API Server on port 8000...")
    print(f"Data file: {DATA_FILE}")
    print("Available endpoints:")
    print("  GET  /        - Health check")
    print("  POST /search  - List available metrics")
    print("  POST /metrics - List available metrics (alias)")
    print("  POST /query   - Query metric data")
    app.run(host='0.0.0.0', port=8000, debug=False)
