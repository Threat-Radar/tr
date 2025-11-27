#!/bin/bash
# Quick start script for Grafana dashboard

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Threat Radar - Grafana Dashboard Startup                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running"
    echo "   Please start Docker Desktop and try again"
    exit 1
fi

echo "✓ Docker is running"
echo ""

# Check if dashboard data exists
if [ ! -f "../full-demo-results/08-reports/dashboard-data.json" ]; then
    echo "⚠️  Warning: dashboard-data.json not found"
    echo "   Run the microservices demo first to generate data:"
    echo "   cd .. && ./00-run-all-services.sh"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "Starting Grafana and JSON server..."
docker-compose up -d

echo ""
echo "Waiting for services to be ready..."
sleep 5

# Check if Grafana is up
if curl -s http://localhost:3000/api/health > /dev/null; then
    echo "✓ Grafana is running"
else
    echo "⚠️  Grafana may still be starting..."
fi

# Check if JSON server is up
if curl -s http://localhost:8000/dashboard-data.json > /dev/null; then
    echo "✓ JSON server is running"
else
    echo "⚠️  JSON server may still be starting..."
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Grafana Dashboard Ready!                                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Access the dashboard:"
echo "  🌐 URL: http://localhost:3000"
echo "  👤 Username: admin"
echo ""
echo "Direct dashboard link:"
echo "  http://localhost:3000/d/threat-radar-vuln-dashboard"
echo ""
echo "To stop:"
echo "  docker-compose down"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f"
echo ""
