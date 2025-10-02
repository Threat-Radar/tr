#!/bin/bash
# Docker CLI command examples for Threat Radar
# Note: Use 'tradar' or 'threat-radar' command (not 'tr' which conflicts with Unix translate)

echo "=========================================="
echo "Threat Radar Docker CLI Examples"
echo "=========================================="

echo -e "\n1. Import and analyze an Alpine image"
echo "Command: tradar docker import-image alpine:3.18"
# tradar docker import-image alpine:3.18

echo -e "\n2. Import Ubuntu with specific tag"
echo "Command: tradar docker import-image ubuntu --tag 22.04"
# tradar docker import-image ubuntu --tag 22.04

echo -e "\n3. Scan a local image (without pulling)"
echo "Command: tradar docker scan alpine:3.18"
# tradar docker scan alpine:3.18

echo -e "\n4. Import and save results to JSON"
echo "Command: tradar docker import-image debian:12 --output debian_analysis.json"
# tradar docker import-image debian:12 --output debian_analysis.json

echo -e "\n5. Scan and save results"
echo "Command: tradar docker scan ubuntu:22.04 --output ubuntu_scan.json"
# tradar docker scan ubuntu:22.04 --output ubuntu_scan.json

echo -e "\n6. List all Docker images"
echo "Command: tradar docker list-images"
# tradar docker list-images

echo -e "\n7. Show packages in an image"
echo "Command: tradar docker packages alpine:3.18"
# tradar docker packages alpine:3.18

echo -e "\n8. Show limited number of packages"
echo "Command: tradar docker packages ubuntu:22.04 --limit 20"
# tradar docker packages ubuntu:22.04 --limit 20

echo -e "\n9. Filter packages by name"
echo "Command: tradar docker packages alpine:3.18 --filter ssl"
# tradar docker packages alpine:3.18 --filter ssl

echo -e "\n10. Filter and limit packages"
echo "Command: tradar docker packages ubuntu:22.04 --filter python --limit 10"
# tradar docker packages ubuntu:22.04 --filter python --limit 10

echo -e "\n=========================================="
echo "Advanced Usage Examples"
echo "=========================================="

echo -e "\n11. Analyze multiple images in sequence"
echo "Commands:"
echo "  tradar docker import-image alpine:3.18 --output alpine.json"
echo "  tradar docker import-image ubuntu:22.04 --output ubuntu.json"
echo "  tradar docker import-image debian:12 --output debian.json"
# tradar docker import-image alpine:3.18 --output alpine.json
# tradar docker import-image ubuntu:22.04 --output ubuntu.json
# tradar docker import-image debian:12 --output debian.json

echo -e "\n12. Find security-related packages"
echo "Command: tradar docker packages ubuntu:22.04 --filter security"
# tradar docker packages ubuntu:22.04 --filter security

echo -e "\n13. Find SSL/TLS related packages"
echo "Command: tradar docker packages debian:12 --filter ssl"
# tradar docker packages debian:12 --filter ssl

echo -e "\n14. Analyze custom images"
echo "Command: tradar docker scan my-app:latest --output my-app-analysis.json"
# tradar docker scan my-app:latest --output my-app-analysis.json

echo -e "\n15. Import from different registries"
echo "Command: tradar docker import-image gcr.io/distroless/base --output distroless.json"
# tradar docker import-image gcr.io/distroless/base --output distroless.json

echo -e "\n=========================================="
echo "Note: Uncomment commands (remove #) to run them"
echo "Make sure Docker daemon is running before executing"
echo "=========================================="
