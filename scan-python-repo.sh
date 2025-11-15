#!/bin/bash
# scan-python-repo.sh - Comprehensive Python repository vulnerability scanning

set -e

REPO_PATH="${1:-.}"
echo "Scanning Python repository: $REPO_PATH"
echo ""

# Step 1: Generate clean requirements file with installed versions
echo "Step 1: Generating pinned requirements..."
if [ -d "$REPO_PATH/venv" ] || [ -d "$REPO_PATH/.venv" ]; then
    echo "  Found virtual environment, using installed packages..."

    # Activate venv if it exists
    if [ -d "$REPO_PATH/venv" ]; then
        source "$REPO_PATH/venv/bin/activate"
    elif [ -d "$REPO_PATH/.venv" ]; then
        source "$REPO_PATH/.venv/bin/activate"
    fi

    # Generate pinned requirements from installed packages
    pip freeze > requirements-scan.txt
    echo "  ✓ Generated requirements-scan.txt with $(wc -l < requirements-scan.txt) packages"
else
    echo "  No virtual environment found, using requirements.txt..."
    if [ -f "$REPO_PATH/requirements.txt" ]; then
        # Extract only pinned dependencies
        grep -E "^[a-zA-Z0-9_-]+==.+" "$REPO_PATH/requirements.txt" > requirements-scan.txt || true
        echo "  ✓ Extracted $(wc -l < requirements-scan.txt) pinned packages"
    else
        echo "  ⚠️  No requirements.txt found!"
        exit 1
    fi
fi

# Step 2: Generate SBOM using Syft
echo ""
echo "Step 2: Generating SBOM..."
threat-radar sbom generate "$REPO_PATH" -o sbom.json --auto-save
echo "  ✓ SBOM generated"

# Step 3: View SBOM statistics
echo ""
echo "Step 3: SBOM Statistics:"
threat-radar sbom stats sbom.json

# Step 4: List Python packages found
echo ""
echo "Step 4: Python packages detected:"
threat-radar sbom components sbom.json --language python | head -20

# Step 5: Scan for vulnerabilities
echo ""
echo "Step 5: Scanning for vulnerabilities..."
threat-radar cve scan-directory "$REPO_PATH" --auto-save -o scan.json

# Step 6: Alternative - scan the SBOM directly
echo ""
echo "Step 6: Scanning SBOM for vulnerabilities..."
threat-radar cve scan-sbom sbom.json --auto-save -o scan-from-sbom.json

# Step 7: Show summary
echo ""
echo "======================================"
echo "Scan Complete!"
echo "======================================"
echo ""
echo "Results:"
echo "  - SBOM: sbom.json"
echo "  - Directory scan: scan.json"
echo "  - SBOM scan: scan-from-sbom.json"
echo ""

# Show vulnerability summary if jq is available
if command -v jq &> /dev/null; then
    echo "Vulnerability Summary (from directory scan):"
    jq -r '.matches | length as $total |
           (.matches | group_by(.vulnerability.severity) |
            map({severity: .[0].vulnerability.severity, count: length}) |
            .[] | "  \(.severity): \(.count)") // "No vulnerabilities found"' scan.json
fi

echo ""
echo "Next steps:"
echo "  1. View detailed results: cat scan.json | jq"
echo "  2. Build graph: threat-radar graph build scan.json -o graph.graphml"
echo "  3. Generate report: threat-radar report generate scan.json -o report.html -f html"
echo "  4. Run threat modeling: threat-radar graph attack-paths graph.graphml -o attack-paths.json"
