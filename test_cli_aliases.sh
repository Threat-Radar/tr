#!/bin/bash
# Test script to verify both 'tradar' and 'threat-radar' commands work as aliases
# This tests Issue #126 - Fix CLI command from 'tr' to 'tradar' (Unix tr conflict)

set -e  # Exit on error

echo "========================================="
echo "Testing CLI Command Aliases (Issue #126)"
echo "========================================="
echo ""

# Test 1: Check both commands are available
echo "Test 1: Checking if both commands exist..."
echo "-------------------------------------------"

if command -v tradar &> /dev/null; then
    echo "✓ 'tradar' command found"
    tradar --version
else
    echo "✗ 'tradar' command not found"
    exit 1
fi

echo ""

if command -v threat-radar &> /dev/null; then
    echo "✓ 'threat-radar' command found (backward compatibility)"
    threat-radar --version
else
    echo "✗ 'threat-radar' command not found"
    exit 1
fi

echo ""
echo "Test 2: Comparing help output..."
echo "-------------------------------------------"

# Test 2: Verify both commands show same help
tradar --help > /tmp/tradar_help.txt
threat-radar --help > /tmp/threat-radar_help.txt

if diff /tmp/tradar_help.txt /tmp/threat-radar_help.txt &> /dev/null; then
    echo "✓ Both commands show identical help output"
else
    echo "✗ Help output differs between commands"
    exit 1
fi

echo ""
echo "Test 3: Testing basic commands..."
echo "-------------------------------------------"

# Test 3: Test basic command functionality
echo "Testing 'tradar --help':"
tradar --help | head -5

echo ""
echo "Testing 'threat-radar --help':"
threat-radar --help | head -5

echo ""
echo "========================================="
echo "All Tests Passed! ✓"
echo "========================================="
echo ""
echo "Summary:"
echo "- 'tradar' is the new primary command (no Unix tr conflict)"
echo "- 'threat-radar' works as an alias for backward compatibility"
echo "- Both commands are functionally identical"
echo ""
echo "Recommendation: Update your scripts to use 'tradar' going forward"
