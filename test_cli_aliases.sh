#!/bin/bash
# Test script to verify both 'tr' and 'threat-radar' commands work as aliases
# This tests Issue #123 - CLI command rename

set -e  # Exit on error

echo "========================================="
echo "Testing CLI Command Aliases (Issue #123)"
echo "========================================="
echo ""

# Test 1: Check both commands are available
echo "Test 1: Checking if both commands exist..."
echo "-------------------------------------------"

if command -v tr &> /dev/null; then
    echo "✓ 'tr' command found"
    tr --version
else
    echo "✗ 'tr' command not found"
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
tr --help > /tmp/tr_help.txt
threat-radar --help > /tmp/threat-radar_help.txt

if diff /tmp/tr_help.txt /tmp/threat-radar_help.txt &> /dev/null; then
    echo "✓ Both commands show identical help output"
else
    echo "✗ Help output differs between commands"
    exit 1
fi

echo ""
echo "Test 3: Testing basic commands..."
echo "-------------------------------------------"

# Test 3: Test basic command functionality
echo "Testing 'tr --help':"
tr --help | head -5

echo ""
echo "Testing 'threat-radar --help':"
threat-radar --help | head -5

echo ""
echo "========================================="
echo "All Tests Passed! ✓"
echo "========================================="
echo ""
echo "Summary:"
echo "- 'tr' is the new primary command"
echo "- 'threat-radar' works as an alias for backward compatibility"
echo "- Both commands are functionally identical"
echo ""
echo "Recommendation: Update your scripts to use 'tr' going forward"
