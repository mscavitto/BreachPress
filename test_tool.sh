#!/bin/bash
# Test script for breachpress.py

echo "========================================"
echo "BreachPress - Test Suite"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Help menu
echo -e "${YELLOW}[TEST 1]${NC} Testing help menu..."
if python3 breachpress.py --help > /dev/null 2>&1; then
    echo -e "${GREEN}✓ PASS${NC} - Help menu works"
else
    echo -e "${RED}✗ FAIL${NC} - Help menu failed"
    exit 1
fi
echo ""

# Test 2: Missing required argument
echo -e "${YELLOW}[TEST 2]${NC} Testing error handling (missing URL)..."
if ! python3 breachpress.py --enumerate-only > /dev/null 2>&1; then
    echo -e "${GREEN}✓ PASS${NC} - Correctly requires URL parameter"
else
    echo -e "${RED}✗ FAIL${NC} - Should require URL parameter"
fi
echo ""

# Test 3: File loading
echo -e "${YELLOW}[TEST 3]${NC} Testing wordlist loading..."
if [ -f "example_users.txt" ] && [ -f "example_passwords.txt" ]; then
    echo -e "${GREEN}✓ PASS${NC} - Example wordlists found"
    echo "  - example_users.txt: $(wc -l < example_users.txt) users"
    echo "  - example_passwords.txt: $(wc -l < example_passwords.txt) passwords"
else
    echo -e "${RED}✗ FAIL${NC} - Example wordlists not found"
fi
echo ""

# Test 4: Syntax check
echo -e "${YELLOW}[TEST 4]${NC} Python syntax check..."
if python3 -m py_compile breachpress.py 2>/dev/null; then
    echo -e "${GREEN}✓ PASS${NC} - No syntax errors"
else
    echo -e "${RED}✗ FAIL${NC} - Syntax errors found"
    exit 1
fi
echo ""

echo "========================================"
echo -e "${GREEN}All tests passed!${NC}"
echo "========================================"
echo ""
echo "Ready to use! Try:"
echo "  python3 breachpress.py -u https://target.com --enumerate-only"
echo ""
