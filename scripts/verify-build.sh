#!/bin/bash

# Cerberus Build Verification Script
# Checks that all components are properly built and configured

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Cerberus Build Verification"
echo "============================"
echo ""

ERRORS=0

# Check Python files syntax
echo "Checking Python syntax..."
find . -name "*.py" -not -path "./.venv/*" -not -path "./venv/*" | while read file; do
    python3 -m py_compile "$file" 2>/dev/null || {
        echo -e "${RED}✗ Syntax error in: $file${NC}"
        ((ERRORS++))
    }
done

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ All Python files have valid syntax${NC}"
fi

# Check required directories
echo ""
echo "Checking directory structure..."
REQUIRED_DIRS=(
    "gatekeeper/api"
    "gatekeeper/ml"
    "switch/api"
    "labyrinth/app"
    "labyrinth/decoy_gen"
    "sentinel/api"
    "sentinel/profiler"
    "sentinel/simulator"
    "sentinel/rule_gen"
    "shared/events"
    "tests/unit"
    "tests/integration"
    "infrastructure/docker"
    "data/events"
    "data/captures"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo -e "${GREEN}✓ $dir${NC}"
    else
        echo -e "${RED}✗ Missing: $dir${NC}"
        ((ERRORS++))
    fi
done

# Check required files
echo ""
echo "Checking required files..."
REQUIRED_FILES=(
    "README.md"
    "QUICKSTART.md"
    "docker-compose.yml"
    "requirements.txt"
    "Makefile"
    "scripts/demo.sh"
    "gatekeeper/api/main.py"
    "switch/api/main.py"
    "labyrinth/app/main.py"
    "sentinel/api/main.py"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓ $file${NC}"
    else
        echo -e "${RED}✗ Missing: $file${NC}"
        ((ERRORS++))
    fi
done

# Check executable scripts
echo ""
echo "Checking executable permissions..."
if [ -x "scripts/demo.sh" ]; then
    echo -e "${GREEN}✓ demo.sh is executable${NC}"
else
    echo -e "${YELLOW}⚠ demo.sh needs chmod +x${NC}"
fi

if [ -x "scripts/panic.sh" ]; then
    echo -e "${GREEN}✓ panic.sh is executable${NC}"
else
    echo -e "${YELLOW}⚠ panic.sh needs chmod +x${NC}"
fi

# Check Docker
echo ""
echo "Checking Docker..."
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✓ Docker is installed${NC}"
    docker --version
else
    echo -e "${RED}✗ Docker not found${NC}"
    ((ERRORS++))
fi

if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
    echo -e "${GREEN}✓ Docker Compose is installed${NC}"
else
    echo -e "${RED}✗ Docker Compose not found${NC}"
    ((ERRORS++))
fi

# Check Python version
echo ""
echo "Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓ Python installed: $PYTHON_VERSION${NC}"
    
    # Check if version is 3.11+
    MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 11 ]; then
        echo -e "${GREEN}✓ Python version is 3.11+${NC}"
    else
        echo -e "${YELLOW}⚠ Python 3.11+ recommended (found $PYTHON_VERSION)${NC}"
    fi
else
    echo -e "${RED}✗ Python3 not found${NC}"
    ((ERRORS++))
fi

# Summary
echo ""
echo "============================"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ Build verification PASSED${NC}"
    echo ""
    echo "Ready to deploy! Run:"
    echo "  make build"
    echo "  make up"
    echo "  make demo"
else
    echo -e "${RED}✗ Build verification FAILED with $ERRORS errors${NC}"
    exit 1
fi
