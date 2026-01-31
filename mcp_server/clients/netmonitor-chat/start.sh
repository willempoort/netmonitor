#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort

# NetMonitor Chat - Development Quick Start Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}NetMonitor Chat - Development Setup${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo

# Check Python version
echo -e "${YELLOW}[1/6]${NC} Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || [ "$PYTHON_MINOR" -lt 10 ]; then
    echo -e "${RED}✗ Python 3.10+ required, found $PYTHON_VERSION${NC}"
    exit 1
fi

if [ "$PYTHON_MINOR" -eq 10 ]; then
    echo -e "${YELLOW}✓ Python $PYTHON_VERSION${NC}"
    echo -e "${YELLOW}  Tip: Python 3.11/3.12 is ~20% faster${NC}"
elif [ "$PYTHON_MINOR" -ge 14 ]; then
    echo -e "${YELLOW}⚠ Python $PYTHON_VERSION detected (bleeding edge)${NC}"
    echo -e "${YELLOW}  Pydantic/FastAPI may have build issues${NC}"
    echo -e "${YELLOW}  Recommended: Python 3.12 or 3.13${NC}"
    echo
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}✗ Aborted${NC}"
        echo
        echo "Create venv with Python 3.12:"
        echo "  python3.12 -m venv venv"
        exit 1
    fi
else
    echo -e "${GREEN}✓ Python $PYTHON_VERSION (optimal)${NC}"
fi

# Check if virtual environment exists
echo
echo -e "${YELLOW}[2/6]${NC} Checking virtual environment..."
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}  Creating virtual environment...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment exists${NC}"
fi

# Activate virtual environment
echo
echo -e "${YELLOW}[3/6]${NC} Activating virtual environment..."
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Install/upgrade dependencies
echo
echo -e "${YELLOW}[4/6]${NC} Installing dependencies..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Check .env file
echo
echo -e "${YELLOW}[5/6]${NC} Checking configuration..."
if [ ! -f ".env" ]; then
    echo -e "${RED}✗ .env file not found${NC}"
    echo
    echo "Please create .env file:"
    echo
    echo "cat > .env << 'EOF'"
    echo "OLLAMA_BASE_URL=http://localhost:11434"
    echo "MCP_SERVER_URL=https://soc.poort.net/mcp"
    echo "MCP_AUTH_TOKEN=your_token_here"
    echo "EOF"
    echo
    echo "chmod 600 .env"
    echo
    exit 1
fi

# Check MCP_AUTH_TOKEN is set
if grep -q "your_token_here" .env 2>/dev/null; then
    echo -e "${YELLOW}⚠ MCP_AUTH_TOKEN appears to be placeholder${NC}"
    echo -e "${YELLOW}  Make sure to set your actual token in .env${NC}"
fi

echo -e "${GREEN}✓ Configuration file exists${NC}"

# Check Ollama
echo
echo -e "${YELLOW}[6/6]${NC} Checking Ollama..."
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "${RED}✗ Ollama not running on localhost:11434${NC}"
    echo
    echo "Start Ollama with:"
    echo "  ollama serve &"
    echo
    echo "Then pull a model:"
    echo "  ollama pull llama3.1:8b"
    echo
    exit 1
fi

# Get model count
MODEL_COUNT=$(curl -s http://localhost:11434/api/tags | python3 -c "import sys, json; print(len(json.load(sys.stdin).get('models', [])))" 2>/dev/null || echo "0")
if [ "$MODEL_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}⚠ No models found${NC}"
    echo
    echo "Pull a model with:"
    echo "  ollama pull llama3.1:8b"
    echo
else
    echo -e "${GREEN}✓ Ollama running with $MODEL_COUNT model(s)${NC}"
fi

# All checks passed
echo
echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}✓ All checks passed!${NC}"
echo -e "${GREEN}======================================================================${NC}"
echo
echo -e "${BLUE}Starting NetMonitor Chat...${NC}"
echo
echo -e "Interface will be available at: ${GREEN}http://localhost:8000${NC}"
echo -e "Press ${YELLOW}Ctrl+C${NC} to stop"
echo
echo -e "${BLUE}======================================================================${NC}"
echo

# Start the application
python3 app.py
