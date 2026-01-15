#!/bin/bash
# Quick Start Script voor Open-WebUI met NetMonitor MCP

set -e

echo "========================================"
echo "Open-WebUI + NetMonitor MCP Setup"
echo "========================================"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker niet gevonden. Installeer eerst Docker:"
    echo "   curl -fsSL https://get.docker.com | sh"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose niet gevonden. Installeer eerst docker-compose:"
    echo "   sudo apt-get install docker-compose-plugin"
    exit 1
fi

echo "✅ Docker found: $(docker --version)"
echo ""

# Check Ollama
echo "Checking Ollama..."
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama is running"
    MODELS=$(curl -s http://localhost:11434/api/tags | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | head -3)
    echo "   Available models:"
    echo "$MODELS" | while read model; do
        echo "   - $model"
    done
else
    echo "⚠️  Ollama not responding on :11434"
    echo "   Start Ollama: ollama serve &"
    echo "   Pull a model: ollama pull llama3.1:8b"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi
echo ""

# Check if already running
if docker ps | grep -q open-webui-mcp; then
    echo "⚠️  Open-WebUI is already running"
    read -p "Restart? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Stopping existing container..."
        docker-compose down
    else
        echo "Keeping existing container running"
        echo "Access at: http://localhost:3000"
        exit 0
    fi
fi

# Create data directory
mkdir -p data
echo "✅ Data directory created"
echo ""

# Check MCP bridge
if [ ! -f "mcp/mcp_bridge.py" ]; then
    echo "❌ mcp_bridge.py not found in mcp/"
    exit 1
fi
echo "✅ MCP bridge found"
echo ""

# Start docker-compose
echo "Starting Open-WebUI..."
docker-compose up -d

echo ""
echo "Waiting for container to be healthy..."
sleep 5

# Check health
for i in {1..30}; do
    if docker ps | grep -q "(healthy).*open-webui-mcp"; then
        echo "✅ Container is healthy!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "⚠️  Container took longer than expected to start"
        echo "   Check logs: docker-compose logs"
    fi
    sleep 2
done

echo ""
echo "========================================"
echo "✅ Open-WebUI Started Successfully!"
echo "========================================"
echo ""
echo "📍 Access: http://localhost:3000"
echo ""
echo "First time setup:"
echo "  1. Create admin account"
echo "  2. Configure Ollama: http://host.docker.internal:11434"
echo "  3. Enable MCP in Settings → Admin Settings → MCP"
echo "  4. Select a model and start chatting!"
echo ""
echo "Test with: 'Laat recente bedreigingen zien'"
echo ""
echo "View logs:    docker-compose logs -f"
echo "Stop:         docker-compose down"
echo "Restart:      docker-compose restart"
echo ""
