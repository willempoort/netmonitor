#!/bin/bash
# Start Ollama-MCP-Bridge-WebUI for NetMonitor

echo "=========================================="
echo "Ollama-MCP-Bridge-WebUI for NetMonitor"
echo "=========================================="
echo ""

# Check if Ollama is running
if ! pgrep -x "ollama" > /dev/null 2>&1; then
    echo "⚠️  Ollama is not running"
    echo "Starting Ollama in background..."
    ollama serve > /dev/null 2>&1 &
    sleep 3
    echo "✅ Ollama started"
else
    echo "✅ Ollama is already running"
fi

# Check if config exists
if [ ! -f "bridge_config.json" ]; then
    echo "❌ ERROR: bridge_config.json not found"
    echo "Please create bridge_config.json first"
    exit 1
fi

# Check if Python bridge exists
if [ ! -f "mcp_bridge.py" ]; then
    echo "❌ ERROR: mcp_bridge.py not found"
    echo "Download from: scp root@soc.poort.net:/tmp/mcp_bridge.py ."
    exit 1
fi

# Check if npm modules are installed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing npm dependencies..."
    npm install
fi

# Build if needed
if [ ! -d "dist" ]; then
    echo "🔨 Building TypeScript..."
    npm run build
fi

echo ""
echo "🚀 Starting Ollama-MCP-Bridge-WebUI..."
echo "📍 WebUI: http://localhost:8080"
echo "🔧 Model: qwen2.5:14b"
echo "🛡️  MCP Server: https://soc.poort.net/mcp"
echo ""
echo "Press Ctrl+C to stop"
echo "=========================================="
echo ""

# Start the bridge
npm start
