#!/bin/bash
# Memory Management Tool for NetMonitor SOC Server
# Usage: ./memory_flush.sh [status|flush]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="${SOC_SERVER_URL:-http://localhost:8080}"

show_help() {
    echo "NetMonitor Memory Management Tool"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  status    Show current memory usage"
    echo "  flush     Trigger emergency memory flush"
    echo "  help      Show this help message"
    echo ""
    echo "Environment:"
    echo "  SOC_SERVER_URL    Server URL (default: http://localhost:8080)"
    echo ""
}

check_status() {
    echo "Fetching memory status from $BASE_URL..."
    curl -s "${BASE_URL}/api/internal/memory/status" | jq '.'
}

trigger_flush() {
    echo "Triggering memory flush on $BASE_URL..."
    echo ""

    # Get before status
    echo "=== BEFORE FLUSH ==="
    curl -s "${BASE_URL}/api/internal/memory/status" | jq '.memory.system, .memory.process'
    echo ""

    # Trigger flush
    echo "=== FLUSHING ==="
    RESULT=$(curl -s -X POST "${BASE_URL}/api/internal/memory/flush")
    echo "$RESULT" | jq '.'
    echo ""

    # Wait a moment
    sleep 2

    # Get after status
    echo "=== AFTER FLUSH ==="
    curl -s "${BASE_URL}/api/internal/memory/status" | jq '.memory.system, .memory.process'
}

# Main
case "${1:-status}" in
    status)
        check_status
        ;;
    flush)
        trigger_flush
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
