#!/bin/bash
# ============================================================================
# NetMonitor Service Installation Script
# ============================================================================
# This script generates systemd service files from templates and installs them.
# It uses .env configuration and replaces __INSTALL_DIR__ placeholders.
#
# Usage:
#   sudo bash install_services.sh
#
# Requirements:
#   - Must be run as root (sudo)
#   - .env file should exist (created from .env.example)
#   - Service templates in services/ directory
# ============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================

echo_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

echo_header() {
    echo ""
    echo "============================================"
    echo "$1"
    echo "============================================"
    echo ""
}

# ============================================================================
# Preflight Checks
# ============================================================================

echo_header "NetMonitor Service Installation"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo_error "This script must be run as root"
    echo "Please run: sudo bash install_services.sh"
    exit 1
fi

# Detect installation directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$SCRIPT_DIR}"

echo_info "Installation directory: $INSTALL_DIR"

# Check if services directory exists
if [ ! -d "$INSTALL_DIR/services" ]; then
    echo_error "Services directory not found: $INSTALL_DIR/services"
    echo "Please ensure you're running this from the NetMonitor directory"
    exit 1
fi

echo ""

# ============================================================================
# Load Configuration from .env
# ============================================================================

echo_info "Loading configuration from .env..."

if [ -f "$INSTALL_DIR/.env" ]; then
    # Export all variables from .env
    set -a  # Automatically export all variables
    source "$INSTALL_DIR/.env"
    set +a
    echo_success "Configuration loaded from .env"
else
    echo_warning "No .env file found - using defaults"
    echo_info "To customize configuration:"
    echo "  cp $INSTALL_DIR/.env.example $INSTALL_DIR/.env"
    echo "  nano $INSTALL_DIR/.env"
    echo ""
fi

# Set defaults if not in .env
DASHBOARD_SERVER="${DASHBOARD_SERVER:-embedded}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"
MCP_API_ENABLED="${MCP_API_ENABLED:-false}"
MCP_API_PORT="${MCP_API_PORT:-8000}"
LOG_DIR="${LOG_DIR:-/var/log/netmonitor}"
RUN_DIR="${RUN_DIR:-/var/run/netmonitor}"
DATA_DIR="${DATA_DIR:-/var/lib/netmonitor}"
CACHE_DIR="${CACHE_DIR:-/var/cache/netmonitor}"

echo ""
echo "Configuration Summary:"
echo "  Dashboard server: $DASHBOARD_SERVER"
echo "  Dashboard port:   $DASHBOARD_PORT"
echo "  MCP API enabled:  $MCP_API_ENABLED"
echo "  MCP API port:     $MCP_API_PORT"
echo ""

# ============================================================================
# Create Required Directories
# ============================================================================

echo_info "Creating required directories..."

for dir in "$LOG_DIR" "$RUN_DIR" "$DATA_DIR" "$CACHE_DIR"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        chown root:root "$dir"
        chmod 755 "$dir"
        echo_success "Created: $dir"
    fi
done

echo ""

# ============================================================================
# Service Template Generation
# ============================================================================

generate_service() {
    local template_file="$1"
    local output_file="$2"
    local service_name="$(basename "$output_file" .service)"

    if [ ! -f "$template_file" ]; then
        echo_warning "Template not found: $template_file"
        return 1
    fi

    echo_info "Generating $service_name..."

    # Replace __INSTALL_DIR__ placeholder
    sed "s|__INSTALL_DIR__|$INSTALL_DIR|g" "$template_file" > "$output_file"

    # Set permissions
    chmod 644 "$output_file"
    chown root:root "$output_file"

    echo_success "$service_name generated"
    return 0
}

echo_header "Generating Service Files from Templates"

SERVICES_INSTALLED=0

# 1. Main NetMonitor Service (always install)
if generate_service \
    "$INSTALL_DIR/services/netmonitor.service.template" \
    "/etc/systemd/system/netmonitor.service"; then
    ((SERVICES_INSTALLED++))
fi

# 2. Dashboard Service (only if using gunicorn)
if [ "$DASHBOARD_SERVER" = "gunicorn" ]; then
    echo_info "Dashboard server mode is 'gunicorn' - installing separate dashboard service"
    if generate_service \
        "$INSTALL_DIR/services/netmonitor-dashboard.service.template" \
        "/etc/systemd/system/netmonitor-dashboard.service"; then
        ((SERVICES_INSTALLED++))
    fi
else
    echo_info "Dashboard server mode is 'embedded' - dashboard runs within netmonitor.service"
fi

# 3. MCP HTTP API Service (only if enabled)
if [ "$MCP_API_ENABLED" = "true" ]; then
    echo_info "MCP HTTP API enabled - installing MCP service"
    if generate_service \
        "$INSTALL_DIR/services/netmonitor-mcp-http.service.template" \
        "/etc/systemd/system/netmonitor-mcp-http.service"; then
        ((SERVICES_INSTALLED++))
    fi
else
    echo_info "MCP HTTP API disabled (set MCP_API_ENABLED=true in .env to enable)"
fi

# 4. Feed Update Service (always install)
if generate_service \
    "$INSTALL_DIR/services/netmonitor-feed-update.service.template" \
    "/etc/systemd/system/netmonitor-feed-update.service"; then
    ((SERVICES_INSTALLED++))
fi

# 5. Feed Update Timer
if generate_service \
    "$INSTALL_DIR/services/netmonitor-feed-update.timer.template" \
    "/etc/systemd/system/netmonitor-feed-update.timer"; then
    echo_success "Feed update timer installed"
fi

echo ""
echo_success "$SERVICES_INSTALLED service(s) generated successfully"
echo ""

# ============================================================================
# Systemd Reload
# ============================================================================

echo_info "Reloading systemd daemon..."
systemctl daemon-reload
echo_success "Systemd daemon reloaded"
echo ""

# ============================================================================
# Service Enablement
# ============================================================================

echo_header "Service Enablement"

echo "Which services would you like to enable and start?"
echo ""

enable_service() {
    local service_name="$1"
    local service_description="$2"
    local auto_enable="${3:-false}"

    if [ ! -f "/etc/systemd/system/$service_name" ]; then
        return 0  # Service not installed, skip
    fi

    if [ "$auto_enable" = "true" ]; then
        # Auto-enable without prompting
        systemctl enable "$service_name" 2>/dev/null || true
        systemctl start "$service_name" 2>/dev/null || true
        echo_success "$service_description enabled and started"
    else
        # Prompt user
        read -p "Enable and start $service_description? (Y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            systemctl enable "$service_name"
            systemctl start "$service_name"
            echo_success "$service_description enabled and started"
        else
            echo_info "$service_description skipped"
        fi
    fi
    echo ""
}

# Enable main service
enable_service "netmonitor.service" "NetMonitor Main Service"

# Enable dashboard service (if installed)
if [ "$DASHBOARD_SERVER" = "gunicorn" ]; then
    enable_service "netmonitor-dashboard.service" "Web Dashboard (Gunicorn)"
fi

# Enable MCP HTTP API (if installed)
if [ "$MCP_API_ENABLED" = "true" ]; then
    enable_service "netmonitor-mcp-http.service" "MCP HTTP API"
fi

# Enable feed update timer
enable_service "netmonitor-feed-update.timer" "Threat Feed Update Timer"

# ============================================================================
# Installation Summary
# ============================================================================

echo_header "Installation Complete"

echo "Service Status:"
echo ""

show_service_status() {
    local service_name="$1"
    if [ -f "/etc/systemd/system/$service_name" ]; then
        echo "--- $(basename "$service_name" .service) ---"
        systemctl status "$service_name" --no-pager --lines=3 || true
        echo ""
    fi
}

show_service_status "netmonitor.service"
[ "$DASHBOARD_SERVER" = "gunicorn" ] && show_service_status "netmonitor-dashboard.service"
[ "$MCP_API_ENABLED" = "true" ] && show_service_status "netmonitor-mcp-http.service"
show_service_status "netmonitor-feed-update.timer"

echo ""
echo_header "Next Steps"

echo "1. Review service logs:"
echo "   sudo journalctl -u netmonitor -f"
echo ""

if [ "$DASHBOARD_SERVER" = "embedded" ]; then
    echo "2. Access Web Dashboard:"
    echo "   http://localhost:$DASHBOARD_PORT"
    echo "   https://$(hostname -f 2>/dev/null || echo 'your-server')"
    echo ""
elif [ "$DASHBOARD_SERVER" = "gunicorn" ]; then
    echo "2. Access Web Dashboard (Gunicorn):"
    echo "   http://localhost:$DASHBOARD_PORT"
    echo "   Logs: sudo journalctl -u netmonitor-dashboard -f"
    echo ""
fi

if [ "$MCP_API_ENABLED" = "true" ]; then
    echo "3. MCP HTTP API:"
    echo "   http://localhost:$MCP_API_PORT/docs (API documentation)"
    echo "   Logs: sudo journalctl -u netmonitor-mcp-http -f"
    echo ""
fi

echo "Useful Commands:"
echo "  systemctl status netmonitor        # Check main service"
echo "  systemctl restart netmonitor       # Restart monitoring"
echo "  journalctl -u netmonitor -f        # Follow logs"
echo ""
echo "  systemctl list-timers              # Check feed update timer"
echo "  systemctl start netmonitor-feed-update.service  # Manual feed update"
echo ""

echo_header "Installation Successful"
