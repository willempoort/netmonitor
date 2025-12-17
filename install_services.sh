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
DASHBOARD_HOST="${DASHBOARD_HOST:-0.0.0.0}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"
DASHBOARD_WORKERS="${DASHBOARD_WORKERS:-4}"
MCP_API_ENABLED="${MCP_API_ENABLED:-false}"
MCP_API_PORT="${MCP_API_PORT:-8000}"
LOG_DIR="${LOG_DIR:-/var/log/netmonitor}"
LOG_LEVEL="${LOG_LEVEL:-info}"
RUN_DIR="${RUN_DIR:-/var/run/netmonitor}"
DATA_DIR="${DATA_DIR:-/var/lib/netmonitor}"
CACHE_DIR="${CACHE_DIR:-/var/cache/netmonitor}"

# Ensure critical variables exist in .env for systemd service
# Systemd reads EnvironmentFile and needs these variables defined
if [ -f "$INSTALL_DIR/.env" ]; then
    for var in DASHBOARD_HOST DASHBOARD_PORT DASHBOARD_WORKERS LOG_DIR LOG_LEVEL RUN_DIR DATA_DIR CACHE_DIR; do
        if ! grep -q "^${var}=" "$INSTALL_DIR/.env"; then
            eval "echo \"${var}=\${$var}\" >> \"$INSTALL_DIR/.env\""
            echo_info "Added default ${var} to .env"
        fi
    done
fi

echo ""
echo "Configuration Summary:"
echo "  Dashboard server: $DASHBOARD_SERVER"
echo "  Dashboard host:   $DASHBOARD_HOST"
echo "  Dashboard port:   $DASHBOARD_PORT"
echo "  Dashboard workers: $DASHBOARD_WORKERS"
echo "  MCP API enabled:  $MCP_API_ENABLED"
echo "  MCP API port:     $MCP_API_PORT"
echo "  Log directory:    $LOG_DIR"
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
    else
        # Directory exists, ensure correct permissions
        chown root:root "$dir" 2>/dev/null || true
        chmod 755 "$dir" 2>/dev/null || true
    fi
done

# Explicitly ensure /var/run/netmonitor exists for gunicorn PID file
# /var/run is often a symlink to /run on modern systems
if [ ! -d "/var/run/netmonitor" ]; then
    if [ -L "/var/run" ]; then
        # /var/run is a symlink to /run
        mkdir -p "/run/netmonitor"
        chown root:root "/run/netmonitor"
        chmod 755 "/run/netmonitor"
        echo_success "Created: /run/netmonitor (symlinked from /var/run/netmonitor)"
    else
        # /var/run is a real directory
        mkdir -p "/var/run/netmonitor"
        chown root:root "/var/run/netmonitor"
        chmod 755 "/var/run/netmonitor"
        echo_success "Created: /var/run/netmonitor"
    fi
else
    chown root:root "/var/run/netmonitor" 2>/dev/null || true
    chmod 755 "/var/run/netmonitor" 2>/dev/null || true
fi

echo ""

# ============================================================================
# Service Cleanup (Legacy/Orphaned Services)
# ============================================================================

echo_header "Cleaning Up Old/Legacy Services"

cleanup_service() {
    local service_name="$1"
    local reason="$2"

    if systemctl list-unit-files | grep -q "^$service_name"; then
        echo_info "Found legacy service: $service_name"
        echo_warning "Reason: $reason"

        # Stop service if running
        if systemctl is-active --quiet "$service_name"; then
            echo_info "Stopping $service_name..."
            systemctl stop "$service_name" 2>/dev/null || true
        fi

        # Disable service if enabled
        if systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
            echo_info "Disabling $service_name..."
            systemctl disable "$service_name" 2>/dev/null || true
        fi

        # Remove service file
        if [ -f "/etc/systemd/system/$service_name" ]; then
            echo_info "Removing /etc/systemd/system/$service_name..."
            rm -f "/etc/systemd/system/$service_name"
            echo_success "$service_name removed"
        fi
    fi
}

# Cleanup old/renamed services
# Add any legacy service names here that should be removed
LEGACY_SERVICES=()

# If switching FROM embedded TO gunicorn, no cleanup needed (dashboard just moves)
# If switching FROM gunicorn TO embedded, cleanup dashboard service
if [ "$DASHBOARD_SERVER" = "embedded" ]; then
    if systemctl list-unit-files | grep -q "^netmonitor-dashboard.service"; then
        echo_warning "Switching from gunicorn to embedded mode"
        cleanup_service "netmonitor-dashboard.service" "Switching to embedded dashboard (dashboard now runs in netmonitor.service)"
    fi
fi

# Cleanup any legacy services
for legacy_service in "${LEGACY_SERVICES[@]}"; do
    cleanup_service "$legacy_service" "Legacy service, replaced by current architecture"
done

# Reload systemd after cleanup
if [ ${#LEGACY_SERVICES[@]} -gt 0 ] || [ "$DASHBOARD_SERVER" = "embedded" ]; then
    echo_info "Reloading systemd after cleanup..."
    systemctl daemon-reload
    echo ""
fi

echo_success "Service cleanup completed"
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

    # Detect gunicorn binary path for dashboard service
    local gunicorn_bin=""
    if [[ "$template_file" == *"dashboard"* ]]; then
        # Try to find gunicorn in common locations (priority order)
        if [ -x "$INSTALL_DIR/venv/bin/gunicorn" ]; then
            gunicorn_bin="$INSTALL_DIR/venv/bin/gunicorn"
        elif [ -x "/usr/bin/gunicorn" ]; then
            gunicorn_bin="/usr/bin/gunicorn"
        elif [ -x "/usr/local/bin/gunicorn" ]; then
            gunicorn_bin="/usr/local/bin/gunicorn"
        elif command -v gunicorn >/dev/null 2>&1; then
            gunicorn_bin="$(command -v gunicorn)"
        else
            echo_warning "Gunicorn not found! Install with: pip install gunicorn"
            gunicorn_bin="/usr/bin/gunicorn"  # Fallback
        fi
        echo_info "Using gunicorn at: $gunicorn_bin"
    fi

    # Replace placeholders
    sed -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" \
        -e "s|__GUNICORN_BIN__|$gunicorn_bin|g" \
        "$template_file" > "$output_file"

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
    SERVICES_INSTALLED=$((SERVICES_INSTALLED + 1))
fi

# 2. Dashboard Service (only if using gunicorn)
if [ "$DASHBOARD_SERVER" = "gunicorn" ]; then
    echo_info "Dashboard server mode is 'gunicorn' - installing separate dashboard service"
    if generate_service \
        "$INSTALL_DIR/services/netmonitor-dashboard.service.template" \
        "/etc/systemd/system/netmonitor-dashboard.service"; then
        SERVICES_INSTALLED=$((SERVICES_INSTALLED + 1))
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
        SERVICES_INSTALLED=$((SERVICES_INSTALLED + 1))
    fi
else
    echo_info "MCP HTTP API disabled (set MCP_API_ENABLED=true in .env to enable)"
fi

# 4. Feed Update Service (always install)
if generate_service \
    "$INSTALL_DIR/services/netmonitor-feed-update.service.template" \
    "/etc/systemd/system/netmonitor-feed-update.service"; then
    SERVICES_INSTALLED=$((SERVICES_INSTALLED + 1))
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

# Check if running in auto-confirm mode (used by install_complete.sh)
AUTO_ENABLE="false"
if [ "$AUTO_CONFIRM" = "yes" ] || [ "$AUTO_CONFIRM" = "true" ]; then
    AUTO_ENABLE="true"
    echo_info "Running in auto-confirm mode - services will be enabled automatically"
    echo ""
fi

# Enable main service
enable_service "netmonitor.service" "NetMonitor Main Service" "$AUTO_ENABLE"

# Enable dashboard service (if installed)
if [ "$DASHBOARD_SERVER" = "gunicorn" ]; then
    enable_service "netmonitor-dashboard.service" "Web Dashboard (Gunicorn)" "$AUTO_ENABLE"
fi

# Enable MCP HTTP API (if installed)
if [ "$MCP_API_ENABLED" = "true" ]; then
    enable_service "netmonitor-mcp-http.service" "MCP HTTP API" "$AUTO_ENABLE"
fi

# Enable feed update timer
enable_service "netmonitor-feed-update.timer" "Threat Feed Update Timer" "$AUTO_ENABLE"

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
