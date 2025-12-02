#!/bin/bash
#
# Fix Bootstrap Icons CSS Font Paths
# Changes relative paths (./fonts/) to absolute paths (/static/fonts/)
#

set -e

INSTALL_DIR="/opt/netmonitor"

echo "=============================================="
echo "Bootstrap Icons CSS Path Fixer"
echo "=============================================="
echo

if [ ! -f "$INSTALL_DIR/web/static/css/bootstrap-icons.css" ]; then
    echo "❌ Error: bootstrap-icons.css not found at $INSTALL_DIR/web/static/css/"
    echo "   Run this script from /opt/netmonitor or set INSTALL_DIR correctly"
    exit 1
fi

echo "📋 Current font paths in CSS:"
grep "url(" "$INSTALL_DIR/web/static/css/bootstrap-icons.css" | head -2
echo

echo "🔧 Fixing font paths..."

# Fix the font paths
sed -i 's|url("./fonts/bootstrap-icons|url("/static/fonts/bootstrap-icons|g' "$INSTALL_DIR/web/static/css/bootstrap-icons.css"
sed -i "s|url('./fonts/bootstrap-icons|url('/static/fonts/bootstrap-icons|g" "$INSTALL_DIR/web/static/css/bootstrap-icons.css"

# Also fix CDN URLs if present (shouldn't be, but just in case)
sed -i 's|https://cdn.jsdelivr.net/npm/bootstrap-icons@[^/]*/font/fonts/|/static/fonts/|g' "$INSTALL_DIR/web/static/css/bootstrap-icons.css"

echo "✅ Font paths updated"
echo

echo "📋 New font paths in CSS:"
grep "url(" "$INSTALL_DIR/web/static/css/bootstrap-icons.css" | head -2
echo

echo "=============================================="
echo "✓ Done! Restart web dashboard and refresh browser (Ctrl+F5)"
echo "=============================================="
echo
echo "Restart command:"
echo "  sudo systemctl restart netmonitor"
echo
echo "Or if running manually:"
echo "  pkill -f web_dashboard.py"
echo "  cd $INSTALL_DIR && source venv/bin/activate && python3 web_dashboard.py &"
echo
