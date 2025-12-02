#!/bin/bash
#
# NetMonitor Dashboard Icon Debug Tool
# Checks all Bootstrap icon dependencies
#

echo "=============================================="
echo "NetMonitor Dashboard Icon Debug"
echo "=============================================="
echo

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ISSUES=0

# Check if we're in the right directory
if [ ! -f "web_dashboard.py" ]; then
    echo -e "${RED}✗ Not in netmonitor directory${NC}"
    exit 1
fi

echo "📋 Step 1: Checking File Existence"
echo "-------------------------------------------"

# CSS Files
if [ -f "web/static/css/bootstrap.min.css" ]; then
    SIZE=$(stat -c%s web/static/css/bootstrap.min.css 2>/dev/null || stat -f%z web/static/css/bootstrap.min.css 2>/dev/null)
    if [ "$SIZE" -gt 10000 ]; then
        echo -e "${GREEN}✓${NC} bootstrap.min.css ($(numfmt --to=iec $SIZE 2>/dev/null || echo "$SIZE bytes"))"
    else
        echo -e "${RED}✗${NC} bootstrap.min.css exists but is too small ($SIZE bytes)"
        ISSUES=$((ISSUES+1))
    fi
else
    echo -e "${RED}✗${NC} bootstrap.min.css MISSING"
    ISSUES=$((ISSUES+1))
fi

if [ -f "web/static/css/bootstrap-icons.css" ]; then
    SIZE=$(stat -c%s web/static/css/bootstrap-icons.css 2>/dev/null || stat -f%z web/static/css/bootstrap-icons.css 2>/dev/null)
    if [ "$SIZE" -gt 10000 ]; then
        echo -e "${GREEN}✓${NC} bootstrap-icons.css ($(numfmt --to=iec $SIZE 2>/dev/null || echo "$SIZE bytes"))"
    else
        echo -e "${RED}✗${NC} bootstrap-icons.css exists but is too small ($SIZE bytes)"
        ISSUES=$((ISSUES+1))
    fi
else
    echo -e "${RED}✗${NC} bootstrap-icons.css MISSING"
    ISSUES=$((ISSUES+1))
fi

if [ -f "web/static/css/bootstrap-icons-fallback.css" ]; then
    echo -e "${GREEN}✓${NC} bootstrap-icons-fallback.css (Unicode emoji fallback)"
else
    echo -e "${YELLOW}⚠${NC} bootstrap-icons-fallback.css missing (fallback emojis won't work)"
fi

echo

# Font Files
echo "🔤 Step 2: Checking Font Files"
echo "-------------------------------------------"

if [ -f "web/static/fonts/bootstrap-icons.woff2" ]; then
    SIZE=$(stat -c%s web/static/fonts/bootstrap-icons.woff2 2>/dev/null || stat -f%z web/static/fonts/bootstrap-icons.woff2 2>/dev/null)
    if [ "$SIZE" -gt 100000 ]; then
        echo -e "${GREEN}✓${NC} bootstrap-icons.woff2 ($(numfmt --to=iec $SIZE 2>/dev/null || echo "$SIZE bytes"))"
    else
        echo -e "${RED}✗${NC} bootstrap-icons.woff2 exists but is too small ($SIZE bytes)"
        echo "  This file should be ~150KB. It may be corrupt or incomplete."
        ISSUES=$((ISSUES+1))
    fi
else
    echo -e "${RED}✗${NC} bootstrap-icons.woff2 MISSING (MOST IMPORTANT!)"
    ISSUES=$((ISSUES+1))
fi

if [ -f "web/static/fonts/bootstrap-icons.woff" ]; then
    SIZE=$(stat -c%s web/static/fonts/bootstrap-icons.woff 2>/dev/null || stat -f%z web/static/fonts/bootstrap-icons.woff 2>/dev/null)
    echo -e "${GREEN}✓${NC} bootstrap-icons.woff ($(numfmt --to=iec $SIZE 2>/dev/null || echo "$SIZE bytes")) - fallback"
else
    echo -e "${YELLOW}⚠${NC} bootstrap-icons.woff missing (optional fallback for old browsers)"
fi

echo

# Check CSS font paths
echo "🔍 Step 3: Checking CSS Font Paths"
echo "-------------------------------------------"

if [ -f "web/static/css/bootstrap-icons.css" ]; then
    # Check if CSS has correct paths
    if grep -q "/static/fonts/bootstrap-icons" web/static/css/bootstrap-icons.css; then
        echo -e "${GREEN}✓${NC} CSS uses correct path: /static/fonts/"

        # Show actual @font-face declaration
        echo "  Font-face declaration:"
        grep -A3 "@font-face" web/static/css/bootstrap-icons.css | head -4 | sed 's/^/    /'
    elif grep -q "fonts/bootstrap-icons" web/static/css/bootstrap-icons.css; then
        echo -e "${YELLOW}⚠${NC} CSS uses relative path: fonts/ (might work)"
        echo "  Font-face declaration:"
        grep -A3 "@font-face" web/static/css/bootstrap-icons.css | head -4 | sed 's/^/    /'
    elif grep -q "cdn.jsdelivr.net" web/static/css/bootstrap-icons.css; then
        echo -e "${RED}✗${NC} CSS still uses CDN URLs!"
        echo "  This will fail if browser has tracking protection enabled."
        echo "  Run: sed -i 's|https://cdn.jsdelivr.net/npm/bootstrap-icons@[^/]*/font/fonts/|/static/fonts/|g' web/static/css/bootstrap-icons.css"
        ISSUES=$((ISSUES+1))
    else
        echo -e "${YELLOW}⚠${NC} Cannot determine font path in CSS"
        echo "  Font-face declaration:"
        grep -A3 "@font-face" web/static/css/bootstrap-icons.css | head -4 | sed 's/^/    /'
    fi
fi

echo

# Check HTML template
echo "📄 Step 4: Checking HTML Template"
echo "-------------------------------------------"

if [ -f "web/templates/dashboard.html" ]; then
    if grep -q "bootstrap-icons.css" web/templates/dashboard.html; then
        echo -e "${GREEN}✓${NC} dashboard.html loads bootstrap-icons.css"
    else
        echo -e "${RED}✗${NC} dashboard.html does NOT load bootstrap-icons.css"
        ISSUES=$((ISSUES+1))
    fi

    if grep -q "bootstrap-icons-fallback.css" web/templates/dashboard.html; then
        echo -e "${GREEN}✓${NC} dashboard.html loads bootstrap-icons-fallback.css"
    else
        echo -e "${YELLOW}⚠${NC} dashboard.html does NOT load fallback CSS (emojis won't show)"
    fi
else
    echo -e "${RED}✗${NC} dashboard.html not found"
    ISSUES=$((ISSUES+1))
fi

echo

# Summary
echo "=============================================="
echo "Summary"
echo "=============================================="

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo
    echo "If icons still don't show:"
    echo "1. Open browser DevTools (F12)"
    echo "2. Go to 'Network' tab"
    echo "3. Filter by 'Fonts' or 'CSS'"
    echo "4. Refresh page (Ctrl+F5)"
    echo "5. Look for red/404 errors"
    echo
    echo "Common issues:"
    echo "  • Browser cache: Hard refresh with Ctrl+F5"
    echo "  • Flask not serving static files: Restart web_dashboard.py"
    echo "  • Wrong Flask static_folder path: Check web_dashboard.py"
else
    echo -e "${RED}✗ Found $ISSUES issue(s)${NC}"
    echo
    echo "=============================================="
    echo "Recommended Fixes:"
    echo "=============================================="
    echo

    if [ ! -f "web/static/fonts/bootstrap-icons.woff2" ] || [ "$(stat -c%s web/static/fonts/bootstrap-icons.woff2 2>/dev/null || stat -f%z web/static/fonts/bootstrap-icons.woff2 2>/dev/null)" -lt 100000 ]; then
        echo "1. Download Bootstrap icon fonts:"
        echo "   wget https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff2 -O web/static/fonts/bootstrap-icons.woff2"
        echo "   wget https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff -O web/static/fonts/bootstrap-icons.woff"
        echo
    fi

    if [ ! -f "web/static/css/bootstrap-icons.css" ]; then
        echo "2. Download Bootstrap Icons CSS:"
        echo "   wget https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css -O web/static/css/bootstrap-icons.css"
        echo "   sed -i 's|https://cdn.jsdelivr.net/npm/bootstrap-icons@[^/]*/font/fonts/|/static/fonts/|g' web/static/css/bootstrap-icons.css"
        echo
    fi

    if grep -q "cdn.jsdelivr.net" web/static/css/bootstrap-icons.css 2>/dev/null; then
        echo "3. Fix CSS font paths:"
        echo "   sed -i 's|https://cdn.jsdelivr.net/npm/bootstrap-icons@[^/]*/font/fonts/|/static/fonts/|g' web/static/css/bootstrap-icons.css"
        echo
    fi

    echo "Or run the complete update script:"
    echo "   bash update_bootstrap_and_defaults.sh"
fi

echo
echo "=============================================="
echo "Browser Debug Instructions:"
echo "=============================================="
echo
echo "1. Open dashboard in browser: http://$(hostname -I | awk '{print $1}'):8080"
echo "2. Press F12 to open Developer Tools"
echo "3. Click 'Network' tab"
echo "4. Refresh page (Ctrl+F5)"
echo "5. Look for:"
echo "   • Red items = failed to load (404)"
echo "   • bootstrap-icons.woff2 status code"
echo "   • Requested URL vs actual file location"
echo
echo "6. Click 'Console' tab"
echo "7. Look for:"
echo "   • Font loading errors"
echo "   • CSS warnings"
echo
