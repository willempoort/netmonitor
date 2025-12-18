#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
#
# NetMonitor Dashboard Assets Checker
#

echo "=========================================="
echo "NetMonitor Dashboard Assets Check"
echo "=========================================="
echo

# Check CSS files
echo "📋 CSS Files:"
if [ -f "web/static/css/bootstrap.min.css" ]; then
    SIZE=$(du -h web/static/css/bootstrap.min.css | cut -f1)
    echo "  ✓ bootstrap.min.css ($SIZE)"
else
    echo "  ✗ bootstrap.min.css MISSING"
fi

if [ -f "web/static/css/bootstrap-icons.css" ]; then
    SIZE=$(du -h web/static/css/bootstrap-icons.css | cut -f1)
    echo "  ✓ bootstrap-icons.css ($SIZE)"

    # Check font path in CSS
    FONT_PATH=$(grep -o "src:.*bootstrap-icons" web/static/css/bootstrap-icons.css | head -1)
    echo "    Font path: $FONT_PATH"

    if grep -q "/static/fonts/bootstrap-icons" web/static/css/bootstrap-icons.css; then
        echo "    ✓ Font path correct (/static/fonts/)"
    else
        echo "    ✗ Font path incorrect (should be /static/fonts/)"
    fi
else
    echo "  ✗ bootstrap-icons.css MISSING"
fi

if [ -f "web/static/css/bootstrap-icons-fallback.css" ]; then
    echo "  ✓ bootstrap-icons-fallback.css (Unicode emoji fallback)"
else
    echo "  ✗ bootstrap-icons-fallback.css MISSING"
fi

echo
echo "🔤 Font Files:"
if [ -f "web/static/fonts/bootstrap-icons.woff2" ]; then
    SIZE=$(du -h web/static/fonts/bootstrap-icons.woff2 | cut -f1)
    echo "  ✓ bootstrap-icons.woff2 ($SIZE)"
    if [ "$SIZE" = "0" ]; then
        echo "    ⚠ WARNING: File is 0 bytes!"
    fi
else
    echo "  ✗ bootstrap-icons.woff2 MISSING"
fi

if [ -f "web/static/fonts/bootstrap-icons.woff" ]; then
    SIZE=$(du -h web/static/fonts/bootstrap-icons.woff | cut -f1)
    echo "  ✓ bootstrap-icons.woff ($SIZE)"
else
    echo "  ℹ bootstrap-icons.woff not present (optional fallback)"
fi

echo
echo "📜 JavaScript Files:"
for js in bootstrap.bundle.min.js chart.umd.min.js socket.io.min.js; do
    if [ -f "web/static/js/$js" ]; then
        SIZE=$(du -h web/static/js/$js | cut -f1)
        echo "  ✓ $js ($SIZE)"
    else
        echo "  ✗ $js MISSING"
    fi
done

echo
echo "=========================================="
echo "Recommendations:"
echo "=========================================="

if [ ! -f "web/static/css/bootstrap-icons.css" ] || [ ! -f "web/static/fonts/bootstrap-icons.woff2" ]; then
    echo "⚠ Bootstrap Icons missing. Run:"
    echo "  bash update_bootstrap_and_defaults.sh"
fi

if [ -f "web/static/fonts/bootstrap-icons.woff2" ]; then
    SIZE_BYTES=$(stat -f%z web/static/fonts/bootstrap-icons.woff2 2>/dev/null || stat -c%s web/static/fonts/bootstrap-icons.woff2 2>/dev/null)
    if [ "$SIZE_BYTES" = "0" ]; then
        echo "⚠ Font file is 0 bytes. Download it with:"
        echo "  wget https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff2 -O web/static/fonts/bootstrap-icons.woff2"
    fi
fi

echo
