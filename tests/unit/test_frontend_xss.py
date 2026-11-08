#!/usr/bin/env python3
"""Audit H1: draait tests/js/xss_render_test.js (vereist node; anders skip)."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_alert_rendering_escapes_untrusted_fields():
    node = shutil.which('node')
    if not node:
        pytest.skip('node niet geïnstalleerd')
    r = subprocess.run([node, str(ROOT / 'tests' / 'js' / 'xss_render_test.js')],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.unit
@pytest.mark.parametrize('template', ['dashboard.html', 'login.html', 'kiosk.html'])
def test_templates_load_shared_escape_helper(template):
    html = (ROOT / 'web' / 'templates' / template).read_text(encoding='utf-8')
    assert "filename='js/escape.js'" in html
    assert 'function escapeHtml' not in html   # geen lokale (zwakkere) kopie
