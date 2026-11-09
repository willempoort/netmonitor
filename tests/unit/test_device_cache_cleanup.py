# SPDX-License-Identifier: AGPL-3.0-only
"""device_cache bevat zowel DB-tijden (met tijdzone) als live tijden (zonder)."""
from datetime import datetime, timedelta, timezone

import pytest

from device_discovery import DeviceDiscovery, _to_local_naive

pytestmark = pytest.mark.unit


def test_cleanup_handles_aware_and_naive():
    dd = DeviceDiscovery(db_manager=None, sensor_id='t', config={})
    dd._running = False
    old_aware = datetime.now(timezone.utc) - timedelta(days=3)   # zoals uit PostgreSQL
    dd.device_cache = {
        'a': {'last_seen': old_aware, 'mac_address': None},
        'b': {'last_seen': datetime.now(), 'mac_address': None},
    }
    dd._cleanup_device_cache()  # gaf: can't subtract offset-naive and offset-aware datetimes
    assert list(dd.device_cache) == ['b']


def test_to_local_naive():
    aware = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
    naive = _to_local_naive(aware)
    assert naive.tzinfo is None
    assert _to_local_naive(None) is None
