# SPDX-License-Identifier: AGPL-3.0-only
"""Sensor-whitelist: serverregels moeten dezelfde betekenis hebben als op de SOC-server."""
import pytest

from detector import ThreatDetector

pytestmark = pytest.mark.unit

# Echte regels uit de productie-database (2026-11-09), zoals /api/whitelist ze teruggeeft
ENTRIES = [
    {'id': 1, 'ip_cidr': '239.0.0.0/8', 'source_ip': None, 'target_ip': '239.0.0.0/8', 'port_filter': None, 'direction': 'inbound'},
    {'id': 2, 'ip_cidr': '10.100.0.91/32', 'source_ip': '10.100.0.91/32', 'target_ip': None, 'port_filter': None, 'direction': 'outbound'},
    {'id': 49, 'ip_cidr': '10.100.0.0/24', 'source_ip': '10.100.0.0/24', 'target_ip': '188.114.96.0/20', 'port_filter': None, 'direction': 'both'},
    {'id': 50, 'ip_cidr': '10.100.0.70/32', 'source_ip': '10.100.0.70/32', 'target_ip': '10.100.0.2/32', 'port_filter': '443', 'direction': 'both'},
    {'id': 60, 'ip_cidr': '192.168.5.0/24', 'source_ip': None, 'target_ip': None, 'port_filter': None, 'direction': 'inbound'},
]


@pytest.fixture
def det():
    d = ThreatDetector({'thresholds': {}, 'whitelist': [], 'blacklist': [],
                        'internal_networks': ['10.0.0.0/8']})
    assert d.set_remote_whitelist(ENTRIES) == len(ENTRIES)
    return d


def test_lan_to_cloudflare_whitelisted(det):
    assert det._is_whitelisted_v2('10.100.0.50', '188.114.97.3', 443)


def test_lan_traffic_elsewhere_not_whitelisted(det):
    # De oude sensorlogica negeerde dit allemaal (10.100.0.0/24 als bron OF doel)
    assert not det._is_whitelisted_v2('10.100.0.50', '8.8.8.8', 53)
    assert not det._is_whitelisted_v2('10.100.0.50', '10.100.0.60', 445)
    assert not det._is_whitelisted_v2('203.0.113.9', '10.100.0.50', 22)


def test_reverse_direction_not_whitelisted(det):
    assert not det._is_whitelisted_v2('188.114.97.3', '10.100.0.50', 51000)


def test_source_only_entry_is_one_way(det):
    assert det._is_whitelisted_v2('10.100.0.91', '1.2.3.4', 80)
    assert not det._is_whitelisted_v2('1.2.3.4', '10.100.0.91', 80)


def test_target_only_entry(det):
    assert det._is_whitelisted_v2('10.100.0.50', '239.255.255.250', 1900)


def test_port_filter(det):
    assert det._is_whitelisted_v2('10.100.0.70', '10.100.0.2', 443)
    assert not det._is_whitelisted_v2('10.100.0.70', '10.100.0.2', 22)
    assert not det._is_whitelisted_v2('10.100.0.70', '10.100.0.2', None)


def test_legacy_direction(det):
    assert det._is_whitelisted_v2('8.8.8.8', '192.168.5.10', 80)
    assert not det._is_whitelisted_v2('192.168.5.10', '8.8.8.8', 80)


def test_invalid_entry_skipped():
    d = ThreatDetector({'thresholds': {}, 'whitelist': [], 'blacklist': []})
    assert d.set_remote_whitelist([{'id': 9, 'source_ip': 'nonsense'}, ENTRIES[1]]) == 1


def test_sensor_client_keeps_rules(monkeypatch):
    """sensor_client._update_whitelist mag serverregels niet meer platslaan tot losse IP's."""
    import sensor_client

    class Resp:
        status_code = 200
        def json(self):
            return {'success': True, 'entries': ENTRIES}

    monkeypatch.setattr(sensor_client.requests, 'get', lambda *a, **k: Resp())
    client = sensor_client.SensorClient.__new__(sensor_client.SensorClient)
    client.server_url = 'https://soc.example'
    client.sensor_id = 'sensor-x'
    client.ssl_verify = True
    client.token = 't'
    client.config = {'whitelist': ['10.100.0.2']}
    client.detector = ThreatDetector({'thresholds': {}, 'whitelist': [], 'blacklist': []})
    import logging
    client.logger = logging.getLogger('test')
    client._get_headers = lambda: {}
    client._update_whitelist()
    d = client.detector
    assert d.config['whitelist'] == ['10.100.0.2']
    assert not d._is_whitelisted_v2('10.100.0.50', '8.8.8.8', 53)
    assert d._is_whitelisted_v2('10.100.0.50', '188.114.97.3', 443)
    assert d._is_whitelisted_v2('10.100.0.2', '8.8.8.8', 53)  # lokale (SOC-)whitelist
