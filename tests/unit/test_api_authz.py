#!/usr/bin/env python3
"""
Regressietests audit M1 (data zonder login leesbaar) en M2 (schrijvende
routes zonder rolcheck). Vereist flask_login (venv/bin/python3 -m pytest).
"""

import time
from unittest.mock import MagicMock, patch

import pytest


def _user(role):
    u = MagicMock()
    u.is_authenticated = True
    u.is_active = True
    u.is_anonymous = False
    u.get_id.return_value = '1'
    u.username = f'{role}-user'
    u.role = role
    return u


@pytest.fixture
def dash():
    pytest.importorskip('flask_login')
    import web_dashboard
    web_dashboard.app.config['TESTING'] = True
    fake_db = MagicMock()
    fake_db.get_sensor_by_id.side_effect = lambda sid: {'sensor_id': sid} if sid == 'sensor-a' else None
    fake_db.get_all_config_parameters.return_value = []
    fake_db.get_threat_type_details.return_value = []
    fake_db.get_retention_config.return_value = {'alerts_days': 365, 'metrics_days': 90}
    fake_auth = MagicMock()
    fake_sensor_auth = MagicMock()
    fake_sensor_auth.validate_token.side_effect = (
        lambda t, p=None: {'sensor_id': 'sensor-a', 'hostname': 'h', 'token_id': 1} if t == 'tok-a' else None)
    web_dashboard._tokenless_warned.clear()
    with patch.object(web_dashboard, 'db', fake_db), \
            patch.object(web_dashboard, 'web_auth', fake_auth), \
            patch.object(web_dashboard, 'sensor_auth', fake_sensor_auth), \
            patch.object(web_dashboard, 'config', {}), \
            patch.object(web_dashboard, 'logger', MagicMock()):
        yield web_dashboard, fake_db, fake_auth


def _client(web_dashboard, fake_auth, role=None, remote='10.100.0.58'):
    c = web_dashboard.app.test_client()
    c.environ_base['REMOTE_ADDR'] = remote
    if role:
        fake_auth.get_user_by_id.return_value = _user(role)
        with c.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True
            sess['last_active'] = time.time()
    return c


# ------------------------------------------------------------------ M1

@pytest.mark.unit
@pytest.mark.parametrize('url', ['/api/config/parameters', '/api/threat-details/PORT_SCAN'])
def test_m1_data_routes_require_login(dash, url):
    web_dashboard, _, fake_auth = dash
    resp = _client(web_dashboard, fake_auth).get(url)
    assert resp.status_code in (302, 401)


@pytest.mark.unit
def test_m1_config_parameters_still_available_for_local_mcp(dash):
    web_dashboard, _, fake_auth = dash
    resp = _client(web_dashboard, fake_auth, remote='127.0.0.1').get('/api/config/parameters')
    assert resp.status_code == 200


@pytest.mark.unit
@pytest.mark.parametrize('url', ['/api/whitelist?sensor_id=whatever', '/api/config?sensor_id=whatever',
                                 '/api/whitelist?sensor_id=sensor-a'])
def test_m1_sensor_id_param_no_longer_bypasses_auth(dash, url):
    """Zonder overgangsmodus geeft ?sensor_id=... geen toegang meer."""
    web_dashboard, _, fake_auth = dash
    resp = _client(web_dashboard, fake_auth).get(url)
    assert resp.status_code == 401


@pytest.mark.unit
def test_m1_transition_mode_only_for_existing_sensor(dash):
    web_dashboard, _, fake_auth = dash
    with patch.object(web_dashboard, 'config', {'sensor_auth': {'allow_missing_token': True}}):
        c = _client(web_dashboard, fake_auth)
        assert c.get('/api/whitelist?sensor_id=whatever').status_code == 401
        assert c.get('/api/whitelist?sensor_id=sensor-a').status_code != 401


@pytest.mark.unit
def test_m1_sensor_token_limited_to_own_sensor_id(dash):
    web_dashboard, _, fake_auth = dash
    c = _client(web_dashboard, fake_auth)
    hdr = {'Authorization': 'Bearer tok-a'}
    assert c.get('/api/whitelist?sensor_id=sensor-b', headers=hdr).status_code == 403
    assert c.get('/api/whitelist?sensor_id=sensor-a', headers=hdr).status_code != 403


# ------------------------------------------------------------------ M2

WRITE_ROUTES = [
    ('delete', '/api/devices/10.0.0.5'),
    ('delete', '/api/device-templates/3'),
    ('post', '/api/device-templates'),
    ('delete', '/api/service-providers/2'),
    ('post', '/api/ml/train'),
    ('delete', '/api/pcap/sensors/x.pcap'),
]


@pytest.mark.unit
@pytest.mark.parametrize('method,url', WRITE_ROUTES + [('post', '/api/data-retention/cleanup')])
def test_m2_viewer_cannot_write(dash, method, url):
    web_dashboard, fake_db, fake_auth = dash
    resp = getattr(_client(web_dashboard, fake_auth, role='viewer'), method)(url, json={})
    assert resp.status_code == 403
    assert resp.get_json()['error'] == 'Insufficient permissions'


@pytest.mark.unit
@pytest.mark.parametrize('method,url', WRITE_ROUTES)
def test_m2_operator_can_write(dash, method, url):
    web_dashboard, _, fake_auth = dash
    resp = getattr(_client(web_dashboard, fake_auth, role='operator'), method)(url, json={})
    # 403 van de rolcheck = 'Insufficient permissions'; andere 403's (bv. builtin
    # templates niet verwijderen) zijn applicatielogica en betekenen dat de rol door mocht
    body = resp.get_json(silent=True) or {}
    assert resp.status_code != 401
    assert body.get('error') != 'Insufficient permissions'


@pytest.mark.unit
def test_m2_data_retention_cleanup_is_admin_only(dash):
    web_dashboard, _, fake_auth = dash
    assert _client(web_dashboard, fake_auth, role='operator').post('/api/data-retention/cleanup').status_code == 403
    assert _client(web_dashboard, fake_auth, role='admin').post('/api/data-retention/cleanup').status_code not in (401, 403)


@pytest.mark.unit
def test_m2_viewer_keeps_self_service(dash):
    web_dashboard, _, fake_auth = dash
    resp = _client(web_dashboard, fake_auth, role='viewer').post('/api/auth/extend-session')
    assert resp.status_code == 200
