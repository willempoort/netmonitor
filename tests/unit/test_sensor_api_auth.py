#!/usr/bin/env python3
"""
Regressietests voor audit-bevinding K1: de sensor-API was zonder authenticatie
bereikbaar en het 'update'-commando kon via 'branch' shell-commando's als root
op een sensor laten uitvoeren.

Vereist flask_login (draai met venv/bin/python3 -m pytest); zonder flask_login
worden de route-tests overgeslagen, de sensor-client tests draaien altijd.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

SENSOR_ID = 'sensor-a'
TOKEN_DETAILS = {
    'token_id': 1, 'sensor_id': SENSOR_ID, 'token_name': 't', 'hostname': 'host-a',
    'location': None, 'status': 'online',
}


@pytest.fixture
def dash():
    pytest.importorskip('flask_login')
    import web_dashboard
    web_dashboard.app.config['TESTING'] = True
    fake_db = MagicMock()
    fake_db.get_sensor_by_id.return_value = {'sensor_id': SENSOR_ID}
    fake_db.create_sensor_command.return_value = 42
    fake_db.register_sensor.return_value = True
    fake_auth = MagicMock()
    fake_auth.validate_token.side_effect = (
        lambda token, perm=None: dict(TOKEN_DETAILS) if token == 'good-token' else None
    )
    with patch.object(web_dashboard, 'db', fake_db), \
            patch.object(web_dashboard, 'sensor_auth', fake_auth), \
            patch.object(web_dashboard, 'logger', MagicMock()):
        yield web_dashboard, fake_db, fake_auth


def _bearer(token='good-token'):
    return {'Authorization': f'Bearer {token}'}


SENSOR_ROUTES = [
    ('post', f'/api/sensors/{SENSOR_ID}/heartbeat', {}),
    ('post', f'/api/sensors/{SENSOR_ID}/metrics', {}),
    ('post', f'/api/sensors/{SENSOR_ID}/traffic', {}),
    ('post', f'/api/sensors/{SENSOR_ID}/alerts', {'alerts': []}),
    ('post', f'/api/sensors/{SENSOR_ID}/devices', {'devices': []}),
    ('get', f'/api/sensors/{SENSOR_ID}/commands', None),
    ('put', f'/api/sensors/{SENSOR_ID}/commands/1', {'status': 'completed'}),
    ('post', '/api/sensors/register', {'sensor_id': SENSOR_ID, 'hostname': 'h'}),
]


@pytest.mark.unit
@pytest.mark.parametrize('method,url,body', SENSOR_ROUTES)
def test_sensor_routes_reject_missing_token(dash, method, url, body):
    web_dashboard, fake_db, _ = dash
    client = web_dashboard.app.test_client()
    resp = getattr(client, method)(url, json=body)
    assert resp.status_code == 401
    fake_db.update_sensor_heartbeat.assert_not_called()
    fake_db.register_sensor.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize('method,url,body', SENSOR_ROUTES)
def test_sensor_routes_reject_invalid_token(dash, method, url, body):
    web_dashboard, _, _ = dash
    client = web_dashboard.app.test_client()
    resp = getattr(client, method)(url, json=body, headers=_bearer('wrong'))
    assert resp.status_code == 403


@pytest.mark.unit
def test_token_of_other_sensor_rejected_in_path(dash):
    web_dashboard, fake_db, _ = dash
    client = web_dashboard.app.test_client()
    resp = client.post('/api/sensors/sensor-b/alerts', json={'alerts': []}, headers=_bearer())
    assert resp.status_code == 403


@pytest.mark.unit
def test_token_of_other_sensor_rejected_on_register(dash):
    web_dashboard, fake_db, _ = dash
    client = web_dashboard.app.test_client()
    resp = client.post('/api/sensors/register', json={'sensor_id': 'sensor-b', 'hostname': 'h'},
                       headers=_bearer())
    assert resp.status_code == 403
    fake_db.register_sensor.assert_not_called()


@pytest.mark.unit
def test_register_with_own_token_succeeds(dash):
    web_dashboard, fake_db, _ = dash
    client = web_dashboard.app.test_client()
    resp = client.post('/api/sensors/register', json={'sensor_id': SENSOR_ID, 'hostname': 'h'},
                       headers=_bearer())
    assert resp.status_code == 200
    fake_db.register_sensor.assert_called_once()


@pytest.mark.unit
@pytest.mark.parametrize('method,url', [
    ('post', f'/api/sensors/{SENSOR_ID}/commands'),
    ('get', f'/api/sensors/{SENSOR_ID}'),
    ('get', f'/api/sensors/{SENSOR_ID}/commands/history'),
])
def test_dashboard_sensor_routes_require_login(dash, method, url):
    web_dashboard, fake_db, _ = dash
    client = web_dashboard.app.test_client()
    resp = getattr(client, method)(url, json={'command_type': 'reboot'})
    # Niet ingelogd: redirect naar login of 401, nooit uitvoeren
    assert resp.status_code in (302, 401)
    fake_db.create_sensor_command.assert_not_called()


@pytest.mark.unit
def test_sensor_token_cannot_create_commands(dash):
    """Een (gestolen) sensortoken mag geen commando's voor sensors aanmaken."""
    web_dashboard, fake_db, _ = dash
    client = web_dashboard.app.test_client()
    resp = client.post(f'/api/sensors/{SENSOR_ID}/commands', json={'command_type': 'reboot'},
                       headers=_bearer())
    assert resp.status_code in (302, 401)
    fake_db.create_sensor_command.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize('branch', [
    'main; id', 'main && curl x | sh', '$(id)', '`id`', '-c', '--upload-pack=x', 'a b', '', 'x' * 101,
])
def test_git_branch_regex_rejects_injection(dash, branch):
    web_dashboard, _, _ = dash
    assert not web_dashboard.GIT_BRANCH_RE.fullmatch(branch)


@pytest.mark.unit
@pytest.mark.parametrize('branch', ['main', 'claude/fix-x-YKCMt', 'release-2.5', 'v2.5.2'])
def test_git_branch_regex_accepts_valid(dash, branch):
    web_dashboard, _, _ = dash
    assert web_dashboard.GIT_BRANCH_RE.fullmatch(branch)


# ---------------------------------------------------------------- sensor-kant

def _bare_sensor_client():
    sensor_client = pytest.importorskip('sensor_client')
    client = sensor_client.SensorClient.__new__(sensor_client.SensorClient)
    client.logger = MagicMock()
    client.server_url = 'https://soc.example'
    client.sensor_id = SENSOR_ID
    client.ssl_verify = True
    client.token = 'tok'
    return sensor_client, client


def _run_update(branch):
    """Draai het echte 'update'-commando met gemockte subprocess/requests."""
    sensor_client, client = _bare_sensor_client()
    runs = []

    def fake_run(cmd, *a, **kw):
        runs.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 0, 'ok', '')

    with patch('subprocess.run', side_effect=fake_run), \
            patch('subprocess.Popen'), \
            patch.object(sensor_client.requests, 'put') as put, \
            patch.object(sensor_client.os.path, 'exists', return_value=False):
        client._execute_command({'id': 7, 'command_type': 'update',
                                 'parameters': {'branch': branch} if branch is not None else {}})
    return runs, put


def _update_invocation(runs):
    return [cmd for cmd, _ in runs if 'bash' in cmd]


@pytest.mark.unit
@pytest.mark.parametrize('branch', ['main; id', '$(id)', '`id`', '-c', 'a b', 'main && curl x|sh'])
def test_sensor_update_rejects_injected_branch(branch):
    runs, put = _run_update(branch)
    assert _update_invocation(runs) == []          # er draait niets
    reported = put.call_args.kwargs['json']['result']
    assert reported['success'] is False


@pytest.mark.unit
def test_sensor_update_passes_branch_as_argument_not_shellcode():
    runs, put = _run_update('claude/fix-x-YKCMt')
    (cmd,) = _update_invocation(runs)
    script = cmd[cmd.index('-c') + 1]
    assert 'claude/fix-x-YKCMt' not in script       # niet in de shellcode
    assert 'claude/fix-x-YKCMt' in cmd[cmd.index('-c') + 2:]   # wel als argv
    assert all(not kw.get('shell') for _, kw in runs)
    # statusupdate stuurt het token mee
    assert put.call_args.kwargs['headers']['Authorization'] == 'Bearer tok'


@pytest.mark.unit
def test_sensor_update_without_branch_runs_plain_pull():
    runs, _ = _run_update(None)
    (cmd,) = _update_invocation(runs)
    args = cmd[cmd.index('-c') + 2:]
    assert args[1] == ''                             # lege branch


@pytest.mark.unit
@pytest.mark.parametrize('branch', ['main; id', '$(id)', '-c'])
def test_sensor_branch_regex_rejects_injection(branch):
    sensor_client, _ = _bare_sensor_client()
    assert not sensor_client.GIT_BRANCH_RE.fullmatch(branch)


# ------------------------------------------------- overgangsmodus (tijdelijk)

@pytest.fixture
def dash_transition(dash):
    web_dashboard, fake_db, fake_auth = dash
    web_dashboard._tokenless_warned.clear()
    with patch.object(web_dashboard, 'config', {'sensor_auth': {'allow_missing_token': True}}):
        yield web_dashboard, fake_db, fake_auth


@pytest.mark.unit
def test_transition_allows_known_sensor_without_token(dash_transition):
    web_dashboard, fake_db, _ = dash_transition
    client = web_dashboard.app.test_client()
    resp = client.post(f'/api/sensors/{SENSOR_ID}/alerts', json={'alerts': []})
    assert resp.status_code != 401


@pytest.mark.unit
def test_transition_rejects_unknown_sensor_without_token(dash_transition):
    web_dashboard, fake_db, _ = dash_transition
    fake_db.get_sensor_by_id.return_value = None
    client = web_dashboard.app.test_client()
    resp = client.post('/api/sensors/unknown/heartbeat', json={})
    assert resp.status_code == 401
    resp = client.post('/api/sensors/register', json={'sensor_id': 'unknown', 'hostname': 'h'})
    assert resp.status_code == 401
    fake_db.register_sensor.assert_not_called()


@pytest.mark.unit
def test_transition_still_rejects_wrong_token(dash_transition):
    web_dashboard, _, _ = dash_transition
    client = web_dashboard.app.test_client()
    resp = client.post(f'/api/sensors/{SENSOR_ID}/heartbeat', json={}, headers=_bearer('wrong'))
    assert resp.status_code == 403


@pytest.mark.unit
def test_transition_never_allows_command_creation_without_login(dash_transition):
    web_dashboard, fake_db, _ = dash_transition
    client = web_dashboard.app.test_client()
    resp = client.post(f'/api/sensors/{SENSOR_ID}/commands',
                       json={'command_type': 'update', 'parameters': {'branch': 'main; id'}})
    assert resp.status_code in (302, 401)
    fake_db.create_sensor_command.assert_not_called()


@pytest.mark.unit
def test_transition_disabled_by_default(dash):
    web_dashboard, _, _ = dash
    with patch.object(web_dashboard, 'config', {}):
        client = web_dashboard.app.test_client()
        resp = client.post(f'/api/sensors/{SENSOR_ID}/heartbeat', json={})
    assert resp.status_code == 401
