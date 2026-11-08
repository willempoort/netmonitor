#!/usr/bin/env python3
"""
Regressietests voor audit-bevinding H2: Socket.IO accepteerde verbindingen
zonder login (met cors_allowed_origins="*"), waardoor iedereen live alerts en
dashboarddata kon ontvangen. Vereist flask_login/flask_socketio (venv).
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def dash():
    pytest.importorskip('flask_login')
    pytest.importorskip('flask_socketio')
    import web_dashboard
    web_dashboard.app.config['TESTING'] = True
    user = MagicMock()
    user.is_authenticated = True
    user.is_active = True
    user.is_anonymous = False
    user.get_id.return_value = '1'
    user.username = 'tester'
    user.role = 'viewer'
    fake_auth = MagicMock()
    fake_auth.get_user_by_id.return_value = user
    fake_db = MagicMock()
    fake_db.get_dashboard_data.return_value = {'ok': True}
    with patch.object(web_dashboard, 'web_auth', fake_auth), \
            patch.object(web_dashboard, 'db', fake_db), \
            patch.object(web_dashboard, 'logger', MagicMock()):
        yield web_dashboard


@pytest.mark.unit
def test_socket_connection_refused_without_login(dash):
    flask_client = dash.app.test_client()
    sio = dash.socketio.test_client(dash.app, flask_test_client=flask_client)
    assert not sio.is_connected()


@pytest.mark.unit
def test_socket_connection_allowed_with_login(dash):
    flask_client = dash.app.test_client()
    with flask_client.session_transaction() as sess:
        sess['_user_id'] = '1'
        sess['_fresh'] = True
        sess['last_active'] = __import__('time').time()
    sio = dash.socketio.test_client(dash.app, flask_test_client=flask_client)
    assert sio.is_connected()
    sio.emit('request_update')
    names = [m['name'] for m in sio.get_received()]
    assert 'dashboard_update' in names
    sio.disconnect()


@pytest.mark.unit
def test_socketio_does_not_allow_any_origin(dash):
    assert dash.socketio.server.eio.cors_allowed_origins != '*'
