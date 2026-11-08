#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Unit tests voor automatisch aanmelden (enrollment) van sensors:
- sensor_auth.token_fingerprint / validatie
- SensorClient aanmeldflow (requests gemockt)
"""

import logging
import os
import stat
from unittest.mock import MagicMock, patch

import pytest

sensor_client = pytest.importorskip('sensor_client')
from sensor_auth import SensorAuthManager, EnrollmentError, token_fingerprint


def _response(status, payload):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload
    r.text = str(payload)
    return r


@pytest.fixture
def client(tmp_path):
    c = object.__new__(sensor_client.SensorClient)
    c.logger = logging.getLogger('test.enrollment')
    c.server_url = 'https://soc.example.com:443'
    c.ssl_verify = True
    c.sensor_id = 'sensor-test'
    c.location = 'lab'
    c.token = None
    c.token_source = None
    c._pending_token = None
    c.enrollment_state = None
    c.token_file = str(tmp_path / '.sensor_token')
    c._detect_ip_address = lambda: '10.0.0.5'
    c._register_sensor = MagicMock(return_value=True)
    return c


@pytest.mark.unit
class TestFingerprint:
    def test_fingerprint_format_and_stable(self):
        fp = token_fingerprint('abc')
        assert fp == token_fingerprint('abc')
        assert len(fp) == 19 and fp.count('-') == 3

    def test_invalid_sensor_id_rejected_before_db(self):
        db = MagicMock()
        auth = SensorAuthManager(db)
        for bad in ['enrollments', 'a/b', '', None, 'x' * 65]:
            with pytest.raises(EnrollmentError):
                auth.request_enrollment(bad)
        db._get_connection.assert_not_called()


@pytest.mark.unit
class TestClientEnrollment:
    def test_new_enrollment_stores_token_0600_and_does_not_send_it(self, client):
        with patch.object(sensor_client.requests, 'post',
                          return_value=_response(202, {'token': 'tok-1', 'status': 'pending'})) as post:
            delay = client._check_enrollment()
        assert delay == 60
        assert client.enrollment_state == 'pending'
        assert client.token is None, 'pending token mag niet als Authorization mee'
        assert open(client.token_file).read().strip() == 'tok-1'
        assert stat.S_IMODE(os.stat(client.token_file).st_mode) == 0o600
        assert post.call_args.kwargs['json']['sensor_id'] == 'sensor-test'

    def test_refuses_enrollment_over_http(self, client):
        client.server_url = 'http://soc.example.com:8080'
        with patch.object(sensor_client.requests, 'post') as post:
            assert client._check_enrollment() is None
        post.assert_not_called()
        assert client.enrollment_state == 'blocked'

    def test_approved_token_from_file_is_used(self, client):
        client._write_token_file('tok-2')
        with patch.object(sensor_client.requests, 'get',
                          return_value=_response(200, {'status': 'approved'})):
            assert client._check_enrollment() is None
        assert client.token == 'tok-2'
        assert client.enrollment_state == 'approved'

    def test_rejected_removes_token_file_and_stops(self, client):
        client._write_token_file('tok-3')
        with patch.object(sensor_client.requests, 'get',
                          return_value=_response(200, {'status': 'rejected'})):
            assert client._check_enrollment() is None
        assert not os.path.exists(client.token_file)
        assert client.token is None
        assert client.enrollment_state == 'rejected'

    def test_unknown_token_triggers_new_request(self, client):
        client._write_token_file('tok-old')
        with patch.object(sensor_client.requests, 'get',
                          return_value=_response(404, {'status': 'unknown'})), \
             patch.object(sensor_client.requests, 'post',
                          return_value=_response(202, {'token': 'tok-new'})):
            client._init_enrollment()
        assert open(client.token_file).read().strip() == 'tok-new'
        assert client.enrollment_state == 'pending'

    def test_tick_registers_after_approval(self, client):
        client._pending_token = 'tok-4'
        client._enrollment_next = 0
        with patch.object(sensor_client.requests, 'get',
                          return_value=_response(200, {'status': 'approved'})):
            client._enrollment_tick()
        assert client.token == 'tok-4'
        client._register_sensor.assert_called_once()
        assert client._get_headers()['Authorization'] == 'Bearer tok-4'

    def test_already_pending_retries_later(self, client):
        with patch.object(sensor_client.requests, 'post',
                          return_value=_response(409, {'error': 'pending', 'code': 'already_pending'})):
            assert client._check_enrollment() == 300
        assert client.token is None
