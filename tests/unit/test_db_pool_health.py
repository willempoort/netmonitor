#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Unit tests: DatabaseManager._get_connection gooit dode pool-verbindingen weg
(PostgreSQL idle_session_timeout) in plaats van ze uit te delen.
"""

import time
from unittest.mock import MagicMock

import psycopg2
import pytest

from database import DatabaseManager


def _conn(alive=True, closed=0):
    c = MagicMock()
    c.closed = closed
    c.autocommit = False
    cur = MagicMock()
    if not alive:
        cur.execute.side_effect = psycopg2.OperationalError(
            'FATAL:  terminating connection due to idle-session timeout')
    c.cursor.return_value.__enter__.return_value = cur
    return c


def _db(conns):
    db = object.__new__(DatabaseManager)
    db.logger = MagicMock()
    db._db_max_conn = 5
    db._conn_last_used = {}
    db.connection_pool = MagicMock()
    db.connection_pool.getconn.side_effect = list(conns)
    return db


@pytest.mark.unit
class TestPoolHealth:
    def test_dead_idle_connection_is_replaced(self):
        dead, good = _conn(alive=False), _conn()
        db = _db([dead, good])
        db._conn_last_used[id(dead)] = time.time() - 600
        assert db._get_connection() is good
        db.connection_pool.putconn.assert_called_once_with(dead, close=True)
        good.rollback.assert_called_once()

    def test_closed_connection_is_replaced_without_query(self):
        closed, good = _conn(closed=1), _conn()
        db = _db([closed, good])
        assert db._get_connection() is good
        closed.cursor.assert_not_called()

    def test_recently_used_connection_is_not_pinged(self):
        conn = _conn()
        db = _db([conn])
        db._conn_last_used[id(conn)] = time.time()
        assert db._get_connection() is conn
        conn.cursor.assert_not_called()

    def test_return_records_time_and_drops_closed(self):
        db = _db([])
        ok, closed = _conn(), _conn(closed=1)
        db._return_connection(ok)
        assert id(ok) in db._conn_last_used
        db._return_connection(closed)
        db.connection_pool.putconn.assert_any_call(closed, close=True)
