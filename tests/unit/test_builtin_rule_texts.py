# SPDX-License-Identifier: AGPL-3.0-only
"""Standaardregels: Engelse tekst, en bestaande DB-rijen met de oude
Nederlandse tekst worden bijgewerkt (aangepaste tekst blijft staan)."""
import logging
from unittest.mock import MagicMock

import pytest

from database import DatabaseManager
from rule_engine import BUILTIN_RULES, LEGACY_BUILTIN_TEXT

pytestmark = pytest.mark.unit


def test_every_builtin_rule_has_legacy_text():
    assert set(LEGACY_BUILTIN_TEXT) == {r['rule_key'] for r in BUILTIN_RULES}
    for r in BUILTIN_RULES:
        assert LEGACY_BUILTIN_TEXT[r['rule_key']][0] != r['name']


def test_init_updates_only_untouched_legacy_text():
    db = DatabaseManager.__new__(DatabaseManager)
    db.logger = logging.getLogger('test')
    conn, cur = MagicMock(), MagicMock()
    cur.rowcount = 0
    conn.cursor.return_value = cur
    db._get_connection = lambda: conn
    db._return_connection = lambda c: None

    db.init_builtin_detection_rules()

    rule = next(r for r in BUILTIN_RULES if r['rule_key'] == 'builtin.openvpn-out')
    old_name, old_desc = LEGACY_BUILTIN_TEXT['builtin.openvpn-out']
    calls = [(sql, params) for sql, params in (c.args for c in cur.execute.call_args_list)]
    name_updates = [p for sql, p in calls if 'SET name' in sql]
    desc_updates = [p for sql, p in calls if 'SET description' in sql]
    # WHERE ... name = <oude tekst>: een door de beheerder aangepaste naam matcht niet
    assert (rule['name'], 'builtin.openvpn-out', old_name) in name_updates
    assert (rule['description'], 'builtin.openvpn-out', old_desc) in desc_updates
    assert len(name_updates) == len(BUILTIN_RULES)
    conn.commit.assert_called_once()
