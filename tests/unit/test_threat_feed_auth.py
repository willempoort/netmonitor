# SPDX-License-Identifier: AGPL-3.0-only
"""abuse.ch-feeds met Auth-Key (sinds 21-10-2026 verplicht voor URLhaus/ThreatFox)."""
import io
import logging
import urllib.error

import pytest

import threat_feeds
from threat_feeds import ThreatFeedManager

pytestmark = pytest.mark.unit
KEY = 'secret-key-123'


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_keyed_feed_skipped_without_key(tmp_path, monkeypatch, caplog):
    monkeypatch.delenv('ABUSE_CH_AUTH_KEY', raising=False)
    called = []
    monkeypatch.setattr(threat_feeds.urllib.request, 'urlopen', lambda *a, **k: called.append(1))
    mgr = ThreatFeedManager(cache_dir=str(tmp_path))
    with caplog.at_level(logging.WARNING):
        assert mgr.download_feed('urlhaus') is False
    assert not called
    assert 'Auth-Key' in caplog.text


def test_key_in_path_but_never_logged(tmp_path, monkeypatch, caplog):
    seen = {}

    def fake_urlopen(req, timeout):
        seen['url'] = req.full_url
        return FakeResp(b'"id","dateadded","url"\n"1","2026-11-09","http://bad.example/x"\n')

    monkeypatch.setattr(threat_feeds.urllib.request, 'urlopen', fake_urlopen)
    mgr = ThreatFeedManager(cache_dir=str(tmp_path), auth_key=KEY)
    with caplog.at_level(logging.DEBUG):
        assert mgr.download_feed('urlhaus', force=True)
    assert seen['url'] == f'https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/recent.csv'
    assert KEY not in caplog.text
    assert mgr.parse_urlhaus(tmp_path / 'urlhaus.csv') == 1


def test_env_key(tmp_path, monkeypatch):
    monkeypatch.setenv('ABUSE_CH_AUTH_KEY', KEY)
    assert ThreatFeedManager(cache_dir=str(tmp_path)).auth_key == KEY


def test_html_error_page_does_not_overwrite_cache(tmp_path, monkeypatch):
    cache = tmp_path / 'threatfox.csv'
    cache.write_text('good data')
    monkeypatch.setattr(threat_feeds.urllib.request, 'urlopen',
                        lambda *a, **k: FakeResp(b'<!DOCTYPE html><html>Gone</html>'))
    mgr = ThreatFeedManager(cache_dir=str(tmp_path), auth_key=KEY)
    assert mgr.download_feed('threatfox', force=True) is False
    assert cache.read_text() == 'good data'


def test_http_error_redacts_key(tmp_path, monkeypatch, caplog):
    def boom(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 404, 'Not Found', {}, None)
    monkeypatch.setattr(threat_feeds.urllib.request, 'urlopen', boom)
    mgr = ThreatFeedManager(cache_dir=str(tmp_path), auth_key=KEY)
    with caplog.at_level(logging.ERROR):
        assert mgr.download_feed('threatfox', force=True) is False
    assert KEY not in caplog.text and 'Auth-Key ongeldig' in caplog.text


def test_deprecated_sslbl_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(threat_feeds.urllib.request, 'urlopen',
                        lambda *a, **k: pytest.fail('should not download'))
    assert ThreatFeedManager(cache_dir=str(tmp_path)).download_feed('sslblacklist', force=True)
