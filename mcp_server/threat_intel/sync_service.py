#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025
"""
Threat Intelligence Sync Service

Periodically synchronizes external threat feeds to local PostgreSQL cache.
This reduces API calls to external services and improves response time.

Supported feeds:
- AbuseIPDB: IP reputation scores (requires API key)
- Tor Exit Nodes: Known Tor exit points (free, public list)
- Emerging Threats: Known bad IPs (free)
- Feodo Tracker: C2 server IPs (free)

Usage:
    # One-time sync
    python sync_service.py --sync-all

    # Run as daemon (syncs based on feed intervals)
    python sync_service.py --daemon

    # Sync specific feed
    python sync_service.py --feed tor_exits
"""

import os
import sys
import json
import asyncio
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass

import httpx
import psycopg2
from psycopg2.extras import execute_values, RealDictCursor
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ThreatIntelSync')

# Load environment
load_dotenv()


@dataclass
class FeedConfig:
    """Configuration for a threat intelligence feed"""
    name: str
    url: str
    feed_type: str  # ip_list, json_api, csv
    sync_interval_minutes: int = 60
    api_key_env_var: Optional[str] = None
    enabled: bool = True
    parser: Optional[str] = None  # Custom parser function name


# Feed configurations
FEEDS: Dict[str, FeedConfig] = {
    'tor_exits': FeedConfig(
        name='tor_exits',
        url='https://check.torproject.org/torbulkexitlist',
        feed_type='ip_list',
        sync_interval_minutes=60,
    ),
    'tor_relays': FeedConfig(
        name='tor_relays',
        url='https://onionoo.torproject.org/details?type=relay&running=true',
        feed_type='json_api',
        sync_interval_minutes=360,
        parser='parse_tor_relays',
    ),
    'feodo_c2': FeedConfig(
        name='feodo_c2',
        url='https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        feed_type='ip_list',
        sync_interval_minutes=60,
    ),
    'emerging_threats': FeedConfig(
        name='emerging_threats',
        url='https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
        feed_type='ip_list',
        sync_interval_minutes=360,
    ),
    'abuseipdb_blacklist': FeedConfig(
        name='abuseipdb_blacklist',
        url='https://api.abuseipdb.com/api/v2/blacklist',
        feed_type='json_api',
        sync_interval_minutes=1440,  # Daily
        api_key_env_var='ABUSEIPDB_API_KEY',
        parser='parse_abuseipdb_blacklist',
    ),
}


class ThreatIntelSync:
    """Synchronizes threat intelligence feeds to local database"""

    def __init__(self):
        self.db_config = {
            'host': os.environ.get('DB_HOST', 'localhost'),
            'database': os.environ.get('DB_NAME', 'netmonitor'),
            'user': os.environ.get('DB_USER', 'netmonitor'),
            'password': os.environ.get('DB_PASSWORD', 'netmonitor'),
        }
        self.http_client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self.http_client = httpx.AsyncClient(timeout=60.0)
        await self._init_schema()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.http_client:
            await self.http_client.aclose()

    def _get_connection(self):
        return psycopg2.connect(**self.db_config)

    async def _init_schema(self):
        """Initialize database schema if not exists"""
        schema_path = Path(__file__).parent / 'schema.sql'
        if not schema_path.exists():
            logger.error(f"Schema file not found: {schema_path}")
            return

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(schema_path.read_text())
            conn.commit()
            logger.info("Database schema initialized")
        except Exception as e:
            logger.error(f"Error initializing schema: {e}")
            conn.rollback()
        finally:
            conn.close()

    async def sync_feed(self, feed_name: str) -> Dict:
        """Sync a single feed"""
        if feed_name not in FEEDS:
            return {'error': f'Unknown feed: {feed_name}'}

        feed = FEEDS[feed_name]
        if not feed.enabled:
            return {'skipped': True, 'reason': 'Feed disabled'}

        # Check if API key required
        if feed.api_key_env_var:
            api_key = os.environ.get(feed.api_key_env_var)
            if not api_key:
                return {'error': f'Missing API key: {feed.api_key_env_var}'}

        logger.info(f"Syncing feed: {feed_name}")
        start_time = datetime.now()

        try:
            # Fetch data
            if feed.feed_type == 'ip_list':
                ips = await self._fetch_ip_list(feed)
            elif feed.feed_type == 'json_api':
                ips = await self._fetch_json_api(feed)
            else:
                return {'error': f'Unknown feed type: {feed.feed_type}'}

            # Store in database
            count = await self._store_ips(feed_name, ips)

            # Update feed status
            await self._update_feed_status(feed_name, feed, count, None)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Feed {feed_name}: synced {count} IPs in {duration:.1f}s")

            return {
                'feed': feed_name,
                'records_synced': count,
                'duration_seconds': duration,
            }

        except Exception as e:
            logger.error(f"Error syncing {feed_name}: {e}")
            await self._update_feed_status(feed_name, feed, 0, str(e))
            return {'error': str(e)}

    async def _fetch_ip_list(self, feed: FeedConfig) -> Set[str]:
        """Fetch plain text IP list"""
        headers = {}
        if feed.api_key_env_var:
            api_key = os.environ.get(feed.api_key_env_var)
            headers['Key'] = api_key

        response = await self.http_client.get(feed.url, headers=headers)
        response.raise_for_status()

        ips = set()
        for line in response.text.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            # Extract IP (might have additional info after space/tab)
            ip = line.split()[0] if ' ' in line or '\t' in line else line
            # Basic IP validation
            if self._is_valid_ip(ip):
                ips.add(ip)

        return ips

    async def _fetch_json_api(self, feed: FeedConfig) -> Set[str]:
        """Fetch JSON API and parse IPs"""
        headers = {'Accept': 'application/json'}
        if feed.api_key_env_var:
            api_key = os.environ.get(feed.api_key_env_var)
            headers['Key'] = api_key

        response = await self.http_client.get(feed.url, headers=headers)
        response.raise_for_status()

        data = response.json()

        # Use custom parser if specified
        if feed.parser:
            parser_func = getattr(self, feed.parser, None)
            if parser_func:
                return parser_func(data)

        # Default: look for 'data' array with 'ip' or 'ipAddress' fields
        ips = set()
        items = data.get('data', data.get('relays', data.get('results', [])))
        for item in items:
            ip = item.get('ip') or item.get('ipAddress') or item.get('or_addresses', [''])[0].split(':')[0]
            if ip and self._is_valid_ip(ip):
                ips.add(ip)

        return ips

    def parse_tor_relays(self, data: Dict) -> Set[str]:
        """Parse Tor relay list from Onionoo API"""
        ips = set()
        for relay in data.get('relays', []):
            # or_addresses contains IP:port pairs
            for addr in relay.get('or_addresses', []):
                ip = addr.split(':')[0]
                # Handle IPv6 brackets
                ip = ip.strip('[]')
                if self._is_valid_ip(ip):
                    ips.add(ip)
        return ips

    def parse_abuseipdb_blacklist(self, data: Dict) -> Set[str]:
        """Parse AbuseIPDB blacklist response"""
        ips = set()
        for item in data.get('data', []):
            ip = item.get('ipAddress')
            if ip and self._is_valid_ip(ip):
                ips.add(ip)
        return ips

    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP validation"""
        import ipaddress
        try:
            ipaddress.ip_address(ip.strip('[]'))
            return True
        except ValueError:
            return False

    async def _store_ips(self, feed_name: str, ips: Set[str]) -> int:
        """Store IPs in database with feed-specific flags"""
        if not ips:
            return 0

        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Determine which flags to set based on feed
            flag_mapping = {
                'tor_exits': {'is_tor_exit': True},
                'tor_relays': {'is_tor_relay': True},
                'feodo_c2': {'is_known_c2': True, 'is_known_attacker': True},
                'emerging_threats': {'is_known_attacker': True},
                'abuseipdb_blacklist': {'is_known_attacker': True},
            }
            flags = flag_mapping.get(feed_name, {})

            # Prepare data for upsert
            now = datetime.now()
            expires = now + timedelta(hours=24)

            # Build the SET clause for flags
            flag_columns = list(flags.keys())
            flag_values = [flags[k] for k in flag_columns]

            # Upsert IPs
            for ip in ips:
                try:
                    cursor.execute(f'''
                        INSERT INTO threat_intel_ip_cache (ip_address, {', '.join(flag_columns)}, sources, last_updated, expires_at)
                        VALUES (%s::inet, {', '.join(['%s'] * len(flag_values))}, %s::jsonb, %s, %s)
                        ON CONFLICT (ip_address) DO UPDATE SET
                            {', '.join(f'{col} = EXCLUDED.{col}' for col in flag_columns)},
                            sources = threat_intel_ip_cache.sources || EXCLUDED.sources,
                            last_updated = EXCLUDED.last_updated,
                            expires_at = EXCLUDED.expires_at
                    ''', (ip, *flag_values, json.dumps([feed_name]), now, expires))
                except Exception as e:
                    logger.debug(f"Error inserting IP {ip}: {e}")
                    continue

            conn.commit()
            return len(ips)

        except Exception as e:
            logger.error(f"Error storing IPs: {e}")
            conn.rollback()
            return 0
        finally:
            conn.close()

    async def _update_feed_status(self, feed_name: str, feed: FeedConfig, count: int, error: Optional[str]):
        """Update feed sync status in database"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            now = datetime.now()

            cursor.execute('''
                INSERT INTO threat_intel_feed_status (feed_name, feed_url, feed_type, last_sync, last_success, last_error, records_synced, sync_interval_minutes, enabled, api_key_env_var)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (feed_name) DO UPDATE SET
                    last_sync = EXCLUDED.last_sync,
                    last_success = CASE WHEN EXCLUDED.last_error IS NULL THEN EXCLUDED.last_sync ELSE threat_intel_feed_status.last_success END,
                    last_error = EXCLUDED.last_error,
                    records_synced = EXCLUDED.records_synced
            ''', (
                feed_name, feed.url, feed.feed_type,
                now,
                now if not error else None,
                error,
                count,
                feed.sync_interval_minutes,
                feed.enabled,
                feed.api_key_env_var
            ))
            conn.commit()
        except Exception as e:
            logger.error(f"Error updating feed status: {e}")
            conn.rollback()
        finally:
            conn.close()

    async def sync_all(self) -> Dict:
        """Sync all enabled feeds"""
        results = {}
        for feed_name in FEEDS:
            results[feed_name] = await self.sync_feed(feed_name)
        return results

    async def sync_due_feeds(self) -> Dict:
        """Sync feeds that are due for refresh"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''
                SELECT feed_name, last_sync, sync_interval_minutes
                FROM threat_intel_feed_status
                WHERE enabled = TRUE
            ''')
            status_map = {row['feed_name']: row for row in cursor.fetchall()}
        finally:
            conn.close()

        results = {}
        now = datetime.now()

        for feed_name, feed in FEEDS.items():
            if not feed.enabled:
                continue

            status = status_map.get(feed_name)
            if status is None:
                # Never synced, sync now
                results[feed_name] = await self.sync_feed(feed_name)
            else:
                last_sync = status['last_sync']
                interval = timedelta(minutes=status['sync_interval_minutes'])
                if last_sync is None or (now - last_sync) > interval:
                    results[feed_name] = await self.sync_feed(feed_name)
                else:
                    results[feed_name] = {'skipped': True, 'reason': 'Not due yet'}

        return results

    async def lookup_ip(self, ip: str) -> Optional[Dict]:
        """Look up IP in cache"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''
                SELECT *
                FROM threat_intel_ip_cache
                WHERE ip_address = %s::inet
            ''', (ip,))
            row = cursor.fetchone()
            if row:
                # Convert to dict and handle special types
                result = dict(row)
                result['ip_address'] = str(result['ip_address'])
                for key in ['first_seen', 'last_updated', 'expires_at', 'abuseipdb_last_reported']:
                    if result.get(key):
                        result[key] = result[key].isoformat()
                return result
            return None
        finally:
            conn.close()

    async def get_stats(self) -> Dict:
        """Get sync statistics"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            # Total IPs cached
            cursor.execute('SELECT COUNT(*) as total FROM threat_intel_ip_cache')
            total_ips = cursor.fetchone()['total']

            # IPs by category
            cursor.execute('''
                SELECT
                    COUNT(*) FILTER (WHERE is_tor_exit) as tor_exits,
                    COUNT(*) FILTER (WHERE is_tor_relay) as tor_relays,
                    COUNT(*) FILTER (WHERE is_known_c2) as known_c2,
                    COUNT(*) FILTER (WHERE is_known_attacker) as known_attackers,
                    COUNT(*) FILTER (WHERE threat_level = 'critical') as critical,
                    COUNT(*) FILTER (WHERE threat_level = 'high') as high,
                    COUNT(*) FILTER (WHERE threat_level = 'medium') as medium
                FROM threat_intel_ip_cache
            ''')
            categories = dict(cursor.fetchone())

            # Feed status
            cursor.execute('''
                SELECT feed_name, last_sync, last_success, records_synced, enabled
                FROM threat_intel_feed_status
            ''')
            feeds = [dict(row) for row in cursor.fetchall()]
            for feed in feeds:
                for key in ['last_sync', 'last_success']:
                    if feed.get(key):
                        feed[key] = feed[key].isoformat()

            return {
                'total_ips_cached': total_ips,
                'categories': categories,
                'feeds': feeds,
            }
        finally:
            conn.close()


async def run_daemon(sync_interval_minutes: int = 15):
    """Run as daemon, syncing feeds periodically"""
    logger.info(f"Starting threat intel sync daemon (interval: {sync_interval_minutes}m)")

    async with ThreatIntelSync() as syncer:
        while True:
            try:
                results = await syncer.sync_due_feeds()
                synced = [k for k, v in results.items() if not v.get('skipped')]
                if synced:
                    logger.info(f"Synced feeds: {', '.join(synced)}")
            except Exception as e:
                logger.error(f"Sync error: {e}")

            await asyncio.sleep(sync_interval_minutes * 60)


async def main():
    parser = argparse.ArgumentParser(description='Threat Intelligence Sync Service')
    parser.add_argument('--sync-all', action='store_true', help='Sync all feeds now')
    parser.add_argument('--feed', type=str, help='Sync specific feed')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    parser.add_argument('--interval', type=int, default=15, help='Daemon check interval (minutes)')
    parser.add_argument('--lookup', type=str, help='Look up IP in cache')
    parser.add_argument('--stats', action='store_true', help='Show sync statistics')
    parser.add_argument('--list-feeds', action='store_true', help='List available feeds')

    args = parser.parse_args()

    if args.list_feeds:
        print("\nAvailable feeds:")
        for name, feed in FEEDS.items():
            api_status = f" (requires {feed.api_key_env_var})" if feed.api_key_env_var else ""
            print(f"  - {name}: {feed.url}{api_status}")
        return

    if args.daemon:
        await run_daemon(args.interval)
        return

    async with ThreatIntelSync() as syncer:
        if args.sync_all:
            results = await syncer.sync_all()
            print(json.dumps(results, indent=2, default=str))
        elif args.feed:
            result = await syncer.sync_feed(args.feed)
            print(json.dumps(result, indent=2, default=str))
        elif args.lookup:
            result = await syncer.lookup_ip(args.lookup)
            if result:
                print(json.dumps(result, indent=2, default=str))
            else:
                print(f"IP {args.lookup} not found in cache")
        elif args.stats:
            stats = await syncer.get_stats()
            print(json.dumps(stats, indent=2, default=str))
        else:
            parser.print_help()


if __name__ == '__main__':
    asyncio.run(main())
