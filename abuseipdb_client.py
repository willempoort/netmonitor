# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
AbuseIPDB API Client
Real-time IP reputation lookups with persistent database caching
"""

import json
import time
import logging
import urllib.request
import urllib.error
import urllib.parse
from collections import deque
from datetime import datetime, timedelta
from typing import Optional, Dict


class AbuseIPDBClient:
    """Client voor AbuseIPDB API met database caching"""

    API_URL = 'https://api.abuseipdb.com/api/v2/check'

    def __init__(self, api_key: str, rate_limit: int = 1000, db=None):
        """
        Initialiseer AbuseIPDB client

        Args:
            api_key: AbuseIPDB API key
            rate_limit: Max queries per dag (default 1000 voor free tier)
            db: Database manager instance voor persistent caching
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.db = db
        self.logger = logging.getLogger('NetMonitor.AbuseIPDB')

        # Rate limiting
        self.query_history = deque(maxlen=rate_limit)
        self.daily_reset_time = time.time() + 86400  # 24 uur

        # In-memory cache voor snelle lookups (backed by database)
        self.cache = {}  # ip -> (result, timestamp)
        self.cache_ttl = 3600  # 1 uur voor in-memory cache
        self.db_cache_ttl = 86400  # 24 uur voor database cache
        self.cache_max_size = 10000  # Max entries in memory cache
        self.last_cache_cleanup = time.time()

        # Stats
        self.queries_today = 0
        self.cache_hits = 0
        self.db_cache_hits = 0

        # Load cached entries from database on startup
        if self.db:
            self._load_db_cache()

        if not self.api_key:
            self.logger.warning("AbuseIPDB API key niet geconfigureerd, real-time lookups disabled")
        else:
            self.logger.info(f"AbuseIPDB client geïnitialiseerd (rate limit: {rate_limit}/dag, db_cache: {len(self.cache)} entries)")

    def _load_db_cache(self):
        """Load cached AbuseIPDB results from database on startup"""
        if not self.db:
            return

        try:
            conn = self.db._get_connection()
            cursor = conn.cursor()

            # Load entries that have abuseipdb_score (were looked up via API)
            # and are not expired
            cursor.execute("""
                SELECT ip_address::text, abuseipdb_score, abuseipdb_reports,
                       abuseipdb_last_reported, last_updated,
                       is_tor_exit, is_vpn, is_proxy, is_datacenter
                FROM threat_intel_ip_cache
                WHERE abuseipdb_score IS NOT NULL
                  AND last_updated > NOW() - INTERVAL '24 hours'
            """)

            loaded = 0
            for row in cursor.fetchall():
                ip, score, reports, last_reported, last_updated, is_tor, is_vpn, is_proxy, is_dc = row
                result = {
                    'ipAddress': ip,
                    'abuseConfidenceScore': score or 0,
                    'totalReports': reports or 0,
                    'lastReportedAt': str(last_reported) if last_reported else None,
                    'isTor': is_tor,
                    'isVpn': is_vpn,
                    'isProxy': is_proxy,
                    'isDatacenter': is_dc,
                    '_from_db_cache': True
                }
                # Use last_updated as cache timestamp
                cache_time = last_updated.timestamp() if last_updated else time.time()
                self.cache[ip] = (result, cache_time)
                loaded += 1

            self.db._return_connection(conn)
            self.logger.info(f"Loaded {loaded} AbuseIPDB entries from database cache")

        except Exception as e:
            self.logger.error(f"Error loading database cache: {e}")

    def _save_to_db_cache(self, ip: str, result: Dict):
        """Save AbuseIPDB result to database cache"""
        if not self.db:
            return

        try:
            conn = self.db._get_connection()
            cursor = conn.cursor()

            score = result.get('abuseConfidenceScore', 0)
            reports = result.get('totalReports', 0)
            last_reported = result.get('lastReportedAt')
            is_tor = result.get('isTor', False)
            is_vpn = result.get('isVpn', False)
            is_proxy = result.get('isProxy', False)
            is_dc = result.get('isDatacenter', False)
            usage_type = result.get('usageType', '')

            # Detect datacenter from usage type
            if not is_dc and usage_type and 'hosting' in usage_type.lower():
                is_dc = True

            cursor.execute("""
                INSERT INTO threat_intel_ip_cache
                    (ip_address, abuseipdb_score, abuseipdb_reports, abuseipdb_last_reported,
                     is_tor_exit, is_vpn, is_proxy, is_datacenter, last_updated, expires_at)
                VALUES (%s::inet, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW() + INTERVAL '24 hours')
                ON CONFLICT (ip_address) DO UPDATE SET
                    abuseipdb_score = EXCLUDED.abuseipdb_score,
                    abuseipdb_reports = EXCLUDED.abuseipdb_reports,
                    abuseipdb_last_reported = EXCLUDED.abuseipdb_last_reported,
                    is_tor_exit = COALESCE(threat_intel_ip_cache.is_tor_exit, EXCLUDED.is_tor_exit),
                    is_vpn = COALESCE(threat_intel_ip_cache.is_vpn, EXCLUDED.is_vpn),
                    is_proxy = COALESCE(threat_intel_ip_cache.is_proxy, EXCLUDED.is_proxy),
                    is_datacenter = COALESCE(threat_intel_ip_cache.is_datacenter, EXCLUDED.is_datacenter),
                    last_updated = NOW(),
                    expires_at = NOW() + INTERVAL '24 hours'
            """, (ip, score, reports, last_reported, is_tor, is_vpn, is_proxy, is_dc))

            conn.commit()
            self.db._return_connection(conn)

        except Exception as e:
            self.logger.warning(f"Error saving to database cache: {e}")

    def _track_api_call(self, is_cache_hit: bool = False):
        """Track API call or cache hit in database for statistics"""
        if not self.db:
            return

        try:
            conn = self.db._get_connection()
            cursor = conn.cursor()

            if is_cache_hit:
                cursor.execute("""
                    INSERT INTO abuseipdb_api_stats (date, cache_hits, updated_at)
                    VALUES (CURRENT_DATE, 1, NOW())
                    ON CONFLICT (date) DO UPDATE SET
                        cache_hits = abuseipdb_api_stats.cache_hits + 1,
                        updated_at = NOW()
                """)
            else:
                cursor.execute("""
                    INSERT INTO abuseipdb_api_stats (date, api_calls, unique_ips_queried, updated_at)
                    VALUES (CURRENT_DATE, 1, 1, NOW())
                    ON CONFLICT (date) DO UPDATE SET
                        api_calls = abuseipdb_api_stats.api_calls + 1,
                        unique_ips_queried = abuseipdb_api_stats.unique_ips_queried + 1,
                        updated_at = NOW()
                """)

            conn.commit()
            self.db._return_connection(conn)

        except Exception as e:
            self.logger.debug(f"Error tracking API call: {e}")

    def check_ip(self, ip: str, max_age_days: int = 90) -> Optional[Dict]:
        """
        Check IP reputation via AbuseIPDB

        Args:
            ip: IP adres om te checken
            max_age_days: Max age van reports (default 90)

        Returns:
            Dict met IP info of None bij error
        """
        if not self.api_key:
            return None

        # Check in-memory cache first
        if ip in self.cache:
            result, timestamp = self.cache[ip]
            cache_age = time.time() - timestamp
            # Use db_cache_ttl for entries loaded from database
            ttl = self.db_cache_ttl if result.get('_from_db_cache') else self.cache_ttl
            if cache_age < ttl:
                self.cache_hits += 1
                if result.get('_from_db_cache'):
                    self.db_cache_hits += 1
                # Track cache hit in database (only every 10th hit to reduce DB writes)
                if self.cache_hits % 10 == 0:
                    self._track_api_call(is_cache_hit=True)
                self.logger.debug(f"Cache hit voor IP: {ip} (age: {cache_age:.0f}s)")
                return result

        # Check rate limit
        if not self._check_rate_limit():
            self.logger.warning("AbuseIPDB rate limit bereikt, query geskipped")
            return None

        # Query API
        try:
            params = {
                'ipAddress': ip,
                'maxAgeInDays': max_age_days,
                'verbose': ''
            }

            url = f"{self.API_URL}?{urllib.parse.urlencode(params)}"

            req = urllib.request.Request(
                url,
                headers={
                    'Key': self.api_key,
                    'Accept': 'application/json'
                }
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))

            result = data.get('data', {})

            # Cache result in memory
            self.cache[ip] = (result, time.time())

            # Also save to database cache for persistence across restarts
            self._save_to_db_cache(ip, result)

            # Track query in database for statistics
            self._track_api_call()

            # Track query
            self.query_history.append(time.time())
            self.queries_today += 1

            self.logger.debug(f"AbuseIPDB lookup voor {ip}: abuse score {result.get('abuseConfidenceScore', 0)}")

            return result

        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.logger.error("AbuseIPDB rate limit exceeded")
            else:
                self.logger.error(f"AbuseIPDB HTTP error {e.code}: {e.reason}")
            return None

        except urllib.error.URLError as e:
            self.logger.error(f"AbuseIPDB connection error: {e}")
            return None

        except Exception as e:
            self.logger.error(f"AbuseIPDB unexpected error: {e}")
            return None

    def _cleanup_cache(self):
        """Verwijder verlopen entries uit in-memory cache om geheugengroei te voorkomen"""
        current_time = time.time()
        # Cleanup elke 5 minuten
        if current_time - self.last_cache_cleanup < 300:
            return

        self.last_cache_cleanup = current_time
        expired = [
            ip for ip, (result, timestamp) in self.cache.items()
            if current_time - timestamp > (self.db_cache_ttl if result.get('_from_db_cache') else self.cache_ttl)
        ]
        for ip in expired:
            del self.cache[ip]

        # Als cache nog steeds te groot is, verwijder oudste entries
        if len(self.cache) > self.cache_max_size:
            sorted_entries = sorted(self.cache.items(), key=lambda x: x[1][1])
            to_remove = len(self.cache) - self.cache_max_size
            for ip, _ in sorted_entries[:to_remove]:
                del self.cache[ip]

        if expired:
            self.logger.debug(f"Cache cleanup: {len(expired)} verlopen entries verwijderd, {len(self.cache)} entries over")

    def _check_rate_limit(self) -> bool:
        """Check of we binnen rate limit zijn"""
        current_time = time.time()

        # Periodieke cache cleanup
        self._cleanup_cache()

        # Reset dagelijkse counter
        if current_time > self.daily_reset_time:
            self.queries_today = 0
            self.query_history.clear()
            self.daily_reset_time = current_time + 86400
            self.logger.info("AbuseIPDB dagelijkse rate limit gereset")

        # Check limit
        return self.queries_today < self.rate_limit

    def is_malicious(self, ip: str, threshold: int = 50) -> tuple:
        """
        Check of IP als malicious beschouwd wordt

        Args:
            ip: IP adres
            threshold: Abuse confidence score threshold (0-100)

        Returns:
            (is_malicious: bool, score: int, total_reports: int)
        """
        result = self.check_ip(ip)

        if not result:
            return False, 0, 0

        score = result.get('abuseConfidenceScore', 0)
        total_reports = result.get('totalReports', 0)

        return score >= threshold, score, total_reports

    def get_ip_info(self, ip: str) -> Dict:
        """
        Get uitgebreide IP info

        Returns:
            Dict met IP informatie
        """
        result = self.check_ip(ip)

        if not result:
            return {}

        return {
            'ip': result.get('ipAddress'),
            'abuse_score': result.get('abuseConfidenceScore', 0),
            'country': result.get('countryCode'),
            'usage_type': result.get('usageType'),
            'isp': result.get('isp'),
            'domain': result.get('domain'),
            'total_reports': result.get('totalReports', 0),
            'num_distinct_users': result.get('numDistinctUsers', 0),
            'last_reported': result.get('lastReportedAt'),
            'is_whitelisted': result.get('isWhitelisted', False)
        }

    def get_stats(self) -> Dict:
        """Get client statistieken"""
        total_lookups = self.queries_today + self.cache_hits
        return {
            'api_enabled': bool(self.api_key),
            'queries_today': self.queries_today,
            'rate_limit': self.rate_limit,
            'remaining_queries': max(0, self.rate_limit - self.queries_today),
            'cache_size': len(self.cache),
            'cache_hits': self.cache_hits,
            'db_cache_hits': self.db_cache_hits,
            'cache_hit_rate': f"{(self.cache_hits / max(1, total_lookups)) * 100:.1f}%",
            'db_cache_enabled': self.db is not None
        }

    def clear_cache(self):
        """Clear IP cache"""
        self.cache.clear()
        self.logger.info("AbuseIPDB cache gecleared")
